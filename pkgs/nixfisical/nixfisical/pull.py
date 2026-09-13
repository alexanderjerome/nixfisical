"""Write Infisical's copy of a secret back down into SOPS.

This is ``reconcile`` run backwards, over the subset of the manifest that
declares ``source = "infisical"``. Everything else about the estate is
unchanged: the value still lands in the same encrypted file at the same key,
sops-nix still delivers it to the host, ``restartUnits`` still fires. The only
thing that moves is where the value comes from.

The two commands partition the manifest rather than sharing it. ``sync`` writes
the values of ``source = "sops"`` entries and refuses to touch the others;
``pull`` does the reverse. No secret is ever written by both, so there is no
conflict to resolve and no last-writer-wins race between a developer's rotation
in the UI and an operator's stale checkout. That partition is the whole safety
argument for this module, and it is enforced in one place -- :func:`_wanted`.

Three things here were deliberate:

* **One API listing per (project, environment), not per secret.** The listing
  is recursive, so a project's whole tree arrives in one call and every entry
  in it is answered from a dict. A folder of thirty secrets costs one request.

* **One SOPS write per file, not per secret.** Writes are grouped by
  destination file and handed to ``sops.set_keys``. Per-secret writes would
  cost one key unwrap each -- one hardware touch each, on a token-backed key --
  which is the same round-trip problem the read side was built to avoid.

* **Unchanged means unwritten.** A pull that finds every value already correct
  writes no file, so it produces no diff and no commit. A scheduled import
  should be silent when there is no news, and an operator who sees a changed
  file should be able to trust that something actually changed.

Nothing here logs a value. Actions name coordinates, file paths and a verdict.
The verdict is itself derived from a plaintext comparison -- that comparison
happens in this process and its inputs are never rendered.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from nixfisical.api import InfisicalClient, InfisicalError
from nixfisical.manifest import entry_source
from nixfisical.sops import SopsError, set_keys

__all__ = ["PullAction", "PullSummary", "pull"]

# How a verdict reads in a dry run. `unchanged` is not conditional -- a key
# that already matches will still match after the write that is not happening,
# so "would-leave-alone" would be a hedge about the one thing this run is sure
# of.
_WOULD = {
    "created": "would-create",
    "updated": "would-update",
    "unchanged": "unchanged",
}


@dataclass(frozen=True)
class PullAction:
    """One thing the pull did, or would have done in a dry run."""

    kind: str
    target: str
    result: str
    detail: str = ""

    def render(self) -> str:
        line = f"{self.result:<14} {self.kind:<11} {self.target}"
        return f"{line}  -- {self.detail}" if self.detail else line


@dataclass
class PullSummary:
    """Counts and a per-action log for one pull run."""

    dry_run: bool = False
    secrets_created: int = 0
    secrets_updated: int = 0
    secrets_unchanged: int = 0
    files_written: int = 0
    considered: int = 0
    errors: list[str] = field(default_factory=list)
    actions: list[PullAction] = field(default_factory=list)

    def record(self, kind: str, target: str, result: str, detail: str = "") -> None:
        self.actions.append(PullAction(kind=kind, target=target, result=result, detail=detail))

    def fail(self, kind: str, target: str, detail: str) -> None:
        self.errors.append(f"{kind} {target}: {detail}")
        self.record(kind, target, "error", detail)

    @property
    def ok(self) -> bool:
        return not self.errors

    def headline(self) -> str:
        verb = "would write" if self.dry_run else "wrote"
        return (
            f"{verb}: secrets +{self.secrets_created}/~{self.secrets_updated}, "
            f"unchanged {self.secrets_unchanged}, files {self.files_written}, "
            f"errors {len(self.errors)}"
        )


def _normalise_folder(folder: Any) -> str:
    """Coerce a manifest ``folder`` to the form the API reports in ``secretPath``.

    Both sides say ``/`` for the root and ``/a/b`` for a nested folder, but the
    manifest's value has been through Nix and a JSON round trip and an empty
    string reaches here as a legitimate-looking "no folder". Anything falsy
    becomes the root, and a trailing slash is dropped so ``/mainnet/`` and
    ``/mainnet`` index the same bucket rather than missing each other.
    """
    text = str(folder or "/").strip() or "/"
    if text != "/" and text.endswith("/"):
        text = text.rstrip("/") or "/"
    return text


def _coordinate(entry: dict[str, Any]) -> str:
    """A printable coordinate for an entry. Never includes a value."""
    return (
        f"{entry.get('project')}/{entry.get('environment')}"
        f"{_normalise_folder(entry.get('folder'))}:{entry.get('name')}"
    )


def _wanted(manifest: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """The entries this command owns: exactly the ``source = "infisical"`` ones.

    The single place the push/pull partition is decided. ``reconcile`` makes
    the complementary test against the same helper, so the two sets cannot
    drift into overlapping.
    """
    return [entry for entry in manifest if entry_source(entry) == "infisical"]


def pull(
    client: InfisicalClient,
    manifest: Iterable[dict[str, Any]],
    *,
    organization_id: str,
    dry_run: bool = False,
) -> PullSummary:
    """Write every Infisical-owned secret in ``manifest`` into its SOPS file."""
    entries = _wanted(manifest)
    summary = PullSummary(dry_run=dry_run)
    summary.considered = len(entries)
    if not entries:
        return summary

    # -- 1. projects -------------------------------------------------------
    try:
        project_ids = client.list_projects(organization_id)
    except InfisicalError as exc:
        summary.fail("organization", organization_id, f"could not list projects: {exc}")
        return summary

    # -- 2. one recursive listing per (project, environment) ---------------
    #
    # Keyed by (secretPath, secretKey) to match how an entry addresses a
    # secret. A failed listing marks the pair rather than raising: one
    # unreachable project should not stop the other four from converging, and
    # the failure is recorded once here instead of once per secret under it.
    wanted_pairs = sorted(
        {
            (str(entry.get("project")), str(entry.get("environment")))
            for entry in entries
        }
    )
    live: dict[tuple[str, str], dict[tuple[str, str], str]] = {}
    unreadable: set[tuple[str, str]] = set()

    for project_name, environment in wanted_pairs:
        target = f"{project_name}/{environment}"
        project_id = project_ids.get(project_name)
        if project_id is None:
            summary.fail(
                "project",
                target,
                "project does not exist in this organization; run 'sync' first",
            )
            unreadable.add((project_name, environment))
            continue
        try:
            secrets = client.list_secrets(
                project_id=project_id, environment=environment, path="/"
            )
        except InfisicalError as exc:
            summary.fail("environment", target, str(exc))
            unreadable.add((project_name, environment))
            continue

        index: dict[tuple[str, str], str] = {}
        for secret in secrets:
            key = secret.get("secretKey")
            if not key:
                continue
            value = secret.get("secretValue")
            if value is None:
                # A secret the identity may see the name of but not the value
                # of. Left out of the index so the entry that wants it reports
                # "not found" with its own coordinate, rather than this loop
                # guessing at why.
                continue
            index[(_normalise_folder(secret.get("secretPath")), str(key))] = str(value)
        live[(project_name, environment)] = index

    # -- 3. resolve each entry to a (file, key, value) ---------------------
    #
    # Grouped by destination file so step 4 can write each file once. The
    # values dict holds plaintext; it is dropped at the end of this function
    # and never rendered into an action.
    planned: dict[Path, dict[str, str]] = {}
    labels: dict[Path, dict[str, str]] = {}

    for entry in entries:
        target = _coordinate(entry)
        pair = (str(entry.get("project")), str(entry.get("environment")))
        if pair in unreadable:
            summary.record("secret", target, "skipped", "its project could not be read")
            continue

        sops_file = entry.get("sopsFile")
        if not sops_file:
            summary.fail(
                "secret",
                target,
                f"no sopsFile for sopsKey {entry.get('sopsKey')!r} and no global default",
            )
            continue

        sops_key = str(entry.get("sopsKey") or "")
        if not sops_key:
            summary.fail("secret", target, "entry has no sopsKey to write to")
            continue

        index = live.get(pair, {})
        coordinate = (_normalise_folder(entry.get("folder")), str(entry.get("name")))
        if coordinate not in index:
            # The ordering failure this feature introduces, and the one worth
            # naming precisely: the estate declared a secret it expects the
            # instance to own, and the instance has never heard of it. Nothing
            # can invent the value, so this is an error, not a warning.
            summary.fail(
                "secret",
                target,
                "declared source=infisical but no such secret exists in the "
                "instance; create it there first",
            )
            continue

        destination = Path(sops_file)
        bucket = planned.setdefault(destination, {})
        if sops_key in bucket:
            # Two entries aiming different Infisical secrets at one SOPS key.
            # `validate` catches duplicate Infisical *destinations*; this is
            # the mirror-image collision on the SOPS side, which only the pull
            # direction can have.
            summary.fail(
                "secret",
                target,
                f"two entries both write {sops_key!r} in {destination}; "
                f"the other is {labels[destination][sops_key]}",
            )
            continue
        bucket[sops_key] = index[coordinate]
        labels.setdefault(destination, {})[sops_key] = target

    # -- 4. one write per file --------------------------------------------
    for destination in sorted(planned):
        values = planned[destination]
        label_for = labels[destination]

        try:
            if dry_run:
                verdicts = _classify(destination, values)
            else:
                verdicts = set_keys(destination, values)
        except SopsError as exc:
            summary.fail("file", str(destination), str(exc))
            continue
        finally:
            values.clear()  # bound the plaintext's lifetime in this frame

        changed = 0
        for sops_key, verdict in sorted(verdicts.items()):
            target = label_for.get(sops_key, sops_key)
            if verdict == "created":
                summary.secrets_created += 1
                changed += 1
            elif verdict == "updated":
                summary.secrets_updated += 1
                changed += 1
            else:
                summary.secrets_unchanged += 1
            summary.record(
                "secret",
                target,
                _WOULD[verdict] if dry_run else verdict,
                f"-> {destination}:{sops_key}",
            )

        if changed:
            summary.files_written += 1
            summary.record(
                "file",
                str(destination),
                "would-write" if dry_run else "written",
                f"{changed} key(s)",
            )

    return summary


def _classify(destination: Path, values: dict[str, str]) -> dict[str, str]:
    """Dry-run half of :func:`nixfisical.sops.set_keys`: verdicts, no write.

    Deliberately not implemented as ``set_keys(..., dry_run=True)``. Giving a
    function whose whole job is to write a file a flag that makes it not write
    the file is how a caller ends up one typo away from a silent no-op on the
    real path.

    The obligation it carries instead is to agree with ``set_keys`` on every
    input, because a dry run that classifies differently from the apply is
    worse than no dry run. Two places where the naive version does not:
    presence is tracked with a flag rather than by testing the value against
    ``None``, so a key explicitly set to YAML ``null`` reads as ``updated``
    here exactly as it does there; and the comparison goes through
    ``scalar_text``, so a boolean is not perpetually "changed".
    """
    from nixfisical.sops import decrypt_yaml, scalar_text

    document: dict[str, Any] = (
        decrypt_yaml(destination, use_cache=False) if destination.is_file() else {}
    )

    verdicts: dict[str, str] = {}
    for sops_key, value in values.items():
        cursor: Any = document
        found = True
        for segment in [part for part in sops_key.split("/") if part]:
            if not isinstance(cursor, dict) or segment not in cursor:
                found = False
                break
            cursor = cursor[segment]

        if not found:
            verdicts[sops_key] = "created"
        elif isinstance(cursor, (dict, list)):
            raise SopsError(
                f"cannot write {sops_key!r} in {destination}: it currently "
                "holds a collection, not a scalar"
            )
        else:
            verdicts[sops_key] = "unchanged" if scalar_text(cursor) == value else "updated"
    return verdicts
