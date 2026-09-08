"""Make a remote Infisical instance match the declarative manifest.

The order below is not cosmetic -- each step is a precondition for the next.
Projects must exist before environments; environments before folders; folders
before the secrets that live in them. Pruning goes last so that a run which
fails partway through has still converged everything it managed to write, and
has deleted nothing on the strength of an incomplete picture.

Failure policy: an individual secret that cannot be resolved or written records
an error and the run continues. One rotated-away SOPS key should not block the
other forty-nine secrets in the estate from converging. The caller (``cli``)
exits non-zero if any error was recorded.

Dry run performs every read -- project list, secret list -- and no write. It is
the safety net that answers "what is this about to do to production?", so it
must be honest about prunes in particular: an unexpected deletion list is
usually a manifest-generation bug, and the dry run is where you find out.

Nothing here prints a secret value. Dry-run output names coordinates only:
project, environment, folder, secret name.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from nixfisical.api import InfisicalClient, InfisicalError
from nixfisical.sops import SopsError, read_key

__all__ = ["Action", "ReconcileSummary", "reconcile", "folder_ancestors"]


@dataclass(frozen=True)
class Action:
    """One thing reconcile did, or would have done in a dry run.

    ``kind`` is the object type (``project``/``environment``/``folder``/
    ``secret``/``prune``), ``target`` its coordinate, ``result`` one of
    ``created``/``updated``/``exists``/``deleted``/``would-*``/``skipped``/
    ``error``.
    """

    kind: str
    target: str
    result: str
    detail: str = ""

    def render(self) -> str:
        line = f"{self.result:<14} {self.kind:<11} {self.target}"
        return f"{line}  -- {self.detail}" if self.detail else line


@dataclass
class ReconcileSummary:
    """Counts and a per-action log for one reconcile run."""

    dry_run: bool = False
    prune: bool = False
    projects_created: int = 0
    environments_created: int = 0
    folders_created: int = 0
    secrets_created: int = 0
    secrets_updated: int = 0
    secrets_pruned: int = 0
    groups_seen: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)

    def record(self, kind: str, target: str, result: str, detail: str = "") -> None:
        self.actions.append(Action(kind=kind, target=target, result=result, detail=detail))

    def fail(self, kind: str, target: str, detail: str) -> None:
        self.errors.append(f"{kind} {target}: {detail}")
        self.record(kind, target, "error", detail)

    @property
    def ok(self) -> bool:
        return not self.errors

    def headline(self) -> str:
        verb = "would apply" if self.dry_run else "applied"
        return (
            f"{verb}: projects +{self.projects_created}, "
            f"environments +{self.environments_created}, "
            f"folders +{self.folders_created}, "
            f"secrets +{self.secrets_created}/~{self.secrets_updated}, "
            f"pruned -{self.secrets_pruned}, errors {len(self.errors)}"
        )


def folder_ancestors(folder: str) -> list[tuple[str, str]]:
    """Expand ``/a/b/c`` into the ``(parent, leaf)`` pairs needed to create it.

    Returns ``[("/", "a"), ("/a", "b"), ("/a/b", "c")]``. The Infisical folder
    endpoint has no ``mkdir -p``: it takes a parent ``path`` that must already
    exist plus a leaf ``name``. The root ``/`` is not a folder anyone creates,
    so it never appears as a leaf.
    """
    segments = [segment for segment in folder.split("/") if segment]
    pairs: list[tuple[str, str]] = []
    parent = "/"
    for segment in segments:
        pairs.append((parent, segment))
        parent = f"{parent.rstrip('/')}/{segment}"
    return pairs


def _full_path(parent: str, leaf: str) -> str:
    return f"{parent.rstrip('/')}/{leaf}"


def _coordinate(entry: dict[str, Any]) -> str:
    """A printable coordinate for an entry. Never includes a value."""
    return (
        f"{entry.get('project')}/{entry.get('environment')}"
        f"{entry.get('folder')}:{entry.get('name')}"
    )


def reconcile(
    client: InfisicalClient,
    manifest: Iterable[dict[str, Any]],
    *,
    organization_id: str,
    prune: bool = True,
    dry_run: bool = False,
) -> ReconcileSummary:
    """Converge the instance onto ``manifest``.

    ``organization_id`` scopes the project listing; it comes from the admin
    file written at bootstrap.
    """
    entries = list(manifest)
    summary = ReconcileSummary(dry_run=dry_run, prune=prune)

    groups: set[str] = set()
    for entry in entries:
        for group in entry.get("groups") or []:
            if isinstance(group, str):
                groups.add(group)
    summary.groups_seen = sorted(groups)

    # -- 1. existing projects ---------------------------------------------
    try:
        project_ids = client.list_projects(organization_id)
    except InfisicalError as exc:
        summary.fail("organization", organization_id, f"could not list projects: {exc}")
        return summary

    # -- 2. missing projects ----------------------------------------------
    wanted_projects = sorted({str(entry["project"]) for entry in entries if entry.get("project")})
    for name in wanted_projects:
        if name in project_ids:
            summary.record("project", name, "exists")
            continue
        if dry_run:
            summary.record("project", name, "would-create")
            summary.projects_created += 1
            continue
        try:
            project_ids[name] = client.create_project(name)
        except InfisicalError as exc:
            summary.fail("project", name, str(exc))
            continue
        summary.projects_created += 1
        summary.record("project", name, "created")

    def resolve_project(entry: dict[str, Any]) -> str | None:
        """Project id for an entry, or None when it does not exist yet.

        In a dry run the project may legitimately not exist -- we did not
        create it. Downstream steps then log what they would do without an id,
        which is the honest thing to report.
        """
        return project_ids.get(str(entry.get("project")))

    # -- 3. environments ---------------------------------------------------
    env_pairs = sorted(
        {
            (str(entry["project"]), str(entry["environment"]))
            for entry in entries
            if entry.get("project") and entry.get("environment")
        }
    )
    for project_name, environment in env_pairs:
        target = f"{project_name}/{environment}"
        project_id = project_ids.get(project_name)
        if project_id is None:
            # Only reachable in a dry run, or after a project creation error.
            summary.record(
                "environment",
                target,
                "would-create" if dry_run else "skipped",
                "project does not exist yet",
            )
            if dry_run:
                summary.environments_created += 1
            continue
        if dry_run:
            summary.record("environment", target, "would-ensure")
            continue
        try:
            created = client.create_environment(
                project_id, name=environment, slug=environment
            )
        except InfisicalError as exc:
            summary.fail("environment", target, str(exc))
            continue
        if created:
            summary.environments_created += 1
        summary.record("environment", target, "created" if created else "exists")

    # -- 4. folders --------------------------------------------------------
    # Every ancestor of every declared folder, deduplicated, then sorted by
    # depth so a parent is always created before its children. Sorting by the
    # string alone is not enough: "/a/b" sorts before "/a" in no ordering we
    # want to depend on, and the API rejects a create whose parent is missing.
    folder_targets: set[tuple[str, str, str, str]] = set()
    for entry in entries:
        folder = str(entry.get("folder") or "/")
        if folder == "/":
            continue
        for parent, leaf in folder_ancestors(folder):
            folder_targets.add(
                (str(entry["project"]), str(entry["environment"]), parent, leaf)
            )

    for project_name, environment, parent, leaf in sorted(
        folder_targets, key=lambda item: (item[0], item[1], item[2].count("/"), item[2], item[3])
    ):
        target = f"{project_name}/{environment}{_full_path(parent, leaf)}"
        project_id = project_ids.get(project_name)
        if project_id is None:
            summary.record(
                "folder",
                target,
                "would-create" if dry_run else "skipped",
                "project does not exist yet",
            )
            if dry_run:
                summary.folders_created += 1
            continue
        if dry_run:
            summary.record("folder", target, "would-ensure")
            continue
        try:
            created = client.create_folder(
                project_id=project_id,
                environment=environment,
                path=parent,
                name=leaf,
            )
        except InfisicalError as exc:
            summary.fail("folder", target, str(exc))
            continue
        if created:
            summary.folders_created += 1
        summary.record("folder", target, "created" if created else "exists")

    # -- 5. secrets --------------------------------------------------------
    for entry in entries:
        target = _coordinate(entry)
        sops_file = entry.get("sopsFile")
        if not sops_file:
            summary.fail(
                "secret",
                target,
                f"no sopsFile for sopsKey {entry.get('sopsKey')!r} and no global default",
            )
            continue

        project_id = resolve_project(entry)
        if project_id is None:
            summary.record(
                "secret",
                target,
                "would-upsert" if dry_run else "skipped",
                "project does not exist yet",
            )
            if dry_run:
                summary.secrets_created += 1
            continue

        if dry_run:
            # Still resolve the value: a dry run that does not touch SOPS would
            # miss the single most common failure (a renamed or rotated key),
            # which is exactly what the operator is dry-running to find out.
            # The value is read and immediately discarded; it is never logged.
            try:
                read_key(Path(sops_file), str(entry["sopsKey"]))
            except SopsError as exc:
                summary.fail("secret", target, str(exc))
                continue
            summary.record("secret", target, "would-upsert", f"from {sops_file}")
            continue

        try:
            value = read_key(Path(sops_file), str(entry["sopsKey"]))
        except SopsError as exc:
            summary.fail("secret", target, str(exc))
            continue

        try:
            outcome = client.upsert_secret(
                str(entry["name"]),
                project_id=project_id,
                environment=str(entry["environment"]),
                secret_path=str(entry.get("folder") or "/"),
                value=value,
            )
        except InfisicalError as exc:
            summary.fail("secret", target, str(exc))
            continue
        finally:
            del value  # bound the plaintext's lifetime in this frame

        if outcome == "created":
            summary.secrets_created += 1
        else:
            summary.secrets_updated += 1
        summary.record("secret", target, outcome)

    # -- 6. prune ----------------------------------------------------------
    # Folders are never pruned. An empty folder is harmless, whereas deleting
    # one would cascade over anything a human put there out-of-band, and the
    # manifest does not claim to describe folder existence -- only secrets.
    if prune:
        declared: set[tuple[str, str, str, str]] = {
            (
                str(entry.get("project")),
                str(entry.get("environment")),
                str(entry.get("folder") or "/"),
                str(entry.get("name")),
            )
            for entry in entries
        }
        for project_name, environment in env_pairs:
            project_id = project_ids.get(project_name)
            if project_id is None:
                summary.record(
                    "prune",
                    f"{project_name}/{environment}",
                    "skipped",
                    "project does not exist yet",
                )
                continue
            try:
                live = client.list_secrets(
                    project_id=project_id, environment=environment, path="/"
                )
            except InfisicalError as exc:
                summary.fail("prune", f"{project_name}/{environment}", str(exc))
                continue

            for secret in live:
                key = secret.get("secretKey")
                path = secret.get("secretPath") or "/"
                if not key:
                    continue
                if (project_name, environment, path, key) in declared:
                    continue
                target = f"{project_name}/{environment}{path}:{key}"
                if dry_run:
                    summary.secrets_pruned += 1
                    summary.record("prune", target, "would-delete", "not in manifest")
                    continue
                try:
                    client.delete_secret(
                        key,
                        project_id=project_id,
                        environment=environment,
                        secret_path=path,
                    )
                except InfisicalError as exc:
                    summary.fail("prune", target, str(exc))
                    continue
                summary.secrets_pruned += 1
                summary.record("prune", target, "deleted", "not in manifest")

    # TODO(access): the Ansible role also reconciled group and host access to
    # each secret, and it did so by writing directly to Infisical's Postgres
    # (there was no supported API for project-group membership at the time).
    # That is out of scope for v0 and deliberately NOT ported: direct database
    # writes against a running Infisical are unversioned, unauthenticated by
    # the application's own rules, and silently break on upstream schema
    # changes. The manifest's `groups` and `hosts` fields are carried through
    # and reported so the data is ready when a supported API exists.

    return summary
