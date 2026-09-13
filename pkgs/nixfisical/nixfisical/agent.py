"""The host-side half: fetch secrets from Infisical at boot, no SOPS involved.

Everything else in this package runs on an operator's machine. This runs on
the host, as root, before the units that need the values it writes. It reads a
world-readable spec from the Nix store (coordinates, destinations, ownership --
never a value), authenticates as that host's own machine identity, and
materialises each secret into a tmpfs.

**This is a different trust model, not a better one**, and the differences are
the whole reason it is opt-in per host rather than a replacement for the export
path:

* **The host holds a credential that can read secrets.** With sops-nix the host
  holds an age key that can only *decrypt what it was already given*. Here it
  holds an identity that can ask the instance for anything that identity may
  read, which is why :func:`nixfisical.provision.provision_host` creates it with
  the organization role ``no-access`` and adds it to named projects one at a
  time. A host identity scoped to the whole organization is a host that can
  read the whole fleet.

* **Boot now depends on the network.** sops-nix decrypts from local disk; this
  makes an unreachable instance a failure to start. It fails closed, which is
  right, but it means the secrets server is in the boot path of everything that
  consumes it. ``--cache`` trades that away for plaintext at rest -- read the
  option's docs before turning it on, because it gives back exactly the
  property the direct path was chosen for.

* **Rotation stops needing a deploy**, which is the point. A value changed in
  the instance reaches the host on the next agent run, and the units named in
  ``restartUnits`` are restarted because their input actually changed -- not
  because a store path moved.

The mechanics mirror :mod:`nixfisical.pull`: one recursive listing per
(project, environment), and a write only where the value differs from what is
already on disk. An unchanged run restarts nothing.
"""

from __future__ import annotations

import argparse
import grp
import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from nixfisical.api import InfisicalClient, InfisicalError, UniversalAuthCredentials

__all__ = ["AgentSpec", "AgentSummary", "SecretSpec", "materialise", "run", "main"]

SPEC_VERSION = 1


class AgentError(RuntimeError):
    """A failure the agent should report and exit 1 on."""


@dataclass(frozen=True)
class SecretSpec:
    """One secret to place on this host. Carries no value."""

    project: str
    environment: str
    folder: str
    name: str
    path: Path
    owner: str = "root"
    group: str = "root"
    mode: str = "0400"
    restart_units: tuple[str, ...] = ()
    project_id: str | None = None

    @property
    def coordinate(self) -> str:
        return f"{self.project}/{self.environment}{self.folder}:{self.name}"

    @classmethod
    def parse(cls, raw: Any, *, index: int) -> "SecretSpec":
        if not isinstance(raw, dict):
            raise AgentError(f"spec secret #{index} is not an object")
        missing = [
            field_name
            for field_name in ("project", "name", "path")
            if not raw.get(field_name)
        ]
        if missing:
            raise AgentError(
                f"spec secret #{index} is missing {', '.join(missing)}"
            )
        folder = str(raw.get("folder") or "/").strip() or "/"
        if folder != "/":
            folder = "/" + folder.strip("/")
        return cls(
            project=str(raw["project"]),
            environment=str(raw.get("environment") or "prod"),
            folder=folder,
            name=str(raw["name"]),
            path=Path(str(raw["path"])),
            owner=str(raw.get("owner") or "root"),
            group=str(raw.get("group") or "root"),
            mode=str(raw.get("mode") or "0400"),
            restart_units=tuple(str(unit) for unit in raw.get("restartUnits") or ()),
            project_id=str(raw["projectId"]) if raw.get("projectId") else None,
        )


@dataclass(frozen=True)
class AgentSpec:
    """The whole of what the module asked for. Generated into the Nix store."""

    url: str
    organization_id: str
    secrets: tuple[SecretSpec, ...]

    @classmethod
    def load(cls, path: Path) -> "AgentSpec":
        try:
            raw = json.loads(path.read_text())
        except OSError as exc:
            raise AgentError(f"cannot read spec {path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise AgentError(f"spec {path} is not valid JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise AgentError(f"spec {path} must be an object")
        version = raw.get("version")
        if version != SPEC_VERSION:
            # A host running an older agent than the module that wrote the spec
            # is the one case where guessing is worse than stopping: the fields
            # it does not understand are the ones that say who may read the
            # file.
            raise AgentError(
                f"spec {path} is version {version!r}, this agent speaks "
                f"{SPEC_VERSION}; the nixfisical package and the module that "
                "generated this spec are from different versions"
            )
        url = str(raw.get("url") or "").strip()
        if not url:
            raise AgentError(f"spec {path} has no url")
        secrets = raw.get("secrets")
        if not isinstance(secrets, list):
            raise AgentError(f"spec {path} has no secrets list")
        return cls(
            url=url,
            organization_id=str(raw.get("organizationId") or "").strip(),
            secrets=tuple(
                SecretSpec.parse(entry, index=index)
                for index, entry in enumerate(secrets)
            ),
        )


@dataclass
class AgentSummary:
    """What one run did. Rendered to stderr; never contains a value."""

    written: int = 0
    unchanged: int = 0
    from_cache: int = 0
    restarted: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def headline(self) -> str:
        cached = f", from cache {self.from_cache}" if self.from_cache else ""
        return (
            f"secrets written {self.written}, unchanged {self.unchanged}{cached}, "
            f"restarted {len(self.restarted)}, errors {len(self.errors)}"
        )


def _read_credential(path: Path, *, what: str) -> str:
    """Read a credential file, stripping the trailing newline an editor adds.

    Whitespace is stripped rather than preserved because every way this file is
    produced -- ``sops -d``, a here-doc, a systemd credential -- can append a
    newline, and the resulting failure is an "Invalid credentials" that looks
    like a wrong secret rather than a stray byte.
    """
    try:
        value = path.read_text().strip()
    except OSError as exc:
        raise AgentError(f"cannot read {what} from {path}: {exc}") from exc
    if not value:
        raise AgentError(f"{what} file {path} is empty")
    return value


def _resolve_ownership(secret: SecretSpec) -> tuple[int, int]:
    try:
        uid = pwd.getpwnam(secret.owner).pw_uid
    except KeyError as exc:
        raise AgentError(
            f"{secret.path}: no such user {secret.owner!r}. The unit that reads "
            "this secret and the user that owns it are declared in different "
            "places; they have drifted."
        ) from exc
    try:
        gid = grp.getgrnam(secret.group).gr_gid
    except KeyError as exc:
        raise AgentError(f"{secret.path}: no such group {secret.group!r}") from exc
    return uid, gid


def materialise(secret: SecretSpec, value: str) -> bool:
    """Place ``value`` at ``secret.path``. Return True if the file changed.

    Written to a temporary file in the destination's own directory and renamed
    into place, with ownership and mode set *before* the rename: a reader that
    opens the path during a run sees either the old file or the new one, never
    a half-written one and never one that is briefly world-readable.
    """
    uid, gid = _resolve_ownership(secret)
    try:
        mode = int(secret.mode, 8)
    except ValueError as exc:
        raise AgentError(f"{secret.path}: mode {secret.mode!r} is not octal") from exc

    destination = secret.path
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise AgentError(f"cannot create {destination.parent}: {exc}") from exc

    if destination.is_file():
        try:
            current = destination.read_text()
        except OSError:
            current = None
        if current == value:
            # Still enforce ownership and mode: those can drift without the
            # value changing (a hand-edited unit, a user recreated with a new
            # uid) and an unchanged value is no reason to leave a secret
            # readable by the wrong account.
            try:
                os.chown(destination, uid, gid)
                os.chmod(destination, mode)
            except OSError as exc:
                raise AgentError(f"cannot fix permissions on {destination}: {exc}") from exc
            return False

    tmp = None
    try:
        handle = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(destination.parent),
            prefix=f".{destination.name}.",
            delete=False,
        )
        tmp = Path(handle.name)
        with handle:
            os.fchmod(handle.fileno(), mode)
            os.fchown(handle.fileno(), uid, gid)
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, destination)
        tmp = None
    except OSError as exc:
        raise AgentError(f"cannot write {destination}: {exc}") from exc
    finally:
        if tmp is not None and tmp.exists():
            tmp.unlink(missing_ok=True)
    return True


def _fetch(
    client: InfisicalClient,
    secrets: Iterable[SecretSpec],
    *,
    organization_id: str,
) -> dict[tuple[str, str, str, str], str]:
    """Resolve every spec entry to a value, one listing per project/environment.

    Projects are addressed by id, and the spec names them by name, so something
    has to translate. The identity's own project listing is that something --
    which is also a permission check for free: a project this host was never
    granted simply is not in the map, and the error says so rather than
    surfacing as a 403 from a secrets call.

    ``projectId`` on an entry skips the lookup. It exists because that listing
    is the one call here that depends on what an *organization-scoped* endpoint
    will do for a ``no-access`` identity, and an estate that hits a wall there
    should have a way through that is not "grant the host more than it needs".
    """
    by_name: dict[str, str] = {}
    needs_lookup = any(s.project_id is None for s in secrets)
    if needs_lookup:
        if not organization_id:
            raise AgentError(
                "spec names projects by name but carries no organizationId, "
                "so they cannot be resolved to ids"
            )
        by_name = client.list_projects(organization_id)

    resolved: dict[str, str] = {}
    for secret in secrets:
        project_id = secret.project_id or by_name.get(secret.project)
        if project_id is None:
            raise AgentError(
                f"project {secret.project!r} is not visible to this host's "
                "identity; run 'nixfisical provision-host' to grant it, or set "
                "its projectId in the spec if this identity may not list "
                "projects"
            )
        resolved[secret.project] = project_id

    wanted = sorted({(s.project, s.environment) for s in secrets})
    values: dict[tuple[str, str, str, str], str] = {}
    for project, environment in wanted:
        listing = client.list_secrets(
            project_id=resolved[project], environment=environment, path="/"
        )
        for entry in listing:
            key = entry.get("secretKey")
            value = entry.get("secretValue")
            if not key or value is None:
                continue
            folder = str(entry.get("secretPath") or "/").strip() or "/"
            if folder != "/":
                folder = "/" + folder.strip("/")
            values[(project, environment, folder, str(key))] = str(value)
    return values


def _restart(units: Iterable[str], summary: AgentSummary) -> None:
    """Restart the units whose input changed, if this system has systemd.

    Only *active* units are restarted. Starting a unit that was deliberately
    stopped because its secret happened to rotate is a surprise the agent has
    no business springing, and at boot the consumer has not started yet and
    will read the new value on its own.
    """
    systemctl = shutil.which("systemctl")
    if systemctl is None:
        return
    for unit in sorted(set(units)):
        active = subprocess.run(
            [systemctl, "is-active", "--quiet", unit], check=False
        )
        if active.returncode != 0:
            continue
        result = subprocess.run(
            [systemctl, "restart", unit], check=False, capture_output=True, text=True
        )
        if result.returncode == 0:
            summary.restarted.append(unit)
        else:
            summary.errors.append(
                f"restart {unit}: {result.stderr.strip() or result.returncode}"
            )


def run(
    spec: AgentSpec,
    *,
    credentials: UniversalAuthCredentials,
    cache: Path | None = None,
    restart: bool = True,
    client: InfisicalClient | None = None,
) -> AgentSummary:
    """Fetch and place every secret in ``spec``. Returns what happened."""
    summary = AgentSummary()
    if not spec.secrets:
        return summary

    owned = client is None
    client = client or InfisicalClient(spec.url)
    degraded: str | None = None
    try:
        client.universal_auth_login(credentials)
        values = _fetch(client, spec.secrets, organization_id=spec.organization_id)
    except (InfisicalError, AgentError) as exc:
        if cache is None:
            summary.errors.append(str(exc))
            return summary
        # The cache exists for exactly this: a reboot during an instance
        # outage. It is a fallback, never a preference -- a run that used it
        # says so loudly, because a fleet quietly serving month-old secrets
        # from disk is the failure this feature could produce silently.
        degraded = str(exc)
        values = _load_cache(cache, spec.secrets, summary)
        if not values:
            summary.errors.append(f"{exc} (and the cache holds nothing usable)")
            return summary
    finally:
        if owned:
            client.close()

    if degraded:
        print(f"nixfisical-agent: DEGRADED, serving cached values: {degraded}", file=sys.stderr)

    to_restart: list[str] = []
    try:
        for secret in spec.secrets:
            key = (secret.project, secret.environment, secret.folder, secret.name)
            if key not in values:
                summary.errors.append(
                    f"{secret.coordinate}: no such secret in the instance"
                )
                continue
            try:
                changed = materialise(secret, values[key])
            except AgentError as exc:
                summary.errors.append(str(exc))
                continue
            if changed:
                summary.written += 1
                to_restart.extend(secret.restart_units)
            else:
                summary.unchanged += 1
            if degraded:
                summary.from_cache += 1

        if cache is not None and not degraded:
            _save_cache(cache, values, summary)
        if restart and to_restart:
            _restart(to_restart, summary)
    finally:
        values.clear()  # bound the plaintext's lifetime in this frame

    return summary


# -- the offline cache ------------------------------------------------------
#
# One file, not a tree: the whole thing is replaced atomically on a good run,
# so there is no state in which half the cache is fresh and half is stale.
# Keyed by coordinate, which means a spec that repoints a secret elsewhere
# still finds the right cached value, and a secret removed from the spec is
# simply never read again -- and is dropped from the file on the next good run,
# because that run writes only what it fetched.
#
# It holds plaintext. Everything about how it is written says so: 0700
# directory, 0600 file, root-owned, and the module that enables it says the
# same thing twice.

CACHE_FILE = "secrets.json"


def _cache_key(key: tuple[str, str, str, str]) -> str:
    return "\x1f".join(key)


def _save_cache(
    cache: Path, values: dict[tuple[str, str, str, str], str], summary: AgentSummary
) -> None:
    """Replace the cache with what this run fetched. Best effort, never fatal.

    A cache that cannot be written must not fail a run that already has the
    real values in hand: the secrets are placed, the host is correct, and the
    only thing lost is the next reboot's fallback. It is reported, not raised.
    """
    payload = {
        "version": SPEC_VERSION,
        "values": {_cache_key(key): value for key, value in values.items()},
    }
    tmp = None
    try:
        cache.mkdir(parents=True, exist_ok=True)
        os.chmod(cache, 0o700)
        handle = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=str(cache), prefix=f".{CACHE_FILE}.",
            delete=False,
        )
        tmp = Path(handle.name)
        with handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(payload, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, cache / CACHE_FILE)
        tmp = None
    except OSError as exc:
        summary.errors.append(f"cache {cache}: {exc}")
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)


def _load_cache(
    cache: Path, secrets: Iterable[SecretSpec], summary: AgentSummary
) -> dict[tuple[str, str, str, str], str]:
    """Read back the values this spec asks for. Missing ones are simply absent.

    They are not reported here: the caller's per-secret loop already says
    "no such secret" against the coordinate that wanted it, and a second
    message from this layer would name the same gap twice in different words.
    """
    path = cache / CACHE_FILE
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        summary.errors.append(f"cache {path} is unusable: {exc}")
        return {}

    stored = raw.get("values") if isinstance(raw, dict) else None
    if not isinstance(stored, dict):
        summary.errors.append(f"cache {path} has no values")
        return {}

    found: dict[tuple[str, str, str, str], str] = {}
    for secret in secrets:
        key = (secret.project, secret.environment, secret.folder, secret.name)
        value = stored.get(_cache_key(key))
        if isinstance(value, str):
            found[key] = value
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="nixfisical-agent",
        description="Fetch this host's secrets from Infisical and place them.",
    )
    parser.add_argument("--spec", required=True, type=Path, help="JSON spec to apply")
    parser.add_argument("--client-id-file", required=True, type=Path)
    parser.add_argument("--client-secret-file", required=True, type=Path)
    parser.add_argument(
        "--cache",
        type=Path,
        default=None,
        help="directory to keep a plaintext fallback copy in (off by default)",
    )
    parser.add_argument(
        "--no-restart",
        action="store_true",
        help="place secrets but do not restart the units that consume them",
    )
    args = parser.parse_args(argv)

    try:
        spec = AgentSpec.load(args.spec)
        credentials = UniversalAuthCredentials(
            client_id=_read_credential(args.client_id_file, what="client id"),
            client_secret=_read_credential(args.client_secret_file, what="client secret"),
        )
    except AgentError as exc:
        print(f"nixfisical-agent: {exc}", file=sys.stderr)
        return 1

    summary = run(
        spec,
        credentials=credentials,
        cache=args.cache,
        restart=not args.no_restart,
    )
    print(f"nixfisical-agent: {summary.headline()}", file=sys.stderr)
    for problem in summary.errors:
        print(f"nixfisical-agent: error: {problem}", file=sys.stderr)
    return 0 if summary.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
