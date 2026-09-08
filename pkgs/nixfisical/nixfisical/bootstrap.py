"""One-time initialisation of a freshly deployed Infisical instance.

The end state is: a superadmin exists, an organization exists, a Universal-Auth
machine identity named ``fleet-sync`` exists with admin role in that
organization, and every credential needed to drive the instance from now on
lives in a single SOPS-encrypted admin file.

``POST /api/v1/admin/bootstrap`` succeeds exactly once per instance, so the
idempotency question -- "has this already been done?" -- is the whole design
problem here. The Ansible role answered it by testing whether the admin file
existed on the control node. That is wrong in both directions: the file can
exist while the instance behind it was rebuilt (stale credentials, silently
broken syncs), and the file can be absent while the instance is perfectly
bootstrapped (a new control node, a lost checkout), in which case re-running
the role hits an instance that refuses to bootstrap and fails confusingly.

We answer it by *proving* it: read the recorded machine identity out of the
admin file and log in with it.

* login succeeds -> already bootstrapped; do nothing, exit 0.
* login fails    -> stop. Do not re-bootstrap. Re-bootstrapping is destructive
                    (it would mint a second identity, or fail against a live
                    instance and leave the operator guessing). Tell the
                    operator the credentials are stale and make them opt in
                    with ``--force``.
* no admin file  -> fresh bootstrap.
"""

from __future__ import annotations

import os
import secrets as _secrets
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from nixfisical.api import InfisicalClient, InfisicalError, UniversalAuthCredentials
from nixfisical.sops import SopsError, encrypt_in_place, extract, sops_key_expr

__all__ = [
    "BootstrapError",
    "BootstrapResult",
    "AdminCredentials",
    "bootstrap",
    "read_sync_credentials",
    "read_organization_id",
    "DEFAULT_COMMIT_MESSAGE",
]

DEFAULT_COMMIT_MESSAGE = "chore(infisical): bootstrap admin credentials"

# Key paths inside the admin file, in manifest ("a/b") notation.
_KEY_CLIENT_ID = "sync_identity/client_id"
_KEY_CLIENT_SECRET = "sync_identity/client_secret"
_KEY_ORG_ID = "organization/id"


class BootstrapError(RuntimeError):
    """Bootstrap could not be completed, or must not be attempted."""


@dataclass(frozen=True)
class AdminCredentials:
    """The superadmin login for the instance.

    ``generated`` records that we invented the password rather than reading it
    from SOPS, which the caller surfaces so the operator knows the admin file
    is now the only copy.
    """

    email: str
    password: str
    generated: bool = False

    def __repr__(self) -> str:  # pragma: no cover - defensive formatting
        return f"AdminCredentials(email={self.email!r}, password=<redacted>, generated={self.generated})"


@dataclass
class BootstrapResult:
    """Outcome of a :func:`bootstrap` call.

    ``status`` is ``"ok"`` when the instance was already bootstrapped and we
    verified it, ``"bootstrapped"`` when we performed the initialisation.
    """

    status: str
    admin_file: Path
    organization_id: str | None = None
    organization_name: str | None = None
    organization_slug: str | None = None
    identity_id: str | None = None
    client_id: str | None = None
    password_generated: bool = False
    committed: bool = False
    messages: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Admin-file reads
# --------------------------------------------------------------------------


def read_sync_credentials(admin_file: Path) -> UniversalAuthCredentials:
    """Extract the sync identity's Universal Auth credentials from the admin file.

    Uses per-key ``sops --extract`` rather than a whole-file decrypt: this is
    two small reads, and it keeps the superadmin password out of this process's
    memory entirely for the common ``sync`` path.
    """
    client_id = extract(admin_file, sops_key_expr(_KEY_CLIENT_ID))
    client_secret = extract(admin_file, sops_key_expr(_KEY_CLIENT_SECRET))
    return UniversalAuthCredentials(client_id=client_id, client_secret=client_secret)


def read_organization_id(admin_file: Path) -> str:
    """Extract the organization id recorded at bootstrap time.

    Every project listing is scoped to an organization, so ``sync`` needs this
    before it can do anything. It is not secret, but it lives in the encrypted
    file because that is where bootstrap recorded it.
    """
    return extract(admin_file, sops_key_expr(_KEY_ORG_ID))


def _verify_existing(
    client: InfisicalClient, admin_file: Path
) -> tuple[bool, str]:
    """Try to authenticate with the admin file's identity.

    Returns ``(ok, detail)``. ``detail`` is a safe, human-readable reason on
    failure -- never a credential.
    """
    try:
        credentials = read_sync_credentials(admin_file)
    except SopsError as exc:
        return False, f"could not read credentials from the admin file: {exc}"

    try:
        client.universal_auth_login(credentials)
    except InfisicalError as exc:
        return False, f"universal auth login was rejected: {exc}"
    return True, "universal auth login succeeded"


# --------------------------------------------------------------------------
# Credential sourcing
# --------------------------------------------------------------------------


def _split_file_key(spec: str, default_file: Path | None, *, what: str) -> tuple[Path, str]:
    """Parse a ``FILE:KEY`` or bare ``KEY`` credential reference.

    A bare key resolves against ``default_file`` (the ``--secrets-file``
    option). The colon split is on the *last* colon so Windows-style or
    colon-bearing paths do not confuse it -- keys never contain colons, paths
    conceivably do.
    """
    if ":" in spec:
        file_part, _, key_part = spec.rpartition(":")
        if file_part and key_part:
            return Path(file_part).expanduser(), key_part
    if default_file is None:
        raise BootstrapError(
            f"{what} was given as a bare key {spec!r} but no --secrets-file was set; "
            f"pass --secrets-file, or write the option as FILE:KEY"
        )
    return default_file, spec


def resolve_admin_credentials(
    *,
    email: str | None,
    email_ref: str | None,
    password_ref: str | None,
    secrets_file: Path | None,
) -> AdminCredentials:
    """Work out the superadmin email and password for a fresh bootstrap.

    Resolution order, documented in the CLI help and the README:

    * email: ``--admin-email`` literal wins (an address is not secret), else
      ``--admin-email-from`` (``FILE:KEY`` or a bare key against
      ``--secrets-file``). One of the two is required.
    * password: ``--admin-password-from`` if given, otherwise a fresh
      ``secrets.token_urlsafe(32)``. Generating is the better default -- nobody
      logs in as the superadmin during normal operation, and a password that
      only ever existed inside the encrypted admin file cannot have been
      reused.
    """
    if email:
        resolved_email = email
    elif email_ref:
        file, key = _split_file_key(email_ref, secrets_file, what="--admin-email-from")
        resolved_email = extract(file, sops_key_expr(key))
    else:
        raise BootstrapError(
            "no superadmin email: pass --admin-email, or --admin-email-from FILE:KEY"
        )

    if password_ref:
        file, key = _split_file_key(
            password_ref, secrets_file, what="--admin-password-from"
        )
        return AdminCredentials(
            email=resolved_email, password=extract(file, sops_key_expr(key))
        )

    return AdminCredentials(
        email=resolved_email, password=_secrets.token_urlsafe(32), generated=True
    )


# --------------------------------------------------------------------------
# Admin-file write
# --------------------------------------------------------------------------


def build_admin_document(
    *,
    credentials: AdminCredentials,
    user_id: str,
    organization: dict[str, Any],
    identity_id: str,
    client_id: str,
    client_secret: str,
) -> dict[str, Any]:
    """Assemble the admin-file document. Shape is fixed by the Ansible role."""
    return {
        "admin": {
            "email": credentials.email,
            "password": credentials.password,
            "user_id": user_id,
        },
        "organization": {
            "id": organization.get("id", ""),
            "name": organization.get("name", ""),
            "slug": organization.get("slug", ""),
        },
        "sync_identity": {
            "id": identity_id,
            "client_id": client_id,
            "client_secret": client_secret,
        },
    }


def write_admin_file(path: Path, document: dict[str, Any]) -> None:
    """Write the admin document as YAML, then encrypt it in place.

    The plaintext window is as narrow as we can make it:

    * the file is created with ``O_CREAT | O_EXCL`` and mode 0600, so it is
      never briefly world-readable and never silently clobbers an existing
      admin file;
    * if ``sops --encrypt`` fails for any reason, the plaintext is deleted and
      the error re-raised. Leaving readable superadmin credentials on disk
      because encryption failed would be a far worse outcome than losing the
      bootstrap and having to start from a clean instance.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            yaml.safe_dump(document, handle, default_flow_style=False, sort_keys=True)
    except Exception:
        path.unlink(missing_ok=True)
        raise

    try:
        encrypt_in_place(path)
    except Exception:
        # Critical: never leave plaintext credentials behind.
        path.unlink(missing_ok=True)
        raise


def git_commit_admin_file(path: Path, message: str) -> tuple[bool, str]:
    """``git add`` + ``git commit`` the encrypted admin file in its own repo.

    Deliberately does not push: pushing credentials, even encrypted ones, is an
    operator decision that should be visible in shell history, not a side
    effect of a bootstrap command. Returns ``(committed, detail)``; a repo with
    nothing to commit is a success, not an error.
    """
    path = Path(path)
    try:
        toplevel = subprocess.run(  # noqa: S603
            ["git", "-C", str(path.parent), "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return False, "git is not on PATH; skipped commit"

    if toplevel.returncode != 0:
        return False, f"{path.parent} is not inside a git repository; skipped commit"
    repo = toplevel.stdout.strip()

    add = subprocess.run(  # noqa: S603
        ["git", "-C", repo, "add", "--", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if add.returncode != 0:
        return False, f"git add failed: {add.stderr.strip()}"

    staged = subprocess.run(  # noqa: S603
        ["git", "-C", repo, "diff", "--cached", "--quiet", "--", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if staged.returncode == 0:
        return False, "admin file is already committed and unchanged"

    commit = subprocess.run(  # noqa: S603
        ["git", "-C", repo, "commit", "-m", message, "--", str(path)],
        capture_output=True,
        text=True,
        check=False,
    )
    if commit.returncode != 0:
        return False, f"git commit failed: {commit.stderr.strip() or commit.stdout.strip()}"
    return True, f"committed {path.name} in {repo} (not pushed)"


# --------------------------------------------------------------------------
# The flow
# --------------------------------------------------------------------------


def bootstrap(
    client: InfisicalClient,
    *,
    admin_file: Path,
    organization: str,
    email: str | None = None,
    email_ref: str | None = None,
    password_ref: str | None = None,
    secrets_file: Path | None = None,
    identity_name: str = "fleet-sync",
    token_ttl: int = 2592000,
    client_secret_description: str = "nixfisical sync identity",
    force: bool = False,
    git_commit: bool = False,
    commit_message: str = DEFAULT_COMMIT_MESSAGE,
) -> BootstrapResult:
    """Bootstrap the instance, or verify that it already is. See module docstring."""
    admin_file = Path(admin_file).expanduser()
    messages: list[str] = []

    if admin_file.exists():
        ok, detail = _verify_existing(client, admin_file)
        if ok:
            messages.append(f"admin file {admin_file} verified: {detail}")
            return BootstrapResult(
                status="ok", admin_file=admin_file, messages=messages
            )
        if not force:
            raise BootstrapError(
                f"admin file {admin_file} exists but its sync identity cannot "
                f"authenticate against {client.base_url} ({detail}).\n"
                "Refusing to re-bootstrap: doing so against a live instance would "
                "mint a duplicate identity, and against a rebuilt instance would "
                "orphan whatever the old credentials still protect.\n"
                "If the instance really was rebuilt, remove the admin file "
                "deliberately and re-run, or pass --force to proceed anyway "
                "(--force will refuse to overwrite the file; move it aside first)."
            )
        messages.append(
            f"--force given; proceeding despite unusable credentials in {admin_file} "
            f"({detail})"
        )
        # write_admin_file uses O_EXCL, so --force still will not silently
        # clobber the existing file. That is intentional: the operator gets to
        # keep the old credentials until they choose to discard them.

    credentials = resolve_admin_credentials(
        email=email,
        email_ref=email_ref,
        password_ref=password_ref,
        secrets_file=secrets_file,
    )
    if credentials.generated:
        messages.append(
            "no superadmin password source given; generated one. The admin file "
            "is now the only copy."
        )

    payload = client.bootstrap_instance(
        email=credentials.email,
        password=credentials.password,
        organization=organization,
    )

    token = payload.get("identity", {}).get("credentials", {}).get("token")
    if not token:
        raise BootstrapError("bootstrap response contained no admin identity token")
    client.token = token

    org = payload.get("organization") or {}
    organization_id = org.get("id")
    if not organization_id:
        raise BootstrapError("bootstrap response contained no organization id")
    user_id = (payload.get("user") or {}).get("id", "")

    identity_id = client.create_identity(
        name=identity_name, organization_id=organization_id, role="admin"
    )
    client_id = client.attach_universal_auth(identity_id, token_ttl=token_ttl)
    client_secret = client.create_client_secret(
        identity_id, description=client_secret_description
    )

    document = build_admin_document(
        credentials=credentials,
        user_id=user_id,
        organization=org,
        identity_id=identity_id,
        client_id=client_id,
        client_secret=client_secret,
    )
    write_admin_file(admin_file, document)
    messages.append(f"wrote and encrypted {admin_file}")

    committed = False
    if git_commit:
        committed, detail = git_commit_admin_file(admin_file, commit_message)
        messages.append(detail)

    return BootstrapResult(
        status="bootstrapped",
        admin_file=admin_file,
        organization_id=organization_id,
        organization_name=org.get("name"),
        organization_slug=org.get("slug"),
        identity_id=identity_id,
        client_id=client_id,
        password_generated=credentials.generated,
        committed=committed,
        messages=messages,
    )
