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

That covers an instance nixfisical has always owned. :func:`adopt` covers the
other one: an instance that is *already initialised* and has no admin file --
set up through the web UI, or bootstrapped by a checkout that has since been
lost. ``POST /api/v1/admin/bootstrap`` is spent for such an instance and will
never succeed again, so :func:`bootstrap` cannot reach it at all; short of
dropping the database there was no way back into a declaratively managed state.

:func:`adopt` gets there by authenticating as the superadmin who already
exists, rather than creating one, and then doing exactly what bootstrap does
afterwards -- mint the ``fleet-sync`` identity, write the admin file. Both
commands converge on :func:`_mint_sync_identity` so the file they produce is
the same file; nothing downstream can tell which one ran.

The asymmetry worth knowing: bootstrap *generates* the superadmin password and
the admin file is its only copy, so it is never typed and never reused. Adopt
must be *given* the password of an account a human already logs in with, and
records it. Rotating it afterwards is the operator's call.

:func:`add_org` is the third entry point, and unlike the first two it is not an
alternative -- it runs *after* one of them, as many times as there are extra
organizations. One instance can host several, and an access token is scoped to
exactly one of them, which makes an organization the natural boundary between
two estates sharing one server. Neither of the other commands can produce one:
bootstrap creates the first and is then spent forever, adopt only finds
organizations that already exist.

How the boundary is enforced varies by route, which is worth knowing before
debugging one. Measured against v0.165.8 with two identities and one org id:
``GET /api/v1/identities`` answers 403 naming both organizations, while
``GET /api/v2/organizations/{id}/workspaces`` answers 200 with an empty list.
Both refuse; only one says so. So an unexpectedly empty project list is the
symptom of the wrong admin file, not of an empty organization.

Its admin file is deliberately *not* quite the same file. It carries the
organization and the machine identity but, by default, no superadmin block --
because the whole point of a second organization is usually that different
people own it, and the superadmin is scoped to the instance rather than to any
one organization. Nothing downstream notices: ``sync``, ``sync-access`` and
``status`` read only the identity and the organization id.
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
    "adopt",
    "add_org",
    "read_sync_credentials",
    "read_organization_id",
    "read_admin_credentials",
    "split_file_key",
    "DEFAULT_COMMIT_MESSAGE",
    "DEFAULT_ADOPT_COMMIT_MESSAGE",
    "DEFAULT_ADD_ORG_COMMIT_MESSAGE",
]

DEFAULT_COMMIT_MESSAGE = "chore(infisical): bootstrap admin credentials"
DEFAULT_ADOPT_COMMIT_MESSAGE = "chore(infisical): adopt admin credentials"
DEFAULT_ADD_ORG_COMMIT_MESSAGE = "chore(infisical): add organization credentials"

# Key paths inside the admin file, in manifest ("a/b") notation.
_KEY_CLIENT_ID = "sync_identity/client_id"
_KEY_CLIENT_SECRET = "sync_identity/client_secret"
_KEY_ORG_ID = "organization/id"
_KEY_ADMIN_EMAIL = "admin/email"
_KEY_ADMIN_PASSWORD = "admin/password"


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
    """Outcome of a :func:`bootstrap` or :func:`adopt` call.

    ``status`` is ``"ok"`` when the admin file already proved itself against the
    instance and there was nothing to do, ``"bootstrapped"`` when we initialised
    the instance, ``"adopted"`` when we minted the sync identity against an
    instance that was already initialised, and ``"added"`` when we minted one
    against an additional organization on an instance already under management.

    ``organization_created`` distinguishes the two halves of ``"added"``: the
    organization was made by this run, or it was already there and only the
    identity is new.
    """

    status: str
    admin_file: Path
    organization_id: str | None = None
    organization_name: str | None = None
    organization_slug: str | None = None
    identity_id: str | None = None
    client_id: str | None = None
    password_generated: bool = False
    organization_created: bool = False
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


def read_admin_credentials(admin_file: Path) -> AdminCredentials:
    """Extract the superadmin login recorded by ``bootstrap`` or ``adopt``.

    The only reader of the ``admin`` block. Everything else in this tool
    authenticates as the machine identity, which is why that block is written
    once and never looked at again -- but ``add-org`` genuinely needs a human
    superadmin, because creating an organization is not something a machine
    identity scoped to a *different* organization is allowed to do.

    Reading it from here rather than making the operator pass
    ``--admin-password-from`` matters for the bootstrap case specifically: that
    password was generated, this file is its only copy, and nobody has it to
    type.
    """
    return AdminCredentials(
        email=extract(admin_file, sops_key_expr(_KEY_ADMIN_EMAIL)),
        password=extract(admin_file, sops_key_expr(_KEY_ADMIN_PASSWORD)),
    )


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


def _admin_file_gate(
    client: InfisicalClient,
    admin_file: Path,
    *,
    force: bool,
    what: str,
    messages: list[str],
) -> BootstrapResult | None:
    """Decide what an existing admin file means for a run that wants to write one.

    Shared by :func:`bootstrap` and :func:`adopt`, which differ in how they
    obtain credentials but not at all in what a pre-existing admin file obliges
    them to do. Returns a finished :class:`BootstrapResult` when the file proves
    the work is already done and the caller should return it, ``None`` when the
    caller should proceed, and raises when it must not.
    """
    if not admin_file.exists():
        return None

    ok, detail = _verify_existing(client, admin_file)
    if ok:
        messages.append(f"admin file {admin_file} verified: {detail}")
        return BootstrapResult(status="ok", admin_file=admin_file, messages=messages)

    if not force:
        raise BootstrapError(
            f"admin file {admin_file} exists but its sync identity cannot "
            f"authenticate against {client.base_url} ({detail}).\n"
            f"Refusing to {what}: doing so against a live instance would "
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
    # write_admin_file uses O_EXCL, so --force still will not silently clobber
    # the existing file. That is intentional: the operator gets to keep the old
    # credentials until they choose to discard them.
    return None


# --------------------------------------------------------------------------
# Credential sourcing
# --------------------------------------------------------------------------


def split_file_key(spec: str, default_file: Path | None, *, what: str) -> tuple[Path, str]:
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
    require_password: bool = False,
) -> AdminCredentials:
    """Work out the superadmin email and password.

    Resolution order, documented in the CLI help and the README:

    * email: ``--admin-email`` literal wins (an address is not secret), else
      ``--admin-email-from`` (``FILE:KEY`` or a bare key against
      ``--secrets-file``). One of the two is required.
    * password: ``--admin-password-from`` if given, otherwise a fresh
      ``secrets.token_urlsafe(32)``. Generating is the better default -- nobody
      logs in as the superadmin during normal operation, and a password that
      only ever existed inside the encrypted admin file cannot have been
      reused.

    ``require_password`` turns that last fallback off. Generating a password is
    only meaningful when we are about to *create* the account with it; ``adopt``
    has to authenticate against an account that already exists, where inventing
    a password would produce a guaranteed 400 with a misleading "invalid
    credentials" message.
    """
    if email:
        resolved_email = email
    elif email_ref:
        file, key = split_file_key(email_ref, secrets_file, what="--admin-email-from")
        resolved_email = extract(file, sops_key_expr(key))
    else:
        raise BootstrapError(
            "no superadmin email: pass --admin-email, or --admin-email-from FILE:KEY"
        )

    if password_ref:
        file, key = split_file_key(
            password_ref, secrets_file, what="--admin-password-from"
        )
        return AdminCredentials(
            email=resolved_email, password=extract(file, sops_key_expr(key))
        )

    if require_password:
        raise BootstrapError(
            "no superadmin password: pass --admin-password-from FILE:KEY.\n"
            "Unlike bootstrap, adopt cannot generate one -- the account already "
            "exists and this has to be the password it was created with."
        )

    return AdminCredentials(
        email=resolved_email, password=_secrets.token_urlsafe(32), generated=True
    )


# --------------------------------------------------------------------------
# Admin-file write
# --------------------------------------------------------------------------


def build_admin_document(
    *,
    credentials: AdminCredentials | None,
    user_id: str,
    organization: dict[str, Any],
    identity_id: str,
    client_id: str,
    client_secret: str,
) -> dict[str, Any]:
    """Assemble the admin-file document. Shape is fixed by the Ansible role.

    ``credentials=None`` omits the ``admin`` block entirely, producing a file
    that names an organization and the machine identity for it and nothing
    else. That is a complete file for everything except ``add-org``: nothing
    else in this tool ever reads ``admin``, so an org file without it can still
    drive ``sync``, ``sync-access`` and ``status``.

    The reason to omit it is that a second organization usually belongs to a
    different estate, with a different set of people and a different set of
    SOPS recipients. Copying the instance superadmin's password into that
    estate's repo would hand whoever can decrypt it the whole instance --
    including every other organization on it. The identity in the file is
    scoped to one organization; the superadmin is not.
    """
    document: dict[str, Any] = {
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
    if credentials is not None:
        document["admin"] = {
            "email": credentials.email,
            "password": credentials.password,
            "user_id": user_id,
        }
    return document


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

    already = _admin_file_gate(
        client, admin_file, force=force, what="re-bootstrap", messages=messages
    )
    if already is not None:
        return already

    # Ask the instance whether it has already been initialised, before going to
    # SOPS for credentials and before putting a password on the wire. Reaching
    # here means the admin file did not settle the question -- which for a lost
    # or never-created admin file is precisely the case where the instance is
    # live and bootstrap is the wrong command.
    if client.instance_config().get("initialized"):
        raise BootstrapError(
            f"{client.base_url} has already been initialised; "
            "/api/v1/admin/bootstrap succeeds exactly once per instance and "
            "will refuse.\n"
            "Use `nixfisical adopt` instead: it logs in as the superadmin that "
            "already exists and mints the sync identity against the "
            "organization that is already there, ending at the same admin file "
            "this command would have written."
        )

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

    try:
        payload = client.bootstrap_instance(
            email=credentials.email,
            password=credentials.password,
            organization=organization,
        )
    except InfisicalError as exc:
        # Backstop for the pre-flight above: an instance initialised in the
        # seconds since, or a server too old to answer /admin/config the way we
        # read it. The endpoint answers 400 "Instance has already been set up".
        raise BootstrapError(
            f"{exc}\n"
            "If the instance is already initialised, use `nixfisical adopt` -- "
            "/api/v1/admin/bootstrap succeeds exactly once per instance."
        ) from exc

    token = payload.get("identity", {}).get("credentials", {}).get("token")
    if not token:
        raise BootstrapError("bootstrap response contained no admin identity token")
    client.token = token

    org = payload.get("organization") or {}
    organization_id = org.get("id")
    if not organization_id:
        raise BootstrapError("bootstrap response contained no organization id")
    user_id = (payload.get("user") or {}).get("id", "")

    return _mint_sync_identity(
        client,
        status="bootstrapped",
        admin_file=admin_file,
        credentials=credentials,
        user_id=user_id,
        organization=org,
        identity_name=identity_name,
        token_ttl=token_ttl,
        client_secret_description=client_secret_description,
        git_commit=git_commit,
        commit_message=commit_message,
        messages=messages,
    )


def adopt(
    client: InfisicalClient,
    *,
    admin_file: Path,
    organization: str | None = None,
    email: str | None = None,
    email_ref: str | None = None,
    password_ref: str | None = None,
    secrets_file: Path | None = None,
    identity_name: str = "fleet-sync",
    token_ttl: int = 2592000,
    client_secret_description: str = "nixfisical sync identity",
    force: bool = False,
    git_commit: bool = False,
    commit_message: str = DEFAULT_ADOPT_COMMIT_MESSAGE,
) -> BootstrapResult:
    """Take over an instance that is already initialised. See module docstring.

    The end state is identical to :func:`bootstrap`'s -- the same admin file,
    with the same shape -- reached from a different starting point: instead of
    creating the superadmin and the organization, we authenticate as a
    superadmin that exists and find the organization that exists.

    The superadmin password is an input here, not an output. That is the one
    real cost of adopting rather than bootstrapping: bootstrap can generate a
    password nobody ever types, adopt has to be told one that a human already
    knows, and it ends up recorded in the admin file alongside the machine
    credentials. Rotate it afterwards if that matters.
    """
    admin_file = Path(admin_file).expanduser()
    messages: list[str] = []

    already = _admin_file_gate(
        client, admin_file, force=force, what="adopt", messages=messages
    )
    if already is not None:
        return already

    credentials = resolve_admin_credentials(
        email=email,
        email_ref=email_ref,
        password_ref=password_ref,
        secrets_file=secrets_file,
        require_password=True,
    )

    # Two-step, because the token from a bare login carries no organization and
    # almost every route -- including the one that creates the identity -- wants
    # one. Between the two we get to enumerate the organizations, which is what
    # lets --organization be optional.
    client.login(email=credentials.email, password=credentials.password)
    org = _select_organization(client, organization, messages=messages)
    client.select_organization(org["id"])

    user_id = client.current_user().get("id", "")

    _refuse_duplicate_identity(client, org, identity_name)

    return _mint_sync_identity(
        client,
        status="adopted",
        admin_file=admin_file,
        credentials=credentials,
        user_id=user_id,
        organization=org,
        identity_name=identity_name,
        token_ttl=token_ttl,
        client_secret_description=client_secret_description,
        git_commit=git_commit,
        commit_message=commit_message,
        messages=messages,
    )


def add_org(
    client: InfisicalClient,
    *,
    org_admin_file: Path,
    organization: str,
    instance_admin_file: Path | None = None,
    email: str | None = None,
    email_ref: str | None = None,
    password_ref: str | None = None,
    secrets_file: Path | None = None,
    record_admin_credentials: bool = False,
    identity_name: str = "fleet-sync",
    token_ttl: int = 2592000,
    client_secret_description: str = "nixfisical sync identity",
    force: bool = False,
    git_commit: bool = False,
    commit_message: str = DEFAULT_ADD_ORG_COMMIT_MESSAGE,
) -> BootstrapResult:
    """Add a second (third, nth) organization to an instance we already manage.

    One Infisical instance can host several organizations, and they are hard
    partitions: an access token is scoped to exactly one, and asking it about
    another gets nothing back. That is the useful property. Two estates can
    share one instance without either one's machine identity being able to
    enumerate, let alone read, the other's projects.

    Measured, because "hard partition" is a security claim: the same
    organization id answers two projects to the identity that owns it and an
    empty list to the one that does not. How the refusal is *phrased* varies by
    route -- ``GET /api/v1/identities`` says 403 and names both organizations,
    ``GET /api/v2/organizations/{id}/workspaces`` says 200 and an empty list --
    so an unexpectedly empty project list means the wrong admin file, not an
    empty organization.

    So this is the third way to reach the same end state as :func:`bootstrap`
    and :func:`adopt` -- an organization with a ``fleet-sync`` identity and an
    encrypted file naming both -- for the case they cannot cover. ``bootstrap``
    is spent after the first run and ``adopt`` only finds organizations that
    already exist; neither creates one.

    Two things make it safe to re-run, and both matter:

    * the organization is looked up by id, slug or name before it is created,
      so a second run finds the first run's work instead of creating a
      same-named twin (Infisical does not enforce unique names);
    * the org admin file gates the whole thing exactly as it does for the other
      two commands -- if its identity can log in, there is nothing to do.

    The superadmin login comes from ``instance_admin_file`` by default, because
    for a bootstrapped instance the generated password lives nowhere else.
    ``email``/``email_ref``/``password_ref`` override that for an instance whose
    superadmin is a human account.

    By default the file this writes carries no superadmin credentials -- see
    :func:`build_admin_document` for why. ``record_admin_credentials`` opts back
    in, for the case where the new organization is another slice of the *same*
    estate and the split buys nothing.
    """
    org_admin_file = Path(org_admin_file).expanduser()
    messages: list[str] = []

    already = _admin_file_gate(
        client, org_admin_file, force=force, what="add the organization", messages=messages
    )
    if already is not None:
        return already

    if email or email_ref or password_ref:
        credentials = resolve_admin_credentials(
            email=email,
            email_ref=email_ref,
            password_ref=password_ref,
            secrets_file=secrets_file,
            require_password=True,
        )
    elif instance_admin_file is not None and Path(instance_admin_file).exists():
        credentials = read_admin_credentials(Path(instance_admin_file).expanduser())
        messages.append(
            f"read the superadmin login from {instance_admin_file}"
        )
    else:
        raise BootstrapError(
            "no superadmin credentials: the instance admin file "
            f"{instance_admin_file} does not exist, and no --admin-email / "
            "--admin-password-from was given.\n"
            "add-org has to act as a human superadmin -- a machine identity is "
            "scoped to one organization and cannot create another."
        )

    client.login(email=credentials.email, password=credentials.password)

    organizations = client.list_organizations()
    org = match_organization(organizations, organization)
    created = org is None
    if org is None:
        org = client.create_organization(organization)
        messages.append(
            f"created organization {org.get('name')!r} (slug {org.get('slug')!r})"
        )
    else:
        messages.append(
            f"organization {org.get('name')!r} already exists (slug "
            f"{org.get('slug')!r}); minting the identity only"
        )

    # Re-login before selecting, when we just created the organization. The
    # token in hand was issued before the enrolment that creation performed,
    # and whether select-organization re-reads membership or trusts the token's
    # claims is not something we established -- so this is one cheap request
    # bought instead of an assumption. The already-exists path needs nothing:
    # that token was issued after the membership, and the probe that designed
    # this command selected an existing organization on exactly such a token.
    if created:
        client.login(email=credentials.email, password=credentials.password)
    client.select_organization(org["id"])

    user_id = client.current_user().get("id", "")

    _refuse_duplicate_identity(client, org, identity_name)

    return _mint_sync_identity(
        client,
        status="added",
        admin_file=org_admin_file,
        credentials=credentials if record_admin_credentials else None,
        user_id=user_id,
        organization=org,
        identity_name=identity_name,
        token_ttl=token_ttl,
        client_secret_description=client_secret_description,
        git_commit=git_commit,
        commit_message=commit_message,
        messages=messages,
        organization_created=created,
    )


def _refuse_duplicate_identity(
    client: InfisicalClient, organization: dict[str, Any], identity_name: str
) -> None:
    """Stop before minting a second identity with a name already in use.

    Infisical does not require identity names to be unique, so this is a
    nicety rather than a constraint it would enforce -- but a duplicate here is
    always a mistake. The client secret of the existing one cannot be read back
    (Infisical shows a secret once, at creation), so if the admin file naming it
    is gone, the identity is unusable and a second one with the same name just
    makes the wreckage ambiguous.
    """
    existing = client.list_identities(organization["id"])
    if identity_name not in existing:
        return
    raise BootstrapError(
        f"organization {organization.get('name')!r} already has a machine "
        f"identity named {identity_name!r}.\n"
        "Refusing to create a second one with the same name. Its client "
        "secret cannot be read back out of Infisical -- secrets are shown "
        "once, at creation -- so there is no way to adopt the existing "
        "identity into an admin file.\n"
        "Either delete it in the UI and re-run, or pass --identity-name to "
        "mint a differently named one alongside it."
    )


def _select_organization(
    client: InfisicalClient,
    wanted: str | None,
    *,
    messages: list[str],
) -> dict[str, Any]:
    """Pick the organization to adopt, by id, slug or name -- or automatically.

    Auto-selection only fires when the account belongs to exactly one
    organization, which is the shape every instance this tool has ever targeted
    has. With more than one, guessing would be picking which estate's secrets to
    reorganise; the operator names it.
    """
    organizations = client.list_organizations()
    if not organizations:
        raise BootstrapError(
            "the superadmin belongs to no organization; there is nothing to "
            "adopt. Create one in the UI first, or bootstrap a fresh instance."
        )

    if wanted is None:
        if len(organizations) > 1:
            raise BootstrapError(
                f"the superadmin belongs to {len(organizations)} organizations; "
                f"pass --organization to say which: "
                f"{describe_organizations(organizations)}"
            )
        org = organizations[0]
        messages.append(
            f"adopting the only organization on the instance: {org.get('name')!r}"
        )
        return org

    org = match_organization(organizations, wanted)
    if org is not None:
        return org

    raise BootstrapError(
        f"no organization matched {wanted!r} by id, slug or name. "
        f"Available: {describe_organizations(organizations)}"
    )


def match_organization(
    organizations: list[dict[str, Any]], wanted: str
) -> dict[str, Any] | None:
    """Find an organization by id, slug or name, or ``None``.

    Most specific first, and a name is the only one of the three a user can
    change after the fact -- so an id that happens to equal another org's name
    resolves the way the operator meant.

    Shared with :func:`add_org`, where a miss is not an error but the signal to
    create. That sharing is the point: ``add-org --organization X`` re-run after
    it created X must *find* X by exactly the rule ``adopt`` would have used,
    or it would create a second organization with the same name every time.
    """
    for field_name in ("id", "slug", "name"):
        for org in organizations:
            if org.get(field_name) == wanted:
                return org
    return None


def describe_organizations(organizations: list[dict[str, Any]]) -> str:
    """Render an organization list for an error message."""
    return ", ".join(
        f"{org.get('name')!r} (slug {org.get('slug')!r})" for org in organizations
    )


def _mint_sync_identity(
    client: InfisicalClient,
    *,
    status: str,
    admin_file: Path,
    credentials: AdminCredentials | None,
    user_id: str,
    organization: dict[str, Any],
    identity_name: str,
    token_ttl: int,
    client_secret_description: str,
    git_commit: bool,
    commit_message: str,
    messages: list[str],
    organization_created: bool = False,
) -> BootstrapResult:
    """Create the sync identity and record everything in the admin file.

    The shared tail of :func:`bootstrap`, :func:`adopt` and :func:`add_org`.
    It is factored out rather than duplicated because all three have to produce
    admin files that are indistinguishable -- everything downstream (``sync``,
    ``sync-access``, the ``secrets`` group) reads one file format and does not
    care which command wrote it.

    ``credentials=None`` (only ``add_org`` passes it) omits the ``admin`` block;
    see :func:`build_admin_document`.
    """
    organization_id = organization["id"]

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
        organization=organization,
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
        status=status,
        admin_file=admin_file,
        organization_id=organization_id,
        organization_name=organization.get("name"),
        organization_slug=organization.get("slug"),
        identity_id=identity_id,
        client_id=client_id,
        password_generated=credentials.generated if credentials else False,
        organization_created=organization_created,
        committed=committed,
        messages=messages,
    )
