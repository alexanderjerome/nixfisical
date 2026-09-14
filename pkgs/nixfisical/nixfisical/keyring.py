"""Put key material in Infisical, and get it back onto a host.

Everything else in this package treats SOPS as the source of truth and
Infisical as the view of it. This module is the one deliberate inversion, and
the age key is why: it *is* what makes SOPS work, so it cannot come from a SOPS
file, and it has to reach a freshly-built host somehow. Today that somehow is an
operator with a USB stick, a scp, or a line in a bootstrap script nobody wants
to read.

SSH keys arrive here by a different road and end up in the same place. Infisical
had an SSH certificate authority; it was deleted from the product (see the
migration ``20260729150000_drop-ssh-and-ai-mcp-tables``), and what replaced it
-- PAM, and the SSH dynamic-secret provider -- is behind a licence. So backing
up an SSH key is not a certificate operation on a self-hosted instance. It is a
secret with a placement policy, which is exactly what this already was.

So: one project, holding key material and the policy for placing it, readable
by the superadmin and by the host identities explicitly granted it.

    keyring/prod/<name>/KEY_TYPE         "age" or "ssh"
                       /PRIVATE_KEY      the key file, verbatim
                       /PUBLIC_KEY       age recipients, or the ssh public line
                       /KEY_PATH         where it goes on a host
                       /KEY_OWNER        who owns it there
                       /KEY_GROUP
                       /KEY_MODE
                       /PUBLIC_KEY_PATH  where the .pub goes (ssh only)

The placement travels with the key on purpose. The alternative is every host
declaring the path itself, which means the day it moves it moves in seventeen
places and the sixteen that were updated look identical to the one that was
not.

What a type changes is narrow and lives in :mod:`nixfisical.material`: how the
material is validated, how its public half is derived, and what it defaults to
on disk. Push, audit and install do not branch on it.

**The circularity, which is the thing to get right.** A host needs a credential
to reach Infisical; that credential normally arrives in a SOPS file; SOPS needs
an age key. Pulling the age key from Infisical does not break that loop on its
own -- it moves where the loop is cut. The cut has to be something the host has
before any of this runs, and the one available on NixOS is the SSH host key::

    sops.age.sshKeyPaths = [ "/etc/ssh/ssh_host_ed25519_key" ];

That derives a per-host age identity from a key the host generated itself, with
no operator and no SOPS involved. It decrypts the small per-host file holding
that host's universal-auth credential -- and nothing else. The host then
authenticates and pulls the *central* key from here, which is the one the
estate's shared secrets are actually encrypted to.

Which is to say this command does not remove the bootstrap problem. It reduces
it to one file per host containing one credential, encrypted to a key the host
made for itself, and that is a materially smaller thing to get onto a machine
than the key that decrypts everything.

**What the host is trusting.** The install path comes from the instance. A host
running this is trusting Infisical to tell it where to write a file as root,
which is a broader trust than "decrypt this blob". It is stated rather than
mitigated away, because the mitigations available here (an allowlist, a
signature) either restate the path locally -- defeating the point of centralising
it -- or need a second root of trust this estate does not have. What *is*
checked is narrower and worth having: the path must be absolute and free of
``..``, the value must parse as a real key of the type the entry claims, and an
existing file at the destination that is not itself a key of that type is never
overwritten. That last one is what stops a mistyped or malicious path from
turning into a clobbered ``/etc/shadow``. The one thing the instance does *not*
get to choose is the mode of the public half; that comes from the type table, so
a keyring cannot be made to write a world-readable private key by any value it
holds.

**One keyring project is one blast radius.** Infisical's project roles do not
scope to a folder without a licensed custom role, so a host granted ``viewer``
here can read every key in the project, not only its own. Two estates that must
not read each other's keys need two keyring projects -- or, better, the
organization boundary this tool already uses for exactly that.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path

from nixfisical.agent import AgentError, SecretSpec, materialise, read_credential
from nixfisical.api import InfisicalClient, InfisicalError, UniversalAuthCredentials
from nixfisical.material import (
    AGE,
    SSH,
    TYPES,
    KeyringError,
    Material,
    derive_public,
    detect,
    looks_like,
    parse_private,
)
from nixfisical.material import get as material_named

__all__ = [
    "AGE",
    "SSH",
    "TYPES",
    "AuditReport",
    "InstallSummary",
    "KeyringError",
    "Material",
    "Placement",
    "PushSummary",
    "audit",
    "detect",
    "install",
    "material_named",
    "parse_age_key_file",
    "push",
    "main",
]

# The project. Not in the manifest, and it must stay out of it: `sync-access`
# adds the operator and the manifest's groups to every project it names, and a
# group grant here would hand the estate's master key to a whole team without
# anybody deciding to. `audit` exists to notice if that happens anyway.
DEFAULT_PROJECT = "keyring"

# One environment. Key material has no dev/staging: there is the key the fleet
# is encrypted to, and there is a key that decrypts nothing.
ENVIRONMENT = "prod"

# The value names inside one entry's folder. Type-neutral on purpose: an entry
# is "some key material plus where it goes", and a host reading one should not
# have to know which kind it is to find the fields.
KEY_TYPE = "KEY_TYPE"
KEY_SECRET = "PRIVATE_KEY"
KEY_PUBLIC = "PUBLIC_KEY"
KEY_PATH = "KEY_PATH"
KEY_OWNER = "KEY_OWNER"
KEY_GROUP = "KEY_GROUP"
KEY_MODE = "KEY_MODE"
KEY_PUBLIC_PATH = "PUBLIC_KEY_PATH"

# The default type when an entry does not name one. Every entry this version
# writes names one; the fallback is for reading an entry written before
# `KEY_TYPE` existed, when age was the only thing the keyring held.
DEFAULT_TYPE = AGE

DEFAULT_OWNER = "root"
DEFAULT_GROUP = "root"

# Kept for callers that predate the type table. Per-type defaults live on the
# `Material` -- see `nixfisical.material` -- and these two are age's.
DEFAULT_INSTALL_PATH = AGE.default_path
DEFAULT_MODE = AGE.default_mode

# The superadmin's role on the keyring project. `admin` rather than `viewer`
# because the human who owns the estate's key needs to be able to rotate it in
# the UI during an incident, when this CLI may be the thing that is broken.
OPERATOR_ROLE = "admin"

# What `provision-host --project keyring` grants a host. Read-only, and the
# reason the push side is a separate credential entirely.
HOST_ROLE = "viewer"


def parse_age_key_file(text: str) -> list[str]:
    """Every secret key in an age key file, validating each.

    A thin name over :func:`nixfisical.material.parse_private` for age, kept
    because "the list of secret keys in this file" is a question with a natural
    answer and callers outside the keyring ask it. The generalized form returns
    a :class:`~nixfisical.material.Parsed`, which separates the printable labels
    from the raw private tokens; this one hands back the tokens, so its result
    must not be logged.
    """
    return list(AGE.parse(text).secrets)


# -- placement --------------------------------------------------------------


@dataclass(frozen=True)
class Placement:
    """Where a key goes on a host, and who may read it there."""

    path: str = DEFAULT_INSTALL_PATH
    owner: str = DEFAULT_OWNER
    group: str = DEFAULT_GROUP
    mode: str = DEFAULT_MODE
    #: Where the public half goes, for the types that install one. Empty means
    #: "beside the private key, with the type's suffix" -- resolved by
    #: :meth:`for_material`, never left empty in a stored entry.
    public_path: str = ""

    @classmethod
    def for_material(
        cls,
        material: Material,
        *,
        path: str | None = None,
        owner: str | None = None,
        group: str | None = None,
        mode: str | None = None,
        public_path: str | None = None,
    ) -> "Placement":
        """A placement with this type's defaults filled in for what was omitted.

        The caller passes ``None`` for "you decide", not the age defaults, so
        that an SSH entry does not silently inherit ``/var/lib/sops-nix/key.txt``
        and ``0400`` from a dataclass default written when age was the only type.
        """
        resolved = path or material.default_path
        return cls(
            path=resolved,
            owner=owner or DEFAULT_OWNER,
            group=group or DEFAULT_GROUP,
            mode=mode or material.default_mode,
            public_path=(
                (public_path or resolved + material.public_suffix)
                if material.installs_public
                else ""
            ),
        )

    def _validated(self, raw: str, *, field_name: str) -> Path:
        """One absolute, non-traversing path, or a refusal naming the field.

        These are the checks that hold whoever controls the instance to
        something less than "write any file on the host as root". They do not
        get all the way there -- see the module docstring -- but they turn the
        two accidents that actually happen, a relative path and a traversal,
        into a refusal.
        """
        raw = raw.strip()
        if not raw:
            raise KeyringError(f"{field_name} is empty")
        if "\x00" in raw:
            raise KeyringError(f"{field_name} contains a NUL byte")
        path = Path(raw)
        if not path.is_absolute():
            raise KeyringError(
                f"{field_name} is {raw!r}, which is relative. The host resolves "
                "it as root from whatever directory the unit happened to start "
                "in, so it must be absolute."
            )
        if ".." in path.parts:
            raise KeyringError(f"{field_name} is {raw!r}, which traverses upward")
        return path

    def validated_path(self) -> Path:
        return self._validated(self.path, field_name=KEY_PATH)

    def validated_public_path(self) -> Path | None:
        """Where the public half goes, or None when this entry stores none."""
        if not self.public_path.strip():
            return None
        return self._validated(self.public_path, field_name=KEY_PUBLIC_PATH)

    def validated_mode(self) -> int:
        """The private half's mode. Owner-only, for every type there is.

        An SSH key is a credential the same way the estate key is, and OpenSSH
        refuses a group-readable one anyway, so there is no type that wants this
        relaxed. The *public* half's mode is not this value and is not stored in
        the instance at all -- it comes from the type table, so a compromised
        instance cannot widen it.
        """
        try:
            mode = int(self.mode, 8)
        except ValueError as exc:
            raise KeyringError(f"{KEY_MODE} is {self.mode!r}, which is not octal") from exc
        if mode & 0o077:
            raise KeyringError(
                f"{KEY_MODE} is {self.mode}, which is readable beyond its owner. "
                "Key material is owner-only, whatever kind it is."
            )
        return mode

    def as_secrets(self) -> dict[str, str]:
        values = {
            KEY_PATH: self.path,
            KEY_OWNER: self.owner,
            KEY_GROUP: self.group,
            KEY_MODE: self.mode,
        }
        if self.public_path:
            values[KEY_PUBLIC_PATH] = self.public_path
        return values

    @classmethod
    def from_secrets(
        cls, values: dict[str, str], material: Material = DEFAULT_TYPE
    ) -> "Placement":
        return cls.for_material(
            material,
            path=values.get(KEY_PATH),
            owner=values.get(KEY_OWNER),
            group=values.get(KEY_GROUP),
            mode=values.get(KEY_MODE),
            public_path=values.get(KEY_PUBLIC_PATH),
        )


# -- summaries --------------------------------------------------------------


@dataclass
class PushSummary:
    """What an upload did. Never contains the key."""

    name: str = ""
    project: str = DEFAULT_PROJECT
    project_id: str = ""
    created_project: bool = False
    #: The type name stored in ``KEY_TYPE``: ``"age"`` or ``"ssh"``.
    key_type: str = ""
    #: What each key in the file is -- ``"age"``, ``"ssh-ed25519"``. Printable.
    kinds: list[str] = field(default_factory=list)
    #: The public half as stored: age recipients, or SSH public key lines.
    public: list[str] = field(default_factory=list)
    replaced: bool = False
    actions: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def headline(self) -> str:
        return (
            f"keyring {self.project}/{self.name}: "
            f"project {'created' if self.created_project else 'reused'}, "
            f"{self.key_type or 'key'} {'replaced' if self.replaced else 'stored'}, "
            f"public {len(self.public)}, errors {len(self.errors)}"
        )


@dataclass
class AuditReport:
    """Who can read the keyring project."""

    project: str = DEFAULT_PROJECT
    project_id: str = ""
    users: dict[str, str] = field(default_factory=dict)
    groups: dict[str, str] = field(default_factory=dict)
    identities: dict[str, str] = field(default_factory=dict)
    keys: list[str] = field(default_factory=list)
    #: Entry name to the type it holds, for the entries that record one.
    key_types: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


@dataclass
class InstallSummary:
    """What one host-side install did. Never contains the key."""

    name: str = ""
    path: str = ""
    key_type: str = ""
    written: bool = False
    unchanged: bool = False
    #: Where the public half was installed, when the type has one.
    public_path: str = ""
    public_written: bool = False
    #: The public half as the instance holds it. Printable.
    public: list[str] = field(default_factory=list)
    keys_in_file: int = 0
    actions: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def headline(self) -> str:
        if not self.ok:
            return f"keyring {self.name}: failed"
        state = "written" if self.written else "unchanged"
        public = ", ".join(self.public) if self.public else "unrecorded"
        return (
            f"keyring {self.name} ({self.key_type or 'unknown type'}): {state} at "
            f"{self.path}, {self.keys_in_file} key(s), public {public}"
        )


# -- the operator half ------------------------------------------------------


def _folder(name: str) -> str:
    return "/" + name.strip("/")


def _existing(client: InfisicalClient, project_id: str, name: str) -> dict[str, str]:
    """Every keyring value already stored under ``name``."""
    folder = _folder(name)
    found: dict[str, str] = {}
    for entry in client.list_secrets(
        project_id=project_id, environment=ENVIRONMENT, path="/"
    ):
        path = str(entry.get("secretPath") or "/").strip() or "/"
        if path != "/":
            path = "/" + path.strip("/")
        if path != folder:
            continue
        key = entry.get("secretKey")
        value = entry.get("secretValue")
        if key and value is not None:
            found[str(key)] = str(value)
    return found


def push(
    client: InfisicalClient,
    *,
    name: str,
    key_text: str,
    organization_id: str,
    operator_email: str | None,
    project: str = DEFAULT_PROJECT,
    material: Material | None = None,
    placement: Placement | None = None,
    public_override: str | None = None,
    replace: bool = False,
    dry_run: bool = False,
) -> PushSummary:
    """Store a key and its placement policy under ``name``.

    ``material`` is the kind of key; ``None`` means sniff it from the file, which
    is what the CLI does unless ``--type`` says otherwise.

    Create-only by default. Overwriting the key a fleet is already encrypted to
    is the single most destructive thing in this package: every host that pulls
    afterwards gets an identity that decrypts nothing, and it fails at the next
    activation rather than now, which is a failure separated from its cause by
    however long that takes. ``replace=True`` is the operator saying they meant
    it, and the summary names both public halves so the change is visible.
    """
    summary = PushSummary(name=name, project=project)

    try:
        material = material or detect(key_text)
    except KeyringError as exc:
        summary.errors.append(str(exc))
        return summary
    summary.key_type = material.name

    placement = placement or Placement.for_material(material)

    try:
        parsed = parse_private(material, key_text)
    except KeyringError as exc:
        summary.errors.append(str(exc))
        return summary
    summary.kinds = list(parsed.kinds)
    keys = parsed.kinds

    # Validated before anything is created, not at install time. A path the
    # host will refuse is a keyring entry that looks stored and is not usable,
    # and the operator is here now.
    try:
        placement.validated_path()
        placement.validated_mode()
        placement.validated_public_path()
    except KeyringError as exc:
        summary.errors.append(str(exc))
        return summary

    if public_override is not None:
        # The sidecar `.pub`, when the operator passed one. It is preferred over
        # the derived line for one reason: it carries the comment, which is what
        # makes an `authorized_keys` entry identifiable a year later. It is also
        # the only source for a PEM key, whose public half cannot be derived.
        public = [line.strip() for line in public_override.splitlines() if line.strip()]
        summary.notes.append("public half taken from the file given, not derived")
    else:
        public, note = derive_public(material, key_text)
        if note:
            summary.notes.append(note)
    summary.public = public

    try:
        project_ids = client.list_projects(organization_id)
    except InfisicalError as exc:
        summary.errors.append(f"list projects: {exc}")
        return summary

    project_id = project_ids.get(project)
    if project_id is None:
        if dry_run:
            summary.actions.append(f"would create project {project!r}")
            summary.created_project = True
            summary.actions.append(
                f"would store {len(keys)} key(s) at {project}/{ENVIRONMENT}"
                f"{_folder(name)}"
            )
            return summary
        try:
            project_id = client.create_project(project)
        except InfisicalError as exc:
            summary.errors.append(f"create project {project!r}: {exc}")
            return summary
        summary.created_project = True
        summary.actions.append(f"created project {project!r}")
    summary.project_id = project_id

    if dry_run:
        summary.actions.append(
            f"would store {len(keys)} key(s) at {project}/{ENVIRONMENT}{_folder(name)}"
        )
        return summary

    try:
        client.create_environment(project_id, name=ENVIRONMENT, slug=ENVIRONMENT)
        client.create_folder(
            project_id=project_id,
            environment=ENVIRONMENT,
            path="/",
            name=name.strip("/"),
        )
    except InfisicalError as exc:
        summary.errors.append(f"prepare {project}/{ENVIRONMENT}{_folder(name)}: {exc}")
        return summary

    try:
        existing = _existing(client, project_id, name)
    except InfisicalError as exc:
        summary.errors.append(f"read existing keyring entry: {exc}")
        return summary

    if existing.get(KEY_SECRET) and not replace:
        previous = existing.get(KEY_PUBLIC) or "unrecorded"
        summary.errors.append(
            f"{project}/{ENVIRONMENT}{_folder(name)} already holds a "
            f"{existing.get(KEY_TYPE) or 'key'} (public: {previous}). Refusing to "
            "overwrite it: every host that has pulled it is using it, and a "
            "replacement fails at their next activation rather than here. Pass "
            "--replace if this is a rotation you have planned for."
        )
        return summary
    summary.replaced = bool(existing.get(KEY_SECRET))

    was = existing.get(KEY_TYPE)
    if was and was != material.name:
        # Allowed -- an entry is a name, not a type -- but it changes what every
        # host that pulls this name installs, and the placement changed with it.
        summary.notes.append(
            f"entry {name!r} held a {was} key and now holds a {material.name} one; "
            "any host pulling it will install the new kind at the new path"
        )

    payload = {
        KEY_TYPE: material.name,
        KEY_SECRET: key_text,
        **placement.as_secrets(),
    }
    if public:
        # Newline-separated, not space-separated: an SSH public key line has
        # spaces in it, so a space join would be unsplittable on the way back.
        payload[KEY_PUBLIC] = "\n".join(public)

    for key, value in payload.items():
        try:
            verdict = client.upsert_secret(
                key,
                project_id=project_id,
                environment=ENVIRONMENT,
                secret_path=_folder(name),
                value=value,
            )
        except InfisicalError as exc:
            summary.errors.append(f"write {key}: {exc}")
            continue
        # The key's own verdict is the only one worth a line; the four
        # placement scalars are noise on every run after the first.
        if key == KEY_SECRET or verdict == "created":
            summary.actions.append(f"{verdict} {key}")

    if operator_email:
        _ensure_operator(client, project_id, operator_email, summary)

    return summary


def _ensure_operator(
    client: InfisicalClient, project_id: str, email: str, summary: PushSummary
) -> None:
    """Make sure the superadmin can see the project they just created.

    A project created through the API is visible to nobody, org admins
    included -- the same surprise ``sync-access`` exists to fix for the
    manifest's projects. Here it matters more: a keyring nobody can open in the
    UI is a keyring that cannot be rotated during the incident where this CLI
    is the thing that is broken.
    """
    try:
        members = client.list_project_users(project_id)
    except InfisicalError as exc:
        summary.errors.append(f"list project users: {exc}")
        return
    if email.strip().lower() in members:
        return
    try:
        client.add_user_to_project(
            project_id=project_id, email=email, role=OPERATOR_ROLE
        )
    except InfisicalError as exc:
        summary.errors.append(f"add {email} to the keyring project: {exc}")
        return
    summary.actions.append(f"added {email} to {summary.project!r} as {OPERATOR_ROLE}")


def audit(
    client: InfisicalClient,
    *,
    organization_id: str,
    operator_email: str | None,
    project: str = DEFAULT_PROJECT,
) -> AuditReport:
    """Report who can read the keyring, and flag anything unexpected.

    "Visible only to the superadmin" is a claim, and a claim about access
    control that nothing checks is a claim that stops being true quietly. The
    two ways it stops being true here are a second human added in the UI and a
    group attached by ``sync-access`` -- which happens the moment somebody adds
    the keyring project to the manifest, with no error and no prompt. Both are
    warnings rather than failures: an estate with two operators is legitimate,
    and this command's job is to make sure that was a decision.
    """
    report = AuditReport(project=project)
    try:
        project_ids = client.list_projects(organization_id)
    except InfisicalError as exc:
        report.errors.append(f"list projects: {exc}")
        return report

    project_id = project_ids.get(project)
    if project_id is None:
        report.errors.append(
            f"no project {project!r} in this organization; nothing has been "
            "pushed to the keyring yet"
        )
        return report
    report.project_id = project_id

    for label, call in (
        ("users", lambda: client.list_project_users(project_id)),
        ("groups", lambda: client.list_project_groups(project_id)),
        ("identities", lambda: client.list_project_identities(project_id)),
    ):
        try:
            setattr(report, label, call())
        except InfisicalError as exc:
            report.errors.append(f"list project {label}: {exc}")

    try:
        folders: set[str] = set()
        types: dict[str, str] = {}
        for entry in client.list_secrets(
            project_id=project_id, environment=ENVIRONMENT, path="/"
        ):
            folder = ("/" + str(entry.get("secretPath") or "/").strip("/")).strip("/")
            if not folder:
                continue
            if entry.get("secretKey") == KEY_SECRET:
                folders.add(folder)
            elif entry.get("secretKey") == KEY_TYPE:
                types[folder] = str(entry.get("secretValue") or "")
        report.keys = sorted(folders)
        report.key_types = {
            folder: types.get(folder, DEFAULT_TYPE.name) for folder in report.keys
        }
    except InfisicalError as exc:
        report.errors.append(f"list keyring entries: {exc}")

    expected = {operator_email.strip().lower()} if operator_email else set()
    for email in sorted(set(report.users) - expected):
        report.warnings.append(
            f"user {email} can read the keyring and is not the superadmin"
        )
    if expected and not (set(report.users) & expected):
        report.warnings.append(
            f"the superadmin ({', '.join(sorted(expected))}) is NOT on the "
            "keyring project and cannot open it in the UI"
        )
    for group in sorted(report.groups):
        report.warnings.append(
            f"group {group!r} has {report.groups[group]!r} on the keyring. A "
            "group grant here hands the estate's master key to everyone in it; "
            "the usual cause is the keyring project being named in the manifest, "
            "where sync-access will re-add this on every run."
        )
    return report


# -- the host half ----------------------------------------------------------


def _refuse_to_clobber(
    destination: Path,
    *,
    recognise,
    what: str,
    field_name: str,
) -> None:
    """Never overwrite a file at ``destination`` that ``recognise`` rejects.

    The path came from the instance. This is the check that keeps a wrong one
    from being destructive rather than merely wrong: if something is already
    there and it does not look like what we are about to write, we stop. A
    keyring pointed at ``/etc/shadow`` then fails loudly on a host that still
    has its ``/etc/shadow``.

    ``recognise`` is deliberately the *shape* test, not an equality test against
    what we fetched -- overwriting one age key with another is the rotation this
    command exists for, and refusing that would refuse the point.
    """
    if not destination.exists():
        return
    if destination.is_dir():
        raise KeyringError(f"{destination} is a directory")
    try:
        current = destination.read_text()
    except (OSError, UnicodeDecodeError) as exc:
        raise KeyringError(
            f"{destination} already exists and cannot be read as text ({exc}), "
            f"so it cannot be confirmed to be {what}. Refusing to overwrite it."
        ) from exc
    if not current.strip():
        # A zero-byte file destroys nothing and is the normal leftover of a
        # half-finished write. Refusing it would make the common case the loud
        # one.
        return
    if not recognise(current):
        raise KeyringError(
            f"{destination} already exists and is not {what}. Refusing to "
            f"overwrite it: {field_name} in the instance points at a file this "
            "host is using for something else."
        )


def install(
    client: InfisicalClient,
    *,
    name: str,
    organization_id: str,
    project: str = DEFAULT_PROJECT,
    project_id: str | None = None,
    path_override: str | None = None,
    dry_run: bool = False,
) -> InstallSummary:
    """Pull the key stored under ``name`` and place it on this host."""
    summary = InstallSummary(name=name)

    if project_id is None:
        if not organization_id:
            summary.errors.append(
                "no organization id, so the keyring project cannot be resolved "
                "by name; pass --project-id"
            )
            return summary
        try:
            project_ids = client.list_projects(organization_id)
        except InfisicalError as exc:
            summary.errors.append(f"list projects: {exc}")
            return summary
        project_id = project_ids.get(project)
        if project_id is None:
            summary.errors.append(
                f"project {project!r} is not visible to this host's identity. "
                f"Grant it with: nixfisical provision-host <host> --project "
                f"{project} --into <sops file>"
            )
            return summary

    try:
        values = _existing(client, project_id, name)
    except InfisicalError as exc:
        summary.errors.append(f"read {project}/{ENVIRONMENT}{_folder(name)}: {exc}")
        return summary

    key_text = values.get(KEY_SECRET)
    if not key_text:
        summary.errors.append(
            f"no {KEY_SECRET} at {project}/{ENVIRONMENT}{_folder(name)}"
        )
        return summary

    # The type comes from the instance too, so it is resolved before anything
    # else -- it decides how the material is validated, and validating an SSH
    # key as an age one would reject it for the wrong reason.
    try:
        material = material_named(values[KEY_TYPE]) if values.get(KEY_TYPE) else DEFAULT_TYPE
    except KeyringError as exc:
        summary.errors.append(f"{KEY_TYPE} from the instance is not usable: {exc}")
        return summary
    summary.key_type = material.name

    # Validated on arrival, before the placement is even resolved. What is about
    # to be overwritten is a working credential, and a value that is not a key
    # of this type can only make that worse.
    try:
        parsed = parse_private(material, key_text)
    except KeyringError as exc:
        summary.errors.append(f"{KEY_SECRET} from the instance is not usable: {exc}")
        return summary
    summary.keys_in_file = len(parsed)
    summary.public = [
        line.strip() for line in (values.get(KEY_PUBLIC) or "").splitlines() if line.strip()
    ]

    placement = Placement.from_secrets(values, material)
    if path_override:
        placement = Placement.for_material(
            material,
            path=path_override,
            owner=placement.owner,
            group=placement.group,
            mode=placement.mode,
        )
        summary.actions.append(
            f"path overridden locally to {path_override} (instance says "
            f"{values.get(KEY_PATH) or material.default_path}); the public half, "
            "if any, follows it"
        )

    try:
        destination = placement.validated_path()
        placement.validated_mode()
        public_destination = placement.validated_public_path()
    except KeyringError as exc:
        summary.errors.append(str(exc))
        return summary
    summary.path = str(destination)

    public_text = ""
    if material.installs_public and public_destination is not None:
        if not summary.public:
            # Not fatal for age (there is nothing to install) but for SSH it
            # means the entry was pushed without a derivable public half, and a
            # private key with no `.pub` beside it breaks `ssh -i`.
            summary.actions.append(
                f"no {KEY_PUBLIC} stored for this entry, so nothing is written to "
                f"{public_destination}; push it again with --public-from-file"
            )
            public_destination = None
        else:
            public_text = "\n".join(summary.public) + "\n"
    else:
        public_destination = None
    summary.public_path = str(public_destination) if public_destination else ""

    try:
        _refuse_to_clobber(
            destination,
            recognise=lambda text: looks_like(material, text),
            what=f"an {material.label}" if material.name == "age" else f"a {material.label}",
            field_name=KEY_PATH,
        )
        if public_destination is not None:
            _refuse_to_clobber(
                public_destination,
                recognise=material.public_matches,
                what=f"a {material.name} public key",
                field_name=KEY_PUBLIC_PATH,
            )
    except KeyringError as exc:
        summary.errors.append(str(exc))
        return summary

    if dry_run:
        summary.actions.append(
            f"would write {len(parsed)} {material.name} key(s) to {destination} as "
            f"{placement.owner}:{placement.group} {placement.mode}"
        )
        if public_destination is not None:
            summary.actions.append(
                f"would write the public half to {public_destination} as "
                f"{placement.owner}:{placement.group} {material.public_mode}"
            )
        return summary

    # materialise() is the agent's: atomic rename, ownership and mode set
    # before the file is visible at its final name. The reader here is sops-nix
    # at activation, which is exactly the "opens it mid-run" case that
    # write-then-chmod would lose to.
    def _spec(path: Path, value_name: str, mode: str) -> SecretSpec:
        return SecretSpec(
            project=project,
            environment=ENVIRONMENT,
            folder=_folder(name),
            name=value_name,
            path=path,
            owner=placement.owner,
            group=placement.group,
            mode=mode,
        )

    try:
        changed = materialise(_spec(destination, KEY_SECRET, placement.mode), key_text)
    except AgentError as exc:
        summary.errors.append(str(exc))
        return summary
    summary.written = changed
    summary.unchanged = not changed

    if public_destination is not None:
        # The public half's mode is the type's, not the instance's -- see
        # `Placement.validated_mode`. Written after the private key so a reader
        # racing us never sees a `.pub` for a key that is not there yet.
        try:
            summary.public_written = materialise(
                _spec(public_destination, KEY_PUBLIC, material.public_mode),
                public_text,
            )
        except AgentError as exc:
            summary.errors.append(f"write {public_destination}: {exc}")
    return summary


def main(argv: list[str] | None = None) -> int:
    """``nixfisical-keyring-install`` -- the host-side half, and only that.

    A separate entry point from ``nixfisical keyring push`` for the reason
    ``nixfisical-agent`` is separate from ``nixfisical``: this runs on every
    host that pulls a key, the push side needs sops and an operator's
    credentials, and the ``minimal`` build ships one and not the other. A host
    that could push to the keyring would be a host that could replace the
    fleet's key.
    """
    parser = argparse.ArgumentParser(
        prog="nixfisical-keyring-install",
        description="Fetch a key from the Infisical keyring and install it. The "
        "kind of key, and where it goes, come from the entry.",
    )
    parser.add_argument("--name", required=True, help="keyring entry to install")
    parser.add_argument("--url", required=True, help="base URL of the instance")
    parser.add_argument("--client-id-file", required=True, type=Path)
    parser.add_argument("--client-secret-file", required=True, type=Path)
    parser.add_argument(
        "--organization-id",
        default="",
        help="organization holding the keyring project; not needed with --project-id",
    )
    parser.add_argument(
        "--project",
        default=DEFAULT_PROJECT,
        help=f"keyring project name (default: {DEFAULT_PROJECT})",
    )
    parser.add_argument(
        "--project-id",
        default=None,
        help="address the project by id, skipping the org-wide project listing",
    )
    parser.add_argument(
        "--path",
        default=None,
        help="install here instead of where the instance says. For a host that "
        "must differ; the instance's value is the one to change otherwise.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="skip TLS verification, for a self-signed instance on a trusted network",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    try:
        credentials = UniversalAuthCredentials(
            client_id=read_credential(args.client_id_file, what="client id"),
            client_secret=read_credential(args.client_secret_file, what="client secret"),
        )
    except AgentError as exc:
        print(f"nixfisical-keyring-install: {exc}", file=sys.stderr)
        return 1

    with InfisicalClient(args.url, verify=not args.insecure) as client:
        try:
            client.universal_auth_login(credentials)
        except InfisicalError as exc:
            print(f"nixfisical-keyring-install: {exc}", file=sys.stderr)
            return 1
        summary = install(
            client,
            name=args.name,
            organization_id=args.organization_id,
            project=args.project,
            project_id=args.project_id,
            path_override=args.path,
            dry_run=args.dry_run,
        )

    for action in summary.actions:
        print(f"nixfisical-keyring-install: {action}", file=sys.stderr)
    print(f"nixfisical-keyring-install: {summary.headline()}", file=sys.stderr)
    for problem in summary.errors:
        print(f"nixfisical-keyring-install: error: {problem}", file=sys.stderr)
    return 0 if summary.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
