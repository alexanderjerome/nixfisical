"""Put the estate's age key in Infisical, and get it back onto a host.

Everything else in this package treats SOPS as the source of truth and
Infisical as the view of it. This module is the one deliberate inversion: the
age key *is* what makes SOPS work, so it cannot come from a SOPS file, and it
has to reach a freshly-built host somehow. Today that somehow is an operator
with a USB stick, a scp, or a line in a bootstrap script nobody wants to read.

So: one project, holding key material and the policy for placing it, readable
by the superadmin and by the host identities explicitly granted it.

    keyring/prod/<name>/AGE_SECRET_KEY   the key file, verbatim
                       /AGE_PUBLIC_KEY   its recipient(s), for `.sops.yaml`
                       /AGE_KEY_PATH     where it goes on a host
                       /AGE_KEY_OWNER    who owns it there
                       /AGE_KEY_GROUP
                       /AGE_KEY_MODE

The placement travels with the key on purpose. The alternative is every host
declaring the path itself, which means the day it moves it moves in seventeen
places and the sixteen that were updated look identical to the one that was
not.

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
``..``, the value must decode as a real age key, and an existing file at the
destination that is not itself an age key file is never overwritten. That last
one is what stops a mistyped or malicious path from turning into a clobbered
``/etc/shadow``.

**One keyring project is one blast radius.** Infisical's project roles do not
scope to a folder without a licensed custom role, so a host granted ``viewer``
here can read every key in the project, not only its own. Two estates that must
not read each other's keys need two keyring projects -- or, better, the
organization boundary this tool already uses for exactly that.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from nixfisical.agent import AgentError, SecretSpec, materialise, read_credential
from nixfisical.api import InfisicalClient, InfisicalError, UniversalAuthCredentials

__all__ = [
    "AuditReport",
    "InstallSummary",
    "KeyringError",
    "Placement",
    "PushSummary",
    "audit",
    "install",
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

KEY_SECRET = "AGE_SECRET_KEY"
KEY_PUBLIC = "AGE_PUBLIC_KEY"
KEY_PATH = "AGE_KEY_PATH"
KEY_OWNER = "AGE_KEY_OWNER"
KEY_GROUP = "AGE_KEY_GROUP"
KEY_MODE = "AGE_KEY_MODE"

# sops-nix's own default for `sops.age.keyFile`. Matching it means a host that
# takes the default needs no configuration at all beyond enabling the pull.
DEFAULT_INSTALL_PATH = "/var/lib/sops-nix/key.txt"
DEFAULT_OWNER = "root"
DEFAULT_GROUP = "root"
DEFAULT_MODE = "0400"

# The superadmin's role on the keyring project. `admin` rather than `viewer`
# because the human who owns the estate's key needs to be able to rotate it in
# the UI during an incident, when this CLI may be the thing that is broken.
OPERATOR_ROLE = "admin"

# What `provision-host --project keyring` grants a host. Read-only, and the
# reason the push side is a separate credential entirely.
HOST_ROLE = "viewer"

_SECRET_KEY_PREFIX = "AGE-SECRET-KEY-1"
_PUBLIC_KEY_COMMENT = "# public key:"


class KeyringError(RuntimeError):
    """A keyring operation that cannot proceed."""


# -- bech32 -----------------------------------------------------------------
#
# Enough of BIP-173 to answer one question: is this string a structurally valid
# age secret key, checksum and all? Implemented here rather than shelled out to
# `age-keygen` because the host side needs the same answer and the host runs
# the `minimal` build, which deliberately carries no operator tooling. A
# truncated paste or a byte flipped in transit produces a key that looks right
# and decrypts nothing, and the place to catch that is before it is written
# over the working one.

_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_GENERATOR = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def _polymod(values: Iterable[int]) -> int:
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = ((checksum & 0x1FFFFFF) << 5) ^ value
        for index in range(5):
            if (top >> index) & 1:
                checksum ^= _GENERATOR[index]
    return checksum


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(char) >> 5 for char in hrp] + [0] + [ord(char) & 31 for char in hrp]


def _convert_bits(data: Iterable[int]) -> bytes | None:
    """5-bit groups to 8-bit bytes, rejecting non-canonical padding."""
    accumulator = 0
    bits = 0
    out = bytearray()
    for value in data:
        accumulator = (accumulator << 5) | value
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((accumulator >> bits) & 0xFF)
    if bits >= 5 or ((accumulator << (8 - bits)) & 0xFF):
        return None
    return bytes(out)


def _bech32_decode(token: str, *, expected_hrp: str) -> bytes:
    """Decode one bech32 string, or raise. Returns the payload bytes."""
    if any(ord(char) < 33 or ord(char) > 126 for char in token):
        raise KeyringError("age key contains characters that cannot appear in one")
    if token.lower() != token and token.upper() != token:
        # Bech32 is case-insensitive but mixed case is invalid, and a key that
        # has been through a spreadsheet or a rich-text field arrives that way.
        raise KeyringError("age key has mixed case, which bech32 does not allow")
    lowered = token.lower()
    separator = lowered.rfind("1")
    if separator < 1:
        raise KeyringError("age key has no bech32 separator")
    hrp = lowered[:separator]
    if hrp != expected_hrp:
        raise KeyringError(
            f"age key has the prefix {hrp!r}, expected {expected_hrp!r}"
        )
    body = lowered[separator + 1 :]
    if len(body) < 6:
        raise KeyringError("age key is too short to carry a checksum")
    try:
        values = [_CHARSET.index(char) for char in body]
    except ValueError as exc:
        raise KeyringError("age key contains a character outside the bech32 set") from exc
    if _polymod(_hrp_expand(hrp) + values) != 1:
        raise KeyringError(
            "age key fails its bech32 checksum -- it is truncated, mistyped, or "
            "otherwise not the key it was when it was generated"
        )
    payload = _convert_bits(values[:-6])
    if payload is None:
        raise KeyringError("age key has invalid bech32 padding")
    return payload


def parse_age_key_file(text: str) -> list[str]:
    """Return every secret key in an age key file, validating each.

    An age key file is a sequence of ``AGE-SECRET-KEY-1...`` lines with
    ``#`` comments between them, and sops-nix is happy with several -- which is
    how a rekeying is done without a flag day. So the file is taken whole and
    every key in it is checked, rather than the first one being extracted and
    the rest silently dropped.
    """
    keys: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not stripped.upper().startswith(_SECRET_KEY_PREFIX):
            raise KeyringError(
                f"line {number} is neither a comment nor an age secret key. "
                "This does not look like an age key file -- an SSH private key "
                "and a sops-nix key file are easy to confuse and only one of "
                "them belongs here."
            )
        try:
            payload = _bech32_decode(stripped, expected_hrp="age-secret-key-")
        except KeyringError as exc:
            raise KeyringError(f"line {number}: {exc}") from exc
        if len(payload) != 32:
            raise KeyringError(
                f"line {number}: age secret key decodes to {len(payload)} bytes, "
                "expected 32"
            )
        keys.append(stripped.upper())
    if not keys:
        raise KeyringError(
            "no age secret key in this file. A file holding only 'age1...' "
            "recipients is the public half; the private half is what a host "
            "needs to decrypt with."
        )
    return keys


def _commented_recipients(text: str) -> list[str]:
    """Recipients from the ``# public key:`` lines age-keygen writes."""
    found = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith(_PUBLIC_KEY_COMMENT):
            candidate = stripped[len(_PUBLIC_KEY_COMMENT) :].strip()
            if candidate.startswith("age1"):
                found.append(candidate)
    return found


def derive_recipients(text: str) -> tuple[list[str], str | None]:
    """Recipients for a key file, and a note when they had to be guessed.

    ``age-keygen -y`` is authoritative and reads the key on stdin, so nothing
    is written to disk to ask it. When it is absent -- a pip install, or the
    `minimal` build -- the ``# public key:`` comments are used instead, and the
    note says so, because a comment is an assertion about the file rather than
    a fact derived from it. When both are available they are compared: a
    disagreement means the file was hand-edited and the comment now names a
    recipient nothing in the file can decrypt for.
    """
    commented = _commented_recipients(text)
    try:
        result = subprocess.run(
            ["age-keygen", "-y"],
            input=text,
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, ValueError):
        result = None

    if result is None or result.returncode != 0:
        if commented:
            return commented, (
                "recipients read from the file's '# public key:' comments; "
                "age-keygen is not on PATH to derive them"
            )
        return [], (
            "no recipients recorded: age-keygen is not on PATH and the file "
            "carries no '# public key:' comment"
        )

    derived = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip().startswith("age1")
    ]
    if commented and sorted(commented) != sorted(derived):
        return derived, (
            "the file's '# public key:' comments disagree with what its keys "
            f"actually derive to ({', '.join(commented)} vs "
            f"{', '.join(derived)}); the derived values are being stored"
        )
    return derived, None


# -- placement --------------------------------------------------------------


@dataclass(frozen=True)
class Placement:
    """Where a key goes on a host, and who may read it there."""

    path: str = DEFAULT_INSTALL_PATH
    owner: str = DEFAULT_OWNER
    group: str = DEFAULT_GROUP
    mode: str = DEFAULT_MODE

    def validated_path(self) -> Path:
        """The install path, checked before anything is written to it.

        These are the checks that hold whoever controls the instance to
        something less than "write any file on the host as root". They do not
        get all the way there -- see the module docstring -- but they turn the
        two accidents that actually happen, a relative path and a traversal,
        into a refusal.
        """
        raw = self.path.strip()
        if not raw:
            raise KeyringError(f"{KEY_PATH} is empty")
        if "\x00" in raw:
            raise KeyringError(f"{KEY_PATH} contains a NUL byte")
        path = Path(raw)
        if not path.is_absolute():
            raise KeyringError(
                f"{KEY_PATH} is {raw!r}, which is relative. The host resolves "
                "it as root from whatever directory the unit happened to start "
                "in, so it must be absolute."
            )
        if ".." in path.parts:
            raise KeyringError(f"{KEY_PATH} is {raw!r}, which traverses upward")
        return path

    def validated_mode(self) -> int:
        try:
            mode = int(self.mode, 8)
        except ValueError as exc:
            raise KeyringError(f"{KEY_MODE} is {self.mode!r}, which is not octal") from exc
        if mode & 0o077:
            raise KeyringError(
                f"{KEY_MODE} is {self.mode}, which is readable beyond its owner. "
                "This is the key the estate's secrets are encrypted to."
            )
        return mode

    def as_secrets(self) -> dict[str, str]:
        return {
            KEY_PATH: self.path,
            KEY_OWNER: self.owner,
            KEY_GROUP: self.group,
            KEY_MODE: self.mode,
        }

    @classmethod
    def from_secrets(cls, values: dict[str, str]) -> "Placement":
        return cls(
            path=values.get(KEY_PATH) or DEFAULT_INSTALL_PATH,
            owner=values.get(KEY_OWNER) or DEFAULT_OWNER,
            group=values.get(KEY_GROUP) or DEFAULT_GROUP,
            mode=values.get(KEY_MODE) or DEFAULT_MODE,
        )


# -- summaries --------------------------------------------------------------


@dataclass
class PushSummary:
    """What an upload did. Never contains the key."""

    name: str = ""
    project: str = DEFAULT_PROJECT
    project_id: str = ""
    created_project: bool = False
    recipients: list[str] = field(default_factory=list)
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
            f"key {'replaced' if self.replaced else 'stored'}, "
            f"recipients {len(self.recipients)}, errors {len(self.errors)}"
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
    written: bool = False
    unchanged: bool = False
    recipients: list[str] = field(default_factory=list)
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
        return (
            f"keyring {self.name}: {state} at {self.path}, "
            f"{self.keys_in_file} key(s), recipients "
            f"{', '.join(self.recipients) if self.recipients else 'unrecorded'}"
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
    placement: Placement | None = None,
    replace: bool = False,
    dry_run: bool = False,
) -> PushSummary:
    """Store an age key and its placement policy under ``name``.

    Create-only by default. Overwriting the key a fleet is already encrypted to
    is the single most destructive thing in this package: every host that pulls
    afterwards gets an identity that decrypts nothing, and it fails at the next
    activation rather than now, which is a failure separated from its cause by
    however long that takes. ``replace=True`` is the operator saying they meant
    it, and the summary names both recipients so the change is visible.
    """
    placement = placement or Placement()
    summary = PushSummary(name=name, project=project)

    try:
        keys = parse_age_key_file(key_text)
    except KeyringError as exc:
        summary.errors.append(str(exc))
        return summary

    # Validated before anything is created, not at install time. A path the
    # host will refuse is a keyring entry that looks stored and is not usable,
    # and the operator is here now.
    try:
        placement.validated_path()
        placement.validated_mode()
    except KeyringError as exc:
        summary.errors.append(str(exc))
        return summary

    recipients, note = derive_recipients(key_text)
    summary.recipients = recipients
    if note:
        summary.notes.append(note)

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
            f"{project}/{ENVIRONMENT}{_folder(name)} already holds a key "
            f"(recipients: {previous}). Refusing to overwrite it: every host "
            "that has pulled it decrypts with it, and a replacement fails at "
            "their next activation rather than here. Pass --replace if this is "
            "a rotation you have planned the re-encryption for."
        )
        return summary
    summary.replaced = bool(existing.get(KEY_SECRET))

    payload = {KEY_SECRET: key_text, **placement.as_secrets()}
    if recipients:
        payload[KEY_PUBLIC] = " ".join(recipients)

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
        folders = {
            "/" + str(entry.get("secretPath") or "/").strip("/")
            for entry in client.list_secrets(
                project_id=project_id, environment=ENVIRONMENT, path="/"
            )
            if entry.get("secretKey") == KEY_SECRET
        }
        report.keys = sorted(folder.strip("/") for folder in folders if folder != "/")
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


def _refuse_to_clobber(destination: Path) -> None:
    """Never overwrite a file at ``destination`` that is not an age key file.

    The path came from the instance. This is the check that keeps a wrong one
    from being destructive rather than merely wrong: if something is already
    there and it does not look like what we are about to write, we stop. A
    keyring pointed at ``/etc/shadow`` then fails loudly on a host that still
    has its ``/etc/shadow``.
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
            "so it cannot be confirmed to be an age key file. Refusing to "
            "overwrite it."
        ) from exc
    if _SECRET_KEY_PREFIX not in current.upper():
        raise KeyringError(
            f"{destination} already exists and holds no age secret key. "
            f"Refusing to overwrite it: {KEY_PATH} in the instance points at a "
            "file this host is using for something else."
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

    # Validated on arrival, before the placement is even resolved. What is
    # about to be overwritten is the only thing that can read this host's
    # secrets, and a value that is not an age key can only make that worse.
    try:
        keys = parse_age_key_file(key_text)
    except KeyringError as exc:
        summary.errors.append(f"{KEY_SECRET} from the instance is not usable: {exc}")
        return summary
    summary.keys_in_file = len(keys)
    stored_recipients = (values.get(KEY_PUBLIC) or "").split()
    summary.recipients = [item for item in stored_recipients if item.startswith("age1")]

    placement = Placement.from_secrets(values)
    if path_override:
        placement = Placement(
            path=path_override,
            owner=placement.owner,
            group=placement.group,
            mode=placement.mode,
        )
        summary.actions.append(
            f"path overridden locally to {path_override} (instance says "
            f"{values.get(KEY_PATH) or DEFAULT_INSTALL_PATH})"
        )

    try:
        destination = placement.validated_path()
        placement.validated_mode()
    except KeyringError as exc:
        summary.errors.append(str(exc))
        return summary
    summary.path = str(destination)

    try:
        _refuse_to_clobber(destination)
    except KeyringError as exc:
        summary.errors.append(str(exc))
        return summary

    if dry_run:
        summary.actions.append(
            f"would write {len(keys)} key(s) to {destination} as "
            f"{placement.owner}:{placement.group} {placement.mode}"
        )
        return summary

    # materialise() is the agent's: atomic rename, ownership and mode set
    # before the file is visible at its final name. The reader here is sops-nix
    # at activation, which is exactly the "opens it mid-run" case that
    # write-then-chmod would lose to.
    spec = SecretSpec(
        project=project,
        environment=ENVIRONMENT,
        folder=_folder(name),
        name=KEY_SECRET,
        path=destination,
        owner=placement.owner,
        group=placement.group,
        mode=placement.mode,
    )
    try:
        changed = materialise(spec, key_text)
    except AgentError as exc:
        summary.errors.append(str(exc))
        return summary
    summary.written = changed
    summary.unchanged = not changed
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
        description="Fetch this host's age key from Infisical and install it.",
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
