"""Key material the keyring can hold: what it is, and how to check it.

:mod:`nixfisical.keyring` moves key material into Infisical and back out onto a
host. This module is the part that knows what the material *is* -- how to tell
one kind from another, how to prove a blob is really a key before it overwrites
a working one, and how to derive the public half so the operator can see what
they stored.

Two types today:

``age``
    The estate's sops-nix key. Validated by bech32 checksum (BIP-173), which
    catches the truncated paste that would otherwise upload cleanly and be
    discovered at some host's next activation.

``ssh``
    An OpenSSH private key. Validated by parsing the ``openssh-key-v1``
    container, which is the format ``ssh-keygen`` has produced by default since
    OpenSSH 7.8.

**Everything here is pure Python, and that is a requirement rather than a
preference.** The host side runs the ``minimal`` build, which carries no
``age``, no ``ssh-keygen`` and nothing else on PATH, and the host is exactly
where a mangled key must be caught -- it is about to be written over the one
that works. A check that only runs on the operator's machine is a check that is
absent when it matters.

It pays off twice for SSH. The public half of an OpenSSH private key is stored
*in cleartext inside the private file*, before the encrypted section, so it can
be derived from a passphrase-protected key without the passphrase and without
shelling out. ``age`` has no equivalent: there ``age-keygen -y`` is
authoritative and the ``# public key:`` comment is the fallback, which is why
:func:`derive_public` reports which source it used.

Adding a type means adding a :class:`Material` and its three functions. It does
not mean touching the keyring's push, audit or install logic, which is the
point of the split.
"""

from __future__ import annotations

import base64
import binascii
import subprocess
from dataclasses import dataclass
from typing import Callable, Iterable

__all__ = [
    "AGE",
    "KeyringError",
    "Material",
    "Parsed",
    "SSH",
    "TYPES",
    "derive_public",
    "detect",
    "get",
    "looks_like",
    "parse_private",
]


class KeyringError(RuntimeError):
    """Key material that cannot be used, or a keyring operation that must stop.

    Defined here rather than in :mod:`nixfisical.keyring` so that module can
    import this one without a cycle. It is re-exported there, which is where
    callers should expect to find it.
    """


@dataclass(frozen=True)
class Parsed:
    """The result of validating a key file: how many keys, and what they are.

    The split between :attr:`kinds` and :attr:`secrets` is the whole reason
    this is a dataclass rather than a list. Summaries, logs and error messages
    take :attr:`kinds`, which is safe to print. :attr:`secrets` holds the raw
    private tokens for the one caller that needs them and is never displayed --
    a plain ``list[str]`` return made that distinction a thing to remember, and
    the failure mode of forgetting is a private key in a systemd journal.
    """

    #: One safe-to-print label per key in the file: ``"age"``, ``"ssh-ed25519"``.
    kinds: tuple[str, ...]
    #: One raw private token per key, for ``age`` only. **Never log these.**
    secrets: tuple[str, ...] = ()

    def __len__(self) -> int:
        return len(self.kinds)


# -- bech32 -----------------------------------------------------------------
#
# Enough of BIP-173 to answer one question: is this string a structurally valid
# age secret key, checksum and all? A truncated paste or a byte flipped in
# transit produces a key that looks right and decrypts nothing, and the place
# to catch that is before it is written over the working one.

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
        raise KeyringError(f"age key has the prefix {hrp!r}, expected {expected_hrp!r}")
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


# -- age --------------------------------------------------------------------

_AGE_SECRET_PREFIX = "AGE-SECRET-KEY-1"
_AGE_PUBLIC_COMMENT = "# public key:"


def _parse_age(text: str) -> Parsed:
    """Validate every secret key in an age key file.

    An age key file is a sequence of ``AGE-SECRET-KEY-1...`` lines with ``#``
    comments between them, and sops-nix is happy with several -- which is how a
    rekeying is done without a flag day. So the file is taken whole and every
    key in it is checked, rather than the first one being extracted and the rest
    silently dropped.
    """
    keys: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not stripped.upper().startswith(_AGE_SECRET_PREFIX):
            raise KeyringError(
                f"line {number} is neither a comment nor an age secret key. "
                "This does not look like an age key file -- an SSH private key "
                "and a sops-nix key file are easy to confuse, and `--type ssh` "
                "is how you say you meant the other one."
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
    return Parsed(kinds=("age",) * len(keys), secrets=tuple(keys))


def _commented_recipients(text: str) -> list[str]:
    """Recipients from the ``# public key:`` lines age-keygen writes."""
    found = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith(_AGE_PUBLIC_COMMENT):
            candidate = stripped[len(_AGE_PUBLIC_COMMENT) :].strip()
            if candidate.startswith("age1"):
                found.append(candidate)
    return found


def _public_age(text: str) -> tuple[list[str], str | None]:
    """Recipients for an age key file, and a note when they had to be guessed.

    ``age-keygen -y`` is authoritative and reads the key on stdin, so nothing is
    written to disk to ask it. When it is absent -- a pip install, or the
    ``minimal`` build -- the ``# public key:`` comments are used instead, and
    the note says so, because a comment is an assertion about the file rather
    than a fact derived from it. When both are available they are compared: a
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


def _looks_like_age(text: str) -> bool:
    return _AGE_SECRET_PREFIX in text.upper()


# -- ssh --------------------------------------------------------------------

_OPENSSH_BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----"
_OPENSSH_END = "-----END OPENSSH PRIVATE KEY-----"
_OPENSSH_MAGIC = b"openssh-key-v1\x00"

# The PEM headers of the formats `ssh-keygen -m PEM` and older OpenSSH emit.
# They are accepted as material but their public half cannot be derived without
# doing RSA/EC arithmetic, which is not worth a dependency here -- see
# `_public_ssh`.
_OTHER_PRIVATE_HEADERS = (
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN DSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
)


def _openssh_body(text: str) -> bytes | None:
    """The base64 payload between the OpenSSH armour, or None if not present."""
    if _OPENSSH_BEGIN not in text:
        return None
    after = text.split(_OPENSSH_BEGIN, 1)[1]
    if _OPENSSH_END not in after:
        raise KeyringError(
            "OpenSSH private key has an opening armour line but no "
            f"'{_OPENSSH_END}'. The file is truncated."
        )
    body = after.split(_OPENSSH_END, 1)[0]
    packed = "".join(body.split())
    try:
        return base64.b64decode(packed, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise KeyringError(
            f"OpenSSH private key body is not valid base64 ({exc}). The file has "
            "been re-wrapped, truncated, or mangled in transit."
        ) from exc


def _ssh_string(blob: bytes, offset: int, *, what: str) -> tuple[bytes, int]:
    """Read one length-prefixed SSH string (RFC 4251 section 5)."""
    if offset + 4 > len(blob):
        raise KeyringError(f"OpenSSH private key ends before its {what} length")
    length = int.from_bytes(blob[offset : offset + 4], "big")
    offset += 4
    if length > len(blob) - offset:
        raise KeyringError(
            f"OpenSSH private key declares a {length}-byte {what} but only "
            f"{len(blob) - offset} bytes remain. It is truncated."
        )
    return blob[offset : offset + length], offset + length


def _openssh_public_blobs(blob: bytes) -> tuple[list[bytes], bool]:
    """Every public-key blob in an ``openssh-key-v1`` container, and whether
    the private section is encrypted.

    The container puts the public keys in cleartext ahead of the encrypted
    section, which is what lets a passphrase-protected key be verified and have
    its public half derived without the passphrase.
    """
    if not blob.startswith(_OPENSSH_MAGIC):
        raise KeyringError(
            "OpenSSH private key does not begin with the 'openssh-key-v1' "
            "magic. The armour says OpenSSH but the contents do not."
        )
    offset = len(_OPENSSH_MAGIC)
    cipher, offset = _ssh_string(blob, offset, what="cipher name")
    _kdf, offset = _ssh_string(blob, offset, what="kdf name")
    _kdfopts, offset = _ssh_string(blob, offset, what="kdf options")
    if offset + 4 > len(blob):
        raise KeyringError("OpenSSH private key ends before its key count")
    count = int.from_bytes(blob[offset : offset + 4], "big")
    offset += 4
    if count == 0:
        raise KeyringError("OpenSSH private key declares zero keys")
    if count > 16:
        raise KeyringError(
            f"OpenSSH private key declares {count} keys, which is not a file "
            "ssh-keygen produces. Refusing to parse it."
        )
    blobs = []
    for index in range(count):
        public, offset = _ssh_string(blob, offset, what=f"public key {index}")
        blobs.append(public)
    return blobs, cipher != b"none"


def _parse_ssh(text: str) -> Parsed:
    """Validate an SSH private key file, and name the keys in it."""
    stripped = text.strip()
    if not stripped:
        raise KeyringError("SSH private key file is empty")

    body = _openssh_body(text)
    if body is not None:
        blobs, _encrypted = _openssh_public_blobs(body)
        kinds = []
        for blob in blobs:
            keytype, _ = _ssh_string(blob, 0, what="key type")
            kinds.append(keytype.decode("ascii", "replace"))
        return Parsed(kinds=tuple(kinds))

    for header in _OTHER_PRIVATE_HEADERS:
        if header in text:
            # Accepted, not parsed. Deriving a public key from PKCS#1 or SEC1
            # means implementing RSA/EC key encoding, and the sidecar `.pub`
            # covers the case without it.
            label = header.removeprefix("-----BEGIN ").removesuffix(" PRIVATE KEY-----")
            return Parsed(kinds=(f"pem-{label.lower() or 'pkcs8'}",))

    if stripped.startswith("ssh-") or stripped.startswith("ecdsa-"):
        raise KeyringError(
            "this is an SSH *public* key, not a private one. The keyring stores "
            "the private half and installs the public one beside it; pass the "
            "file without the '.pub'."
        )
    raise KeyringError(
        "no SSH private key in this file. Expected an "
        f"'{_OPENSSH_BEGIN}' armour line."
    )


def _public_ssh(text: str) -> tuple[list[str], str | None]:
    """The public key line(s) for an SSH private key.

    Derived straight from the private file's own cleartext public section, so
    this works on an encrypted key and needs no ``ssh-keygen``. The comment is
    not recoverable this way -- it lives in the encrypted section -- so the
    caller supplies it from the sidecar ``.pub`` when there is one.
    """
    body = _openssh_body(text)
    if body is None:
        return [], (
            "public key not derived: this is a PEM-format private key, whose "
            "public half cannot be computed without RSA/EC arithmetic. Pass "
            "--public-from-file, or convert the key with "
            "`ssh-keygen -p -m RFC4716 -f <key>`."
        )
    blobs, encrypted = _openssh_public_blobs(body)
    lines = []
    for blob in blobs:
        keytype, _ = _ssh_string(blob, 0, what="key type")
        lines.append(f"{keytype.decode('ascii', 'replace')} {base64.b64encode(blob).decode('ascii')}")
    note = None
    if encrypted:
        note = (
            "the private key is passphrase-protected; it is stored as-is and a "
            "host installing it will need that passphrase to use it"
        )
    return lines, note


def _looks_like_ssh(text: str) -> bool:
    upper = text.upper()
    return _OPENSSH_BEGIN in upper or any(
        header in upper for header in _OTHER_PRIVATE_HEADERS
    )


# Every key-type name OpenSSH puts at the start of a public key line, plus the
# `sk-` FIDO variants. Used only to recognise a file as a public key before
# overwriting it, so a prefix match is the right strictness.
_SSH_PUBLIC_PREFIXES = ("ssh-", "ecdsa-", "sk-ssh-", "sk-ecdsa-")


def _looks_like_ssh_public(text: str) -> bool:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        return stripped.startswith(_SSH_PUBLIC_PREFIXES)
    return False


def _never(_text: str) -> bool:
    return False


# -- the type table ---------------------------------------------------------


@dataclass(frozen=True)
class Material:
    """One kind of key the keyring can hold."""

    name: str
    label: str
    #: Where an entry of this type goes when the push does not say.
    default_path: str
    #: Mode for the private half. Owner-only; the keyring refuses anything else.
    default_mode: str
    #: Whether the public half is installed as a file beside the private one.
    installs_public: bool
    #: Suffix appended to the private path for that file.
    public_suffix: str
    #: Mode for the public half. Deliberately world-readable: an SSH client and
    #: an `authorized_keys` workflow both expect to read it, and it is public.
    public_mode: str
    parse: Callable[[str], Parsed]
    public: Callable[[str], tuple[list[str], str | None]]
    matches: Callable[[str], bool]
    #: Does this text look like *the public half* of this type? Asked before
    #: overwriting an existing file at the public destination, for the same
    #: reason `matches` is asked before overwriting the private one. Never
    #: called when `installs_public` is False.
    public_matches: Callable[[str], bool] = _never


AGE = Material(
    name="age",
    label="age key",
    # sops-nix's own default for `sops.age.keyFile`. Matching it means a host
    # that takes the default needs no configuration at all beyond enabling the
    # pull.
    default_path="/var/lib/sops-nix/key.txt",
    default_mode="0400",
    installs_public=False,
    public_suffix="",
    public_mode="0444",
    parse=_parse_age,
    public=_public_age,
    matches=_looks_like_age,
)

SSH = Material(
    name="ssh",
    label="SSH private key",
    # There is no defensible default for an SSH key the way there is for the
    # estate's age key: it belongs to a user, in that user's home. This value
    # exists so the option is never unset, and the push refuses it loudly
    # rather than silently installing root's key for somebody.
    default_path="/root/.ssh/id_ed25519",
    default_mode="0600",
    installs_public=True,
    public_suffix=".pub",
    public_mode="0644",
    parse=_parse_ssh,
    public=_public_ssh,
    matches=_looks_like_ssh,
    public_matches=_looks_like_ssh_public,
)

TYPES = {material.name: material for material in (AGE, SSH)}


def get(name: str) -> Material:
    """The :class:`Material` called ``name``, or raise."""
    try:
        return TYPES[name.strip().lower()]
    except KeyError:
        raise KeyringError(
            f"unknown key type {name!r}; known types are "
            f"{', '.join(sorted(TYPES))}"
        ) from None


def detect(text: str) -> Material:
    """Work out what kind of key ``text`` holds.

    Sniffing rather than asking is right here because the two formats are not
    remotely confusable -- one is bech32 lines, the other is PEM armour -- and
    an operator who has to name the type is an operator who can name the wrong
    one. ``--type`` stays available to force the issue, and forcing it produces
    a specific error instead of this generic one.
    """
    matched = [material for material in TYPES.values() if material.matches(text)]
    if len(matched) == 1:
        return matched[0]
    if not matched:
        raise KeyringError(
            "cannot tell what kind of key this is: it holds neither an "
            "'AGE-SECRET-KEY-1' line nor a private-key PEM armour line. Pass "
            "--type to say what it should be and get a specific error."
        )
    raise KeyringError(
        "this file holds more than one kind of key material "
        f"({', '.join(sorted(m.name for m in matched))}); split it up. Pass "
        "--type to force one."
    )


def parse_private(material: Material, text: str) -> Parsed:
    """Validate ``text`` as ``material``, describing the keys it holds."""
    return material.parse(text)


def derive_public(material: Material, text: str) -> tuple[list[str], str | None]:
    """The public half of ``text``, and a note when it is not authoritative."""
    return material.public(text)


def looks_like(material: Material, text: str) -> bool:
    """Cheap check used before overwriting a file: is this the same kind?"""
    return material.matches(text)
