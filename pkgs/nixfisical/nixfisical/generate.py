"""Generation of fresh secret material.

This exists because the alternative is a shell one-liner. ``openssl rand -hex
32 | sops --set ...`` is three tools, two pipes and a temp file away from a
secret that is silently truncated, silently newline-suffixed, or silently
written to the shell history -- and it is written from memory, differently,
every time a service needs one. A verb with a named kind is auditable: the
next person reads ``kind: alnum, length: 48`` and knows exactly what is in the
store without decrypting it.

Everything here draws from :mod:`secrets`, i.e. ``os.urandom``. There is no
seeding parameter and no reproducible mode, deliberately: a "generate the same
secret again" feature is a footgun with no legitimate use here, since the way
to get the same secret into two places is to write it to both (see
``store.ensure_generated``), not to regenerate it.

Length is always **output characters**, for every kind, so that what you ask
for is what lands in the store. That differs from ``openssl rand``, which
counts input bytes, and the difference is exactly the trap: ``rand -base64 32``
yields 44 characters, not 32.
"""

from __future__ import annotations

import math
import secrets
import string
import uuid
from dataclasses import dataclass

__all__ = ["GenerateError", "KINDS", "Kind", "entropy_bits", "generate", "kind_help"]

# Below this, a generated credential is not meaningfully better than one a
# human picked, and the tool should not pretend otherwise. Callers wanting a
# short token want a different tool.
MIN_LENGTH = 12


class GenerateError(ValueError):
    """An unknown kind, or a length that would produce weak material."""


@dataclass(frozen=True)
class Kind:
    """One named recipe for secret material."""

    name: str
    default_length: int
    alphabet: str
    summary: str
    #: Require at least one character from each class (upper/lower/digit/
    #: symbol). Only ``password`` sets this, for admin logins behind a UI that
    #: enforces a complexity policy.
    mixed_case_required: bool = False


# The symbol set is conservative on purpose. No quote, backslash, backtick or
# dollar: these values get pasted into dotenv files, systemd EnvironmentFile
# lines, YAML and connection strings, and every one of those has a different
# opinion about at least one of those four characters.
_SYMBOLS = "!@#%^&*()-_=+[]{}"

KINDS: dict[str, Kind] = {
    "alnum": Kind(
        name="alnum",
        default_length=32,
        alphabet=string.ascii_letters + string.digits,
        summary="letters and digits; safe unquoted in URLs, libpq DSNs and env files",
    ),
    "hex": Kind(
        name="hex",
        default_length=64,
        alphabet=string.hexdigits[:16],
        summary="lowercase hex; what most OAuth2 client secrets look like",
    ),
    "urlsafe": Kind(
        name="urlsafe",
        default_length=50,
        alphabet=string.ascii_letters + string.digits + "-_",
        summary="base64url alphabet; signing keys, session keys, API tokens",
    ),
    "base64": Kind(
        name="base64",
        default_length=44,
        alphabet=string.ascii_letters + string.digits + "+/",
        summary="standard base64 alphabet, unpadded; for services that document "
        "`openssl rand -base64`",
    ),
    "password": Kind(
        name="password",
        default_length=32,
        alphabet=string.ascii_letters + string.digits + _SYMBOLS,
        summary="mixed case, digits and safe symbols; for a human-facing login",
        mixed_case_required=True,
    ),
    "uuid": Kind(
        name="uuid",
        default_length=36,
        alphabet="",
        summary="a random UUID4; identifiers, not credentials (--length ignored)",
    ),
}


def entropy_bits(kind: Kind, length: int) -> float:
    """Bits of entropy in a value of this kind and length."""
    if kind.name == "uuid":
        return 122.0  # UUID4 fixes 6 of its 128 bits
    return length * math.log2(len(kind.alphabet))


def kind_help() -> str:
    """A one-line-per-kind summary, for ``--help`` and error messages."""
    width = max(len(name) for name in KINDS)
    return "\n".join(
        f"  {k.name:<{width}}  {k.default_length:>3} chars  "
        f"{entropy_bits(k, k.default_length):>5.0f} bits  {k.summary}"
        for k in KINDS.values()
    )


def _satisfies_policy(value: str) -> bool:
    return (
        any(c.islower() for c in value)
        and any(c.isupper() for c in value)
        and any(c.isdigit() for c in value)
        and any(c in _SYMBOLS for c in value)
    )


def generate(kind_name: str, length: int | None = None) -> str:
    """Return fresh secret material of ``kind_name``.

    ``length`` counts output characters and defaults to the kind's own default.
    Raises :class:`GenerateError` rather than silently downgrading, because the
    caller is about to write the result somewhere durable.
    """
    kind = KINDS.get(kind_name)
    if kind is None:
        raise GenerateError(
            f"unknown kind {kind_name!r}; available kinds:\n{kind_help()}"
        )

    if kind.name == "uuid":
        return str(uuid.uuid4())

    size = kind.default_length if length is None else length
    if size < MIN_LENGTH:
        raise GenerateError(
            f"refusing to generate a {size}-character {kind.name} secret "
            f"({entropy_bits(kind, size):.0f} bits); the floor is {MIN_LENGTH}"
        )

    # Rejection sampling rather than "shuffle in one of each": inserting
    # required characters at fixed-then-shuffled positions is where homegrown
    # password generators leak bias. The loop is expected to run about once.
    for _ in range(1000):
        value = "".join(secrets.choice(kind.alphabet) for _ in range(size))
        if not kind.mixed_case_required or _satisfies_policy(value):
            return value

    raise GenerateError(  # pragma: no cover - unreachable for any sane length
        f"could not satisfy the {kind.name} complexity policy at length {size}"
    )
