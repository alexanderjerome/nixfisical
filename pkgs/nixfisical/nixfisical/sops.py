"""Thin, secret-safe wrapper around the ``sops`` binary.

We shell out rather than binding libsops because the operator's key material
(age keys, GPG agents, KMS profiles) is already wired into their environment
for the ``sops`` CLI; reimplementing that resolution would be a new and worse
source of "works on my machine".

Two rules govern everything in this module:

1. **A decrypted value never reaches a log, an exception message, or stdout.**
   Errors name the file and the key path only. ``sops`` itself writes its
   diagnostics to stderr and its plaintext to stdout, so we capture the two
   separately and only ever propagate stderr.
2. **Decrypt each file at most once per process.** The Ansible role invoked
   ``sops --extract`` once per secret, which meant a 50-secret sync paid 50
   key-unwrap round trips (and, with a hardware-backed key, 50 touch prompts).
   ``read_key`` decrypts a file once, caches the parsed document, and indexes
   into it. ``extract`` is retained for the handful of one-off admin-file reads
   where the caching is not worth holding plaintext in memory.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import yaml

__all__ = [
    "SopsError",
    "decrypt_yaml",
    "encrypt_in_place",
    "extract",
    "read_key",
    "sops_key_expr",
    "clear_cache",
]

# Path (resolved, as a string) -> fully decrypted document. Process-lifetime
# only; nothing here is written back to disk.
_DOCUMENT_CACHE: dict[str, Any] = {}


class SopsError(RuntimeError):
    """A ``sops`` invocation failed, or its output could not be used.

    The message carries the file and the key path being read so an operator can
    act on it, and never the decrypted value.
    """


def sops_key_expr(sops_key: str) -> str:
    """Convert a ``/``-delimited manifest key into sops ``--extract`` syntax.

    ``"services/bitcoin/rpc_password"`` becomes ``'["services"]["bitcoin"]["rpc_password"]'``.
    Leading and trailing slashes are tolerated so a manifest generator that
    emits absolute-looking keys still works.
    """
    segments = [segment for segment in sops_key.split("/") if segment]
    if not segments:
        raise SopsError(f"empty sops key path: {sops_key!r}")
    return "".join(f'["{segment}"]' for segment in segments)


def _run(argv: list[str], *, context: str) -> str:
    """Run ``sops`` and return stdout, raising :class:`SopsError` on failure.

    ``context`` is a human-readable description of what was being attempted; it
    is safe to log. stdout is *not* logged -- it is the plaintext.
    """
    try:
        proc = subprocess.run(  # noqa: S603 - argv is fully constructed here
            argv,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise SopsError(
            "the 'sops' binary is not on PATH; nixfisical requires it "
            f"(while {context})"
        ) from exc

    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise SopsError(f"sops failed while {context}: {stderr}")

    return proc.stdout


def extract(file: Path, key_path: str) -> str:
    """Decrypt ``file`` and return the single value at ``key_path``.

    ``key_path`` is already in sops extract syntax -- pass the output of
    :func:`sops_key_expr`. The returned string is stripped, because sops emits
    a trailing newline for scalar extractions and a trailing newline in an RPC
    password is a very annoying outage.
    """
    file = Path(file)
    if not file.is_file():
        raise SopsError(f"sops file does not exist: {file}")

    out = _run(
        ["sops", "--decrypt", "--extract", key_path, str(file)],
        context=f"extracting {key_path} from {file}",
    )
    value = out.strip()
    if not value:
        raise SopsError(f"sops returned an empty value for {key_path} in {file}")
    return value


def decrypt_yaml(file: Path) -> dict[str, Any]:
    """Fully decrypt ``file`` and parse it as YAML.

    Results are cached per resolved path for the life of the process; see the
    module docstring for why.
    """
    file = Path(file)
    cache_key = str(file.resolve()) if file.exists() else str(file)
    cached = _DOCUMENT_CACHE.get(cache_key)
    if cached is not None:
        return cached

    if not file.is_file():
        raise SopsError(f"sops file does not exist: {file}")

    out = _run(
        ["sops", "--decrypt", "--output-type", "yaml", str(file)],
        context=f"decrypting {file}",
    )
    try:
        document = yaml.safe_load(out)
    except yaml.YAMLError as exc:
        # Deliberately not including the exception's mark/context: PyYAML
        # errors quote the offending line, which here is plaintext.
        raise SopsError(f"decrypted content of {file} is not valid YAML") from None

    if document is None:
        document = {}
    if not isinstance(document, dict):
        raise SopsError(f"decrypted content of {file} is not a mapping")

    _DOCUMENT_CACHE[cache_key] = document
    return document


def read_key(file: Path, sops_key: str) -> str:
    """Return the value at ``sops_key`` (``a/b/c``) from ``file``, via the cache.

    This is the reconciler's path: the first secret from a file pays for the
    decrypt, every subsequent one is a dict lookup. Values are coerced to
    ``str`` because YAML happily parses ``12345`` as an int and Infisical only
    stores strings; booleans are normalised to lowercase so a round trip
    through YAML does not silently rewrite ``true`` to ``True``.
    """
    document = decrypt_yaml(file)

    segments = [segment for segment in sops_key.split("/") if segment]
    if not segments:
        raise SopsError(f"empty sops key path for file {file}")

    cursor: Any = document
    for depth, segment in enumerate(segments):
        if not isinstance(cursor, dict) or segment not in cursor:
            traversed = "/".join(segments[:depth]) or "<root>"
            raise SopsError(
                f"sops key {sops_key!r} not found in {file} "
                f"(no {segment!r} under {traversed})"
            )
        cursor = cursor[segment]

    if cursor is None:
        raise SopsError(f"sops key {sops_key!r} in {file} is null")
    if isinstance(cursor, (dict, list)):
        raise SopsError(
            f"sops key {sops_key!r} in {file} is a collection, not a scalar"
        )
    if isinstance(cursor, bool):
        return "true" if cursor else "false"
    return str(cursor)


def encrypt_in_place(file: Path) -> None:
    """Encrypt ``file`` in place with the ambient ``.sops.yaml`` rules.

    Callers that just wrote plaintext credentials MUST treat a raised
    :class:`SopsError` as fatal and remove that plaintext; see
    ``bootstrap.write_admin_file``.
    """
    file = Path(file)
    _run(
        ["sops", "--encrypt", "--in-place", str(file)],
        context=f"encrypting {file} in place",
    )


def clear_cache() -> None:
    """Drop every cached decrypted document.

    Exposed mainly for tests and for long-lived callers that want to bound how
    long plaintext lingers in this process's heap.
    """
    _DOCUMENT_CACHE.clear()
