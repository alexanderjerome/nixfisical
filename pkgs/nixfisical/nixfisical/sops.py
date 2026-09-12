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

The second half of the module is the write side, which the reconciler never
touches -- it exists for :mod:`nixfisical.store`, the operator's editing
surface. Three things there are load-bearing and were each learned the hard
way:

* ``sops --set`` cannot create a file, so ``set_key`` falls back to encrypting
  a one-key document with ``--filename-override``. That flag makes sops pick
  the format and the ``.sops.yaml`` creation rule from the DESTINATION path
  rather than from ``/dev/stdin``, which is the only way to write the first
  key of a new file without hand-rolling ``-e`` and hand-picking recipients.
* The ``--set`` expression parses its value as JSON, so it goes through
  ``json.dumps``. Hand-quoting corrupts any value containing a newline, a
  double quote, or a backslash -- which is to say, every PEM ever generated.
* Rewriting a whole document (the only way to delete a key: sops has no
  ``--unset``) stages through a temp file **in the same directory, with the
  same suffix**. A ``/tmp`` path matches no creation rule, so sops refuses
  before it even looks at recipients; matching the real rule also re-encrypts
  for the CURRENT full recipient set rather than whatever could be scraped off
  the old file's metadata.

Every mutation invalidates the cache entry for the file it touched.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
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
    "top_level_keys",
    "clear_cache",
    # write side
    "has_key",
    "leaf_keys",
    "lookup",
    "remove_key",
    "set_key",
    "write_document",
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


def _run(
    argv: list[str],
    *,
    context: str,
    stdin: str | None = None,
    cwd: Path | None = None,
) -> str:
    """Run ``sops`` and return stdout, raising :class:`SopsError` on failure.

    ``context`` is a human-readable description of what was being attempted; it
    is safe to log. stdout is *not* logged -- it is the plaintext, and neither
    is ``stdin``, which on the write path is a document about to be encrypted.

    ``cwd`` matters more than it looks: sops discovers ``.sops.yaml`` by walking
    up from where it runs, so writes are issued from the target file's own
    directory to guarantee the repo's rules are the ones that apply.
    """
    try:
        proc = subprocess.run(  # noqa: S603 - argv is fully constructed here
            argv,
            input=stdin,
            capture_output=True,
            text=True,
            check=False,
            cwd=str(cwd) if cwd is not None else None,
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


def top_level_keys(file: Path) -> set[str]:
    """Return ``file``'s top-level key names without decrypting anything.

    sops encrypts values, not key names, so the shape of a document is readable
    from the ciphertext. That is the whole point of this function: it lets a
    caller ask "does this admin file have an ``admin`` block?" -- the difference
    between an instance admin file and a per-org one -- without unwrapping a
    key, prompting for a touch, or holding a superadmin password in memory to
    answer a question about structure.

    ``sops`` itself is excluded; it is metadata, not content.
    """
    file = Path(file)
    if not file.is_file():
        raise SopsError(f"sops file does not exist: {file}")

    try:
        document = yaml.safe_load(file.read_text())
    except yaml.YAMLError as exc:
        raise SopsError(f"{file} is not parseable as YAML: {exc}") from exc

    if not isinstance(document, dict):
        raise SopsError(f"{file} is not a YAML mapping")

    return {str(key) for key in document if key != "sops"}


def _cache_key(file: Path) -> str:
    return str(file.resolve()) if file.exists() else str(file)


def _forget(file: Path) -> None:
    """Drop ``file`` from the document cache after mutating it on disk."""
    _DOCUMENT_CACHE.pop(_cache_key(Path(file)), None)


def decrypt_yaml(file: Path, *, use_cache: bool = True) -> dict[str, Any]:
    """Fully decrypt ``file`` and parse it as YAML.

    Results are cached per resolved path for the life of the process; see the
    module docstring for why. Pass ``use_cache=False`` on a read that is about
    to become a read-modify-write, so a mutation never rebases onto a snapshot
    taken before someone else's edit.
    """
    file = Path(file)
    cache_key = _cache_key(file)
    cached = _DOCUMENT_CACHE.get(cache_key) if use_cache else None
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


# ---------------------------------------------------------------------------
# write side
# ---------------------------------------------------------------------------


def _segments(sops_key: str) -> list[str]:
    parts = [segment for segment in sops_key.split("/") if segment]
    if not parts:
        raise SopsError(f"empty sops key path: {sops_key!r}")
    return parts


def _write_target(file: Path) -> Path:
    """Absolutise a write target, without resolving symlinks.

    Writes run from the file's own directory so sops finds the repo's
    ``.sops.yaml``, which means a relative path handed to sops would be
    interpreted against the wrong base. ``abspath`` rather than ``resolve``
    because creation rules are ``path_regex`` matches against the path as
    given: a repo reached through a symlink should still match the rule
    written for its logical layout.
    """
    return Path(os.path.abspath(Path(file).expanduser()))


def leaf_keys(document: dict[str, Any], prefix: str = "") -> list[str]:
    """List every leaf path in a decrypted document, as ``a/b/c`` strings.

    ``sops`` encrypts values, not structure, so this is also the shape of an
    *un*decrypted file -- but callers here always pass plaintext, and the
    return value is key names only, never values.
    """
    found: list[str] = []
    for key, value in sorted(document.items()):
        if key == "sops":  # sops' own metadata block, not a secret
            continue
        path = f"{prefix}/{key}" if prefix else key
        if isinstance(value, dict):
            found.extend(leaf_keys(value, path))
        else:
            found.append(path)
    return found


def lookup(file: Path, sops_key: str, *, use_cache: bool = True) -> Any:
    """Resolve ``sops_key`` in ``file`` and return the node, or ``None``.

    Unlike :func:`read_key` this does not insist the node is a scalar and does
    not raise when the path is absent -- it is the "does this exist, and what
    shape is it" primitive that the editing commands branch on. A missing file
    is an absent key, not an error: writing the first key of a store is a
    normal thing to do.
    """
    file = Path(file)
    if not file.is_file():
        return None

    cursor: Any = decrypt_yaml(file, use_cache=use_cache)
    for segment in _segments(sops_key):
        if not isinstance(cursor, dict) or segment not in cursor:
            return None
        cursor = cursor[segment]
    return cursor


def has_key(file: Path, sops_key: str, *, use_cache: bool = True) -> bool:
    """True when ``sops_key`` resolves to anything at all in ``file``."""
    return lookup(file, sops_key, use_cache=use_cache) is not None


def _create_with_key(file: Path, segments: list[str], value: str) -> None:
    """Mint a new encrypted file holding exactly one key.

    See the module docstring for why ``--filename-override`` is the whole
    trick. Nothing is written to disk until sops has produced ciphertext, so a
    failure here leaves no plaintext behind.
    """
    tree: dict[str, Any] = {}
    node = tree
    for segment in segments[:-1]:
        node = node.setdefault(segment, {})
    node[segments[-1]] = value

    file.parent.mkdir(parents=True, exist_ok=True)
    ciphertext = _run(
        ["sops", "--encrypt", "--filename-override", str(file), "/dev/stdin"],
        context=f"creating {file}",
        stdin=yaml.safe_dump(tree, default_flow_style=False, sort_keys=False),
        cwd=file.parent,
    )
    file.write_text(ciphertext)


def set_key(file: Path, sops_key: str, value: str) -> str:
    """Write ``value`` at ``sops_key`` in ``file``, creating the file if needed.

    Returns ``"created"`` when the file did not exist, ``"updated"`` otherwise
    -- the caller reports that, because "I meant to edit a store and instead
    minted a second one next to it" is a typo class worth surfacing.
    """
    file = _write_target(file)
    segments = _segments(sops_key)

    if not file.is_file():
        _create_with_key(file, segments, value)
        _forget(file)
        return "created"

    expression = "".join(f'["{segment}"]' for segment in segments)
    _run(
        ["sops", "--set", f"{expression} {json.dumps(value)}", str(file)],
        context=f"setting {sops_key} in {file}",
        cwd=file.parent,
    )
    _forget(file)
    return "updated"


def write_document(file: Path, document: dict[str, Any]) -> None:
    """Replace ``file`` with an encrypted ``document``, atomically.

    Plaintext touches the disk for the width of one sops invocation, in a
    0600 file in the destination's own directory; it is unlinked on every
    path out. The real file is only replaced once ciphertext exists, so an
    interrupted run cannot leave a half-written or plaintext store.
    """
    file = _write_target(file)
    file.parent.mkdir(parents=True, exist_ok=True)

    handle = tempfile.NamedTemporaryFile(
        mode="w",
        dir=file.parent,
        prefix=f".{file.name}.",
        suffix=file.suffix or ".yaml",
        delete=False,
    )
    staging = Path(handle.name)
    try:
        with handle:
            yaml.safe_dump(
                document, handle, default_flow_style=False, sort_keys=False
            )
        _run(
            ["sops", "--encrypt", "--in-place", str(staging)],
            context=f"re-encrypting {file}",
            cwd=file.parent,
        )
        os.replace(staging, file)
        staging = None  # type: ignore[assignment]
    finally:
        if staging is not None and staging.exists():
            staging.unlink()
    _forget(file)


def remove_key(file: Path, sops_key: str) -> None:
    """Delete ``sops_key`` from ``file``.

    sops has no ``--unset``, so this is a decrypt / prune / re-encrypt cycle.
    Emptied parent maps are pruned too: a store littered with ``oidc: {}``
    stanzas reads as "this app still has secrets here" to the next person.
    """
    file = Path(file)
    segments = _segments(sops_key)
    document = dict(decrypt_yaml(file, use_cache=False))

    chain: list[dict[str, Any]] = [document]
    cursor: Any = document
    for depth, segment in enumerate(segments[:-1]):
        if not isinstance(cursor, dict) or segment not in cursor:
            traversed = "/".join(segments[:depth]) or "<root>"
            raise SopsError(
                f"sops key {sops_key!r} not found in {file} "
                f"(no {segment!r} under {traversed})"
            )
        cursor = cursor[segment]
        chain.append(cursor)

    if not isinstance(cursor, dict) or segments[-1] not in cursor:
        raise SopsError(f"sops key {sops_key!r} not found in {file}")
    del cursor[segments[-1]]

    # Walk back up dropping maps this delete just emptied.
    for depth in range(len(chain) - 1, 0, -1):
        if chain[depth]:
            break
        del chain[depth - 1][segments[depth - 1]]

    write_document(file, document)
