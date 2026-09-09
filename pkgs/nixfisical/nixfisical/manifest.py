"""Loading and validation of the declarative secret manifest.

The manifest is a JSON array produced by the Nix half of this repo from the
NixOS configurations of the estate. It is the single source of truth for what
Infisical should contain; ``reconcile`` makes the instance match it.

An entry looks like::

    {
      "sopsKey":     "services/bitcoin/rpc_password",
      "sopsFile":    "secrets/bitcoin.yaml",
      "project":     "bitcoin-nodes",
      "environment": "prod",
      "folder":      "/mainnet",
      "name":        "RPC_PASSWORD",
      "groups":      ["developers"],
      "hosts":       ["btc-mainnet"]
    }

``sopsFile`` being per-entry is the principal improvement over the Ansible
role, which had one global ``infisical_secrets_file``. Secrets in a real estate
are split across files along trust boundaries, and forcing them into one file
to satisfy the tool was the wrong direction of accommodation.

Validation is deliberately a separate pass returning *all* problems rather than
raising on the first: a manifest is generated wholesale, so an operator wants
the full list, not a game of whack-a-mole across regeneration cycles.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

__all__ = ["REQUIRED_FIELDS", "load", "validate", "resolve_paths", "entry_label"]

# Fields every entry must carry. ``sopsFile`` is deliberately absent: it may be
# supplied per entry or fall back to a global default, so it is checked
# separately by :func:`validate`.
REQUIRED_FIELDS: tuple[str, ...] = (
    "sopsKey",
    "project",
    "environment",
    "folder",
    "name",
)

# Infisical environment slugs end up in URLs and in the folder tree; anything
# outside this set produces a project that looks fine in the UI and 404s from
# the API.
_ENV_SLUG_RE = re.compile(r"^[a-z0-9-]+$")


def entry_label(entry: dict[str, Any], index: int) -> str:
    """A stable, secret-free identifier for an entry, for error messages.

    Prefers the ``sopsKey`` (which names a location, not a value) and falls
    back to the array index when the entry is too malformed to have one.
    """
    key = entry.get("sopsKey")
    if isinstance(key, str) and key:
        return f"entry[{index}] sopsKey={key!r}"
    return f"entry[{index}]"


def load(source: str | Path) -> list[dict[str, Any]]:
    """Read a manifest from a JSON file, or from stdin when ``source`` is ``-``.

    Stdin support exists so the Nix side can pipe a freshly evaluated manifest
    straight in without landing it in the store or in ``/tmp``.
    """
    if str(source) == "-":
        raw = sys.stdin.read()
        origin = "<stdin>"
    else:
        path = Path(source)
        if not path.is_file():
            raise ValueError(f"manifest not found: {path}")
        raw = path.read_text(encoding="utf-8")
        origin = str(path)

    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"manifest {origin} is not valid JSON: {exc}") from exc

    if not isinstance(document, list):
        raise ValueError(f"manifest {origin} must be a JSON array of entries")

    entries: list[dict[str, Any]] = []
    for index, entry in enumerate(document):
        if not isinstance(entry, dict):
            raise ValueError(f"manifest {origin} entry[{index}] is not an object")
        entries.append(entry)
    return entries


def validate(
    manifest: Iterable[dict[str, Any]],
    *,
    default_secrets_file: str | Path | None = None,
    require_sops_file: bool = True,
) -> list[str]:
    """Return a list of human-readable problems; empty means the manifest is fine.

    ``default_secrets_file`` mirrors the CLI's ``--secrets-file``: when it is
    set, entries without their own ``sopsFile`` are acceptable. When it is not,
    a missing ``sopsFile`` is a hard error naming the offending ``sopsKey`` --
    the operator needs to know *which* secret has nowhere to be read from.

    ``require_sops_file=False`` drops that one check. It exists for
    ``sync-access``, which reads only ``project`` and ``groups`` and never
    opens a SOPS file: refusing to reconcile access because a secret has
    nowhere to be *read* from would be an unrelated complaint. Every other
    check still runs.
    """
    problems: list[str] = []
    seen: dict[tuple[str, str, str, str], int] = {}

    for index, entry in enumerate(manifest):
        label = entry_label(entry, index)

        for field in REQUIRED_FIELDS:
            value = entry.get(field)
            if not isinstance(value, str) or not value.strip():
                problems.append(f"{label}: missing or empty required field {field!r}")

        folder = entry.get("folder")
        if isinstance(folder, str) and folder and not folder.startswith("/"):
            problems.append(
                f"{label}: folder {folder!r} must be an absolute path starting with '/'"
            )
        if isinstance(folder, str) and folder.endswith("/") and folder != "/":
            problems.append(f"{label}: folder {folder!r} must not have a trailing '/'")

        environment = entry.get("environment")
        if isinstance(environment, str) and environment:
            if not _ENV_SLUG_RE.match(environment):
                problems.append(
                    f"{label}: environment {environment!r} is not a valid slug "
                    "(lowercase letters, digits and '-' only)"
                )

        sops_file = entry.get("sopsFile")
        if sops_file is not None and (not isinstance(sops_file, str) or not sops_file.strip()):
            problems.append(f"{label}: sopsFile must be a non-empty string when present")
        elif sops_file is None and default_secrets_file is None and require_sops_file:
            sops_key = entry.get("sopsKey", "<unknown>")
            problems.append(
                f"{label}: no sopsFile and no --secrets-file default; "
                f"cannot resolve a value for sopsKey {sops_key!r}"
            )

        for field in ("groups", "hosts"):
            value = entry.get(field)
            if value is not None and (
                not isinstance(value, list)
                or not all(isinstance(item, str) for item in value)
            ):
                problems.append(f"{label}: {field!r} must be a list of strings")

        # Duplicate destinations are always a generator bug: two entries writing
        # the same Infisical coordinate means one silently wins, and which one
        # depends on manifest ordering.
        coordinate = (
            str(entry.get("project", "")),
            str(entry.get("environment", "")),
            str(entry.get("folder", "")),
            str(entry.get("name", "")),
        )
        if all(coordinate):
            previous = seen.get(coordinate)
            if previous is not None:
                problems.append(
                    f"{label}: duplicate destination "
                    f"{coordinate[0]}/{coordinate[1]}{coordinate[2]}:{coordinate[3]} "
                    f"(already declared by entry[{previous}])"
                )
            else:
                seen[coordinate] = index

    return problems


def resolve_paths(
    manifest: list[dict[str, Any]],
    root: Path,
    *,
    default_secrets_file: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Return a copy of ``manifest`` with every ``sopsFile`` made absolute.

    Relative paths are resolved against ``root`` (the repo checkout), because a
    manifest generated by Nix is most readable when it names repo-relative
    paths, but this process may run from anywhere. Entries lacking a
    ``sopsFile`` inherit ``default_secrets_file``; entries that still lack one
    are left alone so :func:`validate` remains the single place that reports
    it.
    """
    root = Path(root).expanduser()
    fallback = Path(default_secrets_file).expanduser() if default_secrets_file else None

    resolved: list[dict[str, Any]] = []
    for entry in manifest:
        copied = dict(entry)
        raw = copied.get("sopsFile")
        candidate: Path | None
        if isinstance(raw, str) and raw.strip():
            candidate = Path(raw).expanduser()
        else:
            candidate = fallback

        if candidate is not None:
            if not candidate.is_absolute():
                candidate = root / candidate
            copied["sopsFile"] = str(candidate)
        resolved.append(copied)
    return resolved
