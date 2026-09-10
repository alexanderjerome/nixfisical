"""Operator-facing operations on a SOPS store: list, read, write, generate.

:mod:`nixfisical.sops` knows how to make the ``sops`` binary do a thing.
This module knows which thing is the right one, and what an operator meant.
The split matters most for :func:`ensure_generated`, which is the reason this
module exists at all.

**The multi-destination problem.** A shared credential lives in more than one
encrypted file. Authentik's Postgres password is in the authentik host's file
*and* in the database host's file; an OAuth2 client secret is in the provider's
file *and* in the consumer's. Minting those by hand means generating once and
pasting twice, and the failure mode is not an error -- it is two files that
agree today and diverge at the next rotation, with the mismatch surfacing as an
authentication failure somewhere unrelated, months later.

So the generate verb takes N destinations and *converges* them:

* none of them hold a value  -> generate one, write it to all N
* some hold the same value   -> propagate that value to the rest, generate nothing
* all hold the same value    -> do nothing, exit 0
* they disagree              -> refuse, name the destinations, demand ``--rotate``

which makes it idempotent, re-runnable, and safe to put in a plan file that
describes a service's whole credential set. Adding a consumer later is an edit
to the plan and a re-run, not an archaeology exercise.

Nothing in this module prints a value. :class:`Outcome` carries the generated
material so that ``--print`` can exist for the one legitimate case -- pasting a
bootstrap password into a UI once -- and callers that do not ask for it never
see it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from nixfisical.bootstrap import BootstrapError, split_file_key
from nixfisical.generate import GenerateError, generate
from nixfisical.sops import (
    SopsError,
    decrypt_yaml,
    leaf_keys,
    lookup,
    remove_key,
    set_key,
)

__all__ = [
    "Change",
    "Destination",
    "Outcome",
    "PlanEntry",
    "StoreError",
    "ensure_generated",
    "get_value",
    "list_paths",
    "load_plan",
    "parse_destination",
    "remove_value",
    "set_value",
]


class StoreError(RuntimeError):
    """An operator-level problem: a bad reference, or a refusal to guess."""


@dataclass(frozen=True)
class Destination:
    """One ``FILE:KEY`` coordinate a secret should live at."""

    file: Path
    key: str

    @property
    def label(self) -> str:
        return f"{self.file}:{self.key}"


@dataclass(frozen=True)
class Change:
    """One write this run made, or would have made."""

    target: str
    result: str
    detail: str = ""

    def render(self) -> str:
        line = f"{self.result:<14} {self.target}"
        return f"{line}  -- {self.detail}" if self.detail else line


@dataclass
class Outcome:
    """What one :func:`ensure_generated` call did.

    ``value`` is plaintext. It is populated so that a caller which explicitly
    asked to see the secret can, and for no other reason -- do not log it, do
    not put it in an error, do not return it from anything that renders.
    """

    changes: list[Change] = field(default_factory=list)
    generated: bool = False
    propagated: bool = False
    written: int = 0
    dry_run: bool = False
    value: str | None = None

    def record(self, target: str, result: str, detail: str = "") -> None:
        self.changes.append(Change(target=target, result=result, detail=detail))

    def headline(self) -> str:
        if self.written == 0:
            return "already converged: every destination holds the same value"
        source = (
            "generated a new value"
            if self.generated
            else "propagated the existing value"
        )
        verb = "would write" if self.dry_run else "wrote"
        return f"{source}; {verb} {self.written} destination(s)"


def parse_destination(spec: str, default_file: Path | None, *, what: str) -> Destination:
    """Parse ``FILE:KEY`` (or a bare ``KEY`` against ``default_file``).

    Shares one grammar with the bootstrap credential references, so an operator
    learns ``FILE:KEY`` once.
    """
    try:
        file, key = split_file_key(spec, default_file, what=what)
    except BootstrapError as exc:
        raise StoreError(str(exc)) from None
    return Destination(file=Path(file), key=key)


# ---------------------------------------------------------------------------
# read
# ---------------------------------------------------------------------------


def list_paths(file: Path) -> list[str]:
    """Every leaf key path in ``file``."""
    file = Path(file)
    if not file.is_file():
        raise StoreError(f"no such secrets file: {file}")
    return leaf_keys(decrypt_yaml(file))


def get_value(file: Path, key: str) -> str:
    """Return one scalar value.

    A key that resolves to a map is the common typo -- asking for ``oidc/mealie``
    when you meant ``oidc/mealie/client_secret`` -- so the error names the
    children rather than printing a dict repr the caller would have to parse.
    """
    node = lookup(file, key)
    if node is None:
        raise StoreError(f"key not found: {key} in {file}")
    if isinstance(node, dict):
        children = "\n".join(f"  {child}" for child in leaf_keys(node, key))
        raise StoreError(f"{key!r} in {file} is a group, not a value. It contains:\n{children}")
    if isinstance(node, list):
        raise StoreError(f"{key!r} in {file} is a list, not a value")
    if isinstance(node, bool):
        return "true" if node else "false"
    return str(node)


# ---------------------------------------------------------------------------
# write
# ---------------------------------------------------------------------------


def set_value(file: Path, key: str, value: str, *, must_exist: bool = False) -> Change:
    """Write one value. ``must_exist`` turns this into a replace-only edit."""
    file = Path(file)
    if must_exist and not lookup(file, key, use_cache=False):
        raise StoreError(
            f"key not found: {key} in {file} (this is a replace; use `set` to create it)"
        )
    existed = file.is_file() and lookup(file, key, use_cache=False) is not None
    result = set_key(file, key, value)
    return Change(
        target=f"{file}:{key}",
        result="updated" if existed else "created",
        detail="new store minted" if result == "created" else "",
    )


def remove_value(file: Path, key: str) -> Change:
    """Delete one key, failing if it was not there to begin with."""
    file = Path(file)
    if not file.is_file():
        raise StoreError(f"no such secrets file: {file}")
    if lookup(file, key, use_cache=False) is None:
        raise StoreError(f"key not found: {key} in {file}")
    remove_key(file, key)
    return Change(target=f"{file}:{key}", result="removed")


# ---------------------------------------------------------------------------
# generate
# ---------------------------------------------------------------------------


def ensure_generated(
    destinations: list[Destination],
    *,
    kind: str,
    length: int | None = None,
    rotate: bool = False,
    dry_run: bool = False,
) -> Outcome:
    """Converge every destination onto one identical secret of ``kind``.

    See the module docstring for the four cases. ``rotate=True`` skips the
    convergence logic entirely and writes fresh material everywhere, which is
    what a compromised credential needs -- and is the only way past a
    divergence, since resolving one by picking a side is a decision this tool
    has no business making silently.
    """
    if not destinations:
        raise StoreError("no destinations given")

    outcome = Outcome(dry_run=dry_run)

    present: dict[str, str] = {}
    for dest in destinations:
        node = lookup(dest.file, dest.key, use_cache=False)
        if node is None:
            continue
        if isinstance(node, (dict, list)):
            raise StoreError(
                f"{dest.label} already holds a {type(node).__name__}, not a value; "
                "refusing to overwrite a whole subtree"
            )
        present[dest.label] = str(node)

    if rotate:
        value = generate(kind, length)
        targets = destinations
        outcome.generated = True
    else:
        distinct = set(present.values())
        if len(distinct) > 1:
            holders = ", ".join(sorted(present))
            raise StoreError(
                f"destinations disagree: {holders} hold different values. "
                "One of them is stale, and picking a winner is your call -- "
                "inspect them with `secrets get`, then re-run with --rotate to "
                "replace all of them with fresh material."
            )
        if distinct:
            value = distinct.pop()
            outcome.propagated = True
            targets = [d for d in destinations if d.label not in present]
        else:
            value = generate(kind, length)
            outcome.generated = True
            targets = list(destinations)

    outcome.value = value

    for dest in destinations:
        if dest not in targets:
            outcome.record(dest.label, "exists", "already holds this value")

    for dest in targets:
        if dry_run:
            outcome.record(
                dest.label,
                "would-write",
                "rotate" if rotate and dest.label in present else "",
            )
            outcome.written += 1
            continue
        change = set_value(dest.file, dest.key, value)
        outcome.record(change.target, change.result, change.detail)
        outcome.written += 1

    return outcome


# ---------------------------------------------------------------------------
# plan files
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PlanEntry:
    """One generate-and-place instruction from a plan file."""

    kind: str
    length: int | None
    destinations: list[Destination]
    note: str = ""


def load_plan(path: Path, default_file: Path | None = None) -> list[PlanEntry]:
    """Parse a plan file describing a service's whole credential set.

    A service needs six or seven secrets at once, several of them shared with
    other hosts. Seven ad-hoc command lines are seven chances to fat-finger a
    key path, and they leave nothing behind that says what the store is
    supposed to contain. A plan is reviewable in a PR, re-runnable after adding
    a consumer, and -- because :func:`ensure_generated` converges rather than
    overwrites -- safe to run again at any time.

    .. code-block:: yaml

       # secrets/authentik.plan.yaml
       file: secrets/authentik.yaml     # default for bare keys below
       secrets:
         - kind: urlsafe
           length: 60
           note: AUTHENTIK_SECRET_KEY
           into: [secret_key]
         - kind: alnum
           length: 48
           note: shared with the database host, must stay byte-identical
           into:
             - db_password
             - secrets/infra-db.yaml:authentik

    Paths are resolved relative to the plan file's own directory unless
    absolute, so a plan travels with the repo it describes.
    """
    path = Path(path)
    if not path.is_file():
        raise StoreError(f"no such plan file: {path}")
    try:
        document: Any = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        raise StoreError(f"{path} is not valid YAML: {exc}") from None
    if not isinstance(document, dict):
        raise StoreError(f"{path} must be a mapping with a 'secrets' list")

    base = path.parent
    plan_default = document.get("file")
    fallback = default_file
    if plan_default:
        fallback = Path(plan_default)
        if not fallback.is_absolute():
            fallback = base / fallback

    entries_raw = document.get("secrets")
    if not isinstance(entries_raw, list) or not entries_raw:
        raise StoreError(f"{path} has no 'secrets' list")

    entries: list[PlanEntry] = []
    for index, raw in enumerate(entries_raw):
        where = f"{path} entry {index + 1}"
        if not isinstance(raw, dict):
            raise StoreError(f"{where} is not a mapping")
        kind = raw.get("kind")
        if not kind:
            raise StoreError(f"{where} has no 'kind'")
        into = raw.get("into")
        if isinstance(into, str):
            into = [into]
        if not isinstance(into, list) or not into:
            raise StoreError(f"{where} has no 'into' destinations")

        destinations = []
        for spec in into:
            dest = parse_destination(str(spec), fallback, what=f"{where} 'into'")
            file = dest.file if dest.file.is_absolute() else base / dest.file
            destinations.append(Destination(file=file, key=dest.key))

        length = raw.get("length")
        entries.append(
            PlanEntry(
                kind=str(kind),
                length=int(length) if length is not None else None,
                destinations=destinations,
                note=str(raw.get("note") or ""),
            )
        )
    return entries
