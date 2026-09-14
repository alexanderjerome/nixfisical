"""The CLI's own command tree, as data.

``nixfisical docs`` walks the live click tree and emits it as JSON or
markdown. Nothing here is a second description of the CLI -- it is the same
objects ``--help`` renders, read rather than printed, so a command that exists
and a command that is documented are the same set by construction.

That is the whole reason this module exists instead of a hand-written
reference. A hand-written one is correct on the day it is written and wrong
from the first flag added after it, and the divergence is invisible: nothing
fails, an agent just operates on a CLI that no longer matches what it was told.

WHAT IS DELIBERATELY NOT HERE. Option *values* an operator has configured, any
part of the environment, and anything read from an instance. This renders the
shape of the interface and nothing about the machine it happens to run on, so
the output is identical on every machine at a given version and safe to commit,
publish or hand to a model.
"""

from __future__ import annotations

import json
from typing import Any

import click

# Options declared on the root group that every subcommand inherits. Repeating
# them on all twenty commands would triple the output and bury the flags that
# actually distinguish one command from another.
_GLOBAL_NOTE = (
    "Inherited from the root group; see the `nixfisical` entry for its options."
)


def _param(param: click.Parameter) -> dict[str, Any]:
    """One option or argument, flattened."""
    entry: dict[str, Any] = {
        "name": param.name,
        "kind": "argument" if isinstance(param, click.Argument) else "option",
        "required": bool(param.required),
    }

    opts = list(param.opts) + list(param.secondary_opts)
    if opts:
        entry["flags"] = opts

    # `type.name` is click's own vocabulary ("text", "integer", "path",
    # "choice"), which is stable and already what the help text says.
    entry["type"] = getattr(param.type, "name", "text")
    choices = getattr(param.type, "choices", None)
    if choices:
        entry["choices"] = list(choices)

    if isinstance(param, click.Option):
        entry["multiple"] = bool(param.multiple)
        entry["is_flag"] = bool(param.is_flag)
        if param.envvar:
            # A list when click was given several; normalised so consumers do
            # not have to branch on the type of a field.
            entry["envvar"] = (
                list(param.envvar)
                if isinstance(param.envvar, (list, tuple))
                else [param.envvar]
            )
        if param.help:
            entry["help"] = param.help

    # Defaults are rendered with `str` rather than passed through, because a
    # click default can be a Path, a callable, or a sentinel -- none of which
    # survive `json.dumps`, and all of which are only ever read as text.
    default = param.default
    if default is not None and not callable(default):
        entry["default"] = default if isinstance(default, (bool, int, float, str)) else str(default)

    return entry


def _command(name: str, command: click.Command, path: list[str]) -> dict[str, Any]:
    """One command or group, and its children."""
    entry: dict[str, Any] = {
        "name": name,
        "path": " ".join(path),
        "summary": (command.short_help or "").strip()
        or (command.help or "").strip().split("\n\n", 1)[0].strip(),
        # The full docstring, not the first line. These docstrings carry the
        # operational caveats -- which command prunes, which ordering matters,
        # which failure is legitimate -- and truncating them to a summary drops
        # exactly the part a reader needs before running anything.
        "description": (command.help or "").strip(),
        "hidden": bool(command.hidden),
        "deprecated": bool(command.deprecated),
    }

    # `--help` and `--version` are click's, on every command, and say nothing
    # about what any particular one does.
    params = [_param(p) for p in command.params if p.name not in {"help", "version"}]
    if params:
        entry["params"] = params

    if isinstance(command, click.Group):
        entry["commands"] = [
            _command(child_name, child, path + [child_name])
            for child_name, child in sorted(command.commands.items())
        ]
    elif len(path) > 1:
        entry["inherits"] = _GLOBAL_NOTE

    return entry


def tree(root: click.Group, *, name: str = "nixfisical") -> dict[str, Any]:
    """The whole CLI as a nested dict."""
    from nixfisical import __version__

    return {
        "tool": name,
        "version": __version__,
        "command": _command(name, root, [name]),
    }


def _render(entry: dict[str, Any], out: list[str], depth: int) -> None:
    """One command as markdown, children after it."""
    heading = "#" * min(depth + 1, 6)
    out.append(f"{heading} `{entry['path']}`")
    out.append("")

    if entry.get("deprecated"):
        out.append("**Deprecated.**")
        out.append("")

    if entry.get("description"):
        out.append(entry["description"])
        out.append("")

    for kind, label in (("argument", "Arguments"), ("option", "Options")):
        params = [p for p in entry.get("params", []) if p["kind"] == kind]
        if not params:
            continue
        out.append(f"*{label}*")
        out.append("")
        for param in params:
            flags = ", ".join(f"`{f}`" for f in param.get("flags", [])) or f"`{param['name'].upper()}`"
            bits = [flags]
            if param.get("choices"):
                bits.append("one of " + ", ".join(f"`{c}`" for c in param["choices"]))
            if param.get("required"):
                bits.append("**required**")
            if "default" in param:
                bits.append(f"default `{param['default']}`")
            if param.get("envvar"):
                bits.append("env " + ", ".join(f"`{e}`" for e in param["envvar"]))
            line = " — ".join([" · ".join(bits)] + ([param["help"]] if param.get("help") else []))
            out.append(f"- {line}")
        out.append("")

    for child in entry.get("commands", []):
        _render(child, out, depth + 1)


def render_markdown(data: dict[str, Any]) -> str:
    """The tree from :func:`tree`, as a document."""
    out = [
        f"# `{data['tool']}` command reference",
        "",
        f"Version {data['version']}. Generated from the command tree — "
        "do not edit.",
        "",
    ]
    _render(data["command"], out, 1)
    return "\n".join(out).rstrip() + "\n"


def emit(root: click.Group, fmt: str) -> str:
    """Render the CLI in ``fmt`` (``json`` or ``markdown``)."""
    data = tree(root)
    if fmt == "json":
        return json.dumps(data, indent=2, sort_keys=True) + "\n"
    if fmt == "markdown":
        return render_markdown(data)
    raise ValueError(f"unknown docs format {fmt!r}")
