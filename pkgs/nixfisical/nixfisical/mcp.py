"""An MCP server over a live Infisical instance.

``nixfisical-mcp`` speaks the Model Context Protocol on stdin/stdout so an
agent can ask what is *true of an instance right now*: which projects exist,
what a sync would change, what a prune would delete, who can read the keyring.

WHAT IS DELIBERATELY NOT HERE, AND WHY THAT IS THE DESIGN
=========================================================

**Documentation.** Options and commands are answered by ``nix build .#docs``,
which is a file: no process, no credentials, no network, and generated from the
module system so it cannot drift. A server re-serving static prose is strictly
worse than a file -- it can be stale, and it makes an offline question require
an online thing. Every tool below needs an instance; that is the entry
requirement, and it is the whole reason this is a server at all.

**Secret values.** No tool returns one. Not for a project's secrets, not for a
keyring entry, not in an error message. The single enforcement point is
:func:`_secret_names`, which builds its output from a whitelist rather than by
deleting ``secretValue`` from the API object -- a blacklist here is one
upstream field rename away from being a leak, and the leak would be silent.

Anything that can operate an instance can read every secret its identity may
read. That is unavoidable for the identity; it is entirely avoidable for the
transcript, which is what this rule protects. An agent that needs a value is an
operator running the CLI.

**Writes, by default.** The server starts read-only. ``--allow-writes`` enables
exactly one mutating tool, ``sync_apply``, and that tool additionally refuses to
run unless the caller states how many secrets it expects the prune to delete and
the number matches. ``sync`` prunes: deleting an annotation deletes the secret
from Infisical. A confirmation that is just a boolean is one an agent will
always pass; a confirmation that has to equal a number it can only get from
``sync_diff`` forces it to look first.

WHY THE PROTOCOL IS HAND-WRITTEN
================================

The official Python SDK is in nixpkgs and would work. It also brings pydantic,
starlette, uvicorn and an SSE stack -- a web server -- into the closure of a
tool whose only transport here is a pipe, on a machine that is already carrying
sops, git and age for the operator. Measured standalone at ~250 MiB.

Against that, MCP over stdio is newline-delimited JSON-RPC 2.0 with four
methods, all of them below. It is small enough that writing it is cheaper than
depending on it, and a flake consumed as an input is better off with no
dependency to conflict over. If this ever needs HTTP, resources, prompts or
sampling, that trade flips and the SDK is the right answer.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence

from nixfisical import __version__
from nixfisical.access import sync_access as run_sync_access
from nixfisical.api import InfisicalClient, InfisicalError
from nixfisical.bootstrap import (
    read_admin_email,
    read_organization_id,
    read_sync_credentials,
)
from nixfisical.license import CAPABILITIES, Plan
from nixfisical.manifest import load as load_manifest
from nixfisical.manifest import resolve_paths, validate as validate_manifest
from nixfisical.reconcile import reconcile as run_reconcile
from nixfisical.sops import SopsError
from nixfisical import keyring as keyring_ops

# Protocol revisions this server knows how to answer. A client asking for one
# of these gets it echoed back; anything else is answered with the newest we
# have, which is what the specification says to do and is why an unknown
# version is not an error.
SUPPORTED_PROTOCOLS = ("2024-11-05", "2025-03-26", "2025-06-18")
LATEST_PROTOCOL = SUPPORTED_PROTOCOLS[-1]

# JSON-RPC 2.0.
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class ToolError(RuntimeError):
    """A tool could not do its job. Reported to the model, not to the wire.

    MCP distinguishes a protocol failure (the request was malformed) from a
    tool failure (the request was fine, the world did not cooperate). The
    second is a *result* with ``isError`` set, because a model that cannot see
    the failure cannot correct for it -- a transport-level error would be
    swallowed by the client and the model would only see that nothing happened.
    """


# ---------------------------------------------------------------------------
# session
# ---------------------------------------------------------------------------


@dataclass
class Session:
    """Where the instance is and how to authenticate to it.

    One client per tool call, opened and closed. A long-lived client would
    hold a token that outlives its own expiry and fail on whichever call
    happened to come after it; reconnecting costs one round trip and removes a
    failure that is intermittent by construction.
    """

    url: str
    admin_file: Path
    insecure: bool = False
    timeout: float = 30.0
    allow_writes: bool = False

    @contextmanager
    def client(self) -> Iterator[InfisicalClient]:
        """An unauthenticated client. For the two calls that need no login."""
        with InfisicalClient(
            self.url, verify=not self.insecure, timeout=self.timeout
        ) as client:
            yield client

    @contextmanager
    def authenticated(self) -> Iterator[tuple[InfisicalClient, str]]:
        """A logged-in client and the organization id, or a ToolError.

        Authenticates as the ``fleet-sync`` machine identity in the admin file,
        never as the superadmin: the read-only tools need no more than that,
        and a server holding the superadmin password would be a much larger
        thing to leave running next to an agent.
        """
        if not self.admin_file.exists():
            raise ToolError(
                f"no admin file at {self.admin_file}. This instance has not "
                "been bootstrapped from this checkout, or --admin-file points "
                "somewhere else."
            )
        with self.client() as client:
            try:
                organization_id = read_organization_id(self.admin_file)
                client.universal_auth_login(read_sync_credentials(self.admin_file))
            except (SopsError, InfisicalError) as exc:
                raise ToolError(
                    f"could not authenticate with {self.admin_file}: {exc}"
                ) from exc
            yield client, organization_id


# ---------------------------------------------------------------------------
# redaction
# ---------------------------------------------------------------------------


def _secret_names(entries: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Infisical's raw secret objects, reduced to the parts that are not the secret.

    A WHITELIST, and that is the point. The obvious implementation is
    ``{k: v for k, v in entry.items() if k != "secretValue"}``, which is one
    upstream field addition away from returning a value under a name this code
    has never heard of -- and it would do it silently, into a transcript, which
    is the worst place for a secret to end up quietly.

    ``secretComment`` is excluded too. It is free text a human wrote next to a
    credential, and "the rotation procedure is in vault entry 41" is not
    something to hand out either.
    """
    out: list[dict[str, Any]] = []
    for entry in entries:
        name = entry.get("secretKey")
        if not name:
            continue
        out.append(
            {
                "name": str(name),
                "path": str(entry.get("secretPath") or "/"),
                "version": entry.get("version"),
                "updatedAt": entry.get("updatedAt"),
            }
        )
    return sorted(out, key=lambda e: (e["path"], e["name"]))


# ---------------------------------------------------------------------------
# manifest helpers
# ---------------------------------------------------------------------------


def _load(path: str, root: str | None, secrets_file: str | None) -> list[dict[str, Any]]:
    """Read, validate and path-resolve a rendered manifest.

    Validation is not optional here. Every downstream tool would otherwise
    report a confusing HTTP 4xx from halfway through a run for a problem that
    is visible in the file, and an agent reading that error has no way back to
    the typo that caused it.
    """
    try:
        manifest = load_manifest(path)
    except (ValueError, OSError) as exc:
        raise ToolError(f"could not read manifest {path}: {exc}") from exc

    fallback = Path(secrets_file).expanduser() if secrets_file else None
    problems = validate_manifest(manifest, default_secrets_file=fallback)
    if problems:
        raise ToolError(
            f"manifest has {len(problems)} problem(s):\n  - "
            + "\n  - ".join(problems)
        )
    return resolve_paths(
        manifest, Path(root or "."), default_secrets_file=fallback
    )


def _actions(actions: Sequence[Any]) -> list[dict[str, str]]:
    """Reconcile/access actions as data. ``Action.target`` is a coordinate, never a value."""
    return [
        {
            "kind": a.kind,
            "target": a.target,
            "result": a.result,
            "detail": a.detail,
        }
        for a in actions
    ]


def _deletions(summary: Any) -> list[str]:
    """Every secret a run deleted, or would delete. Pulled out of the action log
    rather than counted, because the count is the thing an operator agrees to
    and the names are the thing they actually need to see first."""
    return sorted(
        a.target
        for a in summary.actions
        if a.kind == "prune" and a.result in {"deleted", "would-delete"}
    )


# ---------------------------------------------------------------------------
# tools
# ---------------------------------------------------------------------------


@dataclass
class Tool:
    name: str
    description: str
    schema: dict[str, Any]
    handler: Callable[[Session, dict[str, Any]], Any]
    #: Writes to the instance. Absent from `tools/list` without --allow-writes,
    #: so a read-only server does not advertise a capability it will refuse.
    mutating: bool = False


def _t_instance_status(session: Session, _: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"url": session.url, "reachable": False}
    with session.client() as client:
        try:
            client.status()
        except InfisicalError as exc:
            result["error"] = str(exc)
            return result
        result["reachable"] = True

        try:
            result["initialized"] = bool(client.instance_config().get("initialized"))
        except InfisicalError as exc:
            result["initialized"] = None
            result["initializedError"] = str(exc)

        result["adminFile"] = str(session.admin_file)
        result["adminFilePresent"] = session.admin_file.exists()
        if not result["adminFilePresent"]:
            # Initialised with no admin file is the one combination bootstrap
            # cannot fix, and saying "not bootstrapped yet" there sends the
            # reader at the wrong command.
            result["syncLogin"] = "unknown"
            result["hint"] = (
                "run 'nixfisical adopt' -- the instance is already initialised"
                if result.get("initialized")
                else "run 'nixfisical bootstrap'"
            )
            return result

        try:
            client.universal_auth_login(read_sync_credentials(session.admin_file))
        except (SopsError, InfisicalError) as exc:
            result["syncLogin"] = "failed"
            result["syncLoginError"] = str(exc)
            return result
        result["syncLogin"] = "ok"
    return result


def _t_license(session: Session, _: dict[str, Any]) -> dict[str, Any]:
    with session.authenticated() as (client, organization_id):
        try:
            payload = client.get_plan(organization_id)
        except InfisicalError as exc:
            raise ToolError(
                f"could not read the organization's plan: {exc}. The route is an "
                "undocumented ee route; a 404 means this build does not have it."
            ) from exc
    plan = Plan.from_payload(payload)
    return {
        "headline": plan.headline(),
        "licensed": plan.licensed,
        "capabilities": {
            name: {
                "allowed": plan.has(capability.feature),
                "summary": capability.summary,
                "workaround": capability.workaround,
            }
            for name, capability in sorted(CAPABILITIES.items())
        },
    }


def _t_list_projects(session: Session, _: dict[str, Any]) -> dict[str, Any]:
    with session.authenticated() as (client, organization_id):
        try:
            projects = client.list_projects(organization_id)
        except InfisicalError as exc:
            raise ToolError(str(exc)) from exc
    return {
        "organizationId": organization_id,
        "projects": [
            {"name": name, "id": pid} for name, pid in sorted(projects.items())
        ],
    }


def _t_list_secret_names(session: Session, args: dict[str, Any]) -> dict[str, Any]:
    project = str(args.get("project") or "")
    if not project:
        raise ToolError("project is required")
    environment = str(args.get("environment") or "prod")
    path = str(args.get("path") or "/")

    with session.authenticated() as (client, organization_id):
        try:
            projects = client.list_projects(organization_id)
        except InfisicalError as exc:
            raise ToolError(str(exc)) from exc
        project_id = projects.get(project)
        if project_id is None:
            raise ToolError(
                f"no project {project!r} in this organization. Known: "
                + (", ".join(sorted(projects)) or "none")
            )
        try:
            entries = client.list_secrets(
                project_id=project_id, environment=environment, path=path
            )
        except InfisicalError as exc:
            raise ToolError(str(exc)) from exc

    return {
        "project": project,
        "projectId": project_id,
        "environment": environment,
        "path": path,
        "secrets": _secret_names(entries),
        "note": "names only; this server never returns secret values",
    }


def _t_validate_manifest(_: Session, args: dict[str, Any]) -> dict[str, Any]:
    path = str(args.get("manifest") or "")
    if not path:
        raise ToolError("manifest is required")
    try:
        manifest = load_manifest(path)
    except (ValueError, OSError) as exc:
        raise ToolError(f"could not read manifest {path}: {exc}") from exc
    secrets_file = args.get("secretsFile")
    problems = validate_manifest(
        manifest,
        default_secrets_file=Path(str(secrets_file)).expanduser() if secrets_file else None,
    )
    return {"entries": len(manifest), "ok": not problems, "problems": problems}


def _sync_diff(session: Session, args: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    manifest = _load(
        str(args.get("manifest") or ""),
        args.get("root"),
        args.get("secretsFile"),
    )
    prune = bool(args.get("prune", True))
    with session.authenticated() as (client, organization_id):
        try:
            summary = run_reconcile(
                client,
                manifest,
                organization_id=organization_id,
                prune=prune,
                dry_run=dry_run,
            )
        except SopsError as exc:
            raise ToolError(
                f"a manifest entry could not be decrypted: {exc}. A dry run "
                "reads every SOPS value on purpose -- a renamed or rotated key "
                "is the most common thing a sync finds out the hard way."
            ) from exc

    deletions = _deletions(summary)
    return {
        "dryRun": summary.dry_run,
        "prune": summary.prune,
        "headline": summary.headline(),
        "counts": {
            "projectsCreated": summary.projects_created,
            "environmentsCreated": summary.environments_created,
            "foldersCreated": summary.folders_created,
            "secretsCreated": summary.secrets_created,
            "secretsUpdated": summary.secrets_updated,
            "secretsPruned": summary.secrets_pruned,
            "secretsDelegated": summary.secrets_delegated,
            "environmentsPlanned": summary.environments_planned,
            "foldersPlanned": summary.folders_planned,
            "secretsPlanned": summary.secrets_planned,
        },
        "deletions": deletions,
        "deletionCount": len(deletions),
        "groupsSeen": summary.groups_seen,
        "errors": summary.errors,
        "ok": summary.ok,
        "actions": _actions(summary.actions),
    }


def _t_sync_diff(session: Session, args: dict[str, Any]) -> dict[str, Any]:
    result = _sync_diff(session, args, dry_run=True)
    if result["deletionCount"]:
        result["warning"] = (
            f"{result['deletionCount']} secret(s) would be DELETED from the "
            "instance. sync prunes: a secret the manifest no longer declares is "
            "removed. Read 'deletions' before applying."
        )
    return result


def _t_sync_apply(session: Session, args: dict[str, Any]) -> dict[str, Any]:
    if not session.allow_writes:
        raise ToolError(
            "this server is read-only; it was started without --allow-writes"
        )

    # The confirmation is a number, not a flag, and it has to be right.
    #
    # A boolean confirmation is one an agent passes every time, because the
    # only information it carries is "I read the parameter list". A count can
    # only be produced by having run sync_diff against this manifest and this
    # instance, and it goes stale the moment either changes -- which is exactly
    # when a second look is warranted.
    if "confirmDeletions" not in args:
        raise ToolError(
            "confirmDeletions is required: run sync_diff first and pass its "
            "deletionCount. sync prunes, and this is the count of secrets that "
            "will be deleted."
        )
    try:
        expected = int(args["confirmDeletions"])
    except (TypeError, ValueError) as exc:
        raise ToolError("confirmDeletions must be an integer") from exc

    planned = _sync_diff(session, args, dry_run=True)
    if not planned["ok"]:
        raise ToolError(
            "the dry run reported errors; refusing to apply:\n  - "
            + "\n  - ".join(planned["errors"])
        )
    if planned["deletionCount"] != expected:
        raise ToolError(
            f"confirmDeletions={expected} but this run would delete "
            f"{planned['deletionCount']} secret(s): "
            + (", ".join(planned["deletions"]) or "none")
            + ". Nothing was written. Re-read sync_diff -- the manifest or the "
            "instance changed since the count you were given."
        )

    applied = _sync_diff(session, args, dry_run=False)
    applied["confirmedDeletions"] = expected
    return applied


def _t_access_diff(session: Session, args: dict[str, Any]) -> dict[str, Any]:
    manifest = _load(
        str(args.get("manifest") or ""),
        args.get("root"),
        args.get("secretsFile"),
    )
    operators = args.get("operators") or []
    if isinstance(operators, str):
        operators = [operators]

    with session.authenticated() as (client, organization_id):
        try:
            plan = Plan.from_payload(client.get_plan(organization_id))
        except InfisicalError as exc:
            # Same fallback the CLI uses: the plan route is an undocumented ee
            # route, and an instance that 404s it is a normal instance.
            plan = Plan.unlicensed(f"plan endpoint unavailable: {exc}")
        try:
            operator_email = read_admin_email(session.admin_file)
        except SopsError:
            # A per-org admin file has no admin block by design. Not an error;
            # it means this run has no operator to add unless one was named.
            operator_email = None
        if not operators and operator_email:
            operators = [operator_email]

        summary = run_sync_access(
            client,
            manifest,
            organization_id=organization_id,
            operators=[str(o) for o in operators],
            plan=plan,
            # `database` stays None. The escape hatch writes to Infisical's
            # Postgres behind the API; a hammer that size is not one an agent
            # gets to pick up, and a dry run that pretended otherwise would
            # report grants that a real run cannot make.
            database=None,
            dry_run=True,
        )

    return {
        "dryRun": True,
        "headline": summary.headline(),
        "counts": {
            "groupsCreated": summary.groups_created,
            "grantsCreated": summary.grants_created,
            "membershipsCreated": summary.memberships_created,
        },
        "operators": [str(o) for o in operators],
        "errors": summary.errors,
        "unsupported": summary.skipped,
        "ok": summary.ok,
        "actions": _actions(summary.actions),
        "note": (
            "Access is never revoked. Group creation needs a licence; see the "
            "'unsupported' list and the license tool."
        ),
    }


def _t_keyring_audit(session: Session, args: dict[str, Any]) -> dict[str, Any]:
    project = str(args.get("project") or keyring_ops.DEFAULT_PROJECT)
    with session.authenticated() as (client, organization_id):
        try:
            operator_email = read_admin_email(session.admin_file)
        except SopsError:
            operator_email = None
        report = keyring_ops.audit(
            client,
            organization_id=organization_id,
            operator_email=operator_email,
            project=project,
        )
    if report.errors:
        raise ToolError("; ".join(report.errors))
    return {
        "project": report.project,
        "projectId": report.project_id,
        # Entry names and the key TYPE each holds. Never the key: `audit` reads
        # the type marker and the folder listing and nothing else.
        "entries": [
            {"name": name, "keyType": report.key_types.get(name, "unknown")}
            for name in report.keys
        ],
        "users": report.users,
        "groups": report.groups,
        "identities": report.identities,
        "warnings": report.warnings,
    }


_MANIFEST_PARAMS = {
    "manifest": {
        "type": "string",
        "description": (
            "Path to a rendered JSON manifest, as produced by "
            "'nix run .#infisical-manifest'."
        ),
    },
    "root": {
        "type": "string",
        "description": "Repo root that relative sopsFile paths resolve against. Defaults to '.'.",
    },
    "secretsFile": {
        "type": "string",
        "description": "Fallback SOPS file for entries with no sopsFile of their own.",
    },
}


TOOLS: list[Tool] = [
    Tool(
        name="instance_status",
        description=(
            "Is the instance reachable, is it initialised, and can the sync "
            "identity log in. The guard to run before anything else; an "
            "uninitialised instance is a legitimate state, not an error."
        ),
        schema={"type": "object", "properties": {}},
        handler=_t_instance_status,
    ),
    Tool(
        name="license",
        description=(
            "Which licence-gated features this instance permits. Answers the "
            "question that is otherwise answered by a 400 halfway through a "
            "deploy -- group creation in particular is gated, and an "
            "unlicensed instance is the normal case."
        ),
        schema={"type": "object", "properties": {}},
        handler=_t_license,
    ),
    Tool(
        name="list_projects",
        description="Every project in the organization, with its id.",
        schema={"type": "object", "properties": {}},
        handler=_t_list_projects,
    ),
    Tool(
        name="list_secret_names",
        description=(
            "Secret NAMES under a project/environment/path, recursively. "
            "Values are never returned by this server."
        ),
        schema={
            "type": "object",
            "properties": {
                "project": {"type": "string", "description": "Project name."},
                "environment": {
                    "type": "string",
                    "description": "Environment slug. Defaults to 'prod'.",
                },
                "path": {
                    "type": "string",
                    "description": "Folder path. Defaults to '/'.",
                },
            },
            "required": ["project"],
        },
        handler=_t_list_secret_names,
    ),
    Tool(
        name="validate_manifest",
        description=(
            "Structural check of a rendered manifest. Touches neither the "
            "network nor SOPS, so it works against a manifest for an instance "
            "you cannot reach."
        ),
        schema={
            "type": "object",
            "properties": {
                "manifest": _MANIFEST_PARAMS["manifest"],
                "secretsFile": _MANIFEST_PARAMS["secretsFile"],
            },
            "required": ["manifest"],
        },
        handler=_t_validate_manifest,
    ),
    Tool(
        name="sync_diff",
        description=(
            "What 'nixfisical sync' would change, without changing it. "
            "IMPORTANT: sync prunes -- 'deletions' lists every secret that "
            "would be removed from the instance because the manifest no longer "
            "declares it. Decrypts every SOPS value it would push (and "
            "discards them), so a renamed or rotated key surfaces here rather "
            "than mid-run."
        ),
        schema={
            "type": "object",
            "properties": dict(
                _MANIFEST_PARAMS,
                prune={
                    "type": "boolean",
                    "description": "Model the prune pass. Defaults to true, which is what sync does.",
                },
            ),
            "required": ["manifest"],
        },
        handler=_t_sync_diff,
    ),
    Tool(
        name="access_diff",
        description=(
            "What 'nixfisical sync-access' would grant, without granting it. "
            "Run sync first in a real convergence: sync-access grants a group "
            "access to a project, so the project has to exist, and sync is "
            "what creates it. Access is never revoked."
        ),
        schema={
            "type": "object",
            "properties": dict(
                _MANIFEST_PARAMS,
                operators={
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "Humans to hold direct membership on every project, as "
                        "EMAIL or EMAIL:ROLE. Defaults to the admin file's own "
                        "admin, where there is one."
                    ),
                },
            ),
            "required": ["manifest"],
        },
        handler=_t_access_diff,
    ),
    Tool(
        name="keyring_audit",
        description=(
            "Who can read the keyring project, and which entries it holds. The "
            "keyring stores the estate's age and SSH private keys, so a group "
            "grant here hands the master key to everyone in it -- warnings "
            "name exactly that. Returns entry names and key types, never key "
            "material."
        ),
        schema={
            "type": "object",
            "properties": {
                "project": {
                    "type": "string",
                    "description": f"Keyring project. Defaults to {keyring_ops.DEFAULT_PROJECT!r}.",
                }
            },
        },
        handler=_t_keyring_audit,
    ),
    Tool(
        name="sync_apply",
        description=(
            "Converge the instance onto the manifest. WRITES, AND DELETES: "
            "requires confirmDeletions to equal the deletionCount that "
            "sync_diff reports for this same manifest, and refuses otherwise "
            "without writing anything. Only available when the server was "
            "started with --allow-writes."
        ),
        schema={
            "type": "object",
            "properties": dict(
                _MANIFEST_PARAMS,
                prune={
                    "type": "boolean",
                    "description": "Delete secrets the manifest no longer declares. Defaults to true.",
                },
                confirmDeletions={
                    "type": "integer",
                    "description": (
                        "The number of secrets you expect to be deleted. Get it "
                        "from sync_diff's deletionCount. A mismatch aborts."
                    ),
                },
            ),
            "required": ["manifest", "confirmDeletions"],
        },
        handler=_t_sync_apply,
        mutating=True,
    ),
]


# ---------------------------------------------------------------------------
# protocol
# ---------------------------------------------------------------------------


@dataclass
class Server:
    session: Session
    tools: list[Tool] = field(default_factory=lambda: list(TOOLS))

    def available(self) -> list[Tool]:
        """The tools this server will answer for.

        A read-only server does not list `sync_apply` at all rather than
        listing it and refusing. Advertising a capability that always fails
        teaches a model to keep trying it, and the refusal is indistinguishable
        from a transient error from the other side of the pipe.
        """
        return [t for t in self.tools if self.session.allow_writes or not t.mutating]

    def handle(self, message: Mapping[str, Any]) -> dict[str, Any] | None:
        """One request in, at most one response out. None for a notification."""
        rid = message.get("id")
        method = message.get("method")
        params = message.get("params") or {}

        # A notification has no id and must never be answered -- a response to
        # one is a response to a request the client is not tracking, and
        # clients differ in how badly they take that.
        is_notification = rid is None

        if not isinstance(method, str):
            return None if is_notification else _error(rid, INVALID_REQUEST, "no method")

        try:
            if method == "initialize":
                result = self._initialize(params)
            elif method == "ping":
                result = {}
            elif method in {"notifications/initialized", "notifications/cancelled"}:
                return None
            elif method == "tools/list":
                result = {
                    "tools": [
                        {
                            "name": t.name,
                            "description": t.description,
                            "inputSchema": t.schema,
                        }
                        for t in self.available()
                    ]
                }
            elif method == "tools/call":
                result = self._call(params)
            else:
                return (
                    None
                    if is_notification
                    else _error(rid, METHOD_NOT_FOUND, f"unknown method {method!r}")
                )
        except ToolError as exc:
            # Reached only for a tool that raised outside _call's own guard.
            return None if is_notification else _error(rid, INTERNAL_ERROR, str(exc))
        except Exception as exc:  # pragma: no cover - defensive
            return None if is_notification else _error(rid, INTERNAL_ERROR, repr(exc))

        return None if is_notification else {"jsonrpc": "2.0", "id": rid, "result": result}

    def _initialize(self, params: Mapping[str, Any]) -> dict[str, Any]:
        wanted = params.get("protocolVersion")
        version = wanted if wanted in SUPPORTED_PROTOCOLS else LATEST_PROTOCOL
        return {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "nixfisical", "version": __version__},
            "instructions": (
                "Live state of a self-hosted Infisical instance. This server "
                "never returns secret values; for what can be declared, read "
                "the generated reference at 'nix build "
                "github:jeirslab/nixfisical#docs' instead of asking here. "
                "Before any convergence: sync_diff, then sync, then "
                "sync-access -- and sync PRUNES."
            ),
        }

    def _call(self, params: Mapping[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            return _tool_result("arguments must be an object", is_error=True)

        for tool in self.available():
            if tool.name == name:
                break
        else:
            # Not a JSON-RPC error: naming a tool that is not there is a thing
            # the model did, and it can only correct for it if it sees it.
            known = ", ".join(t.name for t in self.available())
            return _tool_result(
                f"unknown tool {name!r}. Available: {known}", is_error=True
            )

        try:
            payload = tool.handler(self.session, args)
        except ToolError as exc:
            return _tool_result(str(exc), is_error=True)
        except (InfisicalError, SopsError, OSError) as exc:
            return _tool_result(f"{type(exc).__name__}: {exc}", is_error=True)
        return _tool_result(json.dumps(payload, indent=2, sort_keys=True, default=str))


def _tool_result(text: str, *, is_error: bool = False) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def _error(rid: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}


def serve(server: Server, stdin: Any, stdout: Any) -> None:
    """Read newline-delimited JSON-RPC until stdin closes.

    Everything diagnostic goes to stderr. stdout is the transport: one stray
    print on it is a parse error at the client and the session is over.
    """
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            _write(stdout, _error(None, PARSE_ERROR, str(exc)))
            continue
        if not isinstance(message, dict):
            _write(stdout, _error(None, INVALID_REQUEST, "expected an object"))
            continue
        response = server.handle(message)
        if response is not None:
            _write(stdout, response)


def _write(stdout: Any, payload: Mapping[str, Any]) -> None:
    stdout.write(json.dumps(payload) + "\n")
    stdout.flush()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="nixfisical-mcp",
        description=(
            "MCP server exposing the live state of a self-hosted Infisical "
            "instance. Read-only unless --allow-writes."
        ),
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("INFISICAL_URL", "http://127.0.0.1:8080"),
        help="Base URL of the instance. Also read from INFISICAL_URL.",
    )
    parser.add_argument(
        "--admin-file",
        default=os.environ.get(
            "NIXFISICAL_ADMIN_FILE", "secrets/infisical-admin.yaml"
        ),
        help="SOPS-encrypted file holding the sync identity. Also read from "
        "NIXFISICAL_ADMIN_FILE.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Skip TLS verification. Self-signed instance on a trusted network only.",
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout, seconds.")
    parser.add_argument(
        "--allow-writes",
        action="store_true",
        help="Expose sync_apply, which converges the instance and deletes "
        "secrets the manifest no longer declares. Off by default.",
    )
    args = parser.parse_args(argv)

    session = Session(
        url=args.url,
        admin_file=Path(args.admin_file).expanduser(),
        insecure=args.insecure,
        timeout=args.timeout,
        allow_writes=args.allow_writes,
    )
    print(
        f"nixfisical-mcp {__version__}: {args.url}, "
        + ("writes ENABLED" if args.allow_writes else "read-only"),
        file=sys.stderr,
    )
    serve(Server(session), sys.stdin, sys.stdout)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
