"""Reconcile *who can see* the secrets that ``sync`` writes.

``sync`` converges secret values. It says nothing about access: a project the
manifest created is visible to the org's admins and to nobody else, which is
the safe default and also not the point. The manifest's ``groups`` field says
which groups should be able to read a secret, and this module makes that true.

Access is modelled at the project level, not the secret level, and that is a
deliberate narrowing of what the manifest can express. Infisical's access
boundary that actually holds is the project; folder- and secret-level grants
exist but are an enterprise feature and a much larger surface. So the rule is:
**a group named anywhere in a project's entries gets read access to that whole
project.** The manifest's ``project`` field is therefore the access boundary,
and splitting secrets across projects is how you split visibility. If a group
should not see a secret, that secret belongs in a different project.

Two mechanisms, and the difference between them is the whole reason this is a
separate command:

1. **Adding an existing group to a project** is a supported, documented API
   call and is not gated by the license. This is the common case and it runs by
   default.
2. **Creating the group itself** is gated: ``getDefaultOnPremFeatures()`` in
   upstream sets ``groups: false``, and ``createGroup`` refuses with "Failed to
   create group due to plan restriction" on any self-hosted instance without an
   enterprise license. The only way through is to write the rows the API would
   have written. That is what ``--create-missing-groups`` does, it is off by
   default, and it needs database credentials the rest of nixfisical never
   asks for.

The important asymmetry: upstream gates group *mutation* but not *permission
evaluation*. ``permission-service.ts`` resolves group-derived project
permissions with no reference to the license at all. So rows written behind
the API's back are honoured by the running server -- which is what makes the
escape hatch work, and is also why it deserves the warning it prints.

Nothing in this module reads, decrypts, or transports a secret value. It moves
group names and role names.
"""

from __future__ import annotations

import os
import subprocess
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from nixfisical.api import InfisicalClient, InfisicalError
from nixfisical.reconcile import Action

__all__ = [
    "AccessError",
    "AccessSummary",
    "Database",
    "DEFAULT_PROJECT_ROLE",
    "DEFAULT_ORG_ROLE",
    "SCHEMA_VERIFIED_AGAINST",
    "group_targets",
    "slugify",
    "sync_access",
]

# Least privilege that still achieves the point of exporting a secret. Infisical's
# built-in project roles are admin/member/viewer/no-access; `viewer` reads
# secrets and changes nothing.
DEFAULT_PROJECT_ROLE = "viewer"

# Org-level role given to a group this tool creates. `member` is the weakest
# role that lets someone belong to the org at all; project access is granted
# separately and explicitly below.
DEFAULT_ORG_ROLE = "member"

# The upstream release whose schema the SQL below was read off. Recorded in the
# preflight failure message because the failure mode this guards against is a
# schema change, and the first thing you need to know is what we expected.
SCHEMA_VERIFIED_AGAINST = "v0.165.8"


class AccessError(RuntimeError):
    """An access reconciliation could not proceed.

    Never carries a password: the database URL is assembled from discrete parts
    and the password comes from the environment, so it is not in scope here.
    """


def slugify(name: str) -> str:
    """Reduce a group name to the slug Infisical stores alongside it.

    Upstream slugifies the display name and appends a random suffix when the
    caller supplies no slug. We supply one, deterministically, because the
    manifest names groups by a single string and a run must be able to find the
    group it created last time.
    """
    out = []
    previous_dash = False
    for char in name.strip().lower():
        if char.isalnum():
            out.append(char)
            previous_dash = False
        elif not previous_dash:
            out.append("-")
            previous_dash = True
    slug = "".join(out).strip("-")
    if not slug:
        raise AccessError(f"group name {name!r} does not reduce to a usable slug")
    return slug


@dataclass
class AccessSummary:
    """Counts and a per-action log for one access reconciliation."""

    dry_run: bool = False
    groups_created: int = 0
    grants_created: int = 0
    errors: list[str] = field(default_factory=list)
    actions: list[Action] = field(default_factory=list)

    def record(self, kind: str, target: str, result: str, detail: str = "") -> None:
        self.actions.append(Action(kind=kind, target=target, result=result, detail=detail))

    def fail(self, kind: str, target: str, detail: str) -> None:
        self.errors.append(f"{kind} {target}: {detail}")
        self.record(kind, target, "error", detail)

    @property
    def ok(self) -> bool:
        return not self.errors

    def headline(self) -> str:
        verb = "would apply" if self.dry_run else "applied"
        return (
            f"{verb}: groups +{self.groups_created}, "
            f"project grants +{self.grants_created}, "
            f"errors {len(self.errors)}"
        )


def group_targets(manifest: Iterable[Mapping[str, Any]]) -> dict[str, set[str]]:
    """Collapse a manifest into ``{project name: {group name, ...}}``.

    Per the module docstring, a group mentioned on any entry of a project is
    granted the whole project, so the folder and secret name are dropped here.
    """
    targets: dict[str, set[str]] = {}
    for entry in manifest:
        project = entry.get("project")
        if not isinstance(project, str) or not project:
            continue
        for group in entry.get("groups") or []:
            if isinstance(group, str) and group.strip():
                targets.setdefault(project, set()).add(group.strip())
    return targets


# --------------------------------------------------------------------------
# The guarded direct-database layer
# --------------------------------------------------------------------------

# Columns this module writes or reads, per table. The preflight asserts every
# one of them exists before any write, so a schema drift produces a refusal
# naming the missing column rather than a partial write or a silent no-op.
_REQUIRED_COLUMNS: dict[str, tuple[str, ...]] = {
    "groups": ("id", "orgId", "name", "slug", "createdAt", "updatedAt"),
    "memberships": (
        "id",
        "scope",
        "actorGroupId",
        "scopeOrgId",
        "scopeProjectId",
        "isActive",
        "createdAt",
        "updatedAt",
    ),
    "membership_roles": ("id", "role", "membershipId", "createdAt", "updatedAt"),
}

# Tables upstream dropped in migration 20260107083948_remove-old-memberships.
# Their presence means this database predates the unified membership model, and
# every INSERT below would land in tables the server no longer reads. Refusing
# is the only honest response: the rows would be written, the run would report
# success, and no one would gain access.
_RETIRED_TABLES: tuple[str, ...] = (
    "group_project_memberships",
    "group_project_membership_roles",
    "project_memberships",
    "org_memberships",
)


class Database:
    """A very small, deliberately awkward psql wrapper.

    Shelling out rather than depending on psycopg is the same trade this repo
    makes for sops: the operator's Postgres client, its TLS settings and its
    ``PGSSLMODE`` are already configured, and reimplementing that resolution
    would be a new source of "works on my machine". It also keeps a heavyweight
    driver out of the closure of a feature most deployments never enable.

    Values are interpolated with psql's ``:'name'`` quoting, which emits a
    properly escaped SQL string literal -- the arguments here are group names
    off a manifest, so that matters. That interpolation is done by psql's own
    lexer, which only runs over script input: ``--command`` hands the string
    straight to the server and would send the literal ``:'name'``. So every
    statement goes in on stdin. Keeping SQL off argv is a happy side effect,
    as is keeping the password there: it is passed through the environment, so
    it never appears in ``ps``.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        user: str,
        dbname: str,
        password: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.dbname = dbname
        self._password = password

    def describe(self) -> str:
        """A safe, printable description of the connection. No password."""
        return f"{self.user}@{self.host}:{self.port}/{self.dbname}"

    def _run(
        self, sql: str, *, context: str, variables: Mapping[str, str] | None = None
    ) -> list[list[str]]:
        """Execute ``sql`` and return rows as lists of column strings."""
        argv = [
            "psql",
            "--no-psqlrc",
            "--quiet",
            "--tuples-only",
            "--no-align",
            "--field-separator=\x1f",
            "--set=ON_ERROR_STOP=1",
            f"--host={self.host}",
            f"--port={self.port}",
            f"--username={self.user}",
            f"--dbname={self.dbname}",
        ]
        for name, value in (variables or {}).items():
            argv.append(f"--set={name}={value}")
        argv.append("--file=-")

        env = dict(os.environ)
        if self._password is not None:
            env["PGPASSWORD"] = self._password

        try:
            proc = subprocess.run(  # noqa: S603 - argv is fully constructed here
                argv, input=sql, capture_output=True, text=True, check=False, env=env
            )
        except FileNotFoundError as exc:
            raise AccessError(
                "the 'psql' binary is not on PATH; --create-missing-groups "
                f"requires it (while {context})"
            ) from exc

        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip()
            raise AccessError(f"psql failed while {context}: {stderr}")

        rows: list[list[str]] = []
        for line in (proc.stdout or "").splitlines():
            if not line.strip():
                continue
            rows.append(line.split("\x1f"))
        return rows

    def preflight(self) -> None:
        """Refuse to write unless the schema is the one this SQL was written for.

        This is the load-bearing safety property of the whole escape hatch.
        Writing to a running application's database behind its API is only
        defensible if it fails loudly the moment the application's schema moves
        -- and it does move: upstream dropped six membership tables and two
        ``groups`` columns in a single migration, with a ``down()`` that is a
        no-op comment. A run that silently wrote to tables nobody reads would be
        worse than one that refused.
        """
        present = {
            row[0]
            for row in self._run(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public';",
                context="listing tables",
            )
            if row
        }

        retired = sorted(set(_RETIRED_TABLES) & present)
        if retired:
            raise AccessError(
                f"this database still has {', '.join(retired)}, which upstream "
                "dropped in migration 20260107083948_remove-old-memberships. "
                "It predates the unified membership model, so the rows this "
                "would write are not the rows the server reads. Upgrade "
                "Infisical, or grant access through the UI."
            )

        for table, columns in _REQUIRED_COLUMNS.items():
            if table not in present:
                raise AccessError(
                    f"table {table!r} does not exist; the schema is not the one "
                    f"this was written against ({SCHEMA_VERIFIED_AGAINST})"
                )
            found = {
                row[0]
                for row in self._run(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'public' AND table_name = :'tbl';",
                    context=f"describing {table}",
                    variables={"tbl": table},
                )
                if row
            }
            missing = sorted(set(columns) - found)
            if missing:
                raise AccessError(
                    f"table {table!r} is missing column(s) {', '.join(missing)}; "
                    "the Infisical schema has moved since this was written "
                    f"against {SCHEMA_VERIFIED_AGAINST}. Refusing to write."
                )

    def find_group(self, *, organization_id: str, slug: str) -> str | None:
        """Return the id of the group with ``slug`` in the org, or None."""
        rows = self._run(
            'SELECT id FROM groups WHERE "orgId" = :\'org\' AND slug = :\'slug\';',
            context=f"looking up group {slug!r}",
            variables={"org": organization_id, "slug": slug},
        )
        return rows[0][0] if rows else None

    def create_group(
        self, *, organization_id: str, name: str, slug: str, org_role: str
    ) -> str:
        """Create an org group exactly as ``createGroup`` would, minus the check.

        Three rows in one transaction, mirroring upstream's
        ``group-service.ts``: the group, an organization-scoped membership for
        it, and that membership's role. The group's org role lives in
        ``membership_roles`` now -- ``groups.role`` and ``groups.roleId`` were
        dropped -- which is precisely the kind of move the preflight exists to
        catch.

        Ids are generated here rather than by ``gen_random_uuid()`` so this does
        not depend on pgcrypto being installed, and so the new group's id is
        known without a round trip.
        """
        group_id = str(uuid.uuid4())
        membership_id = str(uuid.uuid4())
        role_id = str(uuid.uuid4())

        self._run(
            "BEGIN;\n"
            'INSERT INTO groups (id, "orgId", name, slug, "createdAt", "updatedAt")\n'
            "VALUES (:'gid'::uuid, :'org'::uuid, :'name', :'slug', now(), now());\n"
            'INSERT INTO memberships (id, scope, "actorGroupId", "scopeOrgId",'
            ' "isActive", "createdAt", "updatedAt")\n'
            "VALUES (:'mid'::uuid, 'organization', :'gid'::uuid, :'org'::uuid,"
            " true, now(), now());\n"
            'INSERT INTO membership_roles (id, role, "membershipId", "createdAt",'
            ' "updatedAt")\n'
            "VALUES (:'rid'::uuid, :'role', :'mid'::uuid, now(), now());\n"
            "COMMIT;",
            context=f"creating group {slug!r}",
            variables={
                "gid": group_id,
                "mid": membership_id,
                "rid": role_id,
                "org": organization_id,
                "name": name,
                "slug": slug,
                "role": org_role,
            },
        )
        return group_id


def database_from_env(
    *,
    host: str | None,
    port: int,
    user: str,
    dbname: str,
    password: str | None,
) -> Database:
    """Build a :class:`Database`, taking the password from ``PGPASSWORD`` if unset."""
    if not host:
        raise AccessError(
            "--create-missing-groups needs --db-host (and usually --db-user, "
            "--db-name); these are the same values the NixOS module's "
            "services.infisical.database.* options carry"
        )
    return Database(
        host=host,
        port=port,
        user=user,
        dbname=dbname,
        password=password if password is not None else os.environ.get("PGPASSWORD"),
    )


# --------------------------------------------------------------------------
# reconciliation
# --------------------------------------------------------------------------


def sync_access(
    client: InfisicalClient,
    manifest: Iterable[Mapping[str, Any]],
    *,
    organization_id: str,
    project_role: str = DEFAULT_PROJECT_ROLE,
    org_role: str = DEFAULT_ORG_ROLE,
    database: Database | None = None,
    dry_run: bool = False,
) -> AccessSummary:
    """Grant every manifest group access to every project it appears in.

    ``database`` is the opt-in escape hatch: when it is None, a group the
    manifest names but the instance does not have is recorded as an error
    explaining why, and the run continues with the groups that do exist.

    Access is never revoked. A group removed from the manifest keeps whatever
    it had, and that is on purpose: this tool does not know why a human granted
    a group access to a project, and silently removing someone's access on the
    strength of a generated file is a worse failure than leaving it. Revoke in
    the UI.
    """
    summary = AccessSummary(dry_run=dry_run)
    targets = group_targets(manifest)
    if not targets:
        return summary

    try:
        project_ids = client.list_projects(organization_id)
    except InfisicalError as exc:
        summary.fail("organization", organization_id, f"could not list projects: {exc}")
        return summary

    try:
        existing_groups = client.list_organization_groups()
    except InfisicalError as exc:
        summary.fail("organization", organization_id, f"could not list groups: {exc}")
        return summary

    if database is not None and not dry_run:
        try:
            database.preflight()
        except AccessError as exc:
            summary.fail("database", database.describe(), str(exc))
            return summary

    # -- 1. groups ---------------------------------------------------------
    wanted = sorted({group for groups in targets.values() for group in groups})
    group_ids: dict[str, str] = {}
    # Groups a dry run said it would create. They have no id, but the grant
    # pass below must still report the grants that would follow -- otherwise
    # the dry run of a first run understates the work by exactly the grants
    # that matter most.
    would_create: set[str] = set()
    for name in wanted:
        slug = slugify(name)
        group_id = existing_groups.get(name) or existing_groups.get(slug)
        if group_id:
            group_ids[name] = group_id
            summary.record("group", name, "exists")
            continue

        if database is None:
            summary.fail(
                "group",
                name,
                "does not exist, and creating one through the API is refused by "
                "Infisical's plan restriction on self-hosted instances. The UI "
                "cannot do it either -- it calls the same gated createGroup. "
                "Re-run with --create-missing-groups and database credentials, "
                "or drop the group from the manifest if administrator-only "
                "visibility is acceptable.",
            )
            continue

        if dry_run:
            summary.groups_created += 1
            would_create.add(name)
            summary.record(
                "group", name, "would-create", f"slug {slug} -- via direct database write"
            )
            continue

        try:
            group_ids[name] = database.create_group(
                organization_id=organization_id, name=name, slug=slug, org_role=org_role
            )
        except AccessError as exc:
            summary.fail("group", name, str(exc))
            continue
        summary.groups_created += 1
        summary.record("group", name, "created", f"slug {slug} -- direct database write")

    # -- 2. project grants -------------------------------------------------
    for project_name in sorted(targets):
        project_id = project_ids.get(project_name)
        if project_id is None:
            summary.fail(
                "grant",
                project_name,
                "project does not exist; run 'nixfisical sync' first",
            )
            continue

        try:
            granted = client.list_project_groups(project_id)
        except InfisicalError as exc:
            summary.fail("grant", project_name, f"could not list project groups: {exc}")
            continue

        for name in sorted(targets[project_name]):
            target = f"{project_name}:{name}"
            group_id = group_ids.get(name)
            if group_id is None:
                if name in would_create:
                    summary.grants_created += 1
                    summary.record(
                        "grant", target, "would-create", f"role {project_role}"
                    )
                else:
                    # Already reported above as a group error; do not double-count.
                    summary.record("grant", target, "skipped", "group does not exist")
                continue
            if group_id in granted:
                summary.record("grant", target, "exists", f"role {granted[group_id]}")
                continue
            if dry_run:
                summary.grants_created += 1
                summary.record("grant", target, "would-create", f"role {project_role}")
                continue
            try:
                client.add_group_to_project(
                    project_id=project_id, group_id=group_id, role=project_role
                )
            except InfisicalError as exc:
                summary.fail("grant", target, str(exc))
                continue
            summary.grants_created += 1
            summary.record("grant", target, "created", f"role {project_role}")

    return summary
