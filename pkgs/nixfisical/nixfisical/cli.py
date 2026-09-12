"""Command-line interface.

Commands map onto the jobs described in the package docstring:

    nixfisical bootstrap   one-time instance initialisation
    nixfisical adopt       same end state, for an instance already initialised
    nixfisical add-org     same end state, for an additional organization
    nixfisical sync        converge the instance onto a manifest
    nixfisical sync-access grant manifest groups project access
    nixfisical validate    check a manifest, offline
    nixfisical status      is the instance up, and can we still log in?
    nixfisical license     which licence-gated features does it permit?
    nixfisical secrets     manage the SOPS store the manifest reads from

``secrets`` is the local half of the tool and talks to no instance. It is here
rather than in a separate binary because it operates on exactly the files the
manifest points at: the same ``FILE:KEY`` grammar, the same ``sops`` wrapper,
the same rule that a value never reaches stdout unless asked for by name. An
estate that keeps its source of truth in SOPS and projects it into Infisical
should not need two tools to do it.

Exit codes are contractual because deploy scripts branch on them:

    0  success
    1  runtime error (network, API, SOPS, git)
    2  validation failure (a bad manifest, a refused re-bootstrap, a store
       whose destinations disagree)

``status`` is the intended guard in front of ``bootstrap`` in an activation
script: run it, and only bootstrap when it reports the instance is reachable
and not yet initialised.

``license`` is the same kind of guard for the other half of the question. A
manifest can be valid and still ask for something the instance's licence will
not permit -- groups, custom roles, a gateway -- and the server says so with a
400 partway through the work. Reading the plan first turns that into a report.
It exits 0 either way: an unlicensed instance is a normal instance.

``bootstrap`` and ``adopt`` are alternatives, not a sequence: they end at the
same admin file, and which one applies is decided by whether the instance has
ever been initialised -- a thing that cannot be undone. ``adopt`` is the
one-way door out of "someone clicked through the setup wizard".

``add-org`` is neither's alternative: it runs after whichever of the two
applied, once per additional organization, and writes a *separate* admin file
that the other commands take with ``--admin-file``. Organizations are the
instance's hard partition -- a token scoped to one sees nothing of another,
whether the route says so with a 403 or with an empty list -- so this is how
two estates share a server without sharing a blast radius.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Any

import click

from nixfisical import __version__
from nixfisical.access import (
    DEFAULT_OPERATOR_ROLE,
    DEFAULT_ORG_ROLE,
    DEFAULT_PROJECT_ROLE,
    SCHEMA_VERIFIED_AGAINST,
    AccessError,
    database_from_env,
    sync_access as run_sync_access,
)
from nixfisical.api import InfisicalClient, InfisicalError
from nixfisical.bootstrap import (
    DEFAULT_ADD_ORG_COMMIT_MESSAGE,
    DEFAULT_ADOPT_COMMIT_MESSAGE,
    DEFAULT_COMMIT_MESSAGE,
    BootstrapError,
    add_org as run_add_org,
    adopt as run_adopt,
    bootstrap as run_bootstrap,
    read_admin_email,
    read_organization_id,
    read_sync_credentials,
    split_file_key,
)
from nixfisical.generate import GenerateError, KINDS, kind_help
from nixfisical.license import CAPABILITIES, Plan
from nixfisical.manifest import load as load_manifest
from nixfisical.manifest import resolve_paths, validate as validate_manifest
from nixfisical.reconcile import reconcile as run_reconcile
from nixfisical.sops import SopsError, extract, sops_key_expr
from nixfisical import store as store_ops

EXIT_OK = 0
EXIT_RUNTIME = 1
EXIT_VALIDATION = 2

DEFAULT_ADMIN_FILE = "secrets/infisical-admin.yaml"


def _fail(message: str, code: int = EXIT_RUNTIME) -> None:
    """Print an error to stderr and exit with the contractual code."""
    click.secho(f"error: {message}", fg="red", err=True)
    sys.exit(code)


def _read_sops_ref(spec: str, secrets_file: Path | None, *, what: str) -> str:
    """Resolve a ``FILE:KEY`` or bare-``KEY`` option into a decrypted value."""
    file, key = split_file_key(spec, secrets_file, what=what)
    return extract(file, sops_key_expr(key))


def _read_plan(client: InfisicalClient, organization_id: str) -> Plan:
    """Read the organization's licence, or fall back to the free-tier defaults.

    Never raises. The plan endpoint is an undocumented ``ee`` route, so an
    instance that answers 404 to it is a situation this tool should survive
    rather than one it should refuse to run against -- the fallback is the
    pessimistic feature set, which yields a skipped feature and a warning
    instead of a wrong success.
    """
    try:
        return Plan.from_payload(client.get_plan(organization_id))
    except InfisicalError as exc:
        return Plan.unlicensed(f"plan endpoint unavailable: {exc}")


def _client(ctx: click.Context) -> InfisicalClient:
    settings: dict[str, Any] = ctx.obj
    return InfisicalClient(
        settings["url"], verify=not settings["insecure"], timeout=settings["timeout"]
    )


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="nixfisical")
@click.option(
    "--url",
    envvar="INFISICAL_URL",
    default="http://127.0.0.1:8080",
    show_default=True,
    help="Base URL of the Infisical instance. Also read from INFISICAL_URL.",
)
@click.option(
    "--insecure",
    is_flag=True,
    default=False,
    help="Skip TLS certificate verification. For a self-signed instance on a "
    "trusted network only.",
)
@click.option(
    "--admin-file",
    envvar="NIXFISICAL_ADMIN_FILE",
    default=DEFAULT_ADMIN_FILE,
    show_default=True,
    type=click.Path(path_type=Path),
    help="SOPS-encrypted file holding the superadmin and sync-identity credentials.",
)
@click.option(
    "--timeout",
    default=30.0,
    show_default=True,
    help="HTTP timeout in seconds.",
)
@click.pass_context
def cli(
    ctx: click.Context, url: str, insecure: bool, admin_file: Path, timeout: float
) -> None:
    """Declarative management of a self-hosted Infisical instance."""
    ctx.ensure_object(dict)
    ctx.obj.update(
        {
            "url": url,
            "insecure": insecure,
            "admin_file": Path(admin_file).expanduser(),
            "timeout": timeout,
        }
    )


# --------------------------------------------------------------------------
# bootstrap
# --------------------------------------------------------------------------


@cli.command("bootstrap")
@click.option(
    "--organization",
    required=True,
    help="Name of the organization to create in the fresh instance.",
)
@click.option(
    "--admin-email",
    default=None,
    help="Superadmin email as a literal. An address is not secret; prefer this "
    "over --admin-email-from unless it lives in SOPS already.",
)
@click.option(
    "--admin-email-from",
    default=None,
    metavar="FILE:KEY|KEY",
    help="Read the superadmin email from SOPS. Either FILE:KEY, or a bare "
    "slash-delimited KEY resolved against --secrets-file.",
)
@click.option(
    "--admin-password-from",
    default=None,
    metavar="FILE:KEY|KEY",
    help="Read the superadmin password from SOPS. If omitted, a strong random "
    "password is generated and recorded in the admin file (recommended: "
    "nothing logs in as the superadmin during normal operation).",
)
@click.option(
    "--secrets-file",
    default=None,
    type=click.Path(path_type=Path),
    help="Default SOPS file for bare-KEY forms of the two options above.",
)
@click.option(
    "--identity-name",
    default="fleet-sync",
    show_default=True,
    help="Name of the Universal-Auth machine identity to create.",
)
@click.option(
    "--token-ttl",
    default=2592000,
    show_default=True,
    type=int,
    help="accessTokenTTL and accessTokenMaxTTL for the machine identity, in seconds.",
)
@click.option(
    "--client-secret-description",
    default="nixfisical sync identity",
    show_default=True,
    help="Description recorded on the minted client secret.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Proceed even though an existing admin file's credentials cannot log "
    "in. The existing file is still never overwritten -- move it aside first.",
)
@click.option(
    "--git-commit",
    is_flag=True,
    default=False,
    help="git add + git commit the encrypted admin file in its own repo. Never pushes.",
)
@click.option(
    "--commit-message",
    default=DEFAULT_COMMIT_MESSAGE,
    show_default=True,
    help="Commit message used by --git-commit.",
)
@click.pass_context
def bootstrap_command(
    ctx: click.Context,
    organization: str,
    admin_email: str | None,
    admin_email_from: str | None,
    admin_password_from: str | None,
    secrets_file: Path | None,
    identity_name: str,
    token_ttl: int,
    client_secret_description: str,
    force: bool,
    git_commit: bool,
    commit_message: str,
) -> None:
    """Initialise a fresh instance and record its credentials in SOPS.

    Safe to re-run: if the admin file's machine identity can already log in,
    this verifies and exits 0 without touching the instance. If it exists but
    cannot log in, this exits 2 rather than risk a destructive re-bootstrap.
    """
    admin_file: Path = ctx.obj["admin_file"]
    with _client(ctx) as client:
        try:
            result = run_bootstrap(
                client,
                admin_file=admin_file,
                organization=organization,
                email=admin_email,
                email_ref=admin_email_from,
                password_ref=admin_password_from,
                secrets_file=secrets_file,
                identity_name=identity_name,
                token_ttl=token_ttl,
                client_secret_description=client_secret_description,
                force=force,
                git_commit=git_commit,
                commit_message=commit_message,
            )
        except BootstrapError as exc:
            _fail(str(exc), EXIT_VALIDATION)
            return
        except (InfisicalError, SopsError, OSError) as exc:
            _fail(str(exc))
            return

    for message in result.messages:
        click.echo(f"  {message}")

    if result.status == "ok":
        click.secho(f"already bootstrapped: {admin_file} verified against {ctx.obj['url']}", fg="green")
        return

    click.secho(f"bootstrapped {ctx.obj['url']}", fg="green")
    click.echo(f"  organization : {result.organization_name} ({result.organization_slug})")
    click.echo(f"  identity     : {identity_name} [{result.identity_id}]")
    click.echo(f"  admin file   : {result.admin_file}")
    if result.password_generated:
        click.secho(
            "  the superadmin password exists only inside the encrypted admin "
            "file -- back that file up.",
            fg="yellow",
        )
    if git_commit and not result.committed:
        click.secho("  admin file was not committed; see the messages above.", fg="yellow")


# --------------------------------------------------------------------------
# adopt
#
# A sibling of bootstrap rather than `bootstrap adopt`, because `bootstrap` is
# a command and turning it into a group would move the existing spelling to
# `bootstrap bootstrap`. The two are alternatives anyway -- exactly one of them
# can ever apply to a given instance -- so they read better side by side.
# --------------------------------------------------------------------------


@cli.command("adopt")
@click.option(
    "--organization",
    default=None,
    help="Which existing organization to adopt, by id, slug or name. Optional "
    "when the superadmin belongs to exactly one.",
)
@click.option(
    "--admin-email",
    default=None,
    help="Superadmin email as a literal. An address is not secret; prefer this "
    "over --admin-email-from unless it lives in SOPS already.",
)
@click.option(
    "--admin-email-from",
    default=None,
    metavar="FILE:KEY|KEY",
    help="Read the superadmin email from SOPS. Either FILE:KEY, or a bare "
    "slash-delimited KEY resolved against --secrets-file.",
)
@click.option(
    "--admin-password-from",
    default=None,
    metavar="FILE:KEY|KEY",
    help="Read the superadmin password from SOPS. Required: unlike bootstrap, "
    "adopt cannot generate one -- the account already exists.",
)
@click.option(
    "--secrets-file",
    default=None,
    type=click.Path(path_type=Path),
    help="Default SOPS file for bare-KEY forms of the two options above.",
)
@click.option(
    "--identity-name",
    default="fleet-sync",
    show_default=True,
    help="Name of the Universal-Auth machine identity to create.",
)
@click.option(
    "--token-ttl",
    default=2592000,
    show_default=True,
    type=int,
    help="accessTokenTTL and accessTokenMaxTTL for the machine identity, in seconds.",
)
@click.option(
    "--client-secret-description",
    default="nixfisical sync identity",
    show_default=True,
    help="Description recorded on the minted client secret.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Proceed even though an existing admin file's credentials cannot log "
    "in. The existing file is still never overwritten -- move it aside first.",
)
@click.option(
    "--git-commit",
    is_flag=True,
    default=False,
    help="git add + git commit the encrypted admin file in its own repo. Never pushes.",
)
@click.option(
    "--commit-message",
    default=DEFAULT_ADOPT_COMMIT_MESSAGE,
    show_default=True,
    help="Commit message used by --git-commit.",
)
@click.pass_context
def adopt_command(
    ctx: click.Context,
    organization: str | None,
    admin_email: str | None,
    admin_email_from: str | None,
    admin_password_from: str | None,
    secrets_file: Path | None,
    identity_name: str,
    token_ttl: int,
    client_secret_description: str,
    force: bool,
    git_commit: bool,
    commit_message: str,
) -> None:
    """Take over an already-initialised instance and record it in SOPS.

    For an instance `bootstrap` can no longer reach: one set up through the web
    UI, or whose admin file was lost. Logs in as the superadmin that already
    exists, mints the sync identity against the organization that already
    exists, and writes the same admin file bootstrap would have.

    Safe to re-run on the same terms as bootstrap: an admin file whose identity
    can already log in is verified and left alone.
    """
    admin_file: Path = ctx.obj["admin_file"]
    with _client(ctx) as client:
        try:
            result = run_adopt(
                client,
                admin_file=admin_file,
                organization=organization,
                email=admin_email,
                email_ref=admin_email_from,
                password_ref=admin_password_from,
                secrets_file=secrets_file,
                identity_name=identity_name,
                token_ttl=token_ttl,
                client_secret_description=client_secret_description,
                force=force,
                git_commit=git_commit,
                commit_message=commit_message,
            )
        except BootstrapError as exc:
            _fail(str(exc), EXIT_VALIDATION)
            return
        except (InfisicalError, SopsError, OSError) as exc:
            _fail(str(exc))
            return

    for message in result.messages:
        click.echo(f"  {message}")

    if result.status == "ok":
        click.secho(f"already adopted: {admin_file} verified against {ctx.obj['url']}", fg="green")
        return

    click.secho(f"adopted {ctx.obj['url']}", fg="green")
    click.echo(f"  organization : {result.organization_name} ({result.organization_slug})")
    click.echo(f"  identity     : {identity_name} [{result.identity_id}]")
    click.echo(f"  admin file   : {result.admin_file}")
    click.secho(
        "  the superadmin password you supplied is now recorded in the admin "
        "file. Rotate it if it is also a human's login.",
        fg="yellow",
    )
    if git_commit and not result.committed:
        click.secho("  admin file was not committed; see the messages above.", fg="yellow")


# --------------------------------------------------------------------------
# add-org
#
# Takes TWO admin files, which is the one thing about this command that needs
# saying twice. The global --admin-file is the instance's, and it is read: the
# superadmin password lives there and creating an organization needs a human.
# --org-admin-file is the one being written, for the new organization, and it
# is what `sync --admin-file <that>` will use from then on.
# --------------------------------------------------------------------------


@cli.command("add-org")
@click.option(
    "--organization",
    required=True,
    help="Name of the organization. Matched against existing ones by id, slug "
    "or name first, and only created if nothing matches -- so re-running is "
    "safe even though Infisical would happily make a same-named twin.",
)
@click.option(
    "--org-admin-file",
    required=True,
    type=click.Path(path_type=Path),
    help="Where to write the new organization's admin file. Must not exist "
    "unless its identity already works, in which case this is a no-op.",
)
@click.option(
    "--admin-email",
    default=None,
    help="Superadmin email as a literal. Defaults to the one recorded in "
    "--admin-file.",
)
@click.option(
    "--admin-email-from",
    default=None,
    metavar="FILE:KEY|KEY",
    help="Read the superadmin email from SOPS instead of --admin-file.",
)
@click.option(
    "--admin-password-from",
    default=None,
    metavar="FILE:KEY|KEY",
    help="Read the superadmin password from SOPS instead of --admin-file. "
    "Only needed for an instance whose superadmin is a human account; a "
    "bootstrapped instance's password exists nowhere but --admin-file.",
)
@click.option(
    "--secrets-file",
    default=None,
    type=click.Path(path_type=Path),
    help="Default SOPS file for bare-KEY forms of the two options above.",
)
@click.option(
    "--record-admin-credentials",
    is_flag=True,
    default=False,
    help="Also write the superadmin block into the new file. Off by default: "
    "that password is scoped to the whole instance, not to this organization, "
    "so copying it into another estate's repo would hand its holders every "
    "other organization too. Turn it on when the new organization is another "
    "slice of the same estate.",
)
@click.option(
    "--identity-name",
    default="fleet-sync",
    show_default=True,
    help="Name of the Universal-Auth machine identity to create.",
)
@click.option(
    "--token-ttl",
    default=2592000,
    show_default=True,
    type=int,
    help="accessTokenTTL and accessTokenMaxTTL for the machine identity, in seconds.",
)
@click.option(
    "--client-secret-description",
    default="nixfisical sync identity",
    show_default=True,
    help="Description recorded on the minted client secret.",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    help="Proceed even though an existing org admin file's credentials cannot "
    "log in. The existing file is still never overwritten -- move it aside first.",
)
@click.option(
    "--git-commit",
    is_flag=True,
    default=False,
    help="git add + git commit the encrypted admin file in its own repo. Never pushes.",
)
@click.option(
    "--commit-message",
    default=DEFAULT_ADD_ORG_COMMIT_MESSAGE,
    show_default=True,
    help="Commit message used by --git-commit.",
)
@click.pass_context
def add_org_command(
    ctx: click.Context,
    organization: str,
    org_admin_file: Path,
    admin_email: str | None,
    admin_email_from: str | None,
    admin_password_from: str | None,
    secrets_file: Path | None,
    record_admin_credentials: bool,
    identity_name: str,
    token_ttl: int,
    client_secret_description: str,
    force: bool,
    git_commit: bool,
    commit_message: str,
) -> None:
    """Add another organization to an instance, with its own sync identity.

    One instance can host several organizations, and they are hard partitions:
    an access token is scoped to exactly one, and asking it about another gets
    nothing back -- a 403 on some routes, an empty list on others. That makes
    an organization the right boundary between two estates sharing a server.

    Run this after bootstrap or adopt, once per extra organization. It creates
    the organization if it is not already there, mints a machine identity in
    it, and writes a second admin file -- which every other command then takes
    with --admin-file:

        nixfisical --admin-file secrets/infisical-admin-other.yaml sync ...

    Safe to re-run: an existing organization is reused rather than duplicated,
    and an org admin file whose identity can log in is verified and left alone.
    """
    admin_file: Path = ctx.obj["admin_file"]
    with _client(ctx) as client:
        try:
            result = run_add_org(
                client,
                org_admin_file=org_admin_file,
                organization=organization,
                instance_admin_file=admin_file,
                email=admin_email,
                email_ref=admin_email_from,
                password_ref=admin_password_from,
                secrets_file=secrets_file,
                record_admin_credentials=record_admin_credentials,
                identity_name=identity_name,
                token_ttl=token_ttl,
                client_secret_description=client_secret_description,
                force=force,
                git_commit=git_commit,
                commit_message=commit_message,
            )
        except BootstrapError as exc:
            _fail(str(exc), EXIT_VALIDATION)
            return
        except (InfisicalError, SopsError, OSError) as exc:
            _fail(str(exc))
            return

    for message in result.messages:
        click.echo(f"  {message}")

    if result.status == "ok":
        click.secho(
            f"already added: {result.admin_file} verified against {ctx.obj['url']}",
            fg="green",
        )
        return

    click.secho(
        ("created" if result.organization_created else "joined")
        + f" organization on {ctx.obj['url']}",
        fg="green",
    )
    click.echo(f"  organization : {result.organization_name} ({result.organization_slug})")
    click.echo(f"  identity     : {identity_name} [{result.identity_id}]")
    click.echo(f"  admin file   : {result.admin_file}")
    if not record_admin_credentials:
        click.echo(
            "  this file holds no superadmin credentials by design; the "
            "instance admin file is still the only copy."
        )
    click.echo(
        f"  use it with: nixfisical --admin-file {result.admin_file} sync ..."
    )
    if git_commit and not result.committed:
        click.secho("  admin file was not committed; see the messages above.", fg="yellow")


# --------------------------------------------------------------------------
# sync
# --------------------------------------------------------------------------


@cli.command("sync")
@click.option(
    "--manifest",
    "manifest_source",
    default="-",
    show_default=True,
    help="Path to the JSON manifest, or '-' for stdin.",
)
@click.option(
    "--secrets-file",
    default=None,
    type=click.Path(path_type=Path),
    help="Fallback SOPS file for manifest entries with no sopsFile of their own.",
)
@click.option(
    "--root",
    default=".",
    show_default=True,
    type=click.Path(path_type=Path),
    help="Repo root that relative sopsFile paths resolve against.",
)
@click.option(
    "--no-prune",
    is_flag=True,
    default=False,
    help="Leave secrets the manifest no longer declares in place. Folders are "
    "never pruned either way.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Read everything, write nothing, and report exactly what would change "
    "-- including which secrets would be deleted.",
)
@click.pass_context
def sync_command(
    ctx: click.Context,
    manifest_source: str,
    secrets_file: Path | None,
    root: Path,
    no_prune: bool,
    dry_run: bool,
) -> None:
    """Converge the instance onto the manifest.

    Authenticates as the ``fleet-sync`` machine identity recorded in the admin
    file, so the superadmin password is never read on this path.
    """
    admin_file: Path = ctx.obj["admin_file"]

    try:
        manifest = load_manifest(manifest_source)
    except ValueError as exc:
        _fail(str(exc), EXIT_VALIDATION)
        return

    problems = validate_manifest(manifest, default_secrets_file=secrets_file)
    if problems:
        click.secho(f"manifest has {len(problems)} problem(s):", fg="red", err=True)
        for problem in problems:
            click.echo(f"  - {problem}", err=True)
        sys.exit(EXIT_VALIDATION)

    manifest = resolve_paths(manifest, Path(root), default_secrets_file=secrets_file)

    with _client(ctx) as client:
        try:
            organization_id = read_organization_id(admin_file)
            client.universal_auth_login(read_sync_credentials(admin_file))
        except (SopsError, InfisicalError) as exc:
            _fail(
                f"could not authenticate with {admin_file}: {exc}. "
                "Run 'nixfisical status' to check the instance, or bootstrap it first."
            )
            return

        summary = run_reconcile(
            client,
            manifest,
            organization_id=organization_id,
            prune=not no_prune,
            dry_run=dry_run,
        )

    for action in summary.actions:
        click.echo(f"  {action.render()}")

    if summary.groups_seen:
        click.echo(f"  groups referenced by the manifest: {', '.join(summary.groups_seen)}")
        click.echo("  run 'nixfisical sync-access' to grant them project access")

    click.secho(
        ("DRY RUN " if dry_run else "") + summary.headline(),
        fg="yellow" if dry_run else ("green" if summary.ok else "red"),
    )
    legend = summary.legend()
    if legend:
        click.secho(legend, fg="yellow")
    if not summary.ok:
        sys.exit(EXIT_RUNTIME)


# --------------------------------------------------------------------------
# sync-access
# --------------------------------------------------------------------------


@cli.command("sync-access")
@click.option(
    "--manifest",
    "manifest_source",
    default="-",
    show_default=True,
    help="Path to the JSON manifest, or '-' for stdin.",
)
@click.option(
    "--role",
    "project_role",
    default=DEFAULT_PROJECT_ROLE,
    show_default=True,
    help="Project role granted to each group. A built-in role: admin, member, "
    "viewer or no-access. Custom roles need an enterprise license.",
)
@click.option(
    "--org-role",
    default=DEFAULT_ORG_ROLE,
    show_default=True,
    help="Organization role recorded for groups this creates. Only used with "
    "--create-missing-groups.",
)
@click.option(
    "--operator",
    "operators",
    multiple=True,
    metavar="EMAIL",
    help="Human who should hold direct membership on every managed project. "
    "Repeatable. Defaults to the admin recorded in the admin file, because a "
    "project created by the sync identity is visible to no human otherwise.",
)
@click.option(
    "--operator-role",
    default=DEFAULT_OPERATOR_ROLE,
    show_default=True,
    help="Project role given to each --operator.",
)
@click.option(
    "--no-operator",
    is_flag=True,
    default=False,
    help="Add nobody. Leaves managed projects visible only to the sync "
    "identity, which is rarely what you want -- see --operator.",
)
@click.option(
    "--create-missing-groups",
    is_flag=True,
    default=False,
    help="Create absent groups by writing to Infisical's Postgres directly, "
    "bypassing the plan restriction that blocks the API. Off by default; "
    "read the warning it prints.",
)
@click.option("--db-host", default=None, help="Infisical's Postgres host.")
@click.option("--db-port", default=5432, show_default=True, type=int)
@click.option("--db-user", default="infisical", show_default=True)
@click.option("--db-name", default="infisical", show_default=True)
@click.option(
    "--db-password-from",
    default=None,
    metavar="FILE:KEY|KEY",
    help="Read the Postgres password from SOPS. Falls back to $PGPASSWORD.",
)
@click.option(
    "--secrets-file",
    default=None,
    type=click.Path(path_type=Path),
    help="Default SOPS file for the bare-KEY form of --db-password-from.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Report what would change and write nothing.",
)
@click.pass_context
def sync_access_command(
    ctx: click.Context,
    manifest_source: str,
    project_role: str,
    org_role: str,
    operators: tuple[str, ...],
    operator_role: str,
    no_operator: bool,
    create_missing_groups: bool,
    db_host: str | None,
    db_port: int,
    db_user: str,
    db_name: str,
    db_password_from: str | None,
    secrets_file: Path | None,
    dry_run: bool,
) -> None:
    """Grant each manifest group read access to the projects it appears in.

    Access is granted at the project level -- a group named on any entry of a
    project gets the whole project -- so the manifest's 'project' field is the
    access boundary. Access is never revoked; remove it in the UI.

    Adding an existing group to a project uses the supported API. Creating a
    group does not: Infisical gates that behind an enterprise plan, so
    --create-missing-groups writes to its database directly.

    Also puts the operator on every managed project. A project created by the
    sync identity has no human members at all -- not even the organization's
    admins -- so without this the instance converges correctly and then looks
    empty to the person who ran it. See --operator and --no-operator.
    """
    admin_file: Path = ctx.obj["admin_file"]

    try:
        manifest = load_manifest(manifest_source)
    except ValueError as exc:
        _fail(str(exc), EXIT_VALIDATION)
        return

    problems = validate_manifest(manifest, require_sops_file=False)
    if problems:
        click.secho(f"manifest has {len(problems)} problem(s):", fg="red", err=True)
        for problem in problems:
            click.echo(f"  - {problem}", err=True)
        sys.exit(EXIT_VALIDATION)

    database = None
    if create_missing_groups:
        click.secho(
            "  ! --create-missing-groups writes to Infisical's database behind "
            "its API.",
            fg="yellow",
            err=True,
        )
        click.secho(
            "    Upstream refuses group creation without an enterprise license, "
            f"and this SQL was read off {SCHEMA_VERIFIED_AGAINST}; a schema "
            "change makes it refuse, not guess. Back the database up first.",
            fg="yellow",
            err=True,
        )
        try:
            password = (
                _read_sops_ref(
                    db_password_from, secrets_file, what="--db-password-from"
                )
                if db_password_from
                else None
            )
            database = database_from_env(
                host=db_host,
                port=db_port,
                user=db_user,
                dbname=db_name,
                password=password,
            )
        except (AccessError, BootstrapError, SopsError) as exc:
            _fail(str(exc), EXIT_VALIDATION)
            return

    with _client(ctx) as client:
        try:
            organization_id = read_organization_id(admin_file)
            client.universal_auth_login(read_sync_credentials(admin_file))
        except (SopsError, InfisicalError) as exc:
            _fail(f"could not authenticate with {admin_file}: {exc}")
            return

        # Read the plan before doing anything, so that a group this run cannot
        # create is reported as a plan restriction rather than as a failure.
        # An unreadable plan is not fatal: sync_access falls back to the
        # behaviour it had before there was a plan to read.
        plan = _read_plan(client, organization_id)
        click.secho(f"  {plan.headline()}", fg="cyan")

        # Default the operator to the admin file's own admin. Reading it is a
        # sops call, so only do it when it will be used.
        chosen_operators: tuple[str, ...] = ()
        if not no_operator:
            if operators:
                chosen_operators = operators
            else:
                try:
                    chosen_operators = (read_admin_email(admin_file),)
                except SopsError as exc:
                    _fail(
                        f"could not read the admin email from {admin_file}: {exc}\n"
                        "  pass --operator <email> to name the human this sync "
                        "should put on its projects,\n"
                        "  or --no-operator to accept projects whose only member "
                        "is the sync machine identity"
                    )
                    return

        summary = run_sync_access(
            client,
            manifest,
            organization_id=organization_id,
            project_role=project_role,
            org_role=org_role,
            operators=chosen_operators,
            operator_role=operator_role,
            database=database,
            plan=plan,
            dry_run=dry_run,
        )

    for action in summary.actions:
        click.echo(f"  {action.render()}")

    for skipped in summary.skipped:
        click.secho(f"  unsupported: {skipped}", fg="yellow", err=True)

    click.secho(
        ("DRY RUN " if dry_run else "") + summary.headline(),
        fg="yellow" if dry_run else ("green" if summary.ok else "red"),
    )
    # `skipped` deliberately does not affect the exit code. See AccessSummary.
    if not summary.ok:
        sys.exit(EXIT_RUNTIME)


# --------------------------------------------------------------------------
# validate
# --------------------------------------------------------------------------


@cli.command("validate")
@click.option(
    "--manifest",
    "manifest_source",
    default="-",
    show_default=True,
    help="Path to the JSON manifest, or '-' for stdin.",
)
@click.option(
    "--secrets-file",
    default=None,
    type=click.Path(path_type=Path),
    help="Fallback SOPS file; when set, entries may omit sopsFile.",
)
def validate_command(manifest_source: str, secrets_file: Path | None) -> None:
    """Check a manifest for structural problems. Does no network or SOPS I/O."""
    try:
        manifest = load_manifest(manifest_source)
    except ValueError as exc:
        _fail(str(exc), EXIT_VALIDATION)
        return

    problems = validate_manifest(manifest, default_secrets_file=secrets_file)
    if problems:
        click.secho(f"{len(problems)} problem(s):", fg="red", err=True)
        for problem in problems:
            click.echo(f"  - {problem}", err=True)
        sys.exit(EXIT_VALIDATION)

    click.secho(f"manifest ok: {len(manifest)} entr(y|ies) validated", fg="green")


# --------------------------------------------------------------------------
# status
# --------------------------------------------------------------------------


@cli.command("status")
@click.pass_context
def status_command(ctx: click.Context) -> None:
    """Report instance reachability and whether the sync identity can log in.

    Intended as the guard in front of ``bootstrap`` in a deploy script: a
    reachable instance with a working sync identity needs nothing done to it.
    Exits 1 when the instance is unreachable; exits 0 otherwise, including when
    the instance is up but not yet bootstrapped -- that is a legitimate state,
    not an error.

    "Initialised" is read off the instance rather than inferred from whether an
    admin file is present locally. The two are independent, and the combination
    that used to be reported as "not bootstrapped yet" -- initialised instance,
    no admin file -- is the one where bootstrap cannot work and ``adopt`` is
    the answer.
    """
    admin_file: Path = ctx.obj["admin_file"]
    url = ctx.obj["url"]

    with _client(ctx) as client:
        try:
            client.status()
        except InfisicalError as exc:
            _fail(f"{url} is not reachable: {exc}")
            return
        click.secho(f"instance   : reachable at {url}", fg="green")

        try:
            initialized = bool(client.instance_config().get("initialized"))
        except InfisicalError as exc:
            click.secho(f"initialised: unknown ({exc})", fg="yellow")
            initialized = None
        else:
            click.secho(
                f"initialised: {'yes' if initialized else 'no -- run bootstrap'}",
                fg="green" if initialized else "yellow",
            )

        if not admin_file.exists():
            if initialized:
                click.secho(
                    f"admin file : {admin_file} does not exist, but the instance "
                    "is already initialised",
                    fg="yellow",
                )
                click.secho(
                    "             bootstrap cannot run against it; see "
                    "'nixfisical adopt --help'",
                    fg="yellow",
                )
            else:
                click.secho(
                    f"admin file : {admin_file} does not exist -- not bootstrapped yet",
                    fg="yellow",
                )
            return

        try:
            client.universal_auth_login(read_sync_credentials(admin_file))
        except (SopsError, InfisicalError) as exc:
            click.secho(
                f"admin file : {admin_file} exists but its sync identity cannot "
                f"log in ({exc})",
                fg="red",
            )
            click.secho(
                "             credentials are stale; see 'nixfisical bootstrap --help'",
                fg="red",
            )
            sys.exit(EXIT_RUNTIME)

        click.secho(f"sync login : ok ({admin_file})", fg="green")


# --------------------------------------------------------------------------
# license
# --------------------------------------------------------------------------


@cli.command("license")
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    default=False,
    help="Emit the raw plan object as the instance reported it.",
)
@click.pass_context
def license_command(ctx: click.Context, as_json: bool) -> None:
    """Report which licence-gated features this instance permits.

    Answers the question that otherwise gets answered by a 400 halfway through
    a deploy. Every row is one thing nixfisical can attempt; "no" means the
    server will refuse it no matter how the declaration is written, and the
    note says what to do instead where there is something to do.

    Exits 0 whether or not the instance is licensed. An unlicensed instance is
    a normal instance -- this command reports, it does not judge.
    """
    admin_file: Path = ctx.obj["admin_file"]

    with _client(ctx) as client:
        try:
            organization_id = read_organization_id(admin_file)
            client.universal_auth_login(read_sync_credentials(admin_file))
        except (SopsError, InfisicalError) as exc:
            _fail(f"could not authenticate with {admin_file}: {exc}")
            return

        try:
            payload = client.get_plan(organization_id)
        except InfisicalError as exc:
            # Unlike every other caller, this command's entire job is to read
            # the plan -- so falling back to assumed defaults here would be
            # answering a question it was asked to check.
            _fail(
                f"could not read the organization's plan: {exc}. The route is "
                "'GET /api/v1/organizations/{id}/plan', an undocumented ee "
                "route; a 404 means this build does not have it."
            )
            return

    if as_json:
        import json as _json

        click.echo(_json.dumps(payload, indent=2, sort_keys=True))
        return

    plan = Plan.from_payload(payload)
    click.secho(plan.headline(), fg="green" if plan.licensed else "yellow")
    click.echo()

    width = max(len(name) for name in CAPABILITIES)
    for name in sorted(CAPABILITIES):
        capability = CAPABILITIES[name]
        allowed = plan.has(capability.feature)
        click.secho(
            f"  {name.ljust(width)}  {'yes' if allowed else 'no '}  "
            f"{capability.summary}",
            fg="green" if allowed else "yellow",
        )
        if not allowed and capability.workaround:
            click.echo(f"  {' ' * width}       -> {capability.workaround}")


# --------------------------------------------------------------------------
# secrets -- the local SOPS store
# --------------------------------------------------------------------------


def _store_fail(exc: Exception) -> None:
    """Map a store-layer exception onto the contractual exit codes."""
    if isinstance(exc, (store_ops.StoreError, GenerateError)):
        _fail(str(exc), EXIT_VALIDATION)
    else:
        _fail(str(exc))


def _resolve_age_key(explicit: Path | None) -> None:
    """Point sops at an age key, and say so when we had to guess.

    sops resolves its own key material from the environment and we do not
    second-guess that -- except for one narrow case. An operator running this
    outside a devshell that exports ``SOPS_AGE_KEY_FILE`` almost always has the
    key at the conventional path, and failing with "no key" when it is sitting
    right there is unhelpful. So: use it, and print that we did, on stderr, so
    the guess is visible and correctable rather than magic.
    """
    if explicit is not None:
        os.environ["SOPS_AGE_KEY_FILE"] = str(Path(explicit).expanduser())
        return
    if os.environ.get("SOPS_AGE_KEY") or os.environ.get("SOPS_AGE_KEY_FILE"):
        return
    fallback = Path.home() / ".ssh" / "sops-age.key"
    if fallback.is_file():
        os.environ["SOPS_AGE_KEY_FILE"] = str(fallback)
        click.secho(
            f"note: SOPS_AGE_KEY_FILE was unset; using {fallback}",
            fg="yellow",
            err=True,
        )


def _store_file(ctx: click.Context, override: Path | None) -> Path:
    """The secrets file a command should act on."""
    chosen = override or ctx.obj.get("secrets_file")
    if chosen is None:
        raise click.UsageError(
            "no secrets file: pass --file, or set NIXFISICAL_SECRETS_FILE"
        )
    return Path(chosen).expanduser()


@cli.group("secrets")
@click.option(
    "-f",
    "--file",
    "secrets_file",
    envvar="NIXFISICAL_SECRETS_FILE",
    default=None,
    type=click.Path(path_type=Path),
    help="Secrets file these commands act on, and the file bare KEY forms "
    "resolve against. Also read from NIXFISICAL_SECRETS_FILE.",
)
@click.option(
    "--age-key-file",
    default=None,
    type=click.Path(path_type=Path),
    help="Age key to decrypt with. Defaults to sops' own resolution "
    "(SOPS_AGE_KEY / SOPS_AGE_KEY_FILE), then to ~/.ssh/sops-age.key.",
)
@click.pass_context
def secrets_group(
    ctx: click.Context, secrets_file: Path | None, age_key_file: Path | None
) -> None:
    """Manage the SOPS store: read, write, and generate secret material.

    Talks to no Infisical instance -- these commands operate on the encrypted
    files the manifest points at, which are the source of truth. Nothing prints
    a secret value unless a command exists solely to do that (``get``, and
    ``gen --print``).

    Keys are slash-delimited (``oidc/mealie/client_secret``). Anywhere a
    destination is taken it may be written ``FILE:KEY`` to name a different
    file, matching the ``--admin-email-from`` grammar.

    Exits 2 on an operator error -- an unknown key, an unknown kind, a store
    whose copies of a shared secret disagree -- and 1 when sops itself fails.
    """
    ctx.ensure_object(dict)
    ctx.obj["secrets_file"] = secrets_file
    _resolve_age_key(age_key_file)


@secrets_group.command("list")
@click.option(
    "-f",
    "--file",
    "secrets_file",
    default=None,
    type=click.Path(path_type=Path),
    help="Secrets file to act on. Overrides the group's --file / "
    "NIXFISICAL_SECRETS_FILE.",
)
@click.pass_context
def secrets_list_command(ctx: click.Context, secrets_file: Path | None) -> None:
    """List every key path in the store. Prints names, never values."""
    file = _store_file(ctx, secrets_file)
    try:
        paths = store_ops.list_paths(file)
    except (store_ops.StoreError, SopsError) as exc:
        _store_fail(exc)
        return
    for path in paths:
        click.echo(path)
    click.secho(f"{len(paths)} key(s) in {file}", fg="green", err=True)


@secrets_group.command("get")
@click.argument("key")
@click.option(
    "-f",
    "--file",
    "secrets_file",
    default=None,
    type=click.Path(path_type=Path),
    help="Secrets file to act on. Overrides the group's --file / "
    "NIXFISICAL_SECRETS_FILE.",
)
@click.option(
    "-n",
    "--no-newline",
    is_flag=True,
    default=False,
    help="Omit the trailing newline, for tools that mind.",
)
@click.pass_context
def secrets_get_command(
    ctx: click.Context, key: str, secrets_file: Path | None, no_newline: bool
) -> None:
    """Print one value, bare, on stdout.

    Safe in command substitution -- every diagnostic goes to stderr, so this
    replaces `sops -d --extract '["a"]["b"]' file.yaml`:

        export PGPASSWORD=$(nixfisical secrets get authentik -f secrets/infra-db.yaml)
    """
    file = _store_file(ctx, secrets_file)
    try:
        value = store_ops.get_value(file, key)
    except (store_ops.StoreError, SopsError) as exc:
        _store_fail(exc)
        return
    click.echo(value, nl=not no_newline)


@secrets_group.command("set")
@click.argument("key")
@click.argument("value", required=False)
@click.option(
    "-f",
    "--file",
    "secrets_file",
    default=None,
    type=click.Path(path_type=Path),
    help="Secrets file to act on. Overrides the group's --file / "
    "NIXFISICAL_SECRETS_FILE.",
)
@click.option(
    "--stdin",
    "from_stdin",
    is_flag=True,
    default=False,
    help="Read the value from stdin. Use for multi-line material (a PEM chain, "
    "a private key) -- a trailing newline is stripped.",
)
@click.option(
    "--replace",
    is_flag=True,
    default=False,
    help="Refuse to create the key; only overwrite one that already exists. "
    "Guards a rotation against a typo'd path that would silently add a "
    "second, unread key beside the real one.",
)
@click.pass_context
def secrets_set_command(
    ctx: click.Context,
    key: str,
    value: str | None,
    secrets_file: Path | None,
    from_stdin: bool,
    replace: bool,
) -> None:
    """Write one value, creating the file if it does not exist yet.

    With no VALUE and no --stdin the value is prompted for, hidden and
    confirmed. That is the default because a secret passed as an argument is
    a secret in the shell history and in every /proc/*/cmdline on the box.
    """
    file = _store_file(ctx, secrets_file)

    if from_stdin:
        if value is not None:
            raise click.UsageError("pass a VALUE or --stdin, not both")
        value = sys.stdin.read().rstrip("\n")
    elif value is None:
        value = click.prompt(
            f"value for {key}", hide_input=True, confirmation_prompt=True
        )
    if not value:
        _fail("refusing to write an empty value", EXIT_VALIDATION)
        return

    try:
        change = store_ops.set_value(file, key, value, must_exist=replace)
    except (store_ops.StoreError, SopsError, OSError) as exc:
        _store_fail(exc)
        return
    click.secho(change.render(), fg="green")


@secrets_group.command("rm")
@click.argument("key")
@click.option(
    "-f",
    "--file",
    "secrets_file",
    default=None,
    type=click.Path(path_type=Path),
    help="Secrets file to act on. Overrides the group's --file / "
    "NIXFISICAL_SECRETS_FILE.",
)
@click.option("-y", "--yes", is_flag=True, default=False, help="Skip confirmation.")
@click.pass_context
def secrets_rm_command(
    ctx: click.Context, key: str, secrets_file: Path | None, yes: bool
) -> None:
    """Delete one key, pruning any map the deletion leaves empty."""
    file = _store_file(ctx, secrets_file)
    if not yes:
        click.confirm(f"remove {key} from {file}?", abort=True)
    try:
        change = store_ops.remove_value(file, key)
    except (store_ops.StoreError, SopsError, OSError) as exc:
        _store_fail(exc)
        return
    click.secho(change.render(), fg="green")


@secrets_group.command("edit")
@click.option(
    "-f",
    "--file",
    "secrets_file",
    default=None,
    type=click.Path(path_type=Path),
    help="Secrets file to act on. Overrides the group's --file / "
    "NIXFISICAL_SECRETS_FILE.",
)
@click.pass_context
def secrets_edit_command(ctx: click.Context, secrets_file: Path | None) -> None:
    """Open the store in $EDITOR through sops (decrypt, edit, re-encrypt).

    Execs sops rather than wrapping it, so the editor gets the real terminal
    and sops' own scratch-file handling applies -- plaintext never lands in a
    file this process created.
    """
    file = _store_file(ctx, secrets_file)
    sops = shutil.which("sops")
    if sops is None:
        _fail("the 'sops' binary is not on PATH")
        return
    os.execv(sops, [sops, str(file)])  # noqa: S606 - path came from which()


@secrets_group.command(
    "gen",
    epilog="kinds:\n" + kind_help(),
    context_settings={"max_content_width": 100},
)
@click.argument("kind", required=False, type=click.Choice(sorted(KINDS)))
@click.option(
    "-f",
    "--file",
    "secrets_file",
    default=None,
    type=click.Path(path_type=Path),
    help="File that bare-KEY --into destinations resolve against.",
)
@click.option(
    "--into",
    "into",
    multiple=True,
    metavar="FILE:KEY|KEY",
    help="Where the value must end up. Repeat for a secret shared between "
    "files; every destination ends up holding the same bytes.",
)
@click.option(
    "--plan",
    "plan_file",
    default=None,
    type=click.Path(path_type=Path),
    help="Read a YAML plan describing several secrets at once. See "
    "`nixfisical.store.load_plan` for the schema.",
)
@click.option(
    "--length",
    default=None,
    type=int,
    help="Output characters. Defaults to the kind's own default.",
)
@click.option(
    "--rotate",
    is_flag=True,
    default=False,
    help="Replace whatever is there with fresh material. Without this, an "
    "existing value is kept and copied to any destination missing it.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Report what would be written. Generates nothing and writes nothing.",
)
@click.option(
    "--print",
    "print_value",
    is_flag=True,
    default=False,
    help="Also print the value on stdout. For the one case that needs it -- "
    "pasting a bootstrap password into a UI once. Not for scripts: use "
    "`secrets get`, which reads the store rather than racing it.",
)
@click.pass_context
def secrets_gen_command(
    ctx: click.Context,
    kind: str | None,
    secrets_file: Path | None,
    into: tuple[str, ...],
    plan_file: Path | None,
    length: int | None,
    rotate: bool,
    dry_run: bool,
    print_value: bool,
) -> None:
    """Generate secret material and place it, idempotently.

    The point of this verb is that a shared credential is generated ONCE and
    written to every place that needs it, in one auditable operation:

        nixfisical secrets gen alnum --length 48 \\
            --into secrets/authentik.yaml:db_password \\
            --into secrets/infra-db.yaml:authentik

    Re-running is a no-op. Adding a fourth consumer later and re-running
    copies the existing value into it rather than rotating the other three.
    If the destinations already disagree, this refuses and says so -- that is
    a bug in the store, and resolving it is not a decision to make silently.
    """
    default_file = secrets_file or ctx.obj.get("secrets_file")
    if plan_file is not None:
        if kind or into:
            raise click.UsageError("pass --plan, or a KIND with --into; not both")
    elif not kind or not into:
        raise click.UsageError("a KIND and at least one --into are required")

    try:
        if plan_file is not None:
            entries = store_ops.load_plan(plan_file, default_file)
        else:
            entries = [
                store_ops.PlanEntry(
                    kind=kind or "",
                    length=length,
                    destinations=[
                        store_ops.parse_destination(spec, default_file, what="--into")
                        for spec in into
                    ],
                )
            ]

        written = 0
        for entry in entries:
            if entry.note:
                click.echo(f"{entry.note}:")
            outcome = store_ops.ensure_generated(
                entry.destinations,
                kind=entry.kind,
                length=entry.length,
                rotate=rotate,
                dry_run=dry_run,
            )
            for change in outcome.changes:
                click.echo(f"  {change.render()}")
            click.echo(f"  {outcome.headline()}")
            written += outcome.written
            if print_value and outcome.value is not None and not dry_run:
                click.echo(outcome.value)
    except (store_ops.StoreError, GenerateError, SopsError, OSError) as exc:
        _store_fail(exc)
        return

    click.secho(
        ("DRY RUN " if dry_run else "")
        + f"{len(entries)} secret(s), {written} destination(s) "
        + ("to write" if dry_run else "written"),
        fg="yellow" if dry_run else "green",
    )


if __name__ == "__main__":  # pragma: no cover
    cli()
