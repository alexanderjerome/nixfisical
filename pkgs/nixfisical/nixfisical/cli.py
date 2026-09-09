"""Command-line interface.

Four commands, mapping onto the two jobs described in the package docstring:

    nixfisical bootstrap   one-time instance initialisation
    nixfisical sync        converge the instance onto a manifest
    nixfisical validate    check a manifest, offline
    nixfisical status      is the instance up, and can we still log in?

Exit codes are contractual because deploy scripts branch on them:

    0  success
    1  runtime error (network, API, SOPS, git)
    2  validation failure (a bad manifest, a refused re-bootstrap)

``status`` is the intended guard in front of ``bootstrap`` in an activation
script: run it, and only bootstrap when it reports the instance is reachable
and not yet initialised.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import click

from nixfisical import __version__
from nixfisical.access import (
    DEFAULT_ORG_ROLE,
    DEFAULT_PROJECT_ROLE,
    SCHEMA_VERIFIED_AGAINST,
    AccessError,
    database_from_env,
    sync_access as run_sync_access,
)
from nixfisical.api import InfisicalClient, InfisicalError
from nixfisical.bootstrap import (
    DEFAULT_COMMIT_MESSAGE,
    BootstrapError,
    bootstrap as run_bootstrap,
    read_organization_id,
    read_sync_credentials,
    split_file_key,
)
from nixfisical.manifest import load as load_manifest
from nixfisical.manifest import resolve_paths, validate as validate_manifest
from nixfisical.reconcile import reconcile as run_reconcile
from nixfisical.sops import SopsError, extract, sops_key_expr

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

        summary = run_sync_access(
            client,
            manifest,
            organization_id=organization_id,
            project_role=project_role,
            org_role=org_role,
            database=database,
            dry_run=dry_run,
        )

    for action in summary.actions:
        click.echo(f"  {action.render()}")

    click.secho(
        ("DRY RUN " if dry_run else "") + summary.headline(),
        fg="yellow" if dry_run else ("green" if summary.ok else "red"),
    )
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

        if not admin_file.exists():
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


if __name__ == "__main__":  # pragma: no cover
    cli()
