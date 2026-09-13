"""Give a host its own machine identity, and put the credentials in SOPS.

Direct injection needs the host to authenticate, which needs a credential on
the host, which is the part that cannot come from Infisical. So it comes from
where every other host credential comes from: a SOPS file, delivered by
sops-nix. Direct injection does not remove SOPS from the estate. It reduces
SOPS to **one credential per host** instead of one per secret, and that
credential is the only thing a rotation of any other secret does not require a
deploy for.

What the exchange buys, stated plainly, because it is not free:

* rotating a secret stops being a deploy, and
* the host's local material is a token, not the plaintext of anything,

against:

* the host can now *ask* for secrets rather than only decrypt the ones it was
  handed, so a compromised host is a read of everything its identity may read,
  and
* the credential that grants that is itself a secret on disk.

Which is why the identity this creates is org-role ``no-access`` and is added
to projects one at a time. An identity with a broad org role is a host that can
read the whole fleet, and nothing downstream would ever notice.

The command converges. Run it twice and the second run creates nothing: an
existing identity is reused, a project it already holds is left alone, and
credentials already in the SOPS file are not re-minted. That matters more here
than elsewhere -- a re-mint would write a new client secret into SOPS while the
running host still holds the old one, and the host would keep working until its
next deploy and then fail to authenticate, which is a failure separated from
its cause by however long that takes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from nixfisical.api import InfisicalClient, InfisicalError
from nixfisical.sops import SopsError, decrypt_yaml, scalar_text, set_keys

__all__ = ["HostCredentials", "ProvisionSummary", "provision_host"]

# The role a host identity gets on each project it is granted. Read-only by
# construction: a host that can write to the estate's secret store is a host
# that can rewrite another host's credentials.
HOST_PROJECT_ROLE = "viewer"

# The org-level role. Infisical's `no-access` grants nothing organization-wide,
# which is the point -- all of this identity's reach comes from the project
# memberships below, so revoking one actually revokes something.
HOST_ORG_ROLE = "no-access"


@dataclass(frozen=True)
class HostCredentials:
    """Where a host's universal-auth credentials live in SOPS."""

    sops_file: Path
    client_id_key: str
    client_secret_key: str


@dataclass
class ProvisionSummary:
    """What provisioning did. Never contains the client secret."""

    identity_name: str = ""
    identity_id: str = ""
    created_identity: bool = False
    minted_credentials: bool = False
    projects_granted: list[str] = field(default_factory=list)
    projects_already: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    def headline(self) -> str:
        return (
            f"identity {self.identity_name!r}: "
            f"{'created' if self.created_identity else 'reused'}, "
            f"credentials {'minted' if self.minted_credentials else 'unchanged'}, "
            f"projects +{len(self.projects_granted)}/"
            f"={len(self.projects_already)}, errors {len(self.errors)}"
        )


def _lookup(document: object, sops_key: str) -> str | None:
    cursor = document
    for segment in [part for part in sops_key.split("/") if part]:
        if not isinstance(cursor, dict) or segment not in cursor:
            return None
        cursor = cursor[segment]
    return scalar_text(cursor) if not isinstance(cursor, (dict, list, type(None))) else None


def _existing_credentials(destination: HostCredentials) -> tuple[str, str] | None:
    """The credentials already in the SOPS file, or None if they are not there.

    Decryption failure is NOT absence and must not be swallowed. The two look
    identical through a ``read_key`` that raises ``SopsError`` for both, and
    conflating them is the worst bug this command could have: a missing age key
    would read as "no credentials yet", mint a fresh client secret, and leave
    the running host authenticating with one that no longer exists. So the file
    is decrypted once and walked here, and a failure to decrypt propagates.

    "Incomplete" *is* treated as absence. A file holding a client id and no
    secret is a half-finished earlier run, and the only thing that can finish
    it is a fresh mint -- Infisical shows a client secret exactly once.
    """
    if not destination.sops_file.is_file():
        return None
    document = decrypt_yaml(destination.sops_file, use_cache=False)
    client_id = _lookup(document, destination.client_id_key)
    client_secret = _lookup(document, destination.client_secret_key)
    if not client_id or not client_secret:
        return None
    return client_id, client_secret


def provision_host(
    client: InfisicalClient,
    *,
    host: str,
    organization_id: str,
    projects: Iterable[str],
    destination: HostCredentials,
    rotate: bool = False,
    dry_run: bool = False,
) -> ProvisionSummary:
    """Ensure ``host`` has an identity that can read ``projects``."""
    identity_name = f"host-{host}"
    summary = ProvisionSummary(identity_name=identity_name)
    wanted = sorted({str(project) for project in projects})

    try:
        identities = client.list_identities(organization_id)
        project_ids = client.list_projects(organization_id)
    except InfisicalError as exc:
        summary.errors.append(str(exc))
        return summary

    missing_projects = [name for name in wanted if name not in project_ids]
    if missing_projects:
        # Fail before creating anything. A half-provisioned host -- identity
        # minted, credentials in SOPS, access to only some of what it needs --
        # is harder to reason about than one that does not exist yet, and the
        # fix for a missing project is `sync`, not this command.
        summary.errors.append(
            "no such project(s) in this organization: "
            f"{', '.join(missing_projects)}; run 'sync' first"
        )
        return summary

    try:
        existing = _existing_credentials(destination)
    except SopsError as exc:
        summary.errors.append(
            f"cannot read {destination.sops_file}: {exc}. Refusing to continue: "
            "a file that will not decrypt is indistinguishable from one with no "
            "credentials in it, and guessing wrong mints a secret the running "
            "host does not have."
        )
        return summary

    # -- the identity ------------------------------------------------------
    identity_id = identities.get(identity_name)
    if identity_id is None:
        if dry_run:
            summary.actions.append(f"would create identity {identity_name!r}")
            identity_id = "<would-be-created>"
        else:
            try:
                identity_id = client.create_identity(
                    name=identity_name,
                    organization_id=organization_id,
                    role=HOST_ORG_ROLE,
                )
            except InfisicalError as exc:
                summary.errors.append(f"create identity {identity_name!r}: {exc}")
                return summary
            summary.actions.append(f"created identity {identity_name!r}")
        summary.created_identity = True
    else:
        summary.actions.append(f"identity {identity_name!r} already exists")
    summary.identity_id = identity_id

    # -- project access ----------------------------------------------------
    #
    # Granted before the credentials are minted. Either order leaves a window,
    # and this is the harmless one: an identity that can authenticate and read
    # nothing yet, rather than one a host is told to use before it can read
    # anything.
    # A dry run that would have created the identity has no id to look up, so
    # there is nothing to compare against and every project reads as a grant.
    hypothetical = dry_run and summary.created_identity
    for name in wanted:
        project_id = project_ids[name]
        try:
            members = {} if hypothetical else client.list_project_identities(project_id)
        except InfisicalError as exc:
            summary.errors.append(f"list identities on project {name!r}: {exc}")
            continue
        if identity_id in members:
            summary.projects_already.append(name)
            continue
        if dry_run:
            summary.actions.append(
                f"would grant {identity_name!r} {HOST_PROJECT_ROLE} on {name!r}"
            )
            summary.projects_granted.append(name)
            continue
        try:
            client.add_identity_to_project(
                project_id=project_id,
                identity_id=identity_id,
                role=HOST_PROJECT_ROLE,
            )
        except InfisicalError as exc:
            summary.errors.append(f"grant project {name!r}: {exc}")
            continue
        summary.actions.append(
            f"granted {identity_name!r} {HOST_PROJECT_ROLE} on {name!r}"
        )
        summary.projects_granted.append(name)

    # -- credentials -------------------------------------------------------
    if existing is not None and not rotate:
        summary.actions.append(
            f"credentials already in {destination.sops_file}; left alone "
            "(pass --rotate to mint new ones)"
        )
        return summary

    if dry_run:
        summary.actions.append(
            f"would mint universal-auth credentials into {destination.sops_file}"
        )
        summary.minted_credentials = True
        return summary

    try:
        client_id = client.attach_universal_auth(identity_id)
    except InfisicalError as exc:
        # Attaching twice is not an error worth stopping on by itself, but we
        # cannot recover the clientId from a failure, and minting a secret
        # against an unknown clientId would write an unusable pair into SOPS.
        summary.errors.append(
            f"attach universal auth to {identity_name!r}: {exc}. If the method "
            "is already attached, read its clientId from the UI and pass it "
            "with --client-id."
        )
        return summary

    try:
        client_secret = client.create_client_secret(
            identity_id, description=f"nixfisical host agent on {host}"
        )
    except InfisicalError as exc:
        summary.errors.append(f"mint client secret for {identity_name!r}: {exc}")
        return summary

    try:
        verdicts = set_keys(
            destination.sops_file,
            {
                destination.client_id_key: client_id,
                destination.client_secret_key: client_secret,
            },
        )
    except SopsError as exc:
        # The credential exists in Infisical and nowhere else now. Say so: the
        # recovery is to re-run with --rotate once the SOPS problem is fixed,
        # and the minted-but-unrecorded secret is dead weight that should be
        # revoked in the UI.
        summary.errors.append(
            f"minted credentials for {identity_name!r} but could not write "
            f"{destination.sops_file}: {exc}. The client secret is not "
            "recoverable -- revoke it in the UI and re-run with --rotate."
        )
        return summary

    summary.minted_credentials = True
    summary.actions.append(
        f"wrote {destination.client_id_key} ({verdicts.get(destination.client_id_key)}) "
        f"and {destination.client_secret_key} "
        f"({verdicts.get(destination.client_secret_key)}) to {destination.sops_file}"
    )
    return summary
