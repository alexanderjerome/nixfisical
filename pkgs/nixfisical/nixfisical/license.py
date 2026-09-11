"""What this instance is *allowed* to do, as distinct from what it can do.

Infisical is one codebase with two feature sets. Self-hosted without a license
key runs ``getDefaultOnPremFeatures()``, which returns a ``TFeatureSet`` with
most flags hard-coded ``false``; with a key, the flags come from the license
server. Every gated operation then reads the same object and throws
``BadRequestError`` when its flag is off. At v0.165.8 that is 166 call sites
across 38 distinct flags.

The point of this module is to move that discovery from *after* the failure to
*before* it.

**Why it matters more than it looks.** A plan restriction does not fail like a
bug. It fails as a 400 with a sentence about upgrading, from an endpoint that
is otherwise correct, on a request that is otherwise valid -- and it fails that
way forever, no matter how many times the reconciler retries. Without this
module the tool's only honest response is to report an error it cannot act on;
:mod:`nixfisical.access` currently *guesses* the reason in prose, and that
guess is right today only because the lab happens to be unlicensed. If a
license were ever added and ``createGroup`` still failed, that message would be
confidently wrong.

So the rule is: **a feature the server does not have is not an error.** It is a
gap between the declaration and the instance, and the run says so, finishes the
work that is possible, and exits successfully. A declaration is written once
for an estate; the estate's license is a property of the server on the day of
the run. Conflating the two makes every unlicensed run look broken.

``abort`` exists for the opposite case: when the declaration is a contract and
converging most of it is worse than converging none.

**One asymmetry worth keeping in view.** Upstream gates mutation, not
evaluation. ``permission-service.ts`` resolves group-derived permissions
without consulting the license at all, which is exactly why the direct-database
escape hatch in :mod:`nixfisical.access` works. This module's job is to tell
those two cases apart: "the API will refuse, and there is a supported way
round" is different advice from "the API will refuse, and that is the end of
it".

Nothing here reads a secret. It reads one JSON object describing a plan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

__all__ = [
    "CAPABILITIES",
    "Capability",
    "DEFAULT_ON_PREM_FEATURES",
    "LicenseError",
    "Plan",
    "UNSUPPORTED_POLICIES",
    "describe_gap",
]

# The upstream release the feature names and gate sites below were read off.
# Recorded because a flag that upstream *renames* is worse than one it removes:
# `plan.get(name)` on a missing key would read as "not licensed" and we would
# skip work the instance can do.
FEATURES_VERIFIED_AGAINST = "v0.165.8"

# What `GET /api/v1/organizations/{orgId}/plan` answers on a self-hosted
# instance with no license key, from `getDefaultOnPremFeatures()`.
#
# Only the flags this tool reasons about are listed; the full set is 60-odd
# fields, most of them limits rather than capabilities. This is the fallback
# when the plan endpoint cannot be reached, and it is the pessimistic one on
# purpose: assuming *less* than the instance has produces a skipped feature and
# a warning, while assuming more produces the 400 this module exists to avoid.
DEFAULT_ON_PREM_FEATURES: dict[str, Any] = {
    "slug": None,
    "tier": -1,
    "groups": False,
    "rbac": False,
    "secretsFolderRbac": False,
    "projectTemplates": False,
    "secretRotation": False,
    "dynamicSecret": False,
    "secretApproval": False,
    "secretScanning": False,
    "gateway": False,
    "gatewayPool": False,
    "externalKms": False,
    "enterpriseAppConnections": False,
    "enterpriseSecretSyncs": False,
    "subOrganization": False,
    "samlSSO": False,
    "oidcSSO": False,
    "scim": False,
    "ldap": False,
    "auditLogs": False,
    "ipAllowlisting": False,
    "machineIdentityAuthTemplates": False,
    "pkiEst": False,
    # The two that are true without a license, and the reason this table is a
    # table rather than "everything is false": `secretVersioning` and
    # `pkiAcme`. Worth knowing before assuming an unlicensed instance is inert.
    "secretVersioning": True,
    "pkiAcme": True,
}

# `settings.onUnsupported` in the declaration. See the module docstring for why
# "warn" is the default rather than the safer-sounding "abort".
UNSUPPORTED_POLICIES = ("warn", "abort")


class LicenseError(RuntimeError):
    """A licence-gated operation was attempted under ``onUnsupported = abort``."""


@dataclass(frozen=True)
class Capability:
    """One thing nixfisical can attempt, and the flag that decides whether it may.

    ``feature`` is the ``TFeatureSet`` key verbatim. Not a friendlier name: the
    string is greppable against the upstream tree, which is the only way to
    check this table has not drifted.

    ``workaround`` is the difference between "you need a licence" and "you need
    a licence *or* this other thing". It is None when there is genuinely no way
    round, and stating that plainly is the useful half of the answer.
    """

    feature: str
    summary: str
    workaround: str | None = None

    def explain(self) -> str:
        text = f"{self.summary} (requires the {self.feature!r} licence feature)"
        if self.workaround:
            text = f"{text}. {self.workaround}"
        return text


# Only the operations this tool can actually attempt. Deliberately not the full
# 38-flag list: a table that catalogues features nixfisical will never call is a
# table nobody updates, and a stale gate map is worse than none -- it would skip
# work the instance permits.
#
# Keys are the tool's own vocabulary, so a caller asks "may I create a group"
# rather than knowing which flag that is.
CAPABILITIES: dict[str, Capability] = {
    # sync-access, and the only gate the lab hits today.
    "create-group": Capability(
        feature="groups",
        summary="create an organization group",
        workaround=(
            "The UI cannot do it either -- it calls the same gated createGroup. "
            "'sync-access --create-missing-groups' writes the rows directly and "
            "the running server honours them, because upstream gates group "
            "mutation but not permission evaluation."
        ),
    ),
    # Granting with a *built-in* role (admin/member/viewer/no-access) is not
    # gated at all, which is why sync-access works on an unlicensed instance and
    # why DEFAULT_PROJECT_ROLE is "viewer". Only custom roles trip rbac.
    "custom-role": Capability(
        feature="rbac",
        summary="create a custom role, or assign one to a user, group or identity",
        workaround=(
            "The four built-in roles -- admin, member, viewer, no-access -- are "
            "ungated. 'viewer' is read access to a whole project, so the "
            "project boundary becomes the access boundary."
        ),
    ),
    "folder-permission": Capability(
        feature="secretsFolderRbac",
        summary="scope a grant to a folder rather than a whole project",
        workaround=(
            "Split the secrets across projects instead. The project boundary is "
            "the one that holds without a licence."
        ),
    ),
    "project-template": Capability(
        feature="projectTemplates",
        summary="create a project template",
        workaround=(
            "Declare the environments and roles on each project. The template "
            "saves repetition; it is not the only way to get the end state."
        ),
    ),
    "secret-rotation": Capability(
        feature="secretRotation",
        summary="declare a secret rotation",
        workaround=(
            "'nixfisical secrets gen --rotate' mints a new value into SOPS and "
            "the next sync pushes it. Manual, but it is the same end state."
        ),
    ),
    "dynamic-secret": Capability(
        feature="dynamicSecret",
        summary="declare a dynamic secret or lease one",
    ),
    "secret-approval": Capability(
        feature="secretApproval",
        summary="declare a secret-approval policy",
    ),
    "secret-scanning": Capability(
        feature="secretScanning",
        summary="configure secret scanning or its data sources",
    ),
    # The one that matters most for a homelab, and the one whose absence is
    # least obvious: a gateway is how Infisical reaches a database on a private
    # VLAN. Registration fails at the handshake, not at declaration time.
    "gateway": Capability(
        feature="gateway",
        summary="register a gateway, or route a connection through one",
        workaround=(
            "Without one, Infisical can only reach what it can route to "
            "directly. Give the instance a path to the target, or keep the "
            "credential in SOPS and let the sync push it outward."
        ),
    ),
    "gateway-pool": Capability(
        feature="gatewayPool",
        summary="create a gateway pool",
        workaround=(
            "Pools have no OpenAPI entry either, so a pool id is an opaque "
            "value from elsewhere even on a licensed instance."
        ),
    ),
    "external-kms": Capability(
        feature="externalKms",
        summary="attach an external KMS, or encrypt a project under one",
    ),
    "sub-organization": Capability(
        feature="subOrganization",
        summary="create a sub-organization",
        workaround=(
            "A second top-level organization is ungated: 'nixfisical add-org'. "
            "It does not inherit the parent's SSO, which is the whole point of "
            "a sub-org, but it is a hard partition and that is usually what was "
            "wanted."
        ),
    ),
    "identity-auth-template": Capability(
        feature="machineIdentityAuthTemplates",
        summary="create a machine-identity auth template",
        workaround="Restate the auth configuration on each identity.",
    ),
    "enterprise-connection": Capability(
        feature="enterpriseAppConnections",
        summary="create an app connection of an enterprise-only kind",
    ),
    "enterprise-sync": Capability(
        feature="enterpriseSecretSyncs",
        summary="create a secret sync to an enterprise-only destination",
    ),
    "audit-logs": Capability(
        feature="auditLogs",
        summary="read the audit log",
    ),
    "ldap-login": Capability(
        feature="ldap",
        summary="configure LDAP as a login source, or LDAP identity auth",
    ),
    "saml-sso": Capability(feature="samlSSO", summary="configure SAML SSO"),
    "oidc-sso": Capability(feature="oidcSSO", summary="configure OIDC SSO"),
    "scim": Capability(feature="scim", summary="configure SCIM provisioning"),
}


@dataclass
class Plan:
    """One organization's resolved feature set, and the questions worth asking it.

    ``measured`` records whether this came off the server or off
    :data:`DEFAULT_ON_PREM_FEATURES`. A caller that is about to tell an
    operator "your instance cannot do X" should be able to say whether it
    checked or assumed, because those warrant different responses.
    """

    features: Mapping[str, Any] = field(default_factory=dict)
    measured: bool = False
    source: str = "assumed unlicensed self-hosted defaults"

    @classmethod
    def unlicensed(cls, reason: str = "") -> "Plan":
        """The pessimistic fallback used when the plan endpoint is unreachable."""
        source = "assumed unlicensed self-hosted defaults"
        if reason:
            source = f"{source} ({reason})"
        return cls(features=dict(DEFAULT_ON_PREM_FEATURES), measured=False, source=source)

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "Plan":
        """Build from the body of ``GET /api/v1/organizations/{id}/plan``.

        The route's response schema is ``z.object({ plan: z.any() })`` -- so
        upstream itself makes no promise about the shape, and neither can we.
        Unwrap the envelope if it is there, take the object as-is if it is not,
        and let :meth:`has` deal with keys that never arrive.
        """
        plan = payload.get("plan") if isinstance(payload.get("plan"), Mapping) else payload
        return cls(features=dict(plan or {}), measured=True, source="reported by the instance")

    # -- questions ---------------------------------------------------------

    @property
    def slug(self) -> str | None:
        value = self.features.get("slug")
        return value if isinstance(value, str) else None

    @property
    def licensed(self) -> bool:
        """Whether anything beyond the free self-hosted baseline is on.

        Deliberately not ``slug is not None``: an offline license sets flags
        without necessarily setting a recognisable slug, and what a caller
        wants to know is whether gated work will succeed, not what the plan is
        called.
        """
        return any(
            self.has(capability.feature)
            for capability in CAPABILITIES.values()
        )

    def has(self, feature: str) -> bool:
        """Whether ``feature`` is on.

        A key the server did not send is *false*, not unknown. Upstream's gates
        are ``if (!plan.x)``, so an absent key fails them; mirroring that is the
        only reading that predicts the server's behaviour.
        """
        return bool(self.features.get(feature, False))

    def allows(self, capability: str) -> bool:
        """Whether a named entry in :data:`CAPABILITIES` is permitted."""
        known = CAPABILITIES.get(capability)
        if known is None:
            # An unknown capability is not a licence question, so do not answer
            # it as one. The caller has a typo, and silently returning False
            # would present it as a plan restriction.
            raise LicenseError(
                f"unknown capability {capability!r}; expected one of "
                f"{', '.join(sorted(CAPABILITIES))}"
            )
        return self.has(known.feature)

    def missing(self, capabilities: Iterable[str]) -> list[str]:
        """Which of ``capabilities`` this plan forbids, in the order given."""
        return [name for name in capabilities if not self.allows(name)]

    def headline(self) -> str:
        """One line for the top of a run summary."""
        if not self.measured:
            return f"licence: unknown -- {self.source}"
        if not self.licensed:
            return "licence: none (self-hosted defaults; groups, RBAC and gateways are off)"
        name = self.slug or "licensed"
        enabled = sorted(
            {c.feature for c in CAPABILITIES.values() if self.has(c.feature)}
        )
        return f"licence: {name} -- {', '.join(enabled)}"


def describe_gap(plan: Plan, capability: str, *, what: str) -> str:
    """The sentence to print when ``what`` cannot be done on this instance.

    Written for someone who has just seen a run skip something and wants to
    know, in order: what was skipped, why, whether the tool checked, and what to
    do instead.
    """
    known = CAPABILITIES[capability]
    checked = "the instance reports" if plan.measured else "assuming defaults,"
    text = f"{what}: skipped -- {checked} it cannot {known.explain()}"
    if not plan.measured:
        text = f"{text} Run 'nixfisical license' to check rather than assume."
    return text
