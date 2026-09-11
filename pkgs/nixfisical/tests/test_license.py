"""Offline tests for :mod:`nixfisical.license`.

Same criterion as the bootstrap suite: cover the failures that are *silent*.
Licence handling is unusually prone to them, because both ways of being wrong
look like a working run.

Read the plan wrong and every feature reads as off, so the tool skips
everything, prints warnings nobody reads, and exits 0 -- on a licensed
instance. Read it too optimistically and the skip never happens, the request
goes out, and the server answers 400 partway through the work. Neither shows up
as a crash, which is why they are asserted here rather than left to a live run.

Nothing here talks to a server. A plan is a JSON object; these are JSON objects.
"""

import pytest

from nixfisical.access import BUILTIN_PROJECT_ROLES, DEFAULT_PROJECT_ROLE
from nixfisical.license import (
    CAPABILITIES,
    DEFAULT_ON_PREM_FEATURES,
    LicenseError,
    Plan,
    describe_gap,
)

# What the route actually returns: the feature set inside a `plan` envelope.
LICENSED = {"plan": {"slug": "enterprise", "groups": True, "rbac": True}}


# -- the envelope ----------------------------------------------------------
#
# The response schema upstream is `z.object({ plan: z.any() })`, so the only
# thing guaranteed is the wrapper. Failing to unwrap it is the worst bug this
# module could have and the hardest to notice: every `features.get(...)` misses,
# `has()` dutifully reports false for all of them, and a fully licensed instance
# is reported as having nothing. The run still exits 0.


def test_payload_envelope_is_unwrapped() -> None:
    plan = Plan.from_payload(LICENSED)
    assert plan.has("groups")
    assert plan.slug == "enterprise"


def test_payload_without_an_envelope_is_taken_as_the_plan() -> None:
    # `z.any()` promises nothing, so tolerate the flags arriving unwrapped
    # rather than reading an unfamiliar shape as an unlicensed instance.
    plan = Plan.from_payload({"slug": "enterprise", "groups": True})
    assert plan.has("groups")


def test_an_empty_plan_is_not_a_crash() -> None:
    assert Plan.from_payload({}).has("groups") is False


# -- absent means off, because that is what the server does ----------------
#
# Upstream's gates are `if (!plan.x)`. A key that never arrives fails them. Any
# other reading here predicts something the server will not do.


def test_an_absent_flag_is_false() -> None:
    assert Plan.from_payload({"plan": {}}).has("groups") is False


def test_a_renamed_flag_reads_as_off_rather_than_on() -> None:
    # The failure mode FEATURES_VERIFIED_AGAINST exists to warn about: upstream
    # renames a flag and our key stops matching. Skipping work the instance
    # permits is the acceptable half of that; attempting work it forbids is not.
    plan = Plan.from_payload({"plan": {"groupsV2": True}})
    assert plan.has("groups") is False


# -- a typo is not a licence answer ----------------------------------------
#
# If `allows("create-groups")` returned False, the caller would skip real work
# forever and the message would blame the licence. It has to be loud.


def test_an_unknown_capability_raises() -> None:
    with pytest.raises(LicenseError):
        Plan.from_payload(LICENSED).allows("create-groups")


def test_every_capability_name_resolves() -> None:
    plan = Plan.from_payload(LICENSED)
    for name in CAPABILITIES:
        plan.allows(name)


# -- the table has to match the flags upstream actually sends --------------
#
# A `feature` string with a typo in it denies its capability permanently, on a
# licensed instance as much as an unlicensed one, and looks exactly like a plan
# restriction. Cross-checking the two tables catches it without a server: the
# defaults were transcribed from `getDefaultOnPremFeatures()`, so a capability
# naming a flag that is not there names a flag that does not exist.


def test_capability_features_are_known_flags() -> None:
    unknown = sorted(
        capability.feature
        for capability in CAPABILITIES.values()
        if capability.feature not in DEFAULT_ON_PREM_FEATURES
    )
    assert unknown == []


# -- the fallback is pessimistic -------------------------------------------


def test_the_fallback_permits_nothing_gated() -> None:
    # If the plan endpoint is unreachable, guessing high turns a missing answer
    # into the 400 this module exists to avoid.
    plan = Plan.unlicensed("endpoint unreachable")
    assert plan.missing(CAPABILITIES) == list(CAPABILITIES)
    assert plan.licensed is False


def test_the_ungated_features_stay_true() -> None:
    # Not decoration: `secretVersioning` and `pkiAcme` are on without a licence,
    # and a later tidy-up that sets the whole table to False would have the tool
    # skip versioning work the instance does support.
    assert DEFAULT_ON_PREM_FEATURES["secretVersioning"] is True
    assert DEFAULT_ON_PREM_FEATURES["pkiAcme"] is True


# -- checked and assumed are different claims ------------------------------


def test_measured_distinguishes_reading_from_guessing() -> None:
    assert Plan.from_payload(LICENSED).measured is True
    assert Plan.unlicensed().measured is False


def test_an_unread_plan_says_so_in_the_gap() -> None:
    # An operator told "your instance cannot do this" deserves to know whether
    # anything checked. The unmeasured wording is the whole point.
    assumed = describe_gap(Plan.unlicensed(), "create-group", what="group 'developers'")
    assert "nixfisical license" in assumed

    measured = describe_gap(
        Plan.from_payload({"plan": {}}), "create-group", what="group 'developers'"
    )
    assert "nixfisical license" not in measured


def test_headline_does_not_claim_a_licence_it_did_not_read() -> None:
    assert "unknown" in Plan.unlicensed().headline()
    assert "enterprise" in Plan.from_payload(LICENSED).headline()


# -- the default project role has to be one of the ungated four ------------
#
# `rbac` gates assigning a custom role, not a built-in one, which is the only
# reason sync-access works on the lab instance at all. If the default ever drifts
# to a custom role, every unlicensed grant starts failing -- and it would fail at
# the server, one project at a time, not here.


def test_the_default_project_role_is_ungated() -> None:
    assert DEFAULT_PROJECT_ROLE in BUILTIN_PROJECT_ROLES


def test_the_builtin_roles_are_the_four_infisical_ships() -> None:
    assert BUILTIN_PROJECT_ROLES == {"admin", "member", "viewer", "no-access"}
