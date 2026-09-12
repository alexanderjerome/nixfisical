"""Offline tests for operator parsing in :mod:`nixfisical.access`.

Same criterion as the other two suites: cover the failures that are *silent*.
Operator specs are unusually exposed to them, because every way of getting the
split wrong still produces a plausible `(email, role)` pair and a run that
exits 0. Parse ``dev@example.org:viewer`` into the wrong halves and the tool
cheerfully asks the server to add a user named "dev@example.org:viewer" with
the default role -- and since `admin` is that default, the quiet outcome of a
parsing bug here is handing someone more access than was written down, which is
the exact thing this module exists to make explicit.

Nothing here talks to a server. The gate test passes ``None`` as the client on
purpose: it asserts that the licence check happens before the first request,
so a client that would explode if touched is the assertion.
"""

import pytest

from nixfisical.access import (
    BUILTIN_PROJECT_ROLES,
    DEFAULT_OPERATOR_ROLE,
    AccessError,
    manifest_projects,
    parse_operators,
    sync_access,
)
from nixfisical.api import InfisicalError
from nixfisical.license import Plan

MANIFEST = [{"project": "platform", "groups": ["developers"]}]


# -- the default-role path is what the admin file depends on ---------------
#
# `sync-access` with no --operator reads a bare email out of the admin file and
# passes it through here. If a bare address stopped taking the default role,
# every estate that never passes --operator would silently stop granting
# anything, and the symptom is an empty project list days later.


def test_bare_email_takes_the_default_role() -> None:
    assert parse_operators(["admin@example.org"]) == {
        "admin@example.org": DEFAULT_OPERATOR_ROLE
    }


def test_bare_email_takes_an_overridden_default() -> None:
    assert parse_operators(["admin@example.org"], default_role="viewer") == {
        "admin@example.org": "viewer"
    }


# -- the split itself ------------------------------------------------------


def test_explicit_role_overrides_the_default() -> None:
    assert parse_operators(["dev@example.org:viewer"], default_role="admin") == {
        "dev@example.org": "viewer"
    }


def test_two_operators_can_hold_different_roles() -> None:
    # The whole point of the feature: one run, two humans, two access levels.
    assert parse_operators(
        ["admin@example.org", "dev@example.org:viewer"], default_role="admin"
    ) == {"admin@example.org": "admin", "dev@example.org": "viewer"}


def test_equals_is_not_a_separator() -> None:
    # `=` is valid in an RFC 5322 local part, which is why `:` was chosen. If
    # someone "fixes" the separator to the more obvious `=`, this address stops
    # resolving to itself and starts resolving to a role named "example.org".
    assert parse_operators(["a=b@example.org"]) == {
        "a=b@example.org": DEFAULT_OPERATOR_ROLE
    }


def test_split_takes_the_last_colon_not_the_first() -> None:
    # rpartition, not partition. A left split on an address that somehow
    # contains a colon would put the domain in the role.
    assert parse_operators(["dev@example.org:viewer"])["dev@example.org"] == "viewer"


# -- normalisation ---------------------------------------------------------


def test_emails_are_lowercased() -> None:
    # `list_project_users` keys on the lowercased address. An operator written
    # in mixed case and not folded here never matches an existing membership,
    # so every run re-adds them: the API call either errors or is a no-op, and
    # either way the summary reports "created" forever.
    assert parse_operators(["Admin@Example.ORG:admin"]) == {
        "admin@example.org": "admin"
    }


def test_roles_are_not_lowercased() -> None:
    # Built-in roles are lowercase, but a custom role slug is whatever the
    # instance says it is. Folding it would silently fail to match.
    assert parse_operators(["dev@example.org:ReadOnly"])["dev@example.org"] == "ReadOnly"


def test_surrounding_whitespace_is_stripped() -> None:
    assert parse_operators(["  dev@example.org : viewer "]) == {
        "dev@example.org": "viewer"
    }


def test_empty_entries_are_dropped() -> None:
    assert parse_operators(["", "   ", "dev@example.org"]) == {
        "dev@example.org": DEFAULT_OPERATOR_ROLE
    }


# -- the failures that must be loud ----------------------------------------


def test_conflicting_roles_for_one_person_is_an_error() -> None:
    # Keeping either one silently grants an access level nobody wrote down.
    with pytest.raises(AccessError, match="named twice"):
        parse_operators(["dev@example.org:viewer", "dev@example.org:admin"])


def test_the_same_role_twice_is_not_a_conflict() -> None:
    assert parse_operators(["dev@example.org:viewer", "Dev@example.org:viewer"]) == {
        "dev@example.org": "viewer"
    }


def test_a_role_with_no_email_is_an_error() -> None:
    with pytest.raises(AccessError, match="no email"):
        parse_operators([":viewer"])


def test_an_empty_role_is_an_error() -> None:
    # `dev@example.org:` is a typo, not a request for the default. Treating it
    # as the default would mean a trailing colon silently grants `admin`.
    with pytest.raises(AccessError, match="empty role"):
        parse_operators(["dev@example.org:"])


# -- the licence gate covers operator roles too -----------------------------
#
# Per-operator roles made it possible to name a custom role without ever
# passing --role. Before this the gate only looked at --role, so a custom
# operator role went unchecked and failed per-project with N identical 400s.


def test_a_custom_operator_role_trips_the_licence_gate() -> None:
    unlicensed = Plan.from_payload({"plan": {"slug": "starter"}})
    summary = sync_access(
        None,  # never touched: the gate returns before the first request
        MANIFEST,
        organization_id="org-id",
        operators=["dev@example.org:some-custom-role"],
        plan=unlicensed,
    )
    assert not summary.ok
    assert any("some-custom-role" in action.detail for action in summary.actions)


def test_built_in_operator_roles_pass_the_gate() -> None:
    # Guards against the gate becoming vacuous in the other direction: if it
    # started rejecting built-ins, every unlicensed instance would stop working
    # and the message would blame the licence. "Passed the gate" is asserted by
    # the run reaching its first request, which this client refuses -- so the
    # recorded failure is about listing projects and not about the role.
    class RefusesEverything:
        def list_projects(self, organization_id: str) -> dict[str, str]:
            raise InfisicalError("nope")

    unlicensed = Plan.from_payload({"plan": {"slug": "starter"}})
    for role in sorted(BUILTIN_PROJECT_ROLES):
        summary = sync_access(
            RefusesEverything(),
            MANIFEST,
            organization_id="org-id",
            operators=[f"dev@example.org:{role}"],
            plan=unlicensed,
        )
        details = " ".join(action.detail for action in summary.actions)
        assert "could not list projects" in details
        assert role not in details


# -- the operator pass must not be driven by `groups` -----------------------
#
# This is the silent failure the module header describes, reached by the route
# nobody checks. The operator pass used to iterate the grant map, which is keyed
# only by projects that name a group. A project shared with no group therefore
# got no operator -- and since `sync` creates projects as a machine identity,
# "no operator" means visible to no human at all. It exits 0, the secrets are
# correct, and the project simply is not there when you log in.
#
# It is the *administrator-only* project that hits this, so the bug removed
# visibility from exactly the secrets chosen to be most closely held.


class FakeClient:
    """Enough of the client for the grant and operator passes to run."""

    def __init__(self, projects: dict[str, str]) -> None:
        self._projects = projects
        self.added_users: list[tuple[str, str, str]] = []

    def list_projects(self, organization_id: str) -> dict[str, str]:
        return dict(self._projects)

    def list_organization_groups(self) -> dict[str, str]:
        return {"developers": "group-id"}

    def list_project_groups(self, project_id: str) -> dict[str, str]:
        return {}

    def list_project_users(self, project_id: str) -> dict[str, str]:
        return {}

    def add_group_to_project(self, *, project_id: str, group_id: str, role: str) -> None:
        return None

    def add_user_to_project(self, *, project_id: str, email: str, role: str) -> None:
        self.added_users.append((project_id, email, role))


def test_a_project_with_no_groups_still_gets_its_operator() -> None:
    client = FakeClient({"shared": "id-shared", "private": "id-private"})
    summary = sync_access(
        client,
        [
            {"project": "shared", "groups": ["developers"]},
            {"project": "private"},  # no `groups` -- administrator only
        ],
        organization_id="org-id",
        operators=["admin@example.org:admin"],
    )
    assert summary.ok
    assert ("id-private", "admin@example.org", "admin") in client.added_users
    assert ("id-shared", "admin@example.org", "admin") in client.added_users


def test_a_manifest_with_no_groups_at_all_still_grants_operators() -> None:
    # The other half of the same bug: `sync_access` returned early when the
    # grant map was empty, so an estate that never uses groups -- which is
    # every unlicensed instance, since group creation is plan-gated -- got no
    # operator memberships from any project.
    client = FakeClient({"private": "id-private"})
    summary = sync_access(
        client,
        [{"project": "private"}],
        organization_id="org-id",
        operators=["admin@example.org:admin"],
    )
    assert summary.ok
    assert client.added_users == [("id-private", "admin@example.org", "admin")]


def test_manifest_projects_is_wider_than_the_grant_map() -> None:
    entries = [
        {"project": "shared", "groups": ["developers"]},
        {"project": "private"},
        {"project": "private", "groups": []},
        {"groups": ["developers"]},  # no project: not a target
    ]
    assert manifest_projects(entries) == {"shared", "private"}


def test_an_operator_is_not_invented_for_a_project_sync_never_created() -> None:
    # Failing loudly matters here: the fix widened the set of projects this
    # pass walks, so a project the manifest names but `sync` has not created
    # reaches it for the first time. Silently skipping would reintroduce the
    # same "looks fine, is not there" outcome one level up.
    client = FakeClient({})
    summary = sync_access(
        client,
        [{"project": "private"}],
        organization_id="org-id",
        operators=["admin@example.org:admin"],
    )
    assert not summary.ok
    assert client.added_users == []
    assert any("run 'nixfisical sync' first" in a.detail for a in summary.actions)
