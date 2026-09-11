"""Offline tests for the pure parts of :mod:`nixfisical.bootstrap`.

Everything here runs without a server, a SOPS key or a network, which is what
makes it acceptable as a `nix flake check`. The functions covered were chosen
by one criterion: they are the ones whose failure mode is *silent*. An import
check catches a packaging mistake loudly; nothing catches an admin block that
quietly lands in the wrong estate's repo, or a find rule that quietly stops
agreeing with the create rule and mints a duplicate organization on every run.
"""

from nixfisical.bootstrap import (
    AdminCredentials,
    build_admin_document,
    describe_organizations,
    match_organization,
)

ORG = {"id": "org-id", "name": "XG Capital Strategies", "slug": "xg-6ece"}
OTHER = {"id": "other-id", "name": "jeirslab", "slug": "jeirslab-07xg"}


# -- the admin block is opt-in ---------------------------------------------
#
# `add-org` writes a file for an organization that usually belongs to a
# different estate, with a different set of SOPS recipients. The superadmin is
# scoped to the *instance*, so recording it there would hand whoever can
# decrypt that file every organization on the server. The block being absent is
# the security property; assert it directly rather than trusting the caller to
# keep passing None.


def test_org_file_omits_the_admin_block() -> None:
    document = build_admin_document(
        credentials=None,
        user_id="u1",
        organization=ORG,
        identity_id="i1",
        client_id="c1",
        client_secret="s1",
    )
    assert "admin" not in document
    assert set(document) == {"organization", "sync_identity"}
    assert document["organization"]["slug"] == "xg-6ece"
    assert document["sync_identity"]["client_secret"] == "s1"


def test_recording_credentials_restores_the_bootstrap_shape() -> None:
    """--record-admin-credentials must produce what bootstrap/adopt produce.

    Downstream readers are keyed by path, not by which command wrote the file,
    so a divergence here would surface as a missing key much later.
    """
    document = build_admin_document(
        credentials=AdminCredentials(email="a@b.c", password="pw", generated=True),
        user_id="u1",
        organization=ORG,
        identity_id="i1",
        client_id="c1",
        client_secret="s1",
    )
    assert set(document) == {"admin", "organization", "sync_identity"}
    assert document["admin"] == {"email": "a@b.c", "password": "pw", "user_id": "u1"}


# -- the find-or-create rule -----------------------------------------------
#
# Infisical does not enforce unique organization names. `add-org` is only
# re-runnable because it finds the organization before creating one, and only
# *correctly* re-runnable because it finds by exactly the rule `adopt` selects
# by -- which is why both call this function instead of each having their own.


def test_match_by_id_slug_and_name() -> None:
    for wanted in ("org-id", "xg-6ece", "XG Capital Strategies"):
        assert match_organization([ORG, OTHER], wanted) is ORG


def test_a_miss_is_a_miss() -> None:
    """No prefix or fuzzy matching: a near-miss must create, not adopt."""
    assert match_organization([ORG, OTHER], "XG Capital") is None
    assert match_organization([], "anything") is None


def test_id_beats_a_colliding_name() -> None:
    """The fields are tried in order, so the specific one wins."""
    collide = [
        {"id": "x", "name": "n", "slug": "s"},
        {"id": "n", "name": "z", "slug": "t"},
    ]
    assert match_organization(collide, "n")["id"] == "n"


def test_describe_organizations_renders_for_an_error_message() -> None:
    rendered = describe_organizations([ORG, OTHER])
    assert "'jeirslab' (slug 'jeirslab-07xg')" in rendered
    assert "'XG Capital Strategies' (slug 'xg-6ece')" in rendered
