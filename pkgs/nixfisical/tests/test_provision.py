"""Tests for per-host identity provisioning.

The dangerous outcome here is not a failed run, it is a *successful* one that
re-mints a credential the running host does not have. Every test below is some
version of that question.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from nixfisical.api import InfisicalError
from nixfisical.provision import (
    HOST_ORG_ROLE,
    HOST_PROJECT_ROLE,
    HostCredentials,
    provision_host,
)
from nixfisical.sops import SopsError

DESTINATION = HostCredentials(
    sops_file=Path("/fleet/secrets/alpha.yaml"),
    client_id_key="infisical/client_id",
    client_secret_key="infisical/client_secret",
)


class FakeClient:
    def __init__(
        self,
        *,
        identities: dict[str, str] | None = None,
        projects: dict[str, str] | None = None,
        members: dict[str, dict[str, str]] | None = None,
    ) -> None:
        self.identities = dict(identities or {})
        self.projects = dict(projects or {"platform": "p1", "databases": "p2"})
        self.members = dict(members or {})
        self.created: list[tuple[str, str]] = []
        self.granted: list[tuple[str, str, str]] = []
        self.minted = 0

    def list_identities(self, organization_id: str) -> dict[str, str]:
        return dict(self.identities)

    def list_projects(self, organization_id: str) -> dict[str, str]:
        return dict(self.projects)

    def create_identity(self, *, name: str, organization_id: str, role: str) -> str:
        self.created.append((name, role))
        self.identities[name] = "new-identity"
        return "new-identity"

    def list_project_identities(self, project_id: str) -> dict[str, str]:
        return dict(self.members.get(project_id, {}))

    def add_identity_to_project(
        self, *, project_id: str, identity_id: str, role: str
    ) -> None:
        self.granted.append((project_id, identity_id, role))

    def attach_universal_auth(self, identity_id: str, **_: Any) -> str:
        return "client-id-value"

    def create_client_secret(self, identity_id: str, **_: Any) -> str:
        self.minted += 1
        return "client-secret-value"


@pytest.fixture
def written(monkeypatch: Any) -> dict[str, str]:
    """Capture what would be written to SOPS, without a sops binary."""
    captured: dict[str, str] = {}

    def fake_set_keys(file: Path, values: dict[str, str]) -> dict[str, str]:
        captured.update(values)
        return {key: "created" for key in values}

    monkeypatch.setattr("nixfisical.provision.set_keys", fake_set_keys)
    return captured


def _no_existing(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "nixfisical.provision._existing_credentials", lambda destination: None
    )


def test_a_fresh_host_gets_a_scoped_identity(
    monkeypatch: Any, written: dict[str, str]
) -> None:
    _no_existing(monkeypatch)
    client = FakeClient()

    summary = provision_host(
        client,
        host="alpha",
        organization_id="org",
        projects=["platform"],
        destination=DESTINATION,
    )

    assert summary.ok
    # The whole safety argument for putting an identity on a host: it reaches
    # nothing organization-wide and is read-only on what it does reach.
    assert client.created == [("host-alpha", HOST_ORG_ROLE)]
    assert client.granted == [("p1", "new-identity", HOST_PROJECT_ROLE)]
    assert written == {
        "infisical/client_id": "client-id-value",
        "infisical/client_secret": "client-secret-value",
    }


def test_a_second_run_mints_nothing(monkeypatch: Any, written: dict[str, str]) -> None:
    # The failure this prevents is separated from its cause by however long it
    # takes to redeploy: a re-mint writes a new client secret into SOPS while
    # the running host still holds the old one, and the host keeps working
    # until its next deploy.
    monkeypatch.setattr(
        "nixfisical.provision._existing_credentials",
        lambda destination: ("client-id-value", "client-secret-value"),
    )
    client = FakeClient(
        identities={"host-alpha": "i1"},
        members={"p1": {"i1": HOST_PROJECT_ROLE}},
    )

    summary = provision_host(
        client,
        host="alpha",
        organization_id="org",
        projects=["platform"],
        destination=DESTINATION,
    )

    assert summary.ok
    assert client.created == []
    assert client.granted == []
    assert client.minted == 0
    assert written == {}
    assert summary.projects_already == ["platform"]


def test_rotate_mints_over_an_existing_pair(
    monkeypatch: Any, written: dict[str, str]
) -> None:
    monkeypatch.setattr(
        "nixfisical.provision._existing_credentials",
        lambda destination: ("old-id", "old-secret"),
    )
    client = FakeClient(identities={"host-alpha": "i1"})

    summary = provision_host(
        client,
        host="alpha",
        organization_id="org",
        projects=["platform"],
        destination=DESTINATION,
        rotate=True,
    )

    assert summary.ok
    assert client.minted == 1
    assert written["infisical/client_secret"] == "client-secret-value"


def test_an_undecryptable_destination_stops_the_run(monkeypatch: Any) -> None:
    # The worst bug this command could have: a missing age key reading as "no
    # credentials yet", minting a fresh secret, and leaving the running host
    # authenticating with one that no longer exists.
    def boom(destination: HostCredentials) -> None:
        raise SopsError("no key could decrypt this file")

    monkeypatch.setattr("nixfisical.provision._existing_credentials", boom)
    client = FakeClient(identities={"host-alpha": "i1"})

    summary = provision_host(
        client,
        host="alpha",
        organization_id="org",
        projects=["platform"],
        destination=DESTINATION,
    )

    assert not summary.ok
    assert client.minted == 0
    assert "Refusing to continue" in summary.errors[0]


def test_a_missing_project_stops_before_anything_is_created(monkeypatch: Any) -> None:
    _no_existing(monkeypatch)
    client = FakeClient(projects={"platform": "p1"})

    summary = provision_host(
        client,
        host="alpha",
        organization_id="org",
        projects=["platform", "nope"],
        destination=DESTINATION,
    )

    assert not summary.ok
    assert "nope" in summary.errors[0]
    # Not half-provisioned: no identity, no credentials, nothing to clean up.
    assert client.created == []
    assert client.minted == 0


def test_a_dry_run_creates_nothing(monkeypatch: Any, written: dict[str, str]) -> None:
    _no_existing(monkeypatch)
    client = FakeClient()

    summary = provision_host(
        client,
        host="alpha",
        organization_id="org",
        projects=["platform", "databases"],
        destination=DESTINATION,
        dry_run=True,
    )

    assert summary.ok
    assert client.created == []
    assert client.granted == []
    assert client.minted == 0
    assert written == {}
    assert summary.projects_granted == ["databases", "platform"]


def test_a_failed_grant_does_not_stop_the_others(
    monkeypatch: Any, written: dict[str, str]
) -> None:
    _no_existing(monkeypatch)
    client = FakeClient()
    real_add = client.add_identity_to_project

    def flaky(*, project_id: str, identity_id: str, role: str) -> None:
        if project_id == "p1":
            raise InfisicalError("403")
        real_add(project_id=project_id, identity_id=identity_id, role=role)

    client.add_identity_to_project = flaky  # type: ignore[method-assign]

    summary = provision_host(
        client,
        host="alpha",
        organization_id="org",
        projects=["platform", "databases"],
        destination=DESTINATION,
    )

    assert not summary.ok
    assert summary.projects_granted == ["databases"]
    # Credentials are still written: the identity exists and works, and a host
    # that can read one of its two projects is a legible half-state. The
    # failure is reported and the exit code is non-zero.
    assert written != {}


def test_a_sops_failure_after_minting_says_the_secret_is_lost(
    monkeypatch: Any
) -> None:
    _no_existing(monkeypatch)

    def boom(file: Path, values: dict[str, str]) -> dict[str, str]:
        raise SopsError("creation rule not found")

    monkeypatch.setattr("nixfisical.provision.set_keys", boom)

    summary = provision_host(
        FakeClient(),
        host="alpha",
        organization_id="org",
        projects=["platform"],
        destination=DESTINATION,
    )

    assert not summary.ok
    assert not summary.minted_credentials
    # The credential exists in Infisical and nowhere else. An error that only
    # said "could not write the file" would leave an operator assuming nothing
    # happened, and a live client secret nobody holds.
    assert "recoverable" in summary.errors[0]
    assert "--rotate" in summary.errors[0]
