"""Tests for the host-side agent.

Offline like the rest: no instance, no network, and every file written under a
tmpdir. Ownership is the one thing that cannot be exercised honestly here --
``chown`` to another user needs root -- so those tests pin the *resolution*
(the error when a user does not exist) and leave the syscall to the one case
that always works, root chowning to the uid it already runs as.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from nixfisical.agent import (
    AgentError,
    AgentSpec,
    SecretSpec,
    SPEC_VERSION,
    _load_cache,
    _save_cache,
    AgentSummary,
    materialise,
    run,
)
from nixfisical.api import UniversalAuthCredentials

CREDENTIALS = UniversalAuthCredentials(client_id="id", client_secret="secret")


def _me() -> tuple[str, str]:
    """The user and group this process already is, so chown is a no-op."""
    import grp
    import pwd

    user = pwd.getpwuid(os.getuid()).pw_name
    group = grp.getgrgid(os.getgid()).gr_name
    return user, group


@pytest.fixture
def whoami() -> dict[str, str]:
    user, group = _me()
    return {"owner": user, "group": group}


def _secret(path: Path, whoami: dict[str, str], **overrides: Any) -> SecretSpec:
    base = dict(
        project="platform",
        environment="prod",
        folder="/grafana",
        name="OIDC_CLIENT_SECRET",
        path=path,
        mode="0600",
        **whoami,
    )
    base.update(overrides)
    return SecretSpec(**base)


class FakeClient:
    """Enough of InfisicalClient for the agent, and nothing it must not call."""

    def __init__(
        self,
        secrets: list[dict[str, Any]] | None = None,
        projects: dict[str, str] | None = None,
        fail: Exception | None = None,
    ) -> None:
        self._secrets = secrets if secrets is not None else []
        self._projects = projects if projects is not None else {"platform": "p1"}
        self._fail = fail
        self.listed: list[tuple[str, str]] = []
        self.logins = 0

    def universal_auth_login(self, credentials: UniversalAuthCredentials) -> str:
        self.logins += 1
        if self._fail is not None:
            raise self._fail
        return "token"

    def list_projects(self, organization_id: str) -> dict[str, str]:
        return dict(self._projects)

    def list_secrets(self, *, project_id: str, environment: str, path: str = "/"):
        self.listed.append((project_id, environment))
        return list(self._secrets)

    def close(self) -> None:  # pragma: no cover - the agent owns its own client
        raise AssertionError("run() must not close a client it did not create")


def _live(value: str = "s3cret", folder: str = "/grafana") -> list[dict[str, Any]]:
    return [
        {"secretKey": "OIDC_CLIENT_SECRET", "secretValue": value, "secretPath": folder}
    ]


# -- spec parsing -----------------------------------------------------------


def test_a_spec_from_the_future_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "spec.json"
    path.write_text(json.dumps({"version": SPEC_VERSION + 1, "url": "x", "secrets": []}))

    with pytest.raises(AgentError, match="different versions"):
        AgentSpec.load(path)


@pytest.mark.parametrize(
    ("given", "expected"),
    [("", "/"), (None, "/"), ("/", "/"), ("/a/b", "/a/b"), ("/a/b/", "/a/b"), ("a/b", "/a/b")],
)
def test_folder_normalisation(tmp_path: Path, given: Any, expected: str) -> None:
    # The agent and the API have to agree on the spelling of a folder or every
    # lookup misses, and the spec has been through Nix and JSON to get here.
    raw = {"project": "p", "name": "N", "path": "/tmp/x"}
    if given is not None:
        raw["folder"] = given
    assert SecretSpec.parse(raw, index=0).folder == expected


def test_a_secret_missing_its_destination_is_refused() -> None:
    with pytest.raises(AgentError, match="path"):
        SecretSpec.parse({"project": "p", "name": "N"}, index=3)


# -- materialising ----------------------------------------------------------


def test_writes_the_value_and_reports_the_change(
    tmp_path: Path, whoami: dict[str, str]
) -> None:
    destination = tmp_path / "nested" / "oidc"
    secret = _secret(destination, whoami)

    assert materialise(secret, "abc") is True
    assert destination.read_text() == "abc"
    assert oct(destination.stat().st_mode)[-4:] == "0600"


def test_an_unchanged_value_is_not_a_change(
    tmp_path: Path, whoami: dict[str, str]
) -> None:
    destination = tmp_path / "oidc"
    secret = _secret(destination, whoami)
    materialise(secret, "abc")

    assert materialise(secret, "abc") is False


def test_an_unchanged_value_still_has_its_mode_enforced(
    tmp_path: Path, whoami: dict[str, str]
) -> None:
    # Ownership drifts without the value rotating -- a hand-chmod, a user
    # recreated with a new uid. An unchanged secret is no reason to leave a
    # credential world-readable.
    destination = tmp_path / "oidc"
    secret = _secret(destination, whoami)
    materialise(secret, "abc")
    os.chmod(destination, 0o644)

    assert materialise(secret, "abc") is False
    assert oct(destination.stat().st_mode)[-4:] == "0600"


def test_no_temporary_file_survives_a_write(
    tmp_path: Path, whoami: dict[str, str]
) -> None:
    materialise(_secret(tmp_path / "oidc", whoami), "abc")

    assert sorted(p.name for p in tmp_path.iterdir()) == ["oidc"]


def test_an_unknown_owner_names_the_option_that_is_wrong(
    tmp_path: Path, whoami: dict[str, str]
) -> None:
    secret = _secret(tmp_path / "oidc", whoami, owner="nobody-called-this")

    with pytest.raises(AgentError, match="no such user"):
        materialise(secret, "abc")
    assert not (tmp_path / "oidc").exists()


def test_a_non_octal_mode_is_refused(tmp_path: Path, whoami: dict[str, str]) -> None:
    with pytest.raises(AgentError, match="octal"):
        materialise(_secret(tmp_path / "oidc", whoami, mode="rw-r--r--"), "abc")


# -- the run ----------------------------------------------------------------


def test_places_every_secret_and_lists_once_per_project(
    tmp_path: Path, whoami: dict[str, str]
) -> None:
    spec = AgentSpec(
        url="https://x",
        organization_id="org",
        secrets=(
            _secret(tmp_path / "a", whoami),
            _secret(tmp_path / "b", whoami, name="OTHER"),
        ),
    )
    client = FakeClient(
        secrets=_live()
        + [{"secretKey": "OTHER", "secretValue": "two", "secretPath": "/grafana"}]
    )

    summary = run(spec, credentials=CREDENTIALS, client=client, restart=False)

    assert summary.ok
    assert summary.written == 2
    assert (tmp_path / "a").read_text() == "s3cret"
    assert (tmp_path / "b").read_text() == "two"
    # Two secrets in one project and environment cost one listing, not two.
    assert client.listed == [("p1", "prod")]


def test_a_secret_the_instance_does_not_have_is_an_error(
    tmp_path: Path, whoami: dict[str, str]
) -> None:
    spec = AgentSpec(
        url="https://x",
        organization_id="org",
        secrets=(_secret(tmp_path / "a", whoami),),
    )

    summary = run(spec, credentials=CREDENTIALS, client=FakeClient(secrets=[]), restart=False)

    assert not summary.ok
    assert "no such secret" in summary.errors[0]
    assert not (tmp_path / "a").exists()


def test_a_project_the_identity_cannot_see_names_the_fix(
    tmp_path: Path, whoami: dict[str, str]
) -> None:
    spec = AgentSpec(
        url="https://x",
        organization_id="org",
        secrets=(_secret(tmp_path / "a", whoami),),
    )
    client = FakeClient(secrets=_live(), projects={})

    summary = run(spec, credentials=CREDENTIALS, client=client, restart=False)

    assert not summary.ok
    assert "provision-host" in summary.errors[0]


def test_an_explicit_project_id_skips_the_lookup(
    tmp_path: Path, whoami: dict[str, str]
) -> None:
    # The escape hatch for an instance that will not let a no-access identity
    # list projects: it must work with no organizationId at all.
    spec = AgentSpec(
        url="https://x",
        organization_id="",
        secrets=(_secret(tmp_path / "a", whoami, project_id="p9"),),
    )
    client = FakeClient(secrets=_live(), projects={})

    summary = run(spec, credentials=CREDENTIALS, client=client, restart=False)

    assert summary.ok
    assert client.listed == [("p9", "prod")]


def test_names_by_name_without_an_organization_is_an_error(
    tmp_path: Path, whoami: dict[str, str]
) -> None:
    spec = AgentSpec(
        url="https://x",
        organization_id="",
        secrets=(_secret(tmp_path / "a", whoami),),
    )

    summary = run(spec, credentials=CREDENTIALS, client=FakeClient(), restart=False)

    assert not summary.ok
    assert "organizationId" in summary.errors[0]


def test_an_unreachable_instance_fails_closed_without_a_cache(
    tmp_path: Path, whoami: dict[str, str]
) -> None:
    from nixfisical.api import InfisicalError

    spec = AgentSpec(
        url="https://x",
        organization_id="org",
        secrets=(_secret(tmp_path / "a", whoami),),
    )
    client = FakeClient(fail=InfisicalError("connection refused"))

    summary = run(spec, credentials=CREDENTIALS, client=client, restart=False)

    assert not summary.ok
    assert not (tmp_path / "a").exists()


def test_nothing_to_do_never_logs_in(tmp_path: Path) -> None:
    client = FakeClient()
    spec = AgentSpec(url="https://x", organization_id="org", secrets=())

    summary = run(spec, credentials=CREDENTIALS, client=client, restart=False)

    assert summary.ok
    assert client.logins == 0


def test_restart_units_fire_only_for_a_changed_value(
    tmp_path: Path, whoami: dict[str, str], monkeypatch: Any
) -> None:
    restarted: list[list[str]] = []
    monkeypatch.setattr(
        "nixfisical.agent._restart",
        lambda units, summary: restarted.append(sorted(set(units))),
    )
    spec = AgentSpec(
        url="https://x",
        organization_id="org",
        secrets=(_secret(tmp_path / "a", whoami, restart_units=("grafana.service",)),),
    )

    run(spec, credentials=CREDENTIALS, client=FakeClient(secrets=_live()), restart=True)
    assert restarted == [["grafana.service"]]

    # Second run: same value, so nothing changed and nothing is restarted. A
    # scheduled agent that bounced its consumers every interval would be worse
    # than no agent at all.
    run(spec, credentials=CREDENTIALS, client=FakeClient(secrets=_live()), restart=True)
    assert restarted == [["grafana.service"]]


# -- the cache --------------------------------------------------------------


def test_the_cache_serves_a_run_that_cannot_reach_the_instance(
    tmp_path: Path, whoami: dict[str, str]
) -> None:
    from nixfisical.api import InfisicalError

    cache = tmp_path / "cache"
    spec = AgentSpec(
        url="https://x",
        organization_id="org",
        secrets=(_secret(tmp_path / "a", whoami),),
    )

    good = run(
        spec,
        credentials=CREDENTIALS,
        client=FakeClient(secrets=_live()),
        cache=cache,
        restart=False,
    )
    assert good.ok and good.from_cache == 0

    (tmp_path / "a").unlink()  # as a reboot would
    degraded = run(
        spec,
        credentials=CREDENTIALS,
        client=FakeClient(fail=InfisicalError("connection refused")),
        cache=cache,
        restart=False,
    )

    assert degraded.ok
    assert degraded.from_cache == 1
    assert (tmp_path / "a").read_text() == "s3cret"


def test_the_cache_is_not_world_readable(tmp_path: Path, whoami: dict[str, str]) -> None:
    # It holds plaintext. That is the trade the option documents, and the mode
    # is the only thing standing behind the documentation.
    cache = tmp_path / "cache"
    summary = AgentSummary()
    _save_cache(cache, {("platform", "prod", "/grafana", "K"): "v"}, summary)

    assert summary.ok
    assert oct(cache.stat().st_mode)[-3:] == "700"
    assert oct((cache / "secrets.json").stat().st_mode)[-3:] == "600"


def test_an_empty_cache_does_not_rescue_a_failed_run(
    tmp_path: Path, whoami: dict[str, str]
) -> None:
    from nixfisical.api import InfisicalError

    spec = AgentSpec(
        url="https://x",
        organization_id="org",
        secrets=(_secret(tmp_path / "a", whoami),),
    )

    summary = run(
        spec,
        credentials=CREDENTIALS,
        client=FakeClient(fail=InfisicalError("down")),
        cache=tmp_path / "empty",
        restart=False,
    )

    assert not summary.ok
    assert not (tmp_path / "a").exists()


def test_a_good_run_replaces_the_cache_rather_than_merging_it(
    tmp_path: Path, whoami: dict[str, str]
) -> None:
    # A cache that accumulates would keep serving a secret the spec no longer
    # asks for, and would keep serving the old value of one that moved.
    cache = tmp_path / "cache"
    summary = AgentSummary()
    _save_cache(cache, {("platform", "prod", "/grafana", "GONE"): "old"}, summary)
    _save_cache(cache, {("platform", "prod", "/grafana", "KEPT"): "new"}, summary)

    stale = SecretSpec(
        project="platform", environment="prod", folder="/grafana",
        name="GONE", path=tmp_path / "x",
    )
    assert _load_cache(cache, [stale], AgentSummary()) == {}
