"""Offline tests for :mod:`nixfisical.pull`.

Same criterion as the other suites: cover the failures that are *silent*. The
pull direction has more of them than the push does, because its output is an
encrypted file nobody reads by eye. A push that goes wrong shows up in the UI;
a pull that goes wrong shows up as a service that will not start, three commits
later, on a host nobody was looking at.

Four such failures are covered here.

* **The partition.** ``sync`` and ``import`` are only safe because they write
  disjoint halves of one manifest. If both ever claimed an entry, a scheduled
  pair of them would overwrite each other forever and the estate would settle
  on whichever ran last. That invariant is asserted directly rather than
  inferred from the two commands' behaviour.

* **Silent defaulting of a bad ``source``.** ``"Infisical"`` with a capital I
  is a well-formed manifest that every tool here would treat as SOPS-owned,
  which hands the next ``sync`` permission to overwrite the instance's copy
  with the local one. It has to be rejected, not defaulted.

* **A missing secret resolving to nothing.** An entry that declares the
  instance owns a value the instance has never heard of must be an error. The
  tempting alternative -- skip it, warn, carry on -- writes nothing to SOPS and
  exits 0, and the operator finds out at the next deploy.

* **Dry run disagreeing with apply.** A dry run that classifies differently
  from the write it is previewing is worse than no dry run at all. The
  round-trip suite pins the two together against real ``sops``; here the
  classifier is pinned against the cases that tempt a naive implementation --
  YAML ``null`` and YAML ``true``.

Nothing here talks to a server or to ``sops``. The client is a stub whose
recorded calls are themselves assertions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from nixfisical.manifest import entry_source, validate
from nixfisical.pull import _classify, _normalise_folder, _wanted, pull
from nixfisical.reconcile import reconcile
from nixfisical.sops import SopsError, scalar_text


class FakeClient:
    """Just enough of ``InfisicalClient`` for the pull to run.

    ``secrets`` is keyed by ``(project name, environment)`` and holds the raw
    shape the API returns, so an entry's lookup exercises the real indexing
    rather than a convenient one.
    """

    def __init__(
        self,
        projects: dict[str, str],
        secrets: dict[tuple[str, str], list[dict[str, Any]]] | None = None,
    ) -> None:
        self.projects = projects
        self.secrets = secrets or {}
        self.listed: list[tuple[str, str]] = []
        self.ids_to_names = {value: key for key, value in projects.items()}

    def list_projects(self, organization_id: str) -> dict[str, str]:
        return dict(self.projects)

    def list_secrets(
        self, *, project_id: str, environment: str, path: str = "/"
    ) -> list[dict[str, Any]]:
        name = self.ids_to_names[project_id]
        self.listed.append((name, environment))
        return list(self.secrets.get((name, environment), []))

    # Only `reconcile` reaches these. They report "already existed" so the
    # structural half of a sync is a no-op and the tests using them are
    # asserting about secrets, which is what they are for.

    def create_environment(self, project_id: str, *, name: str, slug: str) -> bool:
        return False

    def create_folder(
        self, *, project_id: str, environment: str, path: str, name: str
    ) -> bool:
        return False

    def upsert_secret(self, name: str, **kwargs: Any) -> str:
        raise AssertionError(
            "reconcile must not write the value of a source=infisical entry"
        )


def entry(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "sopsKey": "services/grafana/oidc_secret",
        "sopsFile": "/secrets/platform.yaml",
        "project": "platform",
        "environment": "prod",
        "folder": "/grafana",
        "name": "OIDC_SECRET",
        "groups": [],
        "hosts": ["dash"],
        "source": "infisical",
    }
    base.update(overrides)
    return base


def secret(name: str, path: str = "/grafana", value: str = "s3cret") -> dict[str, Any]:
    return {"secretKey": name, "secretPath": path, "secretValue": value}


# -- the partition ---------------------------------------------------------
#
# The safety argument for having two directions at all. Asserted on the
# manifest rather than on outputs, so it holds for entries neither command
# would reach for unrelated reasons (an unreachable project, a missing file).


def test_push_and_pull_claim_disjoint_halves_of_one_manifest() -> None:
    manifest = [
        entry(sopsKey="a", source="sops"),
        entry(sopsKey="b", source="infisical"),
        entry(sopsKey="c"),  # explicit default from the fixture
        {"sopsKey": "d", "project": "p", "environment": "prod", "folder": "/", "name": "D"},
    ]
    pulled = {item["sopsKey"] for item in _wanted(manifest)}
    pushed = {item["sopsKey"] for item in manifest if entry_source(item) == "sops"}

    assert pulled & pushed == set()
    assert pulled | pushed == {"a", "b", "c", "d"}
    assert pulled == {"b", "c"}


def test_an_entry_with_no_source_is_owned_by_sops() -> None:
    # The whole back-compatibility story: a manifest rendered before the field
    # existed must keep meaning exactly what it meant.
    assert entry_source({"sopsKey": "x"}) == "sops"
    assert _wanted([{"sopsKey": "x"}]) == []


def test_reconcile_does_not_write_the_value_of_an_infisical_owned_entry() -> None:
    # `read_key` is not stubbed on purpose: the sopsFile does not exist, so if
    # reconcile ever reached for it this would raise rather than pass.
    summary = reconcile(
        FakeClient({"platform": "p1"}),
        [entry()],
        organization_id="org",
        prune=False,
    )
    assert summary.ok
    assert summary.secrets_delegated == 1
    assert summary.secrets_created == 0
    assert summary.secrets_updated == 0
    assert [action.result for action in summary.actions if action.kind == "secret"] == [
        "delegated"
    ]


def test_prune_leaves_an_infisical_owned_secret_alone() -> None:
    # It is in the manifest, so it is declared, so it survives. Worth pinning:
    # the day `declared` is built from "entries this run wrote" instead of
    # "entries this run saw", prune starts deleting exactly the secrets whose
    # values it refused to manage.
    client = FakeClient(
        {"platform": "p1"},
        {("platform", "prod"): [secret("OIDC_SECRET")]},
    )
    summary = reconcile(client, [entry()], organization_id="org", prune=True)
    assert summary.secrets_pruned == 0
    assert summary.ok


# -- a bad source must not default -----------------------------------------


@pytest.mark.parametrize("bad", ["Infisical", "remote", "pull", "SOPS", ""])
def test_validate_rejects_an_unrecognised_source(bad: str) -> None:
    problems = validate([entry(source=bad)])
    assert any("source" in problem for problem in problems), problems


def test_validate_accepts_both_directions_and_an_absent_field() -> None:
    assert validate([entry(source="sops")]) == []
    assert validate([entry(source="infisical")]) == []

    absent = entry()
    del absent["source"]
    assert validate([absent]) == []


# -- resolution ------------------------------------------------------------


def test_a_value_is_routed_to_its_sops_coordinate(monkeypatch: Any) -> None:
    written: dict[Path, dict[str, str]] = {}

    def fake_set_keys(file: Path, values: dict[str, str]) -> dict[str, str]:
        written[file] = dict(values)
        return {key: "created" for key in values}

    monkeypatch.setattr("nixfisical.pull.set_keys", fake_set_keys)

    client = FakeClient(
        {"platform": "p1"},
        {("platform", "prod"): [secret("OIDC_SECRET", value="from-the-instance")]},
    )
    summary = pull(client, [entry()], organization_id="org")

    assert summary.ok
    assert written == {
        Path("/secrets/platform.yaml"): {
            "services/grafana/oidc_secret": "from-the-instance"
        }
    }
    assert summary.secrets_created == 1
    assert summary.files_written == 1


def test_one_listing_serves_every_secret_in_a_project(monkeypatch: Any) -> None:
    # The reason the listing is recursive and hoisted out of the entry loop. A
    # regression here is invisible in behaviour and only shows up as a sync
    # that takes a minute per folder.
    monkeypatch.setattr(
        "nixfisical.pull.set_keys",
        lambda file, values: {key: "created" for key in values},
    )
    client = FakeClient(
        {"platform": "p1"},
        {
            ("platform", "prod"): [
                secret("OIDC_SECRET", "/grafana"),
                secret("API_TOKEN", "/grafana"),
                secret("WEBHOOK", "/alerting"),
            ]
        },
    )
    manifest = [
        entry(sopsKey="a", name="OIDC_SECRET", folder="/grafana"),
        entry(sopsKey="b", name="API_TOKEN", folder="/grafana"),
        entry(sopsKey="c", name="WEBHOOK", folder="/alerting"),
    ]
    summary = pull(client, manifest, organization_id="org")

    assert summary.ok
    assert client.listed == [("platform", "prod")]
    assert summary.secrets_created == 3


def test_writes_are_batched_one_call_per_destination_file(monkeypatch: Any) -> None:
    calls: list[Path] = []

    def fake_set_keys(file: Path, values: dict[str, str]) -> dict[str, str]:
        calls.append(file)
        return {key: "created" for key in values}

    monkeypatch.setattr("nixfisical.pull.set_keys", fake_set_keys)

    client = FakeClient(
        {"platform": "p1"},
        {("platform", "prod"): [secret("A"), secret("B"), secret("C")]},
    )
    manifest = [
        entry(sopsKey="one", name="A", sopsFile="/secrets/x.yaml"),
        entry(sopsKey="two", name="B", sopsFile="/secrets/x.yaml"),
        entry(sopsKey="three", name="C", sopsFile="/secrets/y.yaml"),
    ]
    summary = pull(client, manifest, organization_id="org")

    assert summary.ok
    assert calls == [Path("/secrets/x.yaml"), Path("/secrets/y.yaml")]


# -- the failures that must stay loud --------------------------------------


def test_a_secret_the_instance_does_not_have_is_an_error() -> None:
    client = FakeClient({"platform": "p1"}, {("platform", "prod"): []})
    summary = pull(client, [entry()], organization_id="org")

    assert not summary.ok
    assert summary.secrets_created == 0
    assert "no such secret exists" in summary.errors[0]


def test_a_value_the_identity_cannot_read_is_an_error() -> None:
    # Infisical can return a secret whose name is visible and whose value is
    # not. Indexing it anyway would write the string "None" into a SOPS file
    # and report success.
    client = FakeClient(
        {"platform": "p1"},
        {("platform", "prod"): [{"secretKey": "OIDC_SECRET", "secretPath": "/grafana"}]},
    )
    summary = pull(client, [entry()], organization_id="org")

    assert not summary.ok
    assert "no such secret exists" in summary.errors[0]


def test_a_missing_project_is_an_error_not_a_silent_skip() -> None:
    summary = pull(FakeClient({}), [entry()], organization_id="org")

    assert not summary.ok
    assert "does not exist" in summary.errors[0]
    assert summary.secrets_created == 0


def test_two_entries_aiming_at_one_sops_key_collide(monkeypatch: Any) -> None:
    # `validate` catches two entries pointing at one Infisical destination.
    # This is the mirror-image collision, which only exists in this direction:
    # two distinct Infisical secrets writing one key in one file. Whichever
    # lost would be invisible.
    #
    # The write is stubbed because the collision is reported and the run
    # continues -- the entry that got there first is still written, which is
    # the deliberate failure policy, not an oversight.
    monkeypatch.setattr(
        "nixfisical.pull.set_keys",
        lambda file, values: {key: "created" for key in values},
    )
    client = FakeClient(
        {"platform": "p1"},
        {("platform", "prod"): [secret("A", value="first"), secret("B", value="second")]},
    )
    manifest = [
        entry(sopsKey="shared", name="A"),
        entry(sopsKey="shared", name="B"),
    ]
    summary = pull(client, manifest, organization_id="org")

    assert not summary.ok
    assert "both write" in summary.errors[0]


def test_an_unreadable_project_does_not_fail_the_secrets_under_another(
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr(
        "nixfisical.pull.set_keys",
        lambda file, values: {key: "created" for key in values},
    )
    client = FakeClient(
        {"platform": "p1"},
        {("platform", "prod"): [secret("OIDC_SECRET")]},
    )
    manifest = [entry(), entry(sopsKey="other", project="missing")]
    summary = pull(client, manifest, organization_id="org")

    assert not summary.ok  # the missing project is still reported
    assert summary.secrets_created == 1  # and the reachable one still landed


def test_nothing_to_do_is_not_an_error() -> None:
    summary = pull(FakeClient({}), [entry(source="sops")], organization_id="org")
    assert summary.ok
    assert summary.considered == 0


# -- folder normalisation --------------------------------------------------


@pytest.mark.parametrize(
    ("manifest_folder", "api_path"),
    [("/", "/"), ("", "/"), (None, "/"), ("/a/b/", "/a/b"), ("/a/b", "/a/b")],
)
def test_folder_forms_that_should_index_the_same_bucket(
    manifest_folder: Any, api_path: str
) -> None:
    assert _normalise_folder(manifest_folder) == _normalise_folder(api_path)


# -- the classifier must agree with the writer -----------------------------


def _classify_against(tmp_path: Path, monkeypatch: Any, document: dict[str, Any],
                      values: dict[str, str]) -> dict[str, str]:
    """Run ``_classify`` against ``document`` without involving real ``sops``."""
    target = tmp_path / "store.yaml"
    target.write_text("placeholder: ciphertext\n")
    monkeypatch.setattr("nixfisical.sops.decrypt_yaml", lambda file, use_cache=True: document)
    return _classify(target, values)


def test_a_yaml_null_reads_as_updated_not_created(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # The trap that a presence check written as `cursor is None` falls into.
    # `set_keys` sees the key in the mapping and says "updated"; a classifier
    # using None as its sentinel says "created". Either verdict is survivable;
    # the two disagreeing is not.
    verdicts = _classify_against(
        tmp_path, monkeypatch, {"api": {"token": None}}, {"api/token": "v"}
    )
    assert verdicts == {"api/token": "updated"}


def test_a_boolean_is_not_perpetually_changed(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # YAML `true` is Python True is `str(True)` == "True", which never equals
    # the "true" Infisical stores. Left uncorrected, every pull rewrites the
    # file and every scheduled run produces a commit that changes nothing.
    verdicts = _classify_against(
        tmp_path, monkeypatch, {"flags": {"enabled": True}}, {"flags/enabled": "true"}
    )
    assert verdicts == {"flags/enabled": "unchanged"}
    assert scalar_text(True) == "true"


def test_an_absent_key_reads_as_created(tmp_path: Path, monkeypatch: Any) -> None:
    verdicts = _classify_against(
        tmp_path, monkeypatch, {"api": {"other": "x"}}, {"api/token": "v"}
    )
    assert verdicts == {"api/token": "created"}


def test_refusing_to_overwrite_a_mapping_with_a_scalar(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # Writing "api/token" when "api/token" is itself a map would discard every
    # credential under it.
    with pytest.raises(SopsError, match="collection"):
        _classify_against(
            tmp_path, monkeypatch, {"api": {"token": {"nested": "x"}}}, {"api/token": "v"}
        )


def test_dry_run_writes_nothing(tmp_path: Path, monkeypatch: Any) -> None:
    def explode(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("a dry run must not call set_keys")

    monkeypatch.setattr("nixfisical.pull.set_keys", explode)
    monkeypatch.setattr(
        "nixfisical.sops.decrypt_yaml", lambda file, use_cache=True: {}
    )
    target = tmp_path / "store.yaml"
    target.write_text("placeholder: ciphertext\n")

    client = FakeClient(
        {"platform": "p1"},
        {("platform", "prod"): [secret("OIDC_SECRET")]},
    )
    summary = pull(
        client, [entry(sopsFile=str(target))], organization_id="org", dry_run=True
    )

    assert summary.ok
    assert summary.secrets_created == 1
    assert [action.result for action in summary.actions if action.kind == "secret"] == [
        "would-create"
    ]
