"""Round-trip tests for the batched SOPS writer, against the real ``sops``.

Every other suite here is pure. This one is not, and the exception is earned:
``set_keys`` is the only function in the package that *replaces an encrypted
file holding secrets*. Its failure mode is not a wrong answer, it is a store
that no longer decrypts, or one silently missing the keys it did not write
this run. Neither is visible to a test that stubs ``sops`` out -- the whole
risk lives in the part a stub replaces.

It is still offline: age is local key material, nothing here touches a network
or an Infisical instance. The keypair below is committed on purpose and is
worth exactly nothing; it exists so the suite is deterministic and needs no
``age-keygen`` at check time.

The suite skips itself when ``sops`` is not on PATH, so a contributor running
``pytest`` in a bare shell gets the other suites rather than a wall of errors.
The Nix build puts ``sops`` in ``nativeCheckInputs``, so in the build that
matters it always runs.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml

from nixfisical.pull import _classify
from nixfisical.sops import SopsError, clear_cache, decrypt_yaml, read_key, set_keys

pytestmark = pytest.mark.skipif(
    shutil.which("sops") is None, reason="needs the sops binary"
)

# A throwaway age keypair. Not a secret: it protects test fixtures in a tmpdir
# and nothing else, ever.
AGE_IDENTITY = (
    "AGE-SECRET-KEY-17W9RA7P52C96QDZAU2AQY7ASY6YW8DZEYZCF7QEERA8N6MUYCXAQ4CXNVU"
)
AGE_RECIPIENT = "age1qq2nt909u726s3fsq9y3p645z8zthcg595y4mf5ly9ed90cc0fjsxls6fd"


@pytest.fixture
def store(tmp_path: Path, monkeypatch: Any) -> Path:
    """An initialised SOPS store: a creation rule, a key, and a clean cache.

    The ``.sops.yaml`` rule matches ``*.yaml`` under the tmpdir, which is what
    lets ``set_keys`` create a file that does not exist yet -- that path picks
    its recipients from the rule matching the *destination*, so without a rule
    there is nothing to pick.
    """
    key_file = tmp_path / "keys.txt"
    key_file.write_text(f"{AGE_IDENTITY}\n")
    monkeypatch.setenv("SOPS_AGE_KEY_FILE", str(key_file))

    (tmp_path / ".sops.yaml").write_text(
        yaml.safe_dump(
            {"creation_rules": [{"path_regex": r".*\.yaml$", "age": AGE_RECIPIENT}]}
        )
    )
    # The document cache is process-global and these tests reuse paths.
    clear_cache()
    return tmp_path / "secrets.yaml"


def test_creates_a_store_that_did_not_exist(store: Path) -> None:
    verdicts = set_keys(store, {"api/token": "abc123"})

    assert verdicts == {"api/token": "created"}
    assert store.is_file()
    assert "abc123" not in store.read_text()  # it is actually encrypted
    assert read_key(store, "api/token") == "abc123"


def test_adds_a_key_without_disturbing_the_others(store: Path) -> None:
    set_keys(store, {"api/token": "abc123", "db/password": "hunter2"})
    clear_cache()
    set_keys(store, {"api/other": "new"})
    clear_cache()

    # The regression this guards: a writer that rebuilds the document from
    # only the keys it was handed this run silently drops every other secret
    # in the file, and the store still decrypts, so nothing complains until a
    # deploy fails.
    assert read_key(store, "api/token") == "abc123"
    assert read_key(store, "db/password") == "hunter2"
    assert read_key(store, "api/other") == "new"


def test_an_unchanged_write_does_not_touch_the_file(store: Path) -> None:
    set_keys(store, {"api/token": "abc123"})
    before = store.read_bytes()
    clear_cache()

    verdicts = set_keys(store, {"api/token": "abc123"})

    assert verdicts == {"api/token": "unchanged"}
    # Byte-identical, not just "still decrypts": sops rewrites the MAC and
    # `lastmodified` on every save, so a writer that saves unconditionally
    # turns every no-op pull into a commit.
    assert store.read_bytes() == before


def test_a_partial_match_still_writes(store: Path) -> None:
    set_keys(store, {"api/token": "abc123", "db/password": "hunter2"})
    clear_cache()

    verdicts = set_keys(store, {"api/token": "abc123", "db/password": "rotated"})

    assert verdicts == {"api/token": "unchanged", "db/password": "updated"}
    assert read_key(store, "db/password") == "rotated"


def test_refuses_to_bury_a_mapping(store: Path) -> None:
    set_keys(store, {"api/token/nested": "x"})
    clear_cache()

    with pytest.raises(SopsError, match="collection"):
        set_keys(store, {"api/token": "scalar"})

    # And the store is intact: the refusal happens before anything is written.
    clear_cache()
    assert read_key(store, "api/token/nested") == "x"


def test_refuses_to_descend_through_a_scalar(store: Path) -> None:
    set_keys(store, {"api/token": "x"})
    clear_cache()

    with pytest.raises(SopsError, match="scalar"):
        set_keys(store, {"api/token/deeper": "y"})

    clear_cache()
    assert read_key(store, "api/token") == "x"


# -- the classifier and the writer must not disagree -----------------------
#
# `_classify` exists to preview `set_keys` without writing. Two independent
# implementations of "what would this do" drift, and the drift is invisible
# until someone trusts a dry run. So the contract is asserted directly, on the
# inputs most likely to split them.


@pytest.mark.parametrize(
    "seed",
    [
        {},
        {"api/token": "abc123"},
        {"api/token": "abc123", "db/password": "hunter2"},
    ],
)
@pytest.mark.parametrize(
    "write",
    [
        {"api/token": "abc123"},
        {"api/token": "different"},
        {"api/token": "abc123", "api/fresh": "new"},
        {"brand/new": "value"},
    ],
)
def test_dry_run_verdicts_match_the_write_they_preview(
    store: Path, seed: dict[str, str], write: dict[str, str]
) -> None:
    if seed:
        set_keys(store, dict(seed))
    clear_cache()

    predicted = _classify(store, dict(write))
    clear_cache()
    actual = set_keys(store, dict(write))

    assert predicted == actual


def test_a_yaml_scalar_that_is_not_a_string_round_trips(store: Path) -> None:
    # YAML parses `12345` as an int and `true` as a bool, and Infisical stores
    # only strings. Both directions have to agree on the rendering or the key
    # is "changed" on every run forever.
    store.write_text(
        _encrypt(store, {"port": 12345, "enabled": True, "name": "plain"})
    )
    clear_cache()

    assert set_keys(store, {"port": "12345"}) == {"port": "unchanged"}
    clear_cache()
    assert set_keys(store, {"enabled": "true"}) == {"enabled": "unchanged"}
    clear_cache()
    assert _classify(store, {"enabled": "true"}) == {"enabled": "unchanged"}


def _encrypt(destination: Path, document: dict[str, Any]) -> str:
    """Encrypt ``document`` for ``destination``'s creation rule, via sops."""
    import subprocess

    proc = subprocess.run(
        ["sops", "--encrypt", "--filename-override", str(destination), "/dev/stdin"],
        input=yaml.safe_dump(document),
        capture_output=True,
        text=True,
        cwd=str(destination.parent),
        check=True,
    )
    return proc.stdout


def test_decrypt_yaml_sees_what_set_keys_wrote(store: Path) -> None:
    set_keys(store, {"a/b": "1", "a/c": "2", "d": "3"})
    clear_cache()
    assert decrypt_yaml(store) == {"a": {"b": "1", "c": "2"}, "d": "3"}
