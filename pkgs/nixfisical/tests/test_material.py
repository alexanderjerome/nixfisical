"""Tests for the type layer: what a key is, and how to prove it before writing.

The interesting claim in :mod:`nixfisical.material` is that the SSH public half
can be derived from the private file in pure Python, with no ``ssh-keygen`` and
no passphrase. That claim is load-bearing -- the host runs the ``minimal`` build,
which has neither -- and it is only worth anything if the answer is byte-exact
against what ``ssh-keygen -y`` produces. So the vectors below are real
``ssh-keygen`` output, private and public half both, and the test compares the
derived line against the recorded one rather than against another run of this
module.

The three vectors cover the three cases that behave differently: an unencrypted
ed25519 key, the *same* format with a passphrase (where the cleartext public
section is the whole point), and RSA (where the blob is a different shape and a
naive parser that assumed a fixed length would pass the first two and fail this
one).

Nothing here has ever protected anything. The keys were generated for this file.
"""

from __future__ import annotations

import pytest

from nixfisical.material import (
    AGE,
    SSH,
    KeyringError,
    derive_public,
    detect,
    get,
    looks_like,
    parse_private,
)

# -- vectors ----------------------------------------------------------------

SSH_ED25519 = """\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBDZb/Z9sZnozqxjFF5N/HFQa2JfWot5T8JrSZXmX16xgAAAKB2yg2SdsoN
kgAAAAtzc2gtZWQyNTUxOQAAACBDZb/Z9sZnozqxjFF5N/HFQa2JfWot5T8JrSZXmX16xg
AAAEBGii0oFPPZS4vJnDKHHZaLOM6gLL5OPR6xAFcmVFy+dUNlv9n2xmejOrGMUXk38cVB
rYl9ai3lPwmtJleZfXrGAAAAGHZlY3Rvci1hQG5peGZpc2ljYWwudGVzdAECAwQF
-----END OPENSSH PRIVATE KEY-----
"""
SSH_ED25519_PUB = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIENlv9n2xmejOrGMUXk38cVBrYl9ai3lPwmt"
    "JleZfXrG"
)
SSH_ED25519_COMMENT = "vector-a@nixfisical.test"

# The same key type, with the passphrase "hunter2". Everything after the public
# section is aes256-ctr; the public section is not.
SSH_ENCRYPTED = """\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABC31aSbRO
KFJ1ULiz3n5GlsAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIJbhtJh9L18e+VaP
Q9/Ok/3Tjnmp1yJYp2KmNaLIPVNsAAAAoEVsSCKWdhCWm6vlp34YF+Hue41q7+FjXsSmqH
sFmRTRIWHowQ8jFqxlNqVbg+PMgN0SHlPt0TwK/2hbVgQEDveKfV86/mxTEqEBFdihtOfy
YFu2aBQZBTIC4+4WIUTc/zBdeW5yl0Acxm0EstBH62/7PVRHldkfRk5LxmuHTsxZLM96ni
6JILQzHQTtydZlwzSECPAhzht/qJOY1fjEnoA=
-----END OPENSSH PRIVATE KEY-----
"""
SSH_ENCRYPTED_PUB = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJbhtJh9L18e+VaPQ9/Ok/3Tjnmp1yJYp2Km"
    "NaLIPVNs"
)

SSH_RSA = """\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAssc9GRalQg54mTF2aIpYYXDN9P7THY4eAPWCURGIn+2cZSz8f7rE
ORjt+U1l2nTWMzkwl16q67izNQoqXBNy0UdIP1zIz25dQXkf/ON+RLUjLw76oJLiKwDehl
MnDM41lYE5HG6tQ6LqhJICUdT+OSm2Fk2obK3Bek9s6BJIli0Jl73MQWHu7k8+L7nYW4qJ
kNshGj0LkcvaTETq6jCMPqjjzBIAopBI+nJS3C6gJnp6/wOoU04oRfINPO8hDsdW0+xtM+
u0MgaCIJCtFCLw5WPnRilfjqjuZfexvftA1YLBx9EochL5QZht62f9nUStB78H6OcEDEuT
Gu/eOR2ZRwAAA9AkVTe5JFU3uQAAAAdzc2gtcnNhAAABAQCyxz0ZFqVCDniZMXZoilhhcM
30/tMdjh4A9YJREYif7ZxlLPx/usQ5GO35TWXadNYzOTCXXqrruLM1CipcE3LRR0g/XMjP
bl1BeR/8435EtSMvDvqgkuIrAN6GUycMzjWVgTkcbq1DouqEkgJR1P45KbYWTahsrcF6T2
zoEkiWLQmXvcxBYe7uTz4vudhbiomQ2yEaPQuRy9pMROrqMIw+qOPMEgCikEj6clLcLqAm
enr/A6hTTihF8g087yEOx1bT7G0z67QyBoIgkK0UIvDlY+dGKV+OqO5l97G9+0DVgsHH0S
hyEvlBmG3rZ/2dRK0Hvwfo5wQMS5Ma7945HZlHAAAAAwEAAQAAAQAFFfE2rH6TrCZhcpcZ
ZDjIFNXBuW9iBi/zpl2drBpZ36rfn0b+Od7pIjzAJyPVnMCXK8embAqqsqdjw9/unJ2wjG
Q8Fonz31eHIZ33q1+6g/iglxQpdeQ52vLO7sChTEsZRK1450EbN8rkwzk5ALkhVn7CkFT7
5SQoND2MizCbbQJjlvFMh6jtB7sz67HNnsATMYi6ILFxVH23uOtiZVFbSndJ/ISR8aTK9T
RGvGK7za+Kf2wp9C4xHF8jIZRqXsA9nGMmOJGbDJNOIECRJZDw4s2FSu8IbeJXBIYPa/57
MEgW5sJQ9VRvGJdeIRzxLr6smdE0SpR6g8j8cEdLEUipAAAAgFxel6HJL2jLAGEGwJIyY8
e0ikWbo8Z1UwecnKmFw+JuuFwud2sfPb6ccSjcfVb/Kerc86jbaRscFKuBhWlPft4R07x1
tdkSR4QIbzMAw+YdUGD7ghaeQ1KvjSWGDuy454rAIS4i0SqvQW8xCOMHzrJ++tPsICnu6/
PM4LAi41zbAAAAgQDY9WHLsoiN1B8idNJEUIkW0VK3VMxwfbQSutoT3WI5951oURnGMIPT
7l7uQ54ct/LehJRyaxGLLgFW+0oOfYGOe2QJKM0+tzFGfQtb7VctYN/UEtF0wREnzKFODC
cK738dDaVp/0K2zWOobBNSBqV52hru/sJv0ThsWQBcIbeBEwAAAIEA0vMCTirYFLTZ43qc
F94S1maD5If08cQ7EBYoo8nWXYuW0pzpsCb0PAZaz2ObhpBjirGYFdDBJd1SN4mi8BAJau
wa++vZmLsGhqdJ/leGOYvIcpNDjMjMWmicCv84mcrngGfB2DX8a8Xb6TzN9HY2fo/vvRUD
vybDBzxt90PDgX0AAAAadmVjdG9yLXJzYUBuaXhmaXNpY2FsLnRlc3QB
-----END OPENSSH PRIVATE KEY-----
"""
SSH_RSA_PUB = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCyxz0ZFqVCDniZMXZoilhhcM30/tMdjh4A"
    "9YJREYif7ZxlLPx/usQ5GO35TWXadNYzOTCXXqrruLM1CipcE3LRR0g/XMjPbl1BeR/8435E"
    "tSMvDvqgkuIrAN6GUycMzjWVgTkcbq1DouqEkgJR1P45KbYWTahsrcF6T2zoEkiWLQmXvcxB"
    "Ye7uTz4vudhbiomQ2yEaPQuRy9pMROrqMIw+qOPMEgCikEj6clLcLqAmenr/A6hTTihF8g08"
    "7yEOx1bT7G0z67QyBoIgkK0UIvDlY+dGKV+OqO5l97G9+0DVgsHH0ShyEvlBmG3rZ/2dRK0H"
    "vwfo5wQMS5Ma7945HZlH"
)

AGE_SECRET = "AGE-SECRET-KEY-1NXC4U76NRFG5S3C44J9K3ZATCRET0039Y753NN30UU58ZTY89C6S40CR7W"
AGE_PUBLIC = "age1sy4gt0mt0dasaygrfhhkarx7q2wpe5uysd09stqv7qh5hnpzlcnq9z9wz5"
AGE_FILE = f"# created: 2026-09-14T02:10:51Z\n# public key: {AGE_PUBLIC}\n{AGE_SECRET}\n"


# -- the type table ----------------------------------------------------------


def test_get_names_a_type() -> None:
    assert get("ssh") is SSH
    assert get(" AGE ") is AGE


def test_get_refuses_a_type_that_does_not_exist() -> None:
    with pytest.raises(KeyringError, match="unknown key type"):
        get("gpg")


def test_only_ssh_installs_a_public_half() -> None:
    """The public file is an SSH property, not a keyring one.

    An age key's recipients are stored so the operator can see what they pushed;
    nothing on a host reads them from a file. Writing one would be a file with
    no reader, at a path taken from the instance.
    """
    assert SSH.installs_public
    assert not AGE.installs_public


def test_private_defaults_are_owner_only_for_every_type() -> None:
    for material in (AGE, SSH):
        assert int(material.default_mode, 8) & 0o077 == 0, material.name


# -- detection ---------------------------------------------------------------


@pytest.mark.parametrize(
    "text, expected",
    [
        (AGE_FILE, AGE),
        (SSH_ED25519, SSH),
        (SSH_ENCRYPTED, SSH),
        (SSH_RSA, SSH),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n", SSH),
    ],
)
def test_detect_tells_the_formats_apart(text: str, expected) -> None:
    assert detect(text) is expected


def test_detect_refuses_something_that_is_neither() -> None:
    with pytest.raises(KeyringError, match="cannot tell what kind of key"):
        detect("hello\n")


def test_detect_refuses_a_file_holding_both() -> None:
    """A concatenation is a mistake with a plausible-looking outcome.

    Whichever type won the sniff, half the file would be stored under a policy
    written for the other half.
    """
    with pytest.raises(KeyringError, match="more than one kind"):
        detect(AGE_FILE + SSH_ED25519)


# -- ssh: parsing ------------------------------------------------------------


def test_parses_an_openssh_ed25519_key() -> None:
    assert parse_private(SSH, SSH_ED25519).kinds == ("ssh-ed25519",)


def test_parses_a_passphrase_protected_key_without_the_passphrase() -> None:
    assert parse_private(SSH, SSH_ENCRYPTED).kinds == ("ssh-ed25519",)


def test_parses_an_rsa_key() -> None:
    assert parse_private(SSH, SSH_RSA).kinds == ("ssh-rsa",)


def test_never_returns_ssh_private_material() -> None:
    """`Parsed.secrets` is the age-only channel, and must stay that way.

    The type exists so a caller can print `kinds` without checking what it is
    holding. An SSH parser that filled `secrets` would make that unsafe for a
    type nobody remembered to re-check.
    """
    assert parse_private(SSH, SSH_ED25519).secrets == ()


def test_refuses_a_public_key_pasted_as_the_private_one() -> None:
    with pytest.raises(KeyringError, match="public"):
        parse_private(SSH, f"{SSH_ED25519_PUB} {SSH_ED25519_COMMENT}\n")


def test_refuses_a_truncated_openssh_key() -> None:
    truncated = SSH_ED25519.replace("-----END OPENSSH PRIVATE KEY-----\n", "")
    with pytest.raises(KeyringError, match="truncated"):
        parse_private(SSH, truncated)


def test_refuses_armour_wrapped_around_something_else() -> None:
    """Right envelope, wrong contents -- what a copy-paste of two keys produces."""
    body = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "bm90IGFuIG9wZW5zc2gga2V5IGF0IGFsbA==\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    )
    with pytest.raises(KeyringError, match="openssh-key-v1"):
        parse_private(SSH, body)


def test_refuses_a_mangled_base64_body() -> None:
    mangled = SSH_ED25519.replace("b3BlbnNzaC1rZXktdjEA", "b3Blbn!!!!zaC1rZXktdjEA")
    with pytest.raises(KeyringError, match="base64"):
        parse_private(SSH, mangled)


def test_a_pem_key_is_accepted_but_named_as_one() -> None:
    """`ssh-keygen -m PEM` output is storable; only its public half is not.

    Refusing it outright would push the operator toward converting a working key
    to get it backed up, which is the opposite of what a backup is for.
    """
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n"
    assert parse_private(SSH, pem).kinds == ("pem-rsa",)


# -- ssh: the derived public half --------------------------------------------


@pytest.mark.parametrize(
    "private, expected",
    [
        (SSH_ED25519, SSH_ED25519_PUB),
        (SSH_ENCRYPTED, SSH_ENCRYPTED_PUB),
        (SSH_RSA, SSH_RSA_PUB),
    ],
)
def test_derives_the_public_half_byte_for_byte(private: str, expected: str) -> None:
    """Against recorded ``ssh-keygen`` output, not against another run of this.

    This is the whole reason the host can validate an SSH key with nothing on
    PATH. If it ever disagrees with ``ssh-keygen`` the fix is here, not in the
    vector.
    """
    lines, _note = derive_public(SSH, private)
    assert lines == [expected]


def test_deriving_from_an_encrypted_key_says_so() -> None:
    """The operator needs to know they stored something a host cannot use alone."""
    _lines, note = derive_public(SSH, SSH_ENCRYPTED)
    assert note is not None and "passphrase" in note


def test_an_unencrypted_key_derives_without_a_note() -> None:
    _lines, note = derive_public(SSH, SSH_ED25519)
    assert note is None


def test_a_pem_key_cannot_derive_and_says_what_to_do() -> None:
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n"
    lines, note = derive_public(SSH, pem)
    assert lines == []
    assert note is not None and "--public-from-file" in note


# -- what may be overwritten -------------------------------------------------


def test_recognises_its_own_kind_before_overwriting() -> None:
    assert looks_like(SSH, SSH_ED25519)
    assert looks_like(AGE, AGE_FILE)


def test_does_not_recognise_the_other_kind() -> None:
    """The clobber guard is the reason this matters: a keyring entry whose path
    points at the wrong file must stop, not overwrite."""
    assert not looks_like(SSH, AGE_FILE)
    assert not looks_like(AGE, SSH_ED25519)


def test_a_public_key_file_is_recognised_as_one() -> None:
    assert SSH.public_matches(f"{SSH_ED25519_PUB} {SSH_ED25519_COMMENT}\n")
    assert SSH.public_matches(f"{SSH_RSA_PUB} vector-rsa@nixfisical.test\n")


def test_something_else_at_the_public_path_is_not() -> None:
    assert not SSH.public_matches("root:x:0:0:root:/root:/bin/bash\n")
    assert not SSH.public_matches(SSH_ED25519)
