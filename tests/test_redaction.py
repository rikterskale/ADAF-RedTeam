"""Redaction is the one guarantee that cannot leak. These tests enforce it."""

import json

import pytest

from adaf_redteam.evidence import write_journal, write_plan
from adaf_redteam.redaction import SecretHandle, SecretVault

SECRET = "S3cr3t-Passw0rd-aabbccddeeff00112233"


def test_handle_never_reveals_value():
    vault = SecretVault()
    handle = vault.redact(SECRET, "nt-hash")
    assert SECRET not in str(handle)
    assert SECRET not in repr(handle)
    assert isinstance(handle, SecretHandle)
    assert handle.handle_id.startswith("nt-hash#redacted-")


def test_vault_has_no_reveal_method():
    vault = SecretVault()
    for name in ("reveal", "get", "value", "plaintext", "raw", "unredact"):
        assert not hasattr(vault, name), f"vault must not expose {name}()"


def test_sha256_is_stable_and_not_reversible():
    vault = SecretVault()
    h = vault.redact(SECRET, "pfx")
    digest = vault.sha256_of(h)
    assert len(digest) == 64 and SECRET not in digest


def test_zeroize_drops_material():
    vault = SecretVault()
    h = vault.redact(SECRET, "ticket")
    vault.zeroize()
    with pytest.raises(KeyError):
        vault.sha256_of(h)


def test_context_manager_zeroizes():
    with SecretVault() as vault:
        h = vault.redact(SECRET, "aes-key")
        assert vault.sha256_of(h)
    with pytest.raises(KeyError):
        vault.sha256_of(h)


def test_evidence_writers_do_not_emit_secret(tmp_path):
    # Only redacted data should ever reach evidence. Prove the secret can't appear.
    vault = SecretVault()
    handle = vault.redact(SECRET, "nt-hash")
    plan = {"target": "svc01", "secretHandles": [handle.handle_id], "hash": vault.sha256_of(handle)}
    p1 = write_plan(plan, tmp_path)
    p2 = write_journal([{"action": "redacted", "handle": handle.handle_id}], tmp_path)
    for path in (p1, p2):
        assert SECRET not in path.read_text(encoding="utf-8")


def test_no_secret_shaped_string_in_serialized_handle():
    vault = SecretVault()
    handle = vault.redact(SECRET, "krbtgt")
    blob = json.dumps({"h": str(handle)})
    assert SECRET not in blob
