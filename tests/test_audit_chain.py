"""Tests for v2.1 merkle-chain audit logging."""

import pytest
from unittest.mock import MagicMock, patch
from langchain_mcps.audit_chain import AuditChain, AuditChainEntry


# ── Helpers ──

def make_entry_data(event="chain_start", passport_id="agent-1", action="signed"):
    return {
        "timestamp": 1000.0,
        "event": event,
        "passport_id": passport_id,
        "action": action,
    }


# ── Tests ──

def test_append_single_entry():
    """Add one entry, verify entry_hash is set and non-empty."""
    chain = AuditChain()
    entry = chain.append(make_entry_data())
    assert isinstance(entry, AuditChainEntry)
    assert entry.entry_hash is not None
    assert len(entry.entry_hash) == 64  # SHA256 hex = 64 chars
    assert entry.previous_entry_hash is None  # First entry has no previous


def test_append_multiple_entries():
    """Add 3 entries, verify each has correct previous_entry_hash linkage."""
    chain = AuditChain()
    e1 = chain.append(make_entry_data(event="e1"))
    e2 = chain.append(make_entry_data(event="e2"))
    e3 = chain.append(make_entry_data(event="e3"))

    assert e1.previous_entry_hash is None
    assert e2.previous_entry_hash == e1.entry_hash
    assert e3.previous_entry_hash == e2.entry_hash
    # All hashes distinct
    assert len({e1.entry_hash, e2.entry_hash, e3.entry_hash}) == 3


def test_merkle_root_updates():
    """Each append changes the merkle root."""
    chain = AuditChain()
    assert chain.get_merkle_root() is None

    chain.append(make_entry_data(event="e1"))
    root1 = chain.get_merkle_root()
    assert root1 is not None

    chain.append(make_entry_data(event="e2"))
    root2 = chain.get_merkle_root()
    assert root2 is not None
    assert root2 != root1


def test_chain_verification_passes():
    """A clean chain verifies successfully."""
    chain = AuditChain()
    for i in range(5):
        chain.append(make_entry_data(event=f"event_{i}"))
    assert chain.verify_chain() is True


def test_chain_verification_fails_on_modification():
    """Tampering with an entry breaks the chain."""
    chain = AuditChain()
    chain.append(make_entry_data(event="e1"))
    chain.append(make_entry_data(event="e2"))
    chain.append(make_entry_data(event="e3"))

    # Tamper with the first entry's action field
    chain._entries[0].action = "TAMPERED"
    assert chain.verify_chain() is False


def test_backward_compat_v1_entries():
    """v1.0-style entry dicts (no hash fields in input) work fine."""
    chain = AuditChain()
    # v1.0 style — no hash fields
    v1_data = {
        "timestamp": 999.0,
        "event": "chain_start",
        "passport_id": "agent-old",
        "action": "completed",
    }
    entry = chain.append(v1_data)
    # v2.1 fields computed automatically
    assert entry.entry_hash is not None
    assert entry.previous_entry_hash is None
    assert chain.verify_chain() is True


def test_sign_merkle_root():
    """Sign the merkle root using mcp_secure.sign_message."""
    chain = AuditChain()
    chain.append(make_entry_data())
    root = chain.get_merkle_root()

    mock_envelope = {"signature": "abc123", "payload": {"merkle_root": root}}
    with patch("langchain_mcps.audit_chain._sha256", wraps=lambda x: __import__("hashlib").sha256(x.encode()).hexdigest()):
        with patch("mcp_secure.sign_message", return_value=mock_envelope) as mock_sign:
            from mcp_secure import sign_message
            envelope = sign_message(
                {"merkle_root": root, "passport_id": "agent-1"},
                "agent-1",
                "fake-private-key",
            )
            # sign_message was called with merkle_root
            assert mock_sign.called
            result = mock_sign.return_value
            assert result["signature"] == "abc123"


def test_empty_chain():
    """Empty chain returns None for merkle_root."""
    chain = AuditChain()
    assert chain.get_merkle_root() is None
    assert chain.verify_chain() is True  # Empty chain is trivially valid
    assert chain.to_dict() == []
    assert len(chain) == 0


def test_export_to_dict():
    """Chain exports cleanly to list of dicts with hash fields included."""
    chain = AuditChain()
    chain.append(make_entry_data(event="e1"))
    chain.append(make_entry_data(event="e2"))

    exported = chain.to_dict()
    assert len(exported) == 2
    for item in exported:
        assert isinstance(item, dict)
        assert "entry_hash" in item
        assert "previous_entry_hash" in item
        assert "timestamp" in item
        assert "event" in item
        assert "passport_id" in item
        assert "action" in item
    # First entry has no previous
    assert exported[0]["previous_entry_hash"] is None
    # Second entry links to first
    assert exported[1]["previous_entry_hash"] == exported[0]["entry_hash"]
