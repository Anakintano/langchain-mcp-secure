"""Integration tests for v1.0 through v2.2 cross-feature interactions."""

import pytest
from unittest.mock import patch
from mcp_secure import generate_key_pair, create_passport, sign_passport, TRUST_LEVELS
from langchain_mcps import MCPSCallbackHandler
from langchain_mcps.capabilities import CapabilitySchema, CapabilityValidator, CapabilityEnforcer


# ── Helpers ──


def _make_passport(trust_level=None, expired=False):
    authority = generate_key_pair()
    agent = generate_key_pair()
    passport = create_passport(
        name="test-agent",
        version="1.0.0",
        public_key=agent["public_key"],
        ttl_days=-1 if expired else 365,
    )
    if trust_level is not None:
        passport["trust_level"] = trust_level
    signed = sign_passport(passport, authority["private_key"])
    return signed, authority, agent


def _make_passport_with_caps(capabilities, trust_level=None, expired=False):
    authority = generate_key_pair()
    agent = generate_key_pair()
    passport = create_passport(
        name="test-agent",
        version="2.0.0",
        public_key=agent["public_key"],
        ttl_days=-1 if expired else 365,
    )
    if trust_level is not None:
        passport["trust_level"] = trust_level
    passport["capabilities"] = capabilities
    signed = sign_passport(passport, authority["private_key"])
    return signed, authority, agent


TOOL_CAPS = {
    "search": {"allowed": True, "constraints": {}},
    "database_read": {
        "allowed": True,
        "constraints": {"allowed_tables": ["customers"]},
    },
    "database_write": {"allowed": False},
}

TIME_CAPS = {
    "search": {
        "allowed": True,
        "constraints": {},
        "permission_windows": [
            {"start_time": 1000.0, "end_time": 2000.0},
        ],
    },
    "gated_tool": {
        "allowed": True,
        "constraints": {},
        "permission_gates": [
            {"gate_type": "manual_approval", "config": {"approval_required": True}}
        ],
    },
}

FULL_CAPS = {
    "search": {
        "allowed": True,
        "constraints": {},
        "permission_windows": [
            {"start_time": 1000.0, "end_time": 2000.0},
        ],
    },
    "gated_tool": {
        "allowed": True,
        "constraints": {},
        "permission_gates": [
            {"gate_type": "manual_approval", "config": {"approval_required": True}}
        ],
    },
    "always_allowed": {
        "allowed": True,
        "constraints": {},
    },
    "forbidden": {"allowed": False},
}


# ══ Suite 1: v1.0 + v2.0 ══


class TestV1PlusV2Integration:

    def test_v1_passport_v2_capabilities(self):
        """Passport with capabilities -> on_tool_start enforces tool allowed."""
        passport, authority, agent = _make_passport_with_caps(TOOL_CAPS)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            private_key=agent["private_key"],
        )
        handler.on_tool_start({"name": "search"}, "query")
        assert handler.is_verified is True
        with pytest.raises(PermissionError, match="tool_not_allowed"):
            handler.on_tool_start({"name": "database_write"}, "data")

    def test_v1_trust_level_v2_tool_access(self):
        """Low trust level -> rejected before capability check."""
        passport, authority, agent = _make_passport_with_caps(TOOL_CAPS, trust_level=1)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            min_trust_level=TRUST_LEVELS["AUDITED"],
        )
        with pytest.raises(PermissionError, match="insufficient_trust"):
            handler.on_tool_start({"name": "search"}, "query")

    def test_v1_expiry_v2_capability_check(self):
        """Expired passport -> rejected at v1.0 layer, capabilities never checked."""
        passport, authority, agent = _make_passport_with_caps(TOOL_CAPS, expired=True)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
        )
        with pytest.raises(PermissionError, match="expired"):
            handler.on_tool_start({"name": "search"}, "query")


# ══ Suite 2: v1.0 + v2.1 ══


class TestV1PlusV21Integration:

    def test_v1_rejection_logged_in_audit_chain(self):
        """Rejected passport -> audit log entry with hash fields."""
        passport, authority, agent = _make_passport()
        other = generate_key_pair()
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=other["public_key"],
        )
        with pytest.raises(PermissionError):
            handler.on_chain_start({"id": ["test"]}, {})
        log = handler.audit_log
        assert len(log) >= 1
        assert log[0]["action"] == "rejected"
        assert "entry_hash" in log[0]
        assert log[0]["previous_entry_hash"] is None

    def test_v1_signature_v2_merkle_root(self):
        """Valid passport -> merkle root computable after actions."""
        passport, authority, agent = _make_passport()
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            private_key=agent["private_key"],
        )
        handler.on_chain_start({"id": ["test"]}, {})
        handler.on_chain_end({"output": "done"})
        root = handler.merkle_root
        assert root is not None
        assert len(root) == 64

    def test_v1_multiple_calls_audit_chain(self):
        """Multiple events -> chained entries in audit log."""
        passport, authority, agent = _make_passport()
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            private_key=agent["private_key"],
        )
        handler.on_chain_start({"id": ["test"]}, {})
        handler.on_tool_start({"name": "search"}, "query")
        handler.on_chain_end({"output": "done"})
        log = handler.audit_log
        assert len(log) >= 3
        for i in range(1, len(log)):
            assert log[i]["previous_entry_hash"] == log[i - 1]["entry_hash"]


# ══ Suite 3: v2.0 + v2.1 ══


class TestV2PlusV21Integration:

    def test_v2_implicit_deny_logged_in_audit(self):
        """Implicit deny -> rejection logged in merkle chain."""
        passport, authority, agent = _make_passport_with_caps(TOOL_CAPS)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
        )
        with pytest.raises(PermissionError, match="tool_not_allowed"):
            handler.on_tool_start({"name": "unknown_tool"}, "data")
        log = handler.audit_log
        assert any(e["action"] == "rejected" for e in log)
        assert handler.verify_audit_chain() is True

    def test_v2_valid_call_merkle_chain(self):
        """Valid capability call -> audit chain verifiable."""
        passport, authority, agent = _make_passport_with_caps(TOOL_CAPS)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            private_key=agent["private_key"],
        )
        handler.on_tool_start({"name": "search"}, "query")
        handler.on_chain_end({"output": "done"})
        assert handler.verify_audit_chain() is True
        assert handler.merkle_root is not None

    def test_v2_forbidden_tool_audit(self):
        """Explicitly forbidden tool -> rejection in audit."""
        passport, authority, agent = _make_passport_with_caps(TOOL_CAPS)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
        )
        with pytest.raises(PermissionError, match="tool_not_allowed"):
            handler.on_tool_start({"name": "database_write"}, "data")
        assert handler.verify_audit_chain() is True


# ══ Suite 4: v2.0 + v2.2 ══


class TestV2PlusV22Integration:

    def test_v2_capability_allowed_time_denied(self):
        """Tool allowed by capabilities but outside time window -> rejected."""
        passport, authority, agent = _make_passport_with_caps(TIME_CAPS)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            current_time_provider=lambda: 5000.0,
        )
        with pytest.raises(PermissionError, match="time_window"):
            handler.on_tool_start({"name": "search"}, "query")

    def test_v2_capability_and_time_valid(self):
        """Tool allowed + inside time window -> passes."""
        passport, authority, agent = _make_passport_with_caps(TIME_CAPS)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            private_key=agent["private_key"],
            current_time_provider=lambda: 1500.0,
        )
        handler.on_tool_start({"name": "search"}, "query")
        assert handler.is_verified is True

    def test_v2_time_window_gate_callback(self):
        """Gate required -> gate callback is called."""
        gate_calls = []

        def mock_gate(tool_name, config):
            gate_calls.append(tool_name)
            return True, "approved"

        passport, authority, agent = _make_passport_with_caps(TIME_CAPS)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            on_permission_gate_triggered=mock_gate,
        )
        handler.on_tool_start({"name": "gated_tool"}, "data")
        assert "gated_tool" in gate_calls


# ══ Suite 5: v2.1 + v2.2 ══


class TestV21PlusV22Integration:

    def test_time_denied_logged_in_audit(self):
        """Time window denied -> rejection in merkle chain."""
        passport, authority, agent = _make_passport_with_caps(TIME_CAPS)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            current_time_provider=lambda: 5000.0,
        )
        with pytest.raises(PermissionError, match="time_window"):
            handler.on_tool_start({"name": "search"}, "query")
        assert handler.verify_audit_chain() is True
        log = handler.audit_log
        assert any("time_window" in e.get("reason", "") for e in log)

    def test_gate_approved_audit(self):
        """Gate approves -> action logged in chain."""
        passport, authority, agent = _make_passport_with_caps(TIME_CAPS)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            private_key=agent["private_key"],
            on_permission_gate_triggered=lambda t, c: (True, "approved"),
        )
        handler.on_tool_start({"name": "gated_tool"}, "data")
        assert handler.verify_audit_chain() is True
        assert handler.merkle_root is not None

    def test_gate_denied_audit(self):
        """Gate denies -> rejection logged in chain."""
        passport, authority, agent = _make_passport_with_caps(TIME_CAPS)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            on_permission_gate_triggered=lambda t, c: (False, "not_approved"),
        )
        with pytest.raises(PermissionError, match="permission_gate"):
            handler.on_tool_start({"name": "gated_tool"}, "data")
        assert handler.verify_audit_chain() is True


# ══ Suite 6: Full Stack (v1.0 + v2.0 + v2.1 + v2.2) ══


class TestFullStackIntegration:

    def test_full_stack_valid_path(self):
        """All layers pass -> action allowed and audited."""
        passport, authority, agent = _make_passport_with_caps(FULL_CAPS)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            private_key=agent["private_key"],
            current_time_provider=lambda: 1500.0,
            on_permission_gate_triggered=lambda t, c: (True, "ok"),
        )
        handler.on_tool_start({"name": "search"}, "query")
        handler.on_tool_start({"name": "gated_tool"}, "data")
        handler.on_tool_start({"name": "always_allowed"}, "data")
        assert handler.is_verified is True
        assert handler.verify_audit_chain() is True
        assert handler.merkle_root is not None

    def test_full_stack_invalid_passport(self):
        """Invalid signature -> rejected at v1.0 layer."""
        other = generate_key_pair()
        passport, authority, agent = _make_passport_with_caps(FULL_CAPS)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=other["public_key"],
        )
        with pytest.raises(PermissionError, match="invalid_signature"):
            handler.on_tool_start({"name": "search"}, "query")

    def test_full_stack_invalid_capability(self):
        """Unlisted tool -> rejected at v2.0 layer."""
        passport, authority, agent = _make_passport_with_caps(FULL_CAPS)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
        )
        with pytest.raises(PermissionError, match="tool_not_allowed"):
            handler.on_tool_start({"name": "not_in_caps"}, "data")

    def test_full_stack_outside_time_window(self):
        """Outside time window -> rejected at v2.2 layer."""
        passport, authority, agent = _make_passport_with_caps(FULL_CAPS)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            current_time_provider=lambda: 9999.0,
        )
        with pytest.raises(PermissionError, match="time_window"):
            handler.on_tool_start({"name": "search"}, "query")

    def test_full_stack_gate_denied(self):
        """Gate denies -> rejected at v2.2 gate layer."""
        passport, authority, agent = _make_passport_with_caps(FULL_CAPS)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            on_permission_gate_triggered=lambda t, c: (False, "denied_by_admin"),
        )
        with pytest.raises(PermissionError, match="permission_gate"):
            handler.on_tool_start({"name": "gated_tool"}, "data")

    def test_full_stack_audit_trail(self):
        """Full execution -> complete, verifiable merkle chain."""
        passport, authority, agent = _make_passport_with_caps(FULL_CAPS)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            private_key=agent["private_key"],
            current_time_provider=lambda: 1500.0,
            on_permission_gate_triggered=lambda t, c: (True, "ok"),
        )
        handler.on_chain_start({"id": ["test"]}, {})
        handler.on_tool_start({"name": "search"}, "query")
        handler.on_tool_start({"name": "always_allowed"}, "data")
        handler.on_tool_start({"name": "gated_tool"}, "data")
        handler.on_chain_end({"output": "done"})

        log = handler.audit_log
        assert len(log) >= 5
        assert handler.verify_audit_chain() is True
        for i in range(1, len(log)):
            assert log[i]["previous_entry_hash"] == log[i - 1]["entry_hash"]
        signed = handler.sign_merkle_root()
        assert signed is not None
