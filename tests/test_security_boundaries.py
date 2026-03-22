"""Security boundary tests for v1.0-v2.2."""

import pytest
from unittest.mock import patch
from mcp_secure import generate_key_pair, create_passport, sign_passport, TRUST_LEVELS
from langchain_mcps import MCPSCallbackHandler
from langchain_mcps.capabilities import CapabilitySchema, CapabilityValidator, CapabilityEnforcer
from langchain_mcps.audit_chain import AuditChain


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


def _make_passport_with_caps(capabilities, trust_level=None):
    authority = generate_key_pair()
    agent = generate_key_pair()
    passport = create_passport(
        name="test-agent",
        version="2.0.0",
        public_key=agent["public_key"],
        ttl_days=365,
    )
    if trust_level is not None:
        passport["trust_level"] = trust_level
    passport["capabilities"] = capabilities
    signed = sign_passport(passport, authority["private_key"])
    return signed, authority, agent


# ══ Zero-Trust Verification ══


class TestZeroTrust:

    def test_implicit_deny_v1_invalid_sig(self):
        """Invalid passport signature -> rejected."""
        passport, authority, agent = _make_passport()
        other = generate_key_pair()
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=other["public_key"],
        )
        with pytest.raises(PermissionError, match="invalid_signature"):
            handler.on_chain_start({"id": ["test"]}, {})

    def test_implicit_deny_v2_unknown_tool(self):
        """v2.0 passport, unknown tool -> rejected."""
        caps = {"search": {"allowed": True, "constraints": {}}}
        passport, authority, agent = _make_passport_with_caps(caps)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
        )
        with pytest.raises(PermissionError, match="tool_not_allowed"):
            handler.on_tool_start({"name": "unknown"}, "data")

    def test_implicit_deny_v2_2_time(self):
        """Outside time window -> rejected."""
        caps = {
            "timed_tool": {
                "allowed": True,
                "constraints": {},
                "permission_windows": [{"start_time": 1000.0, "end_time": 2000.0}],
            }
        }
        passport, authority, agent = _make_passport_with_caps(caps)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            current_time_provider=lambda: 3000.0,
        )
        with pytest.raises(PermissionError, match="time_window"):
            handler.on_tool_start({"name": "timed_tool"}, "data")

    def test_implicit_deny_v2_2_gate_no_callback(self):
        """Gate required but no callback -> rejected."""
        caps = {
            "gated": {
                "allowed": True,
                "constraints": {},
                "permission_gates": [{"gate_type": "manual", "config": {}}],
            }
        }
        passport, authority, agent = _make_passport_with_caps(caps)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
        )
        with pytest.raises(PermissionError, match="permission_gate"):
            handler.on_tool_start({"name": "gated"}, "data")


# ══ Least-Privilege Verification ══


class TestLeastPrivilege:

    def test_tool_escalation_blocked(self):
        """Low trust agent -> rejected with min_trust_level requirement."""
        passport, authority, agent = _make_passport(trust_level=1)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            min_trust_level=TRUST_LEVELS["SCANNED"],
        )
        with pytest.raises(PermissionError, match="insufficient_trust"):
            handler.on_chain_start({"id": ["test"]}, {})

    def test_constraint_escalation_blocked(self):
        """Trying to access forbidden table -> rejected by validator."""
        caps = {
            "database_read": {
                "allowed": True,
                "constraints": {"allowed_tables": ["customers"]},
            }
        }
        schema = CapabilitySchema(caps)
        validator = CapabilityValidator(schema)
        ok, reason = validator.validate_tool_call("database_read", {"table": "secrets"})
        assert ok is False
        assert "secrets" in reason

    def test_rate_limit_enforcement(self):
        """Exceeding rate limit -> rejected."""
        caps = {
            "api_call": {
                "allowed": True,
                "constraints": {"rate_limit": {"value": 2, "window": "hour"}},
            }
        }
        schema = CapabilitySchema(caps)
        enforcer = CapabilityEnforcer(schema)
        base = 1000.0
        for i in range(2):
            ok, _ = enforcer.check_tool_invocation(
                "api_call", {}, "agent-1", current_time=base + i
            )
            assert ok is True
        ok, reason = enforcer.check_tool_invocation(
            "api_call", {}, "agent-1", current_time=base + 2
        )
        assert ok is False
        assert "Rate limit" in reason

    def test_time_window_enforcement(self):
        """Outside time window -> rejected via validator."""
        caps = {
            "timed": {
                "allowed": True,
                "constraints": {},
                "permission_windows": [{"start_time": 100.0, "end_time": 200.0}],
            }
        }
        schema = CapabilitySchema(caps)
        validator = CapabilityValidator(schema)
        ok, reason = validator.validate_time_window("timed", current_time=300.0)
        assert ok is False
        assert "outside" in reason


# ══ Audit Integrity ══


class TestAuditIntegrity:

    def test_merkle_chain_tamper_detection(self):
        """Tampering with entry -> chain verification fails."""
        chain = AuditChain()
        chain.append(
            {"timestamp": 1.0, "event": "e1", "passport_id": "a", "action": "signed"}
        )
        chain.append(
            {"timestamp": 2.0, "event": "e2", "passport_id": "a", "action": "signed"}
        )
        chain.append(
            {"timestamp": 3.0, "event": "e3", "passport_id": "a", "action": "signed"}
        )
        assert chain.verify_chain() is True
        chain._entries[1].action = "HACKED"
        assert chain.verify_chain() is False

    def test_root_signature_verification(self):
        """Sign merkle root -> produces valid envelope."""
        passport, authority, agent = _make_passport()
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            private_key=agent["private_key"],
        )
        handler.on_chain_start({"id": ["test"]}, {})
        handler.on_chain_end({"output": "done"})
        signed = handler.sign_merkle_root()
        assert signed is not None
        assert "mcps" in signed

    def test_revocation_in_audit(self):
        """Revoked agent -> rejection visible in audit chain."""
        passport, authority, agent = _make_passport()
        with patch("langchain_mcps.callback.check_revocation") as mock_rev:
            mock_rev.return_value = {"revoked": True, "reason": "compromised"}
            handler = MCPSCallbackHandler(
                passport=passport,
                authority_public_key=authority["public_key"],
                verify_revocation=True,
            )
            with pytest.raises(PermissionError, match="revoked"):
                handler.on_chain_start({"id": ["test"]}, {})
        log = handler.audit_log
        assert any(e.get("reason") == "revoked" for e in log)
        assert handler.verify_audit_chain() is True
