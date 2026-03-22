"""Edge case and stress tests for v1.0-v2.2."""

import pytest
from mcp_secure import generate_key_pair, create_passport, sign_passport
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


# ══ Boundary Conditions ══


class TestBoundaryConditions:

    def test_expiry_exact_boundary(self):
        """Expired passport (ttl_days=-1) -> rejected."""
        passport, authority, agent = _make_passport(expired=True)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
        )
        with pytest.raises(PermissionError, match="expired"):
            handler.on_chain_start({"id": ["test"]}, {})

    def test_time_window_start_boundary(self):
        """now == start_time -> allowed (inclusive)."""
        caps = {
            "tool": {
                "allowed": True,
                "constraints": {},
                "permission_windows": [{"start_time": 1000.0, "end_time": 2000.0}],
            }
        }
        schema = CapabilitySchema(caps)
        validator = CapabilityValidator(schema)
        ok, _ = validator.validate_time_window("tool", current_time=1000.0)
        assert ok is True

    def test_time_window_end_boundary(self):
        """now == end_time -> rejected (exclusive)."""
        caps = {
            "tool": {
                "allowed": True,
                "constraints": {},
                "permission_windows": [{"start_time": 1000.0, "end_time": 2000.0}],
            }
        }
        schema = CapabilitySchema(caps)
        validator = CapabilityValidator(schema)
        ok, _ = validator.validate_time_window("tool", current_time=2000.0)
        assert ok is False

    def test_rate_limit_exact_boundary(self):
        """3 calls allowed, 3rd ok, 4th rejected."""
        caps = {
            "api": {
                "allowed": True,
                "constraints": {"rate_limit": {"value": 3, "window": "hour"}},
            }
        }
        schema = CapabilitySchema(caps)
        enforcer = CapabilityEnforcer(schema)
        base = 1000.0
        for i in range(3):
            ok, _ = enforcer.check_tool_invocation(
                "api", {}, "agent-1", current_time=base + i
            )
            assert ok is True, f"Call {i + 1} should pass"
        ok, reason = enforcer.check_tool_invocation(
            "api", {}, "agent-1", current_time=base + 3
        )
        assert ok is False
        assert "Rate limit" in reason

    def test_zero_rate_limit(self):
        """rate_limit = 0 -> no calls allowed."""
        caps = {
            "restricted": {
                "allowed": True,
                "constraints": {"rate_limit": {"value": 0, "window": "hour"}},
            }
        }
        schema = CapabilitySchema(caps)
        enforcer = CapabilityEnforcer(schema)
        ok, reason = enforcer.check_tool_invocation(
            "restricted", {}, "agent-1", current_time=1000.0
        )
        assert ok is False
        assert "Rate limit" in reason


# ══ Stress Tests ══


class TestStress:

    def test_1000_audit_entries(self):
        """1000 entries -> merkle root computable + chain verifiable."""
        chain = AuditChain()
        for i in range(1000):
            chain.append(
                {
                    "timestamp": float(i),
                    "event": f"event_{i}",
                    "passport_id": "agent-stress",
                    "action": "signed",
                }
            )
        assert len(chain) == 1000
        root = chain.get_merkle_root()
        assert root is not None
        assert len(root) == 64
        assert chain.verify_chain() is True

    def test_100_sequential_rate_checks(self):
        """100 calls with rate limit 50/hour -> first 50 pass, rest fail."""
        caps = {
            "api": {
                "allowed": True,
                "constraints": {"rate_limit": {"value": 50, "window": "hour"}},
            }
        }
        schema = CapabilitySchema(caps)
        enforcer = CapabilityEnforcer(schema)
        base = 1000.0
        passed = 0
        failed = 0
        for i in range(100):
            ok, _ = enforcer.check_tool_invocation(
                "api", {}, "agent-1", current_time=base + i
            )
            if ok:
                passed += 1
            else:
                failed += 1
        assert passed == 50
        assert failed == 50

    def test_large_payload(self):
        """Large tool_params -> still validated correctly."""
        caps = {
            "big_tool": {
                "allowed": True,
                "constraints": {"allowed_tables": ["users"]},
            }
        }
        schema = CapabilitySchema(caps)
        validator = CapabilityValidator(schema)
        big_params = {"table": "users", "data": "x" * 100000}
        ok, _ = validator.validate_tool_call("big_tool", big_params)
        assert ok is True

    def test_many_overlapping_windows(self):
        """50 time windows -> OR logic finds match."""
        windows = [
            {"start_time": float(i * 100), "end_time": float(i * 100 + 50)}
            for i in range(50)
        ]
        caps = {
            "multi_window": {
                "allowed": True,
                "constraints": {},
                "permission_windows": windows,
            }
        }
        schema = CapabilitySchema(caps)
        validator = CapabilityValidator(schema)
        # Time 2525 is inside window [2500, 2550)
        ok, _ = validator.validate_time_window("multi_window", current_time=2525.0)
        assert ok is True
        # Time 75 is outside all windows ([0,50), [100,150), ...)
        ok, reason = validator.validate_time_window("multi_window", current_time=75.0)
        assert ok is False


# ══ Backward Compatibility ══


class TestBackwardCompat:

    def test_v1_passport_no_v2_fields(self):
        """v1.0 passport through callback -> tool_start works without capabilities."""
        passport, authority, agent = _make_passport()
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
        )
        handler.on_tool_start({"name": "any_tool"}, "query")
        assert handler.is_verified is True

    def test_mixed_entries_audit(self):
        """Mix of different event types -> chain verifies."""
        chain = AuditChain()
        chain.append(
            {
                "timestamp": 1.0,
                "event": "chain_start",
                "passport_id": "a",
                "action": "signed",
            }
        )
        chain.append(
            {
                "timestamp": 2.0,
                "event": "tool_start",
                "passport_id": "a",
                "action": "signed",
            }
        )
        chain.append(
            {
                "timestamp": 3.0,
                "event": "chain_end",
                "passport_id": "a",
                "action": "completed",
            }
        )
        chain.append(
            {
                "timestamp": 4.0,
                "event": "rejected",
                "passport_id": "b",
                "action": "rejected",
                "reason": "expired",
            }
        )
        assert chain.verify_chain() is True
        assert len(chain) == 4

    def test_optional_callback_missing(self):
        """No callback hooks -> no errors."""
        passport, authority, agent = _make_passport()
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
        )
        handler.on_chain_start({"id": ["test"]}, {})
        handler.on_chain_end({"output": "done"})
        assert handler.is_verified is True
