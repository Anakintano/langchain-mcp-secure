"""Tests for v2.0 capability-scoped passports."""

import pytest
from langchain_mcps.capabilities import (
    CapabilityEnforcer,
    CapabilitySchema,
    CapabilityValidator,
)


SAMPLE_CAPABILITIES = {
    "database_read": {
        "allowed": True,
        "constraints": {
            "allowed_tables": ["customers", "orders"],
            "max_rows_per_query": 1000,
            "rate_limit": {"value": 3, "window": "hour"},
        },
    },
    "database_write": {"allowed": False},
    "file_read": {
        "allowed": True,
        "constraints": {
            "allowed_paths": ["/data/*", "/reports/*"],
            "max_file_size_mb": 10,
        },
    },
    "send_email": {
        "allowed": True,
        "constraints": {
            "recipient_domains": ["example.com", "trusted.org"],
        },
    },
}


def make_schema(caps=SAMPLE_CAPABILITIES):
    return CapabilitySchema(caps)


def test_implicit_deny():
    """Tool not in capabilities → not allowed."""
    schema = make_schema()
    assert schema.is_tool_allowed("file_delete") is False
    enforcer = CapabilityEnforcer(schema)
    allowed, reason = enforcer.check_tool_invocation("file_delete", {}, "agent-1")
    assert allowed is False
    assert "file_delete" in reason


def test_constraint_validation_tables():
    """Valid table passes; invalid table fails."""
    schema = make_schema()
    validator = CapabilityValidator(schema)

    ok, reason = validator.validate_tool_call("database_read", {"table": "customers"})
    assert ok is True
    assert reason == ""

    ok, reason = validator.validate_tool_call("database_read", {"table": "secrets"})
    assert ok is False
    assert "secrets" in reason


def test_constraint_validation_domains():
    """Valid recipient domain passes; unknown domain fails."""
    schema = make_schema()
    validator = CapabilityValidator(schema)

    ok, reason = validator.validate_tool_call("send_email", {"recipient": "user@example.com"})
    assert ok is True

    ok, reason = validator.validate_tool_call("send_email", {"recipient": "user@evil.com"})
    assert ok is False
    assert "evil.com" in reason


def test_constraint_validation_paths():
    """Path matching glob passes; non-matching path fails."""
    schema = make_schema()
    validator = CapabilityValidator(schema)

    ok, reason = validator.validate_tool_call("file_read", {"path": "/data/report.csv"})
    assert ok is True

    ok, reason = validator.validate_tool_call("file_read", {"path": "/etc/passwd"})
    assert ok is False
    assert "/etc/passwd" in reason


def test_rate_limiting():
    """3 calls allowed, 4th call rejected with rate_limit=3/hour."""
    schema = make_schema()
    enforcer = CapabilityEnforcer(schema)
    params = {"table": "customers"}
    base_time = 1000.0

    for i in range(3):
        allowed, reason = enforcer.check_tool_invocation(
            "database_read", params, "agent-1", current_time=base_time + i
        )
        assert allowed is True, f"Call {i+1} should be allowed"

    allowed, reason = enforcer.check_tool_invocation(
        "database_read", params, "agent-1", current_time=base_time + 3
    )
    assert allowed is False
    assert "Rate limit exceeded" in reason


def test_backward_compat_no_capabilities():
    """v1.0 passport (None capabilities) allows all tools without crash."""
    schema = CapabilitySchema(None)
    assert schema.is_v2 is False
    assert schema.is_tool_allowed("any_tool") is True
    assert schema.get_constraints("any_tool") == {}
    assert schema.get_rate_limit("any_tool") is None

    enforcer = CapabilityEnforcer(schema)
    allowed, reason = enforcer.check_tool_invocation("any_tool", {}, "agent-1")
    assert allowed is True
    assert reason == ""
