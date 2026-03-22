"""Tests for v2.2 time-bound ephemeral permissions."""

import pytest
from unittest.mock import patch
from langchain_mcps.capabilities import CapabilitySchema, CapabilityValidator


# ── Test Fixtures ──

def make_time_window(start, end):
    return {"start_time": start, "end_time": end}


def make_capabilities_with_windows(tool_name="database_read", windows=None):
    if windows is None:
        windows = [make_time_window(1000.0, 2000.0)]
    return {
        tool_name: {
            "allowed": True,
            "constraints": {},
            "permission_windows": windows,
        }
    }


def make_capabilities_with_gates(tool_name="escalated_delete"):
    return {
        tool_name: {
            "allowed": True,
            "constraints": {},
            "permission_gates": [
                {"gate_type": "manual_approval", "config": {"approval_required": True}}
            ],
        }
    }


# ── Tests ──

def test_time_window_allowed():
    """Agent calls within window → allowed."""
    caps = make_capabilities_with_windows()
    schema = CapabilitySchema(caps)
    validator = CapabilityValidator(schema)

    # Current time 1500 is between 1000 and 2000
    is_valid, reason = validator.validate_time_window("database_read", current_time=1500.0)
    assert is_valid is True
    assert reason == ""


def test_time_window_denied():
    """Agent calls outside window → denied."""
    caps = make_capabilities_with_windows()
    schema = CapabilitySchema(caps)
    validator = CapabilityValidator(schema)

    # Current time 3000 is outside [1000, 2000)
    is_valid, reason = validator.validate_time_window("database_read", current_time=3000.0)
    assert is_valid is False
    assert "outside all permission windows" in reason


def test_boundary_inclusive_start():
    """now == window.start_time → allowed (inclusive start)."""
    caps = make_capabilities_with_windows()
    schema = CapabilitySchema(caps)
    validator = CapabilityValidator(schema)

    # Exactly at start time
    is_valid, reason = validator.validate_time_window("database_read", current_time=1000.0)
    assert is_valid is True


def test_boundary_exclusive_end():
    """now == window.end_time → denied (exclusive end)."""
    caps = make_capabilities_with_windows()
    schema = CapabilitySchema(caps)
    validator = CapabilityValidator(schema)

    # Exactly at end time (exclusive boundary)
    is_valid, reason = validator.validate_time_window("database_read", current_time=2000.0)
    assert is_valid is False


def test_overlapping_windows_one_match():
    """Multiple windows, agent in one → allowed (OR logic)."""
    windows = [
        make_time_window(1000.0, 1500.0),  # Current time NOT in this
        make_time_window(2000.0, 3000.0),  # Current time NOT in this
        make_time_window(2500.0, 3500.0),  # Current time 2800 IS in this
    ]
    caps = make_capabilities_with_windows(windows=windows)
    schema = CapabilitySchema(caps)
    validator = CapabilityValidator(schema)

    is_valid, reason = validator.validate_time_window("database_read", current_time=2800.0)
    assert is_valid is True


def test_backward_compat_no_windows():
    """Tool has no permission_windows → always allowed (v1.0/v2.0 compat)."""
    caps = {
        "database_read": {
            "allowed": True,
            "constraints": {},
            # No permission_windows field
        }
    }
    schema = CapabilitySchema(caps)
    validator = CapabilityValidator(schema)

    is_valid, reason = validator.validate_time_window("database_read", current_time=999999.0)
    assert is_valid is True
    assert reason == ""


def test_permission_gate_callback():
    """Permission gate callback is called and result respected."""
    caps = make_capabilities_with_gates()
    schema = CapabilitySchema(caps)
    validator = CapabilityValidator(schema)

    gate_config = caps["escalated_delete"]["permission_gates"][0]

    # Mock callback that returns allowed
    def mock_gate_approved(tool_name, gate_config):
        return True, "approved"

    is_valid, reason = validator.validate_permission_gate(
        "escalated_delete", gate_config, mock_gate_approved
    )
    assert is_valid is True
    assert reason == "approved"


def test_permission_gate_callback_denied():
    """Permission gate callback denies access."""
    caps = make_capabilities_with_gates()
    schema = CapabilitySchema(caps)
    validator = CapabilityValidator(schema)

    gate_config = caps["escalated_delete"]["permission_gates"][0]

    # Mock callback that denies
    def mock_gate_denied(tool_name, gate_config):
        return False, "awaiting_manual_approval"

    is_valid, reason = validator.validate_permission_gate(
        "escalated_delete", gate_config, mock_gate_denied
    )
    assert is_valid is False
    assert "awaiting_manual_approval" in reason


def test_permission_gate_no_callback():
    """Permission gate without callback → denied."""
    caps = make_capabilities_with_gates()
    schema = CapabilitySchema(caps)
    validator = CapabilityValidator(schema)

    gate_config = caps["escalated_delete"]["permission_gates"][0]

    is_valid, reason = validator.validate_permission_gate(
        "escalated_delete", gate_config, None
    )
    assert is_valid is False
    assert "requires callback" in reason
