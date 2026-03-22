"""Capability schema definitions for v2.0 passport capability scoping."""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class RateLimitWindow(str, Enum):
    """Time windows for rate limiting."""
    SECOND = "second"
    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"


@dataclass
class Constraint:
    """A single capability constraint."""
    constraint_type: str
    value: Any


class CapabilitySchema:
    """
    Parses and exposes the capabilities dict from a passport.

    Supports implicit deny: any tool not listed is forbidden.
    v1.0 passports (no capabilities key) bypass capability checks.
    """

    def __init__(self, capabilities: Optional[Dict[str, Any]]) -> None:
        """
        Args:
            capabilities: The capabilities dict from the passport, or None for v1.0 passports.
        """
        self._capabilities: Optional[Dict[str, Any]] = capabilities

    @property
    def is_v2(self) -> bool:
        """True if this passport has a capabilities dict (v2.0)."""
        return self._capabilities is not None

    def is_tool_allowed(self, tool_name: str) -> bool:
        """
        Check if a tool is allowed by this passport.

        v1.0 passports (no capabilities) allow all tools.
        v2.0 passports implicitly deny tools not listed.

        Args:
            tool_name: Name of the tool to check.

        Returns:
            True if the tool is allowed, False otherwise.
        """
        if not self.is_v2:
            return True
        assert self._capabilities is not None
        tool_config = self._capabilities.get(tool_name)
        if tool_config is None:
            return False
        return bool(tool_config.get("allowed", False))

    def get_constraints(self, tool_name: str) -> Dict[str, Any]:
        """
        Get the constraints dict for a tool.

        Args:
            tool_name: Name of the tool.

        Returns:
            Constraints dict, or empty dict if none.
        """
        if not self.is_v2:
            return {}
        assert self._capabilities is not None
        tool_config = self._capabilities.get(tool_name, {})
        return tool_config.get("constraints", {})

    def get_rate_limit(self, tool_name: str) -> Optional[Dict[str, Any]]:
        """
        Get the rate limit config for a tool.

        Args:
            tool_name: Name of the tool.

        Returns:
            Rate limit dict with 'value' and 'window', or None.
        """
        constraints = self.get_constraints(tool_name)
        return constraints.get("rate_limit")

    def get_permission_windows(self, tool_name: str) -> Optional[List[Dict[str, Any]]]:
        """
        Get the time-window-based permission list for a tool (v2.2).

        Each window specifies a [start_time, end_time) interval during which
        the tool is allowed. If multiple windows exist, agent is allowed if
        in ANY window (OR logic).

        Args:
            tool_name: Name of the tool.

        Returns:
            List of dicts with {start_time: float, end_time: float, trust_level_required: Optional[int]},
            or None if no windows configured (always allowed, backward compat).
        """
        if not self.is_v2:
            return None
        assert self._capabilities is not None
        tool_config = self._capabilities.get(tool_name, {})
        return tool_config.get("permission_windows")

    def get_permission_gates(self, tool_name: str) -> Optional[List[Dict[str, Any]]]:
        """
        Get the event-gated permission list for a tool (v2.2).

        Each gate specifies an external decision point (e.g., manual approval,
        webhook validation). Agent must pass gate callback to invoke tool.

        Args:
            tool_name: Name of the tool.

        Returns:
            List of dicts with {gate_type: str, config: Dict},
            or None if no gates configured.
        """
        if not self.is_v2:
            return None
        assert self._capabilities is not None
        tool_config = self._capabilities.get(tool_name, {})
        return tool_config.get("permission_gates")
