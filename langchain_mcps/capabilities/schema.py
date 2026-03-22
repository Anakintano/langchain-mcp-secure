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
