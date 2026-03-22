"""Rate-limit enforcement and full capability checking for v2.0 passports."""

from __future__ import annotations
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from .schema import CapabilitySchema, RateLimitWindow
from .validator import CapabilityValidator

_WINDOW_SECONDS: Dict[str, float] = {
    RateLimitWindow.SECOND: 1.0,
    RateLimitWindow.MINUTE: 60.0,
    RateLimitWindow.HOUR: 3600.0,
    RateLimitWindow.DAY: 86400.0,
}


class CapabilityEnforcer:
    """
    Full enforcement layer: constraint validation + rate limiting.

    Maintains an in-memory call log per (agent_id, tool_name).
    For distributed systems, replace with Redis-backed storage (v2.5).
    """

    def __init__(self, schema: CapabilitySchema) -> None:
        """
        Args:
            schema: The CapabilitySchema to enforce.
        """
        self._schema = schema
        self._validator = CapabilityValidator(schema)
        # call_log[(agent_id, tool_name)] = list of timestamps
        self._call_log: Dict[Tuple[str, str], List[float]] = defaultdict(list)

    def check_tool_invocation(
        self,
        tool_name: str,
        tool_params: Dict[str, Any],
        agent_id: str,
        current_time: Optional[float] = None,
    ) -> Tuple[bool, str]:
        """
        Full capability check: constraints + rate limiting.

        Args:
            tool_name: Name of the tool being invoked.
            tool_params: Parameters passed to the tool.
            agent_id: Identifier of the calling agent (from passport).
            current_time: Override current time (for testing). Defaults to time.time().

        Returns:
            Tuple of (is_allowed, reason). reason is empty string on success.
        """
        now = current_time if current_time is not None else time.time()

        # 1. Validate constraints
        valid, reason = self._validator.validate_tool_call(tool_name, tool_params)
        if not valid:
            return False, reason

        # 2. Check rate limit
        rate_limit = self._schema.get_rate_limit(tool_name)
        if rate_limit:
            allowed, reason = self._check_rate_limit(tool_name, agent_id, rate_limit, now)
            if not allowed:
                return False, reason

        # 3. Log the successful call
        if rate_limit:
            self._call_log[(agent_id, tool_name)].append(now)

        return True, ""

    def _check_rate_limit(
        self,
        tool_name: str,
        agent_id: str,
        rate_limit: Dict[str, Any],
        now: float,
    ) -> Tuple[bool, str]:
        """Check and enforce rate limit for a tool call."""
        limit_value: int = rate_limit["value"]
        window_str: str = rate_limit["window"]
        window_seconds = _WINDOW_SECONDS.get(window_str, 3600.0)

        key = (agent_id, tool_name)
        # Prune old timestamps outside the window
        cutoff = now - window_seconds
        self._call_log[key] = [t for t in self._call_log[key] if t > cutoff]

        if len(self._call_log[key]) >= limit_value:
            return False, (
                f"Rate limit exceeded for tool '{tool_name}': "
                f"{limit_value} calls per {window_str} allowed"
            )
        return True, ""
