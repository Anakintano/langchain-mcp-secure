"""
Shared quota pool for delegation trees — langchain-mcps v2.3.

All delegates of a single parent agent share one rate-limit pool keyed by
(parent_agent_id, tool_name). This prevents any single delegate from
exhausting the parent's full budget while others go empty-handed.
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

_WINDOW_SECONDS: Dict[str, float] = {
    "second": 1.0,
    "minute": 60.0,
    "hour": 3600.0,
    "day": 86400.0,
}


class QuotaPool:
    """
    Shared, sliding-window rate-limit pool for delegation trees.

    Pool key: (parent_agent_id, tool_name)
    Internally stores a list of call timestamps per key and prunes entries
    outside the current window on each check.

    Usage::

        pool = QuotaPool()
        allowed, reason, remaining = pool.check_and_decrement(
            parent_agent_id="agent-123",
            tool_name="database_read",
            limit=100,
            window="hour",
        )
    """

    def __init__(self) -> None:
        # (parent_agent_id, tool_name) -> sorted list of call timestamps
        self._call_log: Dict[Tuple[str, str], List[float]] = defaultdict(list)

    def check_and_decrement(
        self,
        parent_agent_id: str,
        tool_name: str,
        limit: int,
        window: str,
        current_time: Optional[float] = None,
    ) -> Tuple[bool, str, int]:
        """
        Check quota and record this call if allowed.

        Args:
            parent_agent_id: The delegator's passport_id (shared pool key).
            tool_name: Name of the tool being invoked.
            limit: Maximum calls allowed per window.
            window: Window name: "second", "minute", "hour", or "day".
            current_time: Override current time (for testing).

        Returns:
            (allowed, reason, remaining_quota)
        """
        now = current_time if current_time is not None else time.time()
        window_seconds = _WINDOW_SECONDS.get(window, 3600.0)
        key = (parent_agent_id, tool_name)

        # Prune timestamps outside the sliding window
        cutoff = now - window_seconds
        self._call_log[key] = [t for t in self._call_log[key] if t > cutoff]

        current_count = len(self._call_log[key])
        if current_count >= limit:
            return (
                False,
                f"Quota exhausted for '{tool_name}': {limit} calls/{window} (shared pool)",
                0,
            )

        self._call_log[key].append(now)
        remaining = limit - current_count - 1
        return True, "quota_ok", remaining

    def get_remaining(
        self,
        parent_agent_id: str,
        tool_name: str,
        limit: int,
        window: str,
        current_time: Optional[float] = None,
    ) -> int:
        """Return remaining quota without decrementing."""
        now = current_time if current_time is not None else time.time()
        window_seconds = _WINDOW_SECONDS.get(window, 3600.0)
        key = (parent_agent_id, tool_name)
        cutoff = now - window_seconds
        current_count = sum(1 for t in self._call_log.get(key, []) if t > cutoff)
        return max(0, limit - current_count)
