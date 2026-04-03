"""
Distributed quota backend abstraction for langchain-mcps v2.4.

Provides:
  - QuotaBackend (ABC): interface for atomic increment-and-check operations.
  - InMemoryQuotaBackend: thread-safe in-process backend (default / testing).
  - QuotaExhausted: exception raised when a pool limit is hit.

The parent-pool pattern:
  When agent B is a delegatee of agent A, all of B's quota is charged against
  A's pool (identified by parent_agent_id=A).  This prevents any individual
  delegatee from monopolising the root agent's budget while peers go empty.

arXiv reference: §5.2.3 (Resource Monopolization and Computational DoS)
"""

from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import Dict, List, Optional, Tuple


# ── Exception ─────────────────────────────────────────────────────────────────


class QuotaExhausted(Exception):
    """Raised when a quota limit is exceeded."""

    def __init__(self, message: str, agent_id: str, is_root_agent: bool) -> None:
        super().__init__(message)
        self.agent_id = agent_id
        self.is_root_agent = is_root_agent


# ── Abstract interface ────────────────────────────────────────────────────────


class AbstractQuotaBackend(ABC):
    """
    Abstract base class for quota backends supporting distributed or in-process rate limiting.

    Implementations (InMemoryQuotaBackend, RedisQuotaBackend, etc.) must define
    atomic increment-and-check operations, remaining quota queries, and reset logic.

    The quota pool is keyed on (pool_owner, tool_name) where pool_owner is
    parent_agent_id if delegation is active, otherwise agent_id.

    Future Redis backend (planned for v2.4) inherits from this interface:
    - pool_key → Redis INCR + sliding window TTL
    - Atomic CAS operations prevent race conditions
    - Distributed state shared across replicas
    """

    @abstractmethod
    def increment_and_check(
        self,
        agent_id: str,
        tool_name: str,
        window: str,
        limit: int,
        parent_agent_id: Optional[str] = None,
    ) -> Tuple[int, int]:
        """
        Atomically record one call and verify it does not exceed the limit.

        The quota pool is keyed on (parent_agent_id or agent_id, tool_name).
        When parent_agent_id is provided the call is charged against the
        parent's shared pool, enforcing collective budget constraints.

        Args:
            agent_id: The agent making the call.
            tool_name: Name of the tool being invoked.
            window: Time window — "second", "minute", "hour", or "day".
            limit: Maximum calls allowed per window.
            parent_agent_id: Root delegator whose pool should be charged.

        Returns:
            (current_count, limit) after the increment.

        Raises:
            QuotaExhausted: If the limit would be exceeded.
        """
        ...

    @abstractmethod
    def get_remaining(
        self,
        agent_id: str,
        tool_name: str,
        window: str,
        limit: int,
        parent_agent_id: Optional[str] = None,
    ) -> int:
        """Return remaining quota without consuming a slot."""
        ...

    @abstractmethod
    def reset(
        self,
        agent_id: str,
        tool_name: str,
        parent_agent_id: Optional[str] = None,
    ) -> None:
        """Reset all counters for this pool (useful in tests)."""
        ...


# Backward compatibility alias
QuotaBackend = AbstractQuotaBackend


# ── In-memory implementation ──────────────────────────────────────────────────

_WINDOW_SECONDS: Dict[str, float] = {
    "second": 1.0,
    "minute": 60.0,
    "hour": 3600.0,
    "day": 86400.0,
}


class InMemoryQuotaBackend(AbstractQuotaBackend):
    """
    Thread-safe sliding-window quota backend using in-process storage.

    Reference implementation of AbstractQuotaBackend for single-process deployments.
    Suitable for development, testing, and single-instance production use.

    Pool key: (pool_owner, tool_name)  where pool_owner = parent_agent_id or agent_id.
    Timestamps are stored per key and pruned on each check.

    For distributed deployments (multi-process, multi-replica), use a Redis-backed
    implementation (planned for v2.4) that inherits from AbstractQuotaBackend.
    """

    def __init__(self) -> None:
        # (pool_owner, tool_name) -> sorted list of call timestamps
        self._call_log: Dict[Tuple[str, str], List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def _pool_key(self, agent_id: str, tool_name: str, parent_agent_id: Optional[str]) -> Tuple[str, str]:
        pool_owner = parent_agent_id if parent_agent_id is not None else agent_id
        return (pool_owner, tool_name)

    def increment_and_check(
        self,
        agent_id: str,
        tool_name: str,
        window: str,
        limit: int,
        parent_agent_id: Optional[str] = None,
    ) -> Tuple[int, int]:
        key = self._pool_key(agent_id, tool_name, parent_agent_id)
        window_seconds = _WINDOW_SECONDS.get(window, 3600.0)
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            # Prune expired timestamps
            self._call_log[key] = [t for t in self._call_log[key] if t > cutoff]
            current = len(self._call_log[key])

            if current >= limit:
                raise QuotaExhausted(
                    f"Quota exhausted for '{tool_name}': {current}/{limit} calls/{window} "
                    f"(pool owner: {key[0]})",
                    agent_id=agent_id,
                    is_root_agent=(parent_agent_id is None),
                )

            self._call_log[key].append(now)
            return current + 1, limit

    def get_remaining(
        self,
        agent_id: str,
        tool_name: str,
        window: str,
        limit: int,
        parent_agent_id: Optional[str] = None,
    ) -> int:
        key = self._pool_key(agent_id, tool_name, parent_agent_id)
        window_seconds = _WINDOW_SECONDS.get(window, 3600.0)
        now = time.time()
        cutoff = now - window_seconds

        with self._lock:
            current = sum(1 for t in self._call_log.get(key, []) if t > cutoff)
            return max(0, limit - current)

    def reset(
        self,
        agent_id: str,
        tool_name: str,
        parent_agent_id: Optional[str] = None,
    ) -> None:
        key = self._pool_key(agent_id, tool_name, parent_agent_id)
        with self._lock:
            self._call_log[key] = []
