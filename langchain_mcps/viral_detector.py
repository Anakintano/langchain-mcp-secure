"""
Viral infection detection for langchain-mcps v2.4.

Detects self-replicating delegation token propagation (Morris-II style worms)
by tracking JTI usage across the agent network.

Two signals are monitored:
  1. Widespread usage  — a single JTI is presented by more than `max_unique_agents`
     distinct agents, suggesting token replay or viral re-issuance.
  2. JTI reuse        — the same JTI is registered for more than one agent ID,
     indicating either a replay attack or a viral token copy.

arXiv reference: §5.2.2 (Viral Infection — Self-Replication via Generative Worms)
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Set, Tuple


# ── Abstract JTI Store interface ──────────────────────────────────────────────


class AbstractJTIStore(ABC):
    """
    Abstract base class for JTI (JWT ID) tracking and deduplication.

    Implementations (InMemoryViralDetector, RedisJTIStore, etc.) track JTI usage
    across the agent network to detect replay attacks and viral token propagation.

    The seen-set must be globally consistent in distributed deployments.
    For single-process use, in-memory tracking suffices; for multi-process or
    multi-replica deployments, a Redis-backed store (planned for v2.4) provides
    atomic operations and shared state:

    - register() → Redis SET (jti, agent_id, timestamp)
    - has_seen() → Redis HEXISTS to check if JTI exists
    - get_seen_count() → Redis SMEMBERS to count unique agents per JTI

    This enables push-based revocation via Redis pub/sub and sliding-window cleanup
    with TTL-based key expiration.
    """

    @abstractmethod
    def register(self, jti: str, agent_id: str) -> None:
        """
        Record that agent_id presented or was issued a token with jti.

        Args:
            jti: The JWT ID to register.
            agent_id: The agent associated with this JTI.
        """
        ...

    @abstractmethod
    def has_seen(self, jti: str) -> bool:
        """
        Check if this JTI has been seen before.

        Args:
            jti: The JWT ID to check.

        Returns:
            True if the JTI has been registered, False otherwise.
        """
        ...

    @abstractmethod
    def get_seen_count(self, jti: str) -> int:
        """
        Return the number of times this JTI has been registered (or unique agents).

        Args:
            jti: The JWT ID to query.

        Returns:
            Count of registrations or unique agents for this JTI.
        """
        ...


class ViralDetector(AbstractJTIStore):
    """
    In-memory JTI chain tracker that detects unusual propagation patterns.

    Reference implementation of AbstractJTIStore for single-process deployments.
    Suitable for development, testing, and single-instance production use.

    For distributed deployments (multi-process, multi-replica), use a Redis-backed
    implementation (planned for v2.4) that inherits from AbstractJTIStore.

    Usage::

        detector = ViralDetector(max_nodes=1000)
        detector.register_token_issuance("jti-xyz", "agent-a")

        signal = detector.check_viral_propagation("jti-xyz")
        if signal:
            infection_ratio, infected_agents = signal

        if detector.detect_jti_reuse_anomaly("jti-xyz", "agent-b"):
            raise ValueError("Possible token replay or viral spread")
    """

    # A JTI used by more than this many unique agents is considered viral
    WIDESPREAD_THRESHOLD: int = 10

    def __init__(self, max_nodes: int = 1000) -> None:
        self.max_nodes = max_nodes
        # jti -> list of (agent_id, timestamp)
        self._usage_log: Dict[str, List[Tuple[str, float]]] = {}
        # All JTIs that have ever been registered
        self._all_jtis: Set[str] = set()

    # ── Registration ──────────────────────────────────────────────────────────

    def register(self, jti: str, agent_id: str) -> None:
        """
        Record that *agent_id* presented or was issued a token with *jti*.

        Implements AbstractJTIStore.register().
        """
        self._all_jtis.add(jti)
        if jti not in self._usage_log:
            self._usage_log[jti] = []
        self._usage_log[jti].append((agent_id, time.time()))

    def register_token_issuance(self, jti: str, agent_id: str) -> None:
        """
        Deprecated: use register() instead.

        Kept for backward compatibility.
        """
        self.register(jti, agent_id)

    # ── Detection ─────────────────────────────────────────────────────────────

    def check_viral_propagation(
        self, jti: str
    ) -> Optional[Tuple[float, List[str]]]:
        """
        Check whether a JTI has been used by an unusually large number of agents.

        Args:
            jti: The JWT ID to inspect.

        Returns:
            (infection_ratio, unique_agent_ids) if the threshold is exceeded,
            None otherwise.
        """
        if jti not in self._usage_log:
            return None

        unique_agents = list({agent for agent, _ in self._usage_log[jti]})
        if len(unique_agents) > self.WIDESPREAD_THRESHOLD:
            infection_ratio = len(unique_agents) / self.max_nodes
            return infection_ratio, unique_agents

        return None

    def has_seen(self, jti: str) -> bool:
        """
        Check if this JTI has been seen before.

        Implements AbstractJTIStore.has_seen().

        Args:
            jti: The JWT ID to check.

        Returns:
            True if the JTI has been registered, False otherwise.
        """
        return jti in self._usage_log

    def get_seen_count(self, jti: str) -> int:
        """
        Return the number of unique agents that have presented this JTI.

        Implements AbstractJTIStore.get_seen_count().

        Args:
            jti: The JWT ID to query.

        Returns:
            Count of unique agents for this JTI.
        """
        if jti not in self._usage_log:
            return 0
        return len(set(agent for agent, _ in self._usage_log[jti]))

    def detect_jti_reuse_anomaly(self, jti: str, current_agent: str) -> bool:
        """
        Detect whether *jti* has been used by any agent other than *current_agent*.

        In normal operation a JTI is issued to exactly one delegatee; if it
        appears under a different agent ID this indicates replay or viral copying.

        Args:
            jti: The JWT ID to check.
            current_agent: The agent ID presenting the token now.

        Returns:
            True if the JTI has been seen under a different agent ID.
        """
        if jti not in self._usage_log:
            return False

        other_agents = {agent for agent, _ in self._usage_log[jti] if agent != current_agent}
        return len(other_agents) > 0

    # ── Utilities ────────────────────────────────────────────────────────────

    def known_jtis(self) -> Set[str]:
        """Return the set of all registered JTIs."""
        return set(self._all_jtis)

    def usage_count(self, jti: str) -> int:
        """Return total number of times *jti* has been registered."""
        return len(self._usage_log.get(jti, []))
