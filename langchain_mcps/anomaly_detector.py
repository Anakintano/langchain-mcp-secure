"""
Anomaly detection for capability abuse — langchain-mcps v2.4.

Scans the tamper-evident audit chain for behavioral patterns that indicate a
compromised or misbehaving agent:
  - High failure rate  (>50 % of attempts rejected)
  - Repeated constraint violations  (≥4 violations in the window)

Flagged capabilities are stored in a taint registry.  The DelegationToken
issuer can consult this registry before re-delegating to prevent a tainted
capability propagating further down the chain.

arXiv reference: §5.2.1 (Intent Decomposition), §3.3 (Cognitive Integrity Defences)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .audit_chain import AuditChain


@dataclass
class AnomalySignal:
    """A single anomaly observation for (agent_id, tool_name)."""

    agent_id: str
    tool_name: str
    signal_type: str          # "high_failure_rate" | "constraint_violations"
    confidence: float         # 0.0–1.0
    details: str
    timestamp: float = field(default_factory=time.time)


class AnomalyDetector:
    """
    Scans the audit chain for capability-abuse patterns.

    Usage::

        detector = AnomalyDetector(audit_chain)
        signal = detector.detect_capability_abuse("agent-a", "read_table")
        if signal and signal.confidence > 0.7:
            detector.flag_capability_as_abused("agent-a", "read_table", signal)

        tainted, sig = detector.is_capability_tainted("agent-a", "read_table")
    """

    # Minimum number of constraint violations before flagging
    VIOLATION_THRESHOLD: int = 4

    def __init__(self, audit_chain: AuditChain) -> None:
        self.audit = audit_chain
        # {f"{agent_id}:{tool_name}": [AnomalySignal, ...]}
        self._taint_registry: Dict[str, List[AnomalySignal]] = {}

    # ── Detection ─────────────────────────────────────────────────────────────

    def detect_capability_abuse(
        self,
        agent_id: str,
        tool_name: str,
        window_minutes: int = 10,
    ) -> Optional[AnomalySignal]:
        """
        Analyse recent audit entries for abuse patterns.

        Args:
            agent_id: Agent whose usage to inspect.
            tool_name: Tool to inspect.
            window_minutes: How far back to look (default 10 min).

        Returns:
            AnomalySignal if abuse detected, None otherwise.
        """
        cutoff = time.time() - window_minutes * 60
        recent = [
            e for e in self.audit.entries
            if e.passport_id == agent_id
            and (
                # Match on event name containing tool_name, or a dedicated tool_name field
                tool_name in (e.event or "")
                or tool_name in (e.reason or "")
                or getattr(e, "tool_name", None) == tool_name
                or e.event in ("tool_start", "delegation_verified", "tool_error")
                and tool_name in str(e)
            )
            and e.timestamp >= cutoff
        ]

        # Fallback: accept all entries for this agent in window if no tool filter matched
        if not recent:
            recent = [
                e for e in self.audit.entries
                if e.passport_id == agent_id and e.timestamp >= cutoff
            ]

        if not recent:
            return None

        rejected = [e for e in recent if e.action == "rejected"]
        total = len(recent)
        failure_rate = len(rejected) / total if total > 0 else 0.0

        if failure_rate > 0.5:
            return AnomalySignal(
                agent_id=agent_id,
                tool_name=tool_name,
                signal_type="high_failure_rate",
                confidence=min(failure_rate, 1.0),
                details=f"{len(rejected)}/{total} attempts rejected",
            )

        violations = [
            e for e in recent
            if e.action == "rejected" and "constraint" in (e.reason or "").lower()
        ]
        if len(violations) >= self.VIOLATION_THRESHOLD:
            return AnomalySignal(
                agent_id=agent_id,
                tool_name=tool_name,
                signal_type="constraint_violations",
                confidence=0.8,
                details=f"{len(violations)} constraint violations in {total} attempts",
            )

        return None

    # ── Taint registry ────────────────────────────────────────────────────────

    def flag_capability_as_abused(
        self,
        agent_id: str,
        tool_name: str,
        signal: AnomalySignal,
    ) -> None:
        """Record a taint signal for (agent_id, tool_name)."""
        key = f"{agent_id}:{tool_name}"
        self._taint_registry.setdefault(key, []).append(signal)

    def is_capability_tainted(
        self, agent_id: str, tool_name: str
    ) -> Tuple[bool, Optional[AnomalySignal]]:
        """
        Check whether (agent_id, tool_name) has been flagged as abused.

        Returns:
            (True, most_recent_signal) if tainted, (False, None) otherwise.
        """
        key = f"{agent_id}:{tool_name}"
        signals = self._taint_registry.get(key)
        if signals:
            return True, signals[-1]
        return False, None

    def clear_taint(self, agent_id: str, tool_name: str) -> None:
        """Remove taint record for (agent_id, tool_name)."""
        self._taint_registry.pop(f"{agent_id}:{tool_name}", None)
