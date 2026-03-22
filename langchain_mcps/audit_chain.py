"""
Merkle-chain audit logging for langchain-mcps v2.1.

Each audit entry cryptographically commits to the previous entry via SHA256 hashing,
forming an append-only tamper-evident chain. The merkle_root (last entry hash) can
be exported and signed for third-party verification.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


def _sha256(data: str) -> str:
    """Compute SHA256 hex digest of a string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass
class AuditChainEntry:
    """
    A single entry in the merkle-chain audit log.

    Each entry contains the standard audit fields plus cryptographic
    linkage to the previous entry via hash chaining.
    """

    timestamp: float
    event: str
    passport_id: str
    action: str
    previous_entry_hash: Optional[str]
    # Optional fields
    reason: Optional[str] = None
    error: Optional[str] = None
    # Computed on creation
    entry_hash: str = field(init=False)

    def __post_init__(self) -> None:
        """Compute entry_hash after all fields are set."""
        self.entry_hash = self.compute_hash()

    def compute_hash(self) -> str:
        """
        Compute SHA256 hash of this entry's data + previous_entry_hash.

        Uses a deterministic JSON serialization (sorted keys) to ensure
        hash consistency across platforms and Python versions.

        Returns:
            SHA256 hex digest string.
        """
        data = {
            "timestamp": self.timestamp,
            "event": self.event,
            "passport_id": self.passport_id,
            "action": self.action,
            "previous_entry_hash": self.previous_entry_hash,
            "reason": self.reason,
            "error": self.error,
        }
        serialized = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return _sha256(serialized)

    def to_dict(self) -> Dict[str, Any]:
        """
        Serialize entry to dict (includes hash fields).

        Returns:
            Dict with all entry fields including entry_hash and previous_entry_hash.
        """
        d = asdict(self)
        # entry_hash is excluded from asdict (it's not an init param after field(init=False))
        d["entry_hash"] = self.entry_hash
        return d


class AuditChain:
    """
    Append-only merkle-chain audit log.

    Each appended entry cryptographically commits to all previous entries.
    The merkle_root is the entry_hash of the last entry — a single value
    that can be signed and published for tamper-evident audit proofs.

    Usage::

        chain = AuditChain()
        chain.append({"event": "chain_start", "passport_id": "agent-1", ...})
        root = chain.get_merkle_root()
        assert chain.verify_chain()
    """

    def __init__(self) -> None:
        """Initialize an empty chain."""
        self._entries: List[AuditChainEntry] = []

    def append(self, entry_data: Dict[str, Any]) -> AuditChainEntry:
        """
        Append a new entry to the chain.

        Automatically computes previous_entry_hash from the last entry
        and entry_hash from the new entry's data.

        Args:
            entry_data: Dict containing audit fields. Required keys:
                        event, passport_id, action.
                        Optional: reason, error, timestamp.

        Returns:
            The newly created AuditChainEntry.
        """
        previous_hash = self._entries[-1].entry_hash if self._entries else None

        entry = AuditChainEntry(
            timestamp=entry_data.get("timestamp", time.time()),
            event=entry_data.get("event", ""),
            passport_id=entry_data.get("passport_id", ""),
            action=entry_data.get("action", ""),
            previous_entry_hash=previous_hash,
            reason=entry_data.get("reason"),
            error=entry_data.get("error"),
        )
        self._entries.append(entry)
        return entry

    def get_merkle_root(self) -> Optional[str]:
        """
        Return the merkle root of the chain (entry_hash of last entry).

        Computed lazily — zero cost when not called.

        Returns:
            SHA256 hex string, or None if chain is empty.
        """
        if not self._entries:
            return None
        return self._entries[-1].entry_hash

    def verify_chain(self) -> bool:
        """
        Verify cryptographic integrity of the entire chain.

        Recomputes every entry_hash and checks:
        - Each entry_hash matches the recomputed value
        - Each previous_entry_hash matches the prior entry's entry_hash

        Returns:
            True if chain is intact, False if any entry has been tampered with.
        """
        for i, entry in enumerate(self._entries):
            expected_prev = self._entries[i - 1].entry_hash if i > 0 else None
            if entry.previous_entry_hash != expected_prev:
                return False
            if entry.entry_hash != entry.compute_hash():
                return False
        return True

    def to_dict(self) -> List[Dict[str, Any]]:
        """
        Export the full chain as a list of dicts.

        Returns:
            List of entry dicts including hash fields.
        """
        return [e.to_dict() for e in self._entries]

    @property
    def entries(self) -> List[AuditChainEntry]:
        """Read-only view of chain entries."""
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)
