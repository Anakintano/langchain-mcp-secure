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
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend


def _sha256(data: str) -> str:
    """Compute SHA256 hex digest of a string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass
class AuditChainEntry:
    """
    A single entry in the merkle-chain audit log.

    Each entry contains the standard audit fields plus cryptographic
    linkage to the previous entry via hash chaining.

    v2.4 additions:
        delegation_chain_path: Full ancestor chain of the acting agent.
        delegation_depth: Depth in the delegation tree.
        parameter_passing_integrity: "preserved" or "narrowed" — records whether
            capability constraints were narrowed at this delegation hop.
    """

    timestamp: float
    event: str
    passport_id: str
    action: str
    previous_entry_hash: Optional[str]
    # Optional fields
    reason: Optional[str] = None
    error: Optional[str] = None
    # v2.4 delegation forensics
    delegation_chain_path: Optional[List[str]] = None
    delegation_depth: Optional[int] = None
    parameter_passing_integrity: Optional[str] = None
    # v2.5 PoP and other extensible fields
    tool: Optional[str] = None
    pop_jti: Optional[str] = None
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
        Includes delegation forensics fields so they are tamper-evident.

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
            "delegation_chain_path": self.delegation_chain_path,
            "delegation_depth": self.delegation_depth,
            "parameter_passing_integrity": self.parameter_passing_integrity,
            "tool": self.tool,
            "pop_jti": self.pop_jti,
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
            delegation_chain_path=entry_data.get("delegation_chain_path"),
            delegation_depth=entry_data.get("delegation_depth"),
            parameter_passing_integrity=entry_data.get("parameter_passing_integrity"),
            tool=entry_data.get("tool"),
            pop_jti=entry_data.get("pop_jti"),
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

    def export_forensic_trail(self, agent_id: str) -> Dict[str, Any]:
        """
        Return a structured forensic report for all actions taken by agent_id.

        Enables investigators to trace full delegation lineage without manual
        cross-referencing of separate audit records.

        Args:
            agent_id: passport_id of the agent whose actions to trace.

        Returns:
            Dict with agent_id and list of action dicts including delegation chain.
        """
        actions = []
        for e in self._entries:
            if e.passport_id != agent_id:
                continue
            chain = e.delegation_chain_path or []
            actions.append({
                "timestamp": e.timestamp,
                "event": e.event,
                "action": e.action,
                "delegation_chain": chain,
                "authorized_by": chain[0] if chain else "direct",
                "delegation_depth": e.delegation_depth,
                "parameter_integrity": e.parameter_passing_integrity,
                "reason": e.reason,
            })
        return {"agent_id": agent_id, "actions": actions}

    def __len__(self) -> int:
        return len(self._entries)

    def export_root(self, agent_private_key: str) -> Tuple[str, float, str]:
        """
        Export the merkle root with a signature for external anchoring.

        Generates an ECDSA P-256 signature over (merkle_root_hex || timestamp)
        using the agent's private key. This allows production deployments to
        anchor the root to external durable stores (S3, certificate transparency
        logs, TPM) for protection against process kill and VM rollback attacks.

        Args:
            agent_private_key: PEM-encoded ECDSA P-256 private key string.

        Returns:
            Tuple of (merkle_root_hex, timestamp, agent_signature_hex) where:
            - merkle_root_hex: Current merkle root as hex string
            - timestamp: Current time as float (seconds since epoch)
            - agent_signature_hex: ECDSA signature as hex string

        Raises:
            ValueError: If audit chain is empty (no root to export).
        """
        root = self.get_merkle_root()
        if root is None:
            raise ValueError("Cannot export root from empty audit chain")

        current_time = time.time()

        # Load private key and sign (merkle_root_hex || timestamp)
        try:
            private_key_obj = serialization.load_pem_private_key(
                agent_private_key.encode("utf-8"),
                password=None,
                backend=default_backend(),
            )
        except Exception as e:
            raise ValueError(f"Failed to load private key: {e}")

        # Create signing data: concatenate root hex and timestamp
        signing_data = f"{root}||{current_time}".encode("utf-8")

        # Sign with ECDSA P-256
        signature_bytes = private_key_obj.sign(signing_data, ec.ECDSA(hashes.SHA256()))

        # Convert signature to hex string for transport
        signature_hex = signature_bytes.hex()

        return (root, current_time, signature_hex)
