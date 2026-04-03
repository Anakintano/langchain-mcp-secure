"""
MCPS Callback Handler for LangChain.
Verifies agent identity and signs actions at every step of the chain.
"""

import time
from typing import Any, Callable, Dict, List, Optional, Union
from langchain_core.callbacks import BaseCallbackHandler
from mcp_secure import (
    verify_passport_signature,
    validate_passport_format,
    is_passport_expired,
    sign_message,
    check_revocation,
    TRUST_LEVELS,
)

from .audit_chain import AuditChain
from .delegation import DelegationToken, DelegationTokenValidator, DelegationVerificationResult
from .passport_pop import PassportPoPVerifier, PassportPoPGenerator, extract_public_key_from_cnf


class MCPSCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that enforces MCPS identity verification.

    Verifies agent passport on chain/tool/agent start events.
    Optionally signs outgoing actions and logs a cryptographically-chained audit trail.

    v2.1: Audit log is now a merkle-chain — each entry commits to the previous
    entry via SHA256. Call `handler.merkle_root` to get the current root hash.

    Args:
        passport: Signed passport dict (from mcp_secure.create_passport + sign_passport)
        authority_public_key: PEM public key of the Trust Authority (for signature verification)
        private_key: PEM private key for signing actions (optional)
        min_trust_level: Minimum trust level required (default: IDENTIFIED=1)
        verify_revocation: Check live revocation status (default: False)
        trust_authority: Trust Authority URL for revocation checks
        on_verified: Callback(passport_id, event) on successful verification
        on_rejected: Callback(passport_id, reason) on failed verification
        on_action: Callback(signed_envelope) for audit logging
        on_merkle_root_finalized: Callback(root, signature) when merkle root is finalized (optional)
    """

    def __init__(
        self,
        passport: Dict[str, Any],
        authority_public_key: str,
        private_key: Optional[str] = None,
        min_trust_level: int = TRUST_LEVELS["IDENTIFIED"],
        verify_revocation: bool = False,
        trust_authority: str = "https://agentsign.dev",
        on_verified: Optional[Callable] = None,
        on_rejected: Optional[Callable] = None,
        on_action: Optional[Callable] = None,
        on_merkle_root_finalized: Optional[Callable] = None,
        on_permission_gate_triggered: Optional[Callable] = None,
        current_time_provider: Optional[Callable[[], float]] = None,
        delegation_token_jwt: Optional[str] = None,
        delegator_passport: Optional[Dict[str, Any]] = None,
        verify_pop: bool = False,
    ):
        self.passport = passport
        self.authority_public_key = authority_public_key
        self.private_key = private_key
        self.min_trust_level = min_trust_level
        self.verify_revocation = verify_revocation
        self.trust_authority = trust_authority
        self.on_verified = on_verified
        self.on_rejected = on_rejected
        self.on_action = on_action
        self.on_merkle_root_finalized = on_merkle_root_finalized
        self.on_permission_gate_triggered = on_permission_gate_triggered
        self._current_time_provider = current_time_provider or (lambda: time.time())
        self._verified = False
        self._passport_id = passport.get("passport_id", "")
        self._audit_chain = AuditChain()
        # v2.3: delegation support
        self._delegation_token_jwt = delegation_token_jwt
        self._delegator_passport = delegator_passport
        self._delegation_validator = DelegationTokenValidator()
        # v2.5: PoP support
        self._verify_pop_enabled = verify_pop
        self._pop_verifier = PassportPoPVerifier() if verify_pop else None

    def _check_permission_gate(self, tool_name: str) -> tuple:
        """Check permission gate for a tool (v2.2)."""
        from .capabilities import CapabilitySchema, CapabilityValidator
        schema = CapabilitySchema(self.passport.get("capabilities"))

        if not schema.is_v2:
            return True, ""

        gates = schema.get_permission_gates(tool_name)
        if gates is None:
            return True, ""

        if not gates:
            return True, ""

        # At least one gate exists - need callback
        for gate in gates:
            validator = CapabilityValidator(schema)
            is_allowed, reason = validator.validate_permission_gate(
                tool_name, gate, self.on_permission_gate_triggered
            )
            if not is_allowed:
                return False, reason

        return True, ""

    def _verify_identity(self, event: str) -> bool:
        """Core verification -- passport format, signature, expiry, trust level, revocation."""
        # Format check
        fmt = validate_passport_format(self.passport)
        if not fmt["valid"]:
            self._reject(event, fmt["error"]["message"])
            return False

        # Signature check
        if not verify_passport_signature(self.passport, self.authority_public_key):
            self._reject(event, "invalid_signature")
            return False

        # Expiry check
        if is_passport_expired(self.passport):
            self._reject(event, "expired")
            return False

        # Trust level check
        if self.passport.get("trust_level", 0) < self.min_trust_level:
            self._reject(event, "insufficient_trust")
            return False

        # Revocation check (optional, hits network)
        if self.verify_revocation:
            rev = check_revocation(self._passport_id, self.trust_authority)
            if rev["revoked"]:
                self._reject(event, "revoked")
                return False

        self._verified = True
        if self.on_verified:
            self.on_verified(self._passport_id, event)
        return True

    def _verify_pop(self, tool_name: str, current_time: float) -> bool:
        """Verify Proof-of-Possession for a tool invocation (v2.5).

        If verify_pop is enabled, generates a PoP challenge and verifies the signature
        using the passport's cnf claim.

        Returns:
            True if PoP verification passes (or PoP is disabled).
            Raises PermissionError if PoP verification fails.
        """
        if not self._verify_pop_enabled or self._pop_verifier is None:
            return True

        # Extract public key from passport cnf claim
        cnf = self.passport.get("cnf")
        if cnf is None:
            # No cnf claim — PoP verification required but passport lacks cnf
            self._reject("tool_start", "passport_pop_missing_cnf_claim")

        public_key_pem = extract_public_key_from_cnf(cnf)
        if public_key_pem is None:
            self._reject("tool_start", "passport_pop_cannot_extract_public_key")

        # Generate PoP for this invocation
        pop = PassportPoPGenerator.generate_pop(tool_name, self.private_key or "", timestamp=current_time)

        # Verify PoP signature
        valid, reason = self._pop_verifier.verify(
            pop,
            public_key_pem,
            current_time=current_time,
            expected_tool_name=tool_name,
        )
        if not valid:
            self._reject("tool_start", f"passport_pop_verification_failed: {reason}")

        # Log PoP verification in audit chain
        self._audit_chain.append({
            "timestamp": current_time,
            "event": "pop_verified",
            "passport_id": self._passport_id,
            "action": "pop_verified",
            "tool": tool_name,
            "pop_jti": pop.jti,
        })

        return True

    def _verify_delegation(self, tool_name: str, current_time: float) -> DelegationVerificationResult:
        """Verify delegation token (Steps 2-6). Step 1 must already have passed."""
        if self._delegator_passport is None:
            self._reject("tool_start", "delegation_missing_delegator_passport")

        delegator_pub_key = self._delegator_passport.get("public_key", "")  # type: ignore[union-attr]
        delegator_pid = self._delegator_passport.get("passport_id", "")  # type: ignore[union-attr]
        delegatee_pid = self._passport_id

        result = self._delegation_validator.verify(
            token_jwt=self._delegation_token_jwt,  # type: ignore[arg-type]
            delegator_public_key=delegator_pub_key,
            delegatee_agent_id=delegatee_pid,
            delegator_passport_id=delegator_pid,
            requested_tool=tool_name,
            current_time=current_time,
        )

        if not result.valid:
            # Log delegation rejection in audit chain then raise
            self._audit_chain.append({
                "timestamp": current_time,
                "event": "tool_start",
                "passport_id": self._passport_id,
                "action": "rejected",
                "reason": result.reason,
            })
            if self.on_rejected:
                self.on_rejected(self._passport_id, result.reason)
            raise PermissionError(
                f"MCPS delegation: {self._passport_id} rejected — {result.reason}"
            )

        # Log successful delegation verification with forensic chain data
        tok = result.delegation_token
        self._audit_chain.append({
            "timestamp": current_time,
            "event": "delegation_verified",
            "passport_id": self._passport_id,
            "action": "delegation_verified",
            "reason": f"delegated_by:{delegator_pid}",
            "delegation_chain_path": tok.delegation_chain_path if tok else None,
            "delegation_depth": tok.delegation_depth if tok else None,
        })
        return result

    def _reject(self, event: str, reason: str) -> None:
        """Handle rejection."""
        self._verified = False
        self._audit_chain.append({
            "timestamp": time.time(),
            "event": event,
            "passport_id": self._passport_id,
            "action": "rejected",
            "reason": reason,
        })
        if self.on_rejected:
            self.on_rejected(self._passport_id, reason)
        raise PermissionError(
            f"MCPS: Agent {self._passport_id} rejected -- {reason}"
        )

    def _sign_action(self, event: str, data: Dict) -> Optional[Dict]:
        """Sign an action if private key is available."""
        if not self.private_key:
            return None
        msg = {"event": event, **data}
        envelope = sign_message(msg, self._passport_id, self.private_key)
        self._audit_chain.append({
            "timestamp": time.time(),
            "event": event,
            "passport_id": self._passport_id,
            "action": "signed",
        })
        if self.on_action:
            self.on_action(envelope)
        return envelope

    # ── LangChain Callback Hooks ──

    def on_chain_start(
        self, serialized: Dict[str, Any], inputs: Dict[str, Any], **kwargs
    ) -> None:
        """Verify identity when a chain starts."""
        if not self._verified:
            self._verify_identity("chain_start")
        self._sign_action("chain_start", {
            "chain": serialized.get("id", ["unknown"])[-1],
        })

    def on_tool_start(
        self, serialized: Dict[str, Any], input_str: str, **kwargs
    ) -> None:
        """Verify identity and sign when a tool is invoked."""
        if not self._verified:
            self._verify_identity("tool_start")

        tool_name = serialized.get("name", "unknown")
        current_time = self._current_time_provider()

        # v2.5: PoP verification (if enabled)
        if self._verify_pop:
            self._verify_pop(tool_name, current_time)

        if self._delegation_token_jwt is not None:
            # v2.3 delegation mode: 6-step token verification is authoritative.
            # Passport capability checks (v2.0/v2.2) are bypassed — the token
            # already carries the intersected, verifier-enforced permissions.
            self._verify_delegation(tool_name, current_time)
        else:
            # Normal mode: capability + time window + gate checks (v2.0/v2.2)
            from .capabilities import CapabilitySchema, CapabilityValidator
            schema = CapabilitySchema(self.passport.get("capabilities"))
            validator = CapabilityValidator(schema)

            # Implicit deny: tool must be listed in capabilities (v2.0+)
            if schema.is_v2 and not schema.is_tool_allowed(tool_name):
                self._reject("tool_start", f"tool_not_allowed: '{tool_name}' not in passport capabilities")

            # Check time windows
            if schema.is_v2:
                time_valid, time_reason = validator.validate_time_window(tool_name, current_time)
                if not time_valid:
                    self._reject("tool_start", f"time_window_check_failed: {time_reason}")

            # Permission gate check (v2.2)
            if schema.is_v2:
                gate_valid, gate_reason = self._check_permission_gate(tool_name)
                if not gate_valid:
                    self._reject("tool_start", f"permission_gate_denied: {gate_reason}")

        self._sign_action("tool_start", {
            "tool": tool_name,
        })

    def on_agent_action(self, action: Any, **kwargs) -> None:
        """Verify identity and sign agent actions."""
        if not self._verified:
            self._verify_identity("agent_action")
        tool_name = getattr(action, "tool", "unknown")
        self._sign_action("agent_action", {"tool": tool_name})

    def on_llm_start(
        self, serialized: Dict[str, Any], prompts: List[str], **kwargs
    ) -> None:
        """Verify identity on LLM calls."""
        if not self._verified:
            self._verify_identity("llm_start")

    def on_chain_end(self, outputs: Dict[str, Any], **kwargs) -> None:
        """Log chain completion."""
        self._audit_chain.append({
            "timestamp": time.time(),
            "event": "chain_end",
            "passport_id": self._passport_id,
            "action": "completed",
        })

    def on_chain_error(self, error: BaseException, **kwargs) -> None:
        """Log chain errors."""
        self._audit_chain.append({
            "timestamp": time.time(),
            "event": "chain_error",
            "passport_id": self._passport_id,
            "action": "error",
            "error": str(error)[:200],
        })

    def on_tool_end(self, output: str, **kwargs) -> None:
        pass

    def on_tool_error(self, error: BaseException, **kwargs) -> None:
        """Log tool errors."""
        self._audit_chain.append({
            "timestamp": time.time(),
            "event": "tool_error",
            "passport_id": self._passport_id,
            "action": "error",
            "error": str(error)[:200],
        })

    def on_llm_end(self, response: Any, **kwargs) -> None:
        pass

    def on_llm_error(self, error: BaseException, **kwargs) -> None:
        pass

    # ── Public API ──

    @property
    def audit_log(self) -> List[Dict]:
        """Return the audit trail as a list of dicts (backward compatible with v1.0).

        Each entry includes v2.1 fields: entry_hash, previous_entry_hash.
        """
        return self._audit_chain.to_dict()

    @property
    def merkle_root(self) -> Optional[str]:
        """Return the current merkle root (entry_hash of last audit entry).

        Lazily computed — zero cost when not accessed.

        Returns:
            SHA256 hex string, or None if no audit entries yet.
        """
        return self._audit_chain.get_merkle_root()

    def sign_merkle_root(self) -> Optional[Dict]:
        """Sign the current merkle root using the agent's private key.

        Returns:
            Signed envelope dict, or None if no private key or empty chain.
        """
        root = self.merkle_root
        if root is None or not self.private_key:
            return None
        envelope = sign_message(
            {"merkle_root": root, "passport_id": self._passport_id},
            self._passport_id,
            self.private_key,
        )
        if self.on_merkle_root_finalized:
            self.on_merkle_root_finalized(root, envelope)
        return envelope

    def verify_audit_chain(self) -> bool:
        """Verify the cryptographic integrity of the audit chain.

        Returns:
            True if chain is intact, False if tampered.
        """
        return self._audit_chain.verify_chain()

    @property
    def is_verified(self) -> bool:
        """Whether the agent has been verified."""
        return self._verified
