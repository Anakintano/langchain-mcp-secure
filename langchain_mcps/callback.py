"""
MCPS Callback Handler for LangChain.
Verifies agent identity and signs actions at every step of the chain.
"""

import time
from typing import Any, Dict, List, Optional, Union
from langchain_core.callbacks import BaseCallbackHandler
from mcp_secure import (
    verify_passport_signature,
    validate_passport_format,
    is_passport_expired,
    sign_message,
    check_revocation,
    TRUST_LEVELS,
)


class MCPSCallbackHandler(BaseCallbackHandler):
    """LangChain callback handler that enforces MCPS identity verification.

    Verifies agent passport on chain/tool/agent start events.
    Optionally signs outgoing actions and logs audit trail.

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
    """

    def __init__(
        self,
        passport: Dict[str, Any],
        authority_public_key: str,
        private_key: Optional[str] = None,
        min_trust_level: int = TRUST_LEVELS["IDENTIFIED"],
        verify_revocation: bool = False,
        trust_authority: str = "https://agentsign.dev",
        on_verified: Optional[Any] = None,
        on_rejected: Optional[Any] = None,
        on_action: Optional[Any] = None,
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
        self._verified = False
        self._passport_id = passport.get("passport_id", "")
        self._audit_log: List[Dict] = []

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

    def _reject(self, event: str, reason: str):
        """Handle rejection."""
        self._verified = False
        entry = {
            "timestamp": time.time(),
            "event": event,
            "passport_id": self._passport_id,
            "action": "rejected",
            "reason": reason,
        }
        self._audit_log.append(entry)
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
        entry = {
            "timestamp": time.time(),
            "event": event,
            "passport_id": self._passport_id,
            "action": "signed",
        }
        self._audit_log.append(entry)
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
        self._sign_action("tool_start", {
            "tool": serialized.get("name", "unknown"),
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
        self._audit_log.append({
            "timestamp": time.time(),
            "event": "chain_end",
            "passport_id": self._passport_id,
            "action": "completed",
        })

    def on_chain_error(self, error: BaseException, **kwargs) -> None:
        """Log chain errors."""
        self._audit_log.append({
            "timestamp": time.time(),
            "event": "chain_error",
            "passport_id": self._passport_id,
            "action": "error",
            "error": str(error)[:200],
        })

    def on_tool_end(self, output: str, **kwargs) -> None:
        pass

    def on_tool_error(self, error: BaseException, **kwargs) -> None:
        self._audit_log.append({
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
        """Return the audit trail."""
        return list(self._audit_log)

    @property
    def is_verified(self) -> bool:
        """Whether the agent has been verified."""
        return self._verified
