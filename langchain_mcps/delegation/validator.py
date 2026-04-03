"""
6-step delegation token verification gate for langchain-mcps v2.3.

Verification sequence:
  Step 1 — Delegatee passport (called by MCPSCallbackHandler._verify_identity)
  Step 2 — JWT structure (algorithm, header)
  Step 3 — ECDSA P-256 signature (delegator's public key)
  Step 4 — TTL + nonce (replay prevention) + revocation check
  Step 5 — Capability intersection (privilege escalation prevention)
  Step 6 — Delegation chain (subject, parent ID, depth)
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Set

import jwt as pyjwt

from .token import DelegationToken


@dataclass
class DelegationVerificationResult:
    """Result of a 6-step delegation token verification."""

    valid: bool
    reason: str
    delegation_token: Optional[DelegationToken] = None


class DelegationTokenValidator:
    """
    Stateful 6-step verification gate for delegation tokens.

    Maintains:
    - nonce_cache (Set[str]): Seen JTIs — prevents token replay.
    - dtrl (Set[str]): Delegation Token Revocation List.

    Both are in-memory for MVP. Replace with Redis for distributed deployments.
    """

    def __init__(self) -> None:
        self._nonce_cache: Set[str] = set()
        self._dtrl: Set[str] = set()

    def verify(
        self,
        token_jwt: str,
        delegator_public_key: str,
        delegatee_agent_id: str,
        delegator_passport_id: str,
        requested_tool: str,
        current_time: Optional[float] = None,
    ) -> DelegationVerificationResult:
        """
        Execute 6-step verification gate.

        Step 1 is the caller's responsibility (MCPSCallbackHandler._verify_identity
        must be called before this method).

        Args:
            token_jwt: Signed JWT delegation token string.
            delegator_public_key: PEM public key of the token issuer (Agent A).
            delegatee_agent_id: passport_id of the agent presenting the token (B).
            delegator_passport_id: passport_id that issued the token (A's passport).
            requested_tool: Name of the tool Agent B wants to use.
            current_time: Override current time (for testing). Defaults to time.time().

        Returns:
            DelegationVerificationResult with valid=True on success.
        """
        now = current_time if current_time is not None else time.time()

        # ── Step 2: JWT structure ──────────────────────────────────────────────
        try:
            header = pyjwt.get_unverified_header(token_jwt)
        except Exception as exc:
            return DelegationVerificationResult(False, f"malformed_jwt: {exc}")

        alg = header.get("alg", "")
        if alg != "ES256":
            return DelegationVerificationResult(
                False, f"invalid_jwt_algorithm: expected ES256, got {alg!r}"
            )

        # ── Step 3: ECDSA signature ───────────────────────────────────────────
        try:
            token = DelegationToken.from_jwt(
                token_jwt,
                delegator_public_key,
                verify_exp=False,  # We do TTL manually (Step 4) to use injected clock
            )
        except pyjwt.InvalidSignatureError:
            return DelegationVerificationResult(False, "invalid_delegation_signature")
        except pyjwt.DecodeError as exc:
            return DelegationVerificationResult(False, f"jwt_decode_error: {exc}")
        except Exception as exc:
            return DelegationVerificationResult(False, f"signature_verification_failed: {exc}")

        # ── Step 4a: TTL check (manual, uses injected clock) ──────────────────
        if now > token.exp:
            return DelegationVerificationResult(False, "delegation_token_expired")

        if now < token.iat - 5:  # 5-second clock-skew tolerance
            return DelegationVerificationResult(False, "delegation_token_future_dated")

        # ── Step 4b: Replay prevention (JTI nonce cache) ─────────────────────
        if token.jti in self._nonce_cache:
            return DelegationVerificationResult(False, "delegation_token_replayed")

        # ── Step 4c: Revocation list ──────────────────────────────────────────
        if token.jti in self._dtrl:
            return DelegationVerificationResult(False, "delegation_token_revoked")

        # Mark JTI as consumed *after* all Step 4 checks pass
        self._nonce_cache.add(token.jti)

        # ── Step 5: Capability intersection (privilege escalation prevention) ─
        if requested_tool not in token.capabilities:
            return DelegationVerificationResult(
                False, f"tool_not_delegated: '{requested_tool}' not in token capabilities"
            )

        tool_cap = token.capabilities[requested_tool]
        if not tool_cap.get("allowed", False):
            return DelegationVerificationResult(
                False, f"tool_denied_in_delegation: '{requested_tool}'"
            )

        # ── Step 6: Delegation chain validation ──────────────────────────────
        if token.sub != delegatee_agent_id:
            return DelegationVerificationResult(
                False,
                f"delegation_subject_mismatch: token.sub={token.sub!r} "
                f"!= delegatee={delegatee_agent_id!r}",
            )

        if token.parent_passport_id != delegator_passport_id:
            return DelegationVerificationResult(
                False,
                f"delegation_parent_id_mismatch: token.parent_passport_id="
                f"{token.parent_passport_id!r} != delegator={delegator_passport_id!r}",
            )

        if token.max_delegation_depth is not None and token.delegation_depth > token.max_delegation_depth:
            return DelegationVerificationResult(
                False,
                f"delegation_depth_exceeded: depth={token.delegation_depth} "
                f"> max={token.max_delegation_depth}",
            )

        # ── Step 6b: Chain path well-formed ──────────────────────────────────
        chain = token.delegation_chain_path or []
        if len(chain) != len(set(chain)):
            return DelegationVerificationResult(False, "delegation_chain_path_contains_duplicates")
        # Depth should match chain length (chain holds ancestors, not the delegatee itself)
        if chain and token.delegation_depth != len(chain):
            return DelegationVerificationResult(
                False,
                f"delegation_chain_path_length_mismatch: len={len(chain)} != depth={token.delegation_depth}",
            )

        return DelegationVerificationResult(
            valid=True,
            reason="delegation_verified",
            delegation_token=token,
        )

    def revoke_token(self, jti: str) -> None:
        """Explicitly revoke a delegation token by JTI."""
        self._dtrl.add(jti)

    def is_revoked(self, jti: str) -> bool:
        """Check if a JTI is in the revocation list."""
        return jti in self._dtrl

    def is_used(self, jti: str) -> bool:
        """Check if a JTI has already been consumed."""
        return jti in self._nonce_cache
