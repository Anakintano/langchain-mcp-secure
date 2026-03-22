"""
RFC 8693 delegation token for langchain-mcps v2.3.

Agent A signs a DelegationToken granting Agent B a time-limited, capability-scoped
authorisation. Capabilities in the token are the intersection of A's permissions and
the requested scope, preventing privilege escalation at the protocol level.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import jwt as pyjwt
from jwt.algorithms import ECAlgorithm as _ECAlgorithm


def _resolve_public_key(key: Any) -> Any:
    """Accept a PEM string or JWK dict and return a form usable by PyJWT."""
    if isinstance(key, dict):
        return _ECAlgorithm.from_jwk(key)
    return key  # already a PEM string or cryptography key object


# ── Capability intersection ───────────────────────────────────────────────────


def _intersect_constraints(
    delegator: Dict[str, Any],
    requested: Dict[str, Any],
) -> Dict[str, Any]:
    """Merge two constraint dicts — delegator's constraints win (most restrictive)."""
    merged: Dict[str, Any] = {}

    # allowed_tables: set intersection
    if "allowed_tables" in delegator:
        del_tables = set(delegator["allowed_tables"])
        req_tables = set(requested.get("allowed_tables", delegator["allowed_tables"]))
        merged["allowed_tables"] = sorted(del_tables & req_tables)
    elif "allowed_tables" in requested:
        merged["allowed_tables"] = list(requested["allowed_tables"])

    # rate_limit: min value (most restrictive), delegator's window
    if "rate_limit" in delegator:
        del_rl = delegator["rate_limit"]
        req_rl = requested.get("rate_limit", del_rl)
        merged["rate_limit"] = {
            "value": min(del_rl["value"], req_rl.get("value", del_rl["value"])),
            "window": del_rl["window"],
        }
    elif "rate_limit" in requested:
        merged["rate_limit"] = dict(requested["rate_limit"])

    # All other delegator constraints propagate unchanged
    for key, val in delegator.items():
        if key not in merged:
            merged[key] = val

    return merged


def intersect_capabilities(
    delegator_caps: Dict[str, Any],
    requested_caps: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Compute capability intersection: requested ∩ delegator.

    Rules:
    - Tool must exist in delegator_caps with allowed=True.
    - allowed_tables: set intersection (B gets only what A already has).
    - rate_limit: min(delegator, requested) by value; delegator's window wins.
    - Other constraints: delegator's value propagates unchanged.

    Raises:
        ValueError: If requested tool is not in delegator's capabilities or is denied.
    """
    result: Dict[str, Any] = {}
    for tool_name, req_config in requested_caps.items():
        del_config = delegator_caps.get(tool_name)
        if del_config is None:
            raise ValueError(
                f"Delegator not authorized for tool '{tool_name}' — cannot delegate it"
            )
        if not del_config.get("allowed", False):
            raise ValueError(
                f"Delegator's tool '{tool_name}' is denied — cannot delegate a denied tool"
            )
        if not req_config.get("allowed", False):
            # Requested as denied — skip (not delegating it)
            continue

        merged_constraints = _intersect_constraints(
            del_config.get("constraints", {}),
            req_config.get("constraints", {}),
        )
        result[tool_name] = {
            "allowed": True,
            "constraints": merged_constraints,
        }

    return result


# ── DelegationToken ───────────────────────────────────────────────────────────


@dataclass
class DelegationToken:
    """
    RFC 8693 delegation token (ECDSA P-256 signed JWT).

    Fields:
        iss: Delegator agent ID (issuer).
        sub: Delegatee agent ID (subject).
        aud: Audience (fixed to "langchain-mcps").
        iat: Issued-at timestamp (Unix float).
        exp: Expiry timestamp (Unix float).
        jti: Unique token ID — nonce for replay prevention.
        act: RFC 8693 act claim {"sub": delegatee_id}.
        capabilities: Intersected capabilities (A's ∩ requested scope).
        parent_passport_id: Delegator's passport_id.
        delegation_depth: Depth in chain (1 for MVP single-hop).
        max_delegation_depth: Maximum allowed chain depth.
    """

    iss: str
    sub: str
    aud: str
    iat: float
    exp: float
    jti: str
    act: Dict[str, str]
    capabilities: Dict[str, Any]
    parent_passport_id: str
    delegation_depth: int
    max_delegation_depth: int

    # ── Factory ──

    @staticmethod
    def create(
        delegator_agent_id: str,
        delegatee_agent_id: str,
        delegator_capabilities: Dict[str, Any],
        requested_capabilities: Dict[str, Any],
        ttl_seconds: int = 1800,
    ) -> "DelegationToken":
        """
        Create a new delegation token with capability intersection.

        Args:
            delegator_agent_id: The delegator's passport_id / agent ID.
            delegatee_agent_id: The delegatee's passport_id / agent ID.
            delegator_capabilities: The delegator's full capabilities dict.
            requested_capabilities: The subset being delegated (requested scope).
            ttl_seconds: Token lifetime in seconds (default 30 min).

        Returns:
            Unsigned DelegationToken. Call .to_jwt(private_key) to sign.

        Raises:
            ValueError: If requested capabilities exceed delegator's permissions.
        """
        caps = intersect_capabilities(delegator_capabilities, requested_capabilities)
        now = time.time()
        return DelegationToken(
            iss=delegator_agent_id,
            sub=delegatee_agent_id,
            aud="langchain-mcps",
            iat=now,
            exp=now + ttl_seconds,
            jti=f"dt-{secrets.token_hex(16)}",
            act={"sub": delegatee_agent_id},
            capabilities=caps,
            parent_passport_id=delegator_agent_id,
            delegation_depth=1,
            max_delegation_depth=1,
        )

    # ── Serialisation ──

    def to_jwt(self, private_key: str) -> str:
        """Sign and encode as ES256 JWT string."""
        payload = {
            "iss": self.iss,
            "sub": self.sub,
            "aud": self.aud,
            "iat": self.iat,
            "exp": self.exp,
            "jti": self.jti,
            "act": self.act,
            "capabilities": self.capabilities,
            "parent_passport_id": self.parent_passport_id,
            "delegation_depth": self.delegation_depth,
            "max_delegation_depth": self.max_delegation_depth,
        }
        return pyjwt.encode(payload, private_key, algorithm="ES256")

    @staticmethod
    def from_jwt(
        token_str: str,
        public_key: str,
        verify_exp: bool = True,
        current_time: Optional[float] = None,
    ) -> "DelegationToken":
        """
        Decode and verify a JWT delegation token.

        Args:
            token_str: Encoded JWT string.
            public_key: Delegator's PEM public key.
            verify_exp: Whether to verify token expiry (disable for manual TTL check).
            current_time: Custom current time for expiry verification.

        Returns:
            Decoded DelegationToken.

        Raises:
            jwt.InvalidSignatureError: If signature doesn't match.
            jwt.ExpiredSignatureError: If token has expired (when verify_exp=True).
        """
        options: Dict[str, Any] = {"verify_aud": False}
        if not verify_exp:
            options["verify_exp"] = False

        leeway = 0
        if current_time is not None:
            # Pass leeway to account for custom clock offset
            import datetime
            real_now = time.time()
            leeway = int(abs(real_now - current_time)) + 1

        resolved_key = _resolve_public_key(public_key)
        payload = pyjwt.decode(
            token_str,
            resolved_key,
            algorithms=["ES256"],
            options=options,
            leeway=leeway,
        )
        return DelegationToken(
            iss=payload["iss"],
            sub=payload["sub"],
            aud=payload["aud"],
            iat=float(payload["iat"]),
            exp=float(payload["exp"]),
            jti=payload["jti"],
            act=payload["act"],
            capabilities=payload["capabilities"],
            parent_passport_id=payload["parent_passport_id"],
            delegation_depth=int(payload["delegation_depth"]),
            max_delegation_depth=int(payload["max_delegation_depth"]),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to plain dict (without JWT encoding)."""
        return {
            "iss": self.iss,
            "sub": self.sub,
            "aud": self.aud,
            "iat": self.iat,
            "exp": self.exp,
            "jti": self.jti,
            "act": self.act,
            "capabilities": self.capabilities,
            "parent_passport_id": self.parent_passport_id,
            "delegation_depth": self.delegation_depth,
            "max_delegation_depth": self.max_delegation_depth,
        }
