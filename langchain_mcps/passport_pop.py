"""
Passport Proof-of-Possession (PoP) for MCPS v2.5+.

Implements DPoP-style per-request proof-of-possession signing for passports.
Each tool invocation generates a challenge (timestamp + tool_name + nonce) signed by the
agent's private key. The verifier checks the signature against the passport's public key
before dispatching the tool.

Also includes passport-level JTI (JWT ID) + nonce tracking to prevent replay attacks,
separate from delegation token tracking.

RFC References:
  - RFC 8693 (Delegation)
  - draft-ietf-oauth-dpop (DPoP pattern)
"""

from __future__ import annotations

import secrets
import time
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional, Set
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import jwt as pyjwt


@dataclass
class PassportCnf:
    """
    Confirmation claim (cnf) for passport.

    Contains the agent's public key (for PoP signature verification).
    Follows RFC 8705 (MTLS PoP) pattern adapted for ECDSA.

    Fields:
        jwk: JWK dict containing public key (ECDSA P-256)
    """
    jwk: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict."""
        return {"jwk": self.jwk}


@dataclass
class PassportPoP:
    """
    Per-request Proof-of-Possession envelope.

    Fields:
        jti: Passport-level JWT ID (unique per invocation).
        nonce: Random nonce for this invocation.
        timestamp: Unix timestamp of challenge creation.
        tool_name: Name of the tool being invoked.
        signature: Base64url-encoded ECDSA signature over (timestamp || tool_name || nonce).
    """
    jti: str
    nonce: str
    timestamp: float
    tool_name: str
    signature: str

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict."""
        return {
            "jti": self.jti,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
            "tool_name": self.tool_name,
            "signature": self.signature,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> PassportPoP:
        """Deserialize from dict."""
        return PassportPoP(
            jti=data["jti"],
            nonce=data["nonce"],
            timestamp=float(data["timestamp"]),
            tool_name=data["tool_name"],
            signature=data["signature"],
        )


class PassportPoPGenerator:
    """Generate PoP challenges and signatures."""

    @staticmethod
    def create_challenge(timestamp: float, tool_name: str, nonce: str) -> bytes:
        """Create a challenge from components.

        Format: timestamp_as_str || '.' || tool_name || '.' || nonce
        """
        challenge_str = f"{timestamp:.0f}.{tool_name}.{nonce}"
        return challenge_str.encode("utf-8")

    @staticmethod
    def generate_pop(
        tool_name: str,
        private_key_pem: str,
        timestamp: Optional[float] = None,
        nonce: Optional[str] = None,
        jti: Optional[str] = None,
    ) -> PassportPoP:
        """Generate a PoP signature for a tool invocation.

        Args:
            tool_name: Name of the tool being invoked.
            private_key_pem: PEM-encoded ECDSA private key (ES256).
            timestamp: Unix timestamp (default: now).
            nonce: Random nonce (default: generated).
            jti: JWT ID (default: generated).

        Returns:
            PassportPoP envelope with signature.
        """
        if timestamp is None:
            timestamp = time.time()
        if nonce is None:
            nonce = secrets.token_urlsafe(32)
        if jti is None:
            jti = f"pp-{secrets.token_hex(16)}"

        challenge = PassportPoPGenerator.create_challenge(timestamp, tool_name, nonce)

        # Load private key and sign
        from cryptography.hazmat.primitives import serialization
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None,
            backend=default_backend(),
        )

        signature_der = private_key.sign(challenge, ec.ECDSA(hashes.SHA256()))

        # Convert DER to base64url (no padding)
        import base64
        signature_b64 = base64.urlsafe_b64encode(signature_der).decode("ascii").rstrip("=")

        return PassportPoP(
            jti=jti,
            nonce=nonce,
            timestamp=timestamp,
            tool_name=tool_name,
            signature=signature_b64,
        )


class PassportPoPVerifier:
    """Verify PoP signatures and prevent replay attacks."""

    def __init__(self, timestamp_tolerance_seconds: float = 30.0):
        """
        Initialize verifier.

        Args:
            timestamp_tolerance_seconds: Maximum age of a valid PoP challenge.
        """
        self.timestamp_tolerance_seconds = timestamp_tolerance_seconds
        self._seen_jtis: Set[str] = set()

    def verify(
        self,
        pop: PassportPoP,
        public_key_pem: str,
        current_time: Optional[float] = None,
        expected_tool_name: Optional[str] = None,
    ) -> tuple[bool, str]:
        """
        Verify a PoP signature.

        Args:
            pop: PassportPoP envelope to verify.
            public_key_pem: PEM-encoded ECDSA public key (from passport cnf.jwk or metadata).
            current_time: Current Unix timestamp (default: now).
            expected_tool_name: Expected tool name (optional, for extra validation).

        Returns:
            (valid: bool, reason: str) tuple.
                - (True, "") if valid
                - (False, reason) if invalid
        """
        if current_time is None:
            current_time = time.time()

        # Check JTI replay
        if pop.jti in self._seen_jtis:
            return False, "passport_pop_jti_already_seen"

        # Check timestamp freshness
        age = abs(current_time - pop.timestamp)
        if age > self.timestamp_tolerance_seconds:
            return False, f"passport_pop_timestamp_too_old: age={age:.1f}s > {self.timestamp_tolerance_seconds}s"

        # Check tool name if provided
        if expected_tool_name is not None and pop.tool_name != expected_tool_name:
            return False, f"passport_pop_tool_name_mismatch: expected={expected_tool_name}, got={pop.tool_name}"

        # Verify signature
        try:
            from cryptography.hazmat.primitives import serialization
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode("utf-8"),
                backend=default_backend(),
            )
        except Exception as e:
            return False, f"passport_pop_invalid_public_key: {str(e)}"

        challenge = PassportPoPGenerator.create_challenge(
            pop.timestamp, pop.tool_name, pop.nonce
        )

        # Convert base64url signature back to DER
        import base64
        try:
            # Add padding
            sig_b64 = pop.signature + "=" * (4 - len(pop.signature) % 4)
            signature_der = base64.urlsafe_b64decode(sig_b64)
        except Exception as e:
            return False, f"passport_pop_signature_decode_failed: {str(e)}"

        try:
            public_key.verify(signature_der, challenge, ec.ECDSA(hashes.SHA256()))
        except Exception as e:
            return False, f"passport_pop_signature_invalid: {str(e)}"

        # Record JTI to prevent replay
        self._seen_jtis.add(pop.jti)

        return True, ""

    def clear_seen_jtis(self) -> None:
        """Clear the JTI seen-set (use with caution)."""
        self._seen_jtis.clear()


def extract_public_key_from_cnf(cnf_claim: Dict[str, Any]) -> Optional[str]:
    """
    Extract public key (in PEM or JWK format) from cnf claim.

    Args:
        cnf_claim: The 'cnf' claim dict from passport.

    Returns:
        Public key as PEM string, or None if not found.
    """
    if not cnf_claim:
        return None

    jwk = cnf_claim.get("jwk")
    if not jwk:
        return None

    # If JWK is already a PEM string, return it
    if isinstance(jwk, str) and jwk.startswith("-----BEGIN"):
        return jwk

    # If JWK is a dict, try to convert it to PEM
    if isinstance(jwk, dict):
        try:
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            from cryptography.hazmat.backends import default_backend
            # Try to use PyJWT's JWK handling
            from jwt.algorithms import ECAlgorithm
            key = ECAlgorithm.from_jwk(jwk)
            # Export to PEM
            from cryptography.hazmat.primitives import serialization
            pem = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            return pem.decode("utf-8")
        except Exception:
            return None

    return None


def create_cnf_claim(public_key_pem: str) -> Dict[str, Any]:
    """
    Create a cnf (confirmation) claim for a passport.

    Args:
        public_key_pem: PEM-encoded ECDSA public key.

    Returns:
        cnf claim dict with jwk.
    """
    # Try to load as JWK first
    try:
        from jwt.algorithms import ECAlgorithm
        from cryptography.hazmat.primitives import serialization

        # If it's already a PEM string, load it and convert to JWK
        if isinstance(public_key_pem, str) and public_key_pem.startswith("-----BEGIN"):
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            from cryptography.hazmat.backends import default_backend
            key = load_pem_public_key(
                public_key_pem.encode("utf-8"),
                backend=default_backend(),
            )
            jwk = ECAlgorithm.to_jwk(key)
            if isinstance(jwk, bytes):
                jwk = json.loads(jwk.decode("utf-8"))
            elif isinstance(jwk, str):
                jwk = json.loads(jwk)
            return {"jwk": jwk}
    except Exception:
        pass

    # Fallback: store as PEM string
    return {"jwk": public_key_pem}
