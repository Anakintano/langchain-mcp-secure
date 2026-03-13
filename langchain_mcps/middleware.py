"""
MCPS Middleware for LangChain.
Wraps any chain/agent with passport verification as a pre-execution gate.
"""

from typing import Any, Dict, Optional
from mcp_secure import (
    verify_passport_signature,
    validate_passport_format,
    is_passport_expired,
    check_revocation,
    TRUST_LEVELS,
)


class MCPSChainWrapper:
    """Wraps a LangChain chain/agent with MCPS passport verification.

    Verification runs once before the first invocation. Subsequent calls
    reuse the cached verification result until the passport expires.

    Args:
        chain: Any LangChain Runnable (chain, agent, etc.)
        passport: Signed passport dict
        authority_public_key: PEM public key of the Trust Authority
        min_trust_level: Minimum trust level required
        verify_revocation: Check live revocation (hits network)
        trust_authority: Trust Authority URL
    """

    def __init__(
        self,
        chain: Any,
        passport: Dict[str, Any],
        authority_public_key: str,
        min_trust_level: int = TRUST_LEVELS["IDENTIFIED"],
        verify_revocation: bool = False,
        trust_authority: str = "https://agentsign.dev",
    ):
        self.chain = chain
        self.passport = passport
        self.authority_public_key = authority_public_key
        self.min_trust_level = min_trust_level
        self.verify_revocation = verify_revocation
        self.trust_authority = trust_authority
        self._verified = False

    def _gate(self):
        """Verify passport before allowing execution."""
        if self._verified:
            if not is_passport_expired(self.passport):
                return
            self._verified = False

        fmt = validate_passport_format(self.passport)
        if not fmt["valid"]:
            raise PermissionError(f"MCPS: {fmt['error']['message']}")

        if not verify_passport_signature(self.passport, self.authority_public_key):
            raise PermissionError("MCPS: Invalid passport signature")

        if self.passport.get("trust_level", 0) < self.min_trust_level:
            raise PermissionError("MCPS: Insufficient trust level")

        if self.verify_revocation:
            pid = self.passport.get("passport_id", "")
            rev = check_revocation(pid, self.trust_authority)
            if rev["revoked"]:
                raise PermissionError("MCPS: Passport revoked")

        self._verified = True

    def invoke(self, input: Any, config: Optional[Dict] = None, **kwargs) -> Any:
        """Verify then invoke the wrapped chain."""
        self._gate()
        return self.chain.invoke(input, config=config, **kwargs)

    async def ainvoke(self, input: Any, config: Optional[Dict] = None, **kwargs) -> Any:
        """Verify then async invoke the wrapped chain."""
        self._gate()
        return await self.chain.ainvoke(input, config=config, **kwargs)

    def stream(self, input: Any, config: Optional[Dict] = None, **kwargs):
        """Verify then stream from the wrapped chain."""
        self._gate()
        return self.chain.stream(input, config=config, **kwargs)

    def batch(self, inputs: list, config: Optional[Dict] = None, **kwargs) -> list:
        """Verify then batch invoke the wrapped chain."""
        self._gate()
        return self.chain.batch(inputs, config=config, **kwargs)


def with_mcps(chain, passport, authority_public_key, **kwargs):
    """Convenience function to wrap any LangChain Runnable with MCPS verification.

    Usage:
        from langchain_mcps import with_mcps
        secure_chain = with_mcps(my_chain, passport, authority_pub_key)
        result = secure_chain.invoke({"question": "hello"})
    """
    return MCPSChainWrapper(chain, passport, authority_public_key, **kwargs)
