"""
langchain-mcps -- MCPS (MCP Secure) integration for LangChain.
Cryptographic identity, trust verification, and audit logging for AI agents.

Copyright (c) 2026 CyberSecAI Ltd. All rights reserved.
License: MIT
"""

from .callback import MCPSCallbackHandler
from .middleware import MCPSChainWrapper, with_mcps
from .capabilities import CapabilitySchema, CapabilityValidator, CapabilityEnforcer, Constraint, RateLimitWindow
from .delegation import (
    DelegationToken, DelegationTokenValidator, DelegationVerificationResult,
    QuotaPool, intersect_capabilities, QuotaBackend, InMemoryQuotaBackend, QuotaExhausted,
)
from .anomaly_detector import AnomalyDetector, AnomalySignal
from .viral_detector import ViralDetector
from .passport_pop import (
    PassportPoP, PassportCnf, PassportPoPGenerator, PassportPoPVerifier,
    create_cnf_claim, extract_public_key_from_cnf,
)

__version__ = "0.2.5"
__all__ = [
    "MCPSCallbackHandler",
    "MCPSChainWrapper",
    "with_mcps",
    "CapabilitySchema",
    "CapabilityValidator",
    "CapabilityEnforcer",
    "Constraint",
    "RateLimitWindow",
    "DelegationToken",
    "DelegationTokenValidator",
    "DelegationVerificationResult",
    "QuotaPool",
    "intersect_capabilities",
    "QuotaBackend",
    "InMemoryQuotaBackend",
    "QuotaExhausted",
    "AnomalyDetector",
    "AnomalySignal",
    "PassportPoP",
    "PassportCnf",
    "PassportPoPGenerator",
    "PassportPoPVerifier",
    "create_cnf_claim",
    "extract_public_key_from_cnf",
]
