"""
langchain-mcps -- MCPS (MCP Secure) integration for LangChain.
Cryptographic identity, trust verification, and audit logging for AI agents.

Copyright (c) 2026 CyberSecAI Ltd. All rights reserved.
License: MIT
"""

from .callback import MCPSCallbackHandler
from .middleware import MCPSChainWrapper, with_mcps

__version__ = "0.1.0"
__all__ = [
    "MCPSCallbackHandler",
    "MCPSChainWrapper",
    "with_mcps",
]
