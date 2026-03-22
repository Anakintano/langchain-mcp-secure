# langchain-mcps

**MCPS (MCP Secure) integration for LangChain** -- cryptographic identity and trust verification for AI agents.

Add zero-trust identity verification to any LangChain agent or chain with one line of code.

## Install

```bash
pip install langchain-mcps
```

## Quick Start

### Callback Handler (recommended)

Attach to any LangChain agent or chain via callbacks:

```python
from mcp_secure import generate_key_pair, create_passport, sign_passport
from langchain_mcps import MCPSCallbackHandler

# Generate keys and create a signed passport
authority_keys = generate_key_pair()
agent_keys = generate_key_pair()
passport = create_passport(
    name="my-agent",
    version="1.0.0",
    public_key=agent_keys["public_key"],
)
signed_passport = sign_passport(passport, authority_keys["private_key"])

# Create the handler
handler = MCPSCallbackHandler(
    passport=signed_passport,
    authority_public_key=authority_keys["public_key"],
    private_key=agent_keys["private_key"],  # optional: signs actions
)

# Use with any LangChain chain or agent
result = my_chain.invoke(
    {"question": "What is MCPS?"},
    config={"callbacks": [handler]},
)

# Check verification status and audit log
print(handler.is_verified)  # True
print(handler.audit_log)    # [{timestamp, event, action, ...}, ...]
```

### Middleware Wrapper

Wrap any LangChain Runnable with a verification gate:

```python
from langchain_mcps import with_mcps

secure_chain = with_mcps(my_chain, signed_passport, authority_keys["public_key"])
result = secure_chain.invoke({"question": "hello"})
# Raises PermissionError if passport is invalid, expired, or revoked
```

## Features

- **Identity verification** -- ECDSA P-256 passport verification before any agent action
- **Action signing** -- cryptographically sign every chain/tool invocation
- **Trust levels** -- enforce minimum trust (L0 Unsigned through L4 Audited)
- **Revocation checks** -- optional live revocation via AgentSign Trust Authority
- **Audit trail** -- full log of verified/rejected events
- **Replay protection** -- nonce-based replay attack prevention
- **Zero config** -- works with any LangChain Runnable (chains, agents, tools)

## Trust Levels

| Level | Name | Meaning |
|-------|------|---------|
| L0 | UNSIGNED | No verification |
| L1 | IDENTIFIED | Agent has a passport |
| L2 | VERIFIED | Passport signature verified |
| L3 | SCANNED | Agent code passed OWASP scan |
| L4 | AUDITED | Full security audit completed |

## API

### `MCPSCallbackHandler`

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `passport` | dict | required | Signed agent passport |
| `authority_public_key` | str | required | Trust Authority PEM public key |
| `private_key` | str | None | Agent PEM private key (for signing) |
| `min_trust_level` | int | 1 | Minimum trust level to accept |
| `verify_revocation` | bool | False | Check live revocation status |
| `trust_authority` | str | "https://agentsign.dev" | Trust Authority URL |
| `on_verified` | callable | None | Callback on successful verification |
| `on_rejected` | callable | None | Callback on failed verification |
| `on_action` | callable | None | Callback with signed action envelopes |

### `with_mcps(chain, passport, authority_public_key, **kwargs)`

Convenience wrapper. Returns an `MCPSChainWrapper` with `.invoke()`, `.ainvoke()`, `.stream()`, `.batch()`.


