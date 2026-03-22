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
- **Merkle-chain audit logs** (v2.1) -- cryptographically tamper-evident audit trail with SHA256 chain hashing
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
| `on_merkle_root_finalized` | callable | None | Callback when merkle root is finalized (v2.1) |

### Properties & Methods (v2.1)

**Merkle-Chain Audit Trail:**

```python
# Get the merkle root (single tamper-evident hash of entire audit trail)
root = handler.merkle_root  # str or None

# Verify the entire audit chain is intact
is_valid = handler.verify_audit_chain()  # bool

# Sign the merkle root for external publication
signed_root = handler.sign_merkle_root()  # dict with signature

# Access full audit log with cryptographic hashes
log = handler.audit_log  # [{timestamp, event, passport_id, action, entry_hash, previous_entry_hash, ...}, ...]
```

**Example: Export merkle root for tamper-detection service**

```python
handler = MCPSCallbackHandler(
    passport=signed_passport,
    authority_public_key=authority_keys["public_key"],
    private_key=agent_keys["private_key"],
    on_merkle_root_finalized=lambda root, signature: print(f"Root: {root}\nSig: {signature}"),
)

# ... run agent/chain ...

# Sign and export merkle root
signed_root = handler.sign_merkle_root()
# Send signed_root to IPFS, blockchain, or audit service for tamper-evident proof
```

### `with_mcps(chain, passport, authority_public_key, **kwargs)`

Convenience wrapper. Returns an `MCPSChainWrapper` with `.invoke()`, `.ainvoke()`, `.stream()`, `.batch()`.

---

## v2.1: Merkle-Chain Audit Logs

Each audit entry is cryptographically linked to the previous entry via SHA256 hashing, forming a tamper-evident chain. The **merkle root** (hash of the last entry) is a single value that can be signed and published to prove the audit trail hasn't been modified.

### How It Works

```
Entry 1: {timestamp, event, ...} → hash(entry_1) = hash_1
Entry 2: {timestamp, event, previous_hash: hash_1, ...} → hash(entry_2 + hash_1) = hash_2
Entry 3: {timestamp, event, previous_hash: hash_2, ...} → hash(entry_3 + hash_2) = hash_3 ← merkle_root
```

If any entry is tampered with, the chain breaks and `verify_audit_chain()` returns False.

### Use Cases

1. **Compliance auditing** -- Export merkle root to prove audit trail integrity
2. **Tamper detection** -- Call `verify_audit_chain()` to detect modifications
3. **Third-party verification** -- Sign merkle root and publish (IPFS, blockchain, etc.)
4. **Forensic proof** -- Cryptographic proof that logs haven't been altered

### Backward Compatibility

v2.1 is fully backward compatible with v1.0:
- v1.0 passports (no capabilities) still work
- v1.0 audit logs still accessible via `handler.audit_log`
- v2.1 just adds hash fields to each entry


