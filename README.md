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
- **Time-bound ephemeral permissions** (v2.2) -- grant temporary tool access via time windows and event gates
- **Delegation chains** (v2.3) -- agent-to-agent authorization with privilege escalation prevention
- **Audit trail** -- full log of verified/rejected events including delegation events
- **Replay protection** -- nonce-based replay attack prevention (passports + delegation tokens)
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
| `on_permission_gate_triggered` | callable | None | Gate callback `(tool, gate_config) → (bool, str)` (v2.2) |
| `current_time_provider` | callable | `time.time` | Time source override for testing (v2.2) |

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

## v2.2: Time-Bound Ephemeral Permissions

Grant temporary, time-window-based tool access. Tools can be restricted to specific time intervals (e.g., maintenance windows, contractor access, emergency escalations).

### Passport Capabilities Schema (v2.2)

```python
signed_passport["capabilities"] = {
    "database_write": {
        "allowed": True,
        "constraints": {},
        "permission_windows": [
            # Only allowed Saturday 2am-4am UTC
            {"start_time": 1711324800.0, "end_time": 1711332000.0},
        ],
    },
    "send_email": {
        "allowed": True,
        "constraints": {"recipient_domains": ["example.com"]},
        # No permission_windows = always allowed during valid passport
    },
    "escalated_delete": {
        "allowed": True,
        "constraints": {},
        "permission_gates": [
            {"gate_type": "manual_approval", "config": {"approval_required": True}}
        ],
    },
    "file_delete": {"allowed": False},  # Explicitly forbidden
}
```

### Time Windows

- **Interval:** `[start_time, end_time)` — inclusive start, exclusive end
- **Logic:** OR — agent is allowed if current time falls in ANY window
- **No windows field:** tool is always allowed (backward compatible)
- **Empty windows list `[]`:** tool is never allowed

```python
handler = MCPSCallbackHandler(
    passport=signed_passport,
    authority_public_key=authority_keys["public_key"],
    current_time_provider=lambda: time.time(),  # injectable for testing
)
```

### Permission Gates

Gates require an external decision before a tool can be invoked. The `on_permission_gate_triggered` callback must return `(is_allowed: bool, reason: str)`.

```python
def my_approval_gate(tool_name, gate_config):
    approved = approval_service.check(tool_name)
    return approved, "approved" if approved else "awaiting_approval"

handler = MCPSCallbackHandler(
    passport=signed_passport,
    authority_public_key=authority_keys["public_key"],
    on_permission_gate_triggered=my_approval_gate,
)
```

### Implicit Deny (v2.0+)

Any tool **not listed** in a v2.0+ passport's capabilities dict is automatically rejected.

### Backward Compatibility

- v1.0 passports (no capabilities) allow all tools at any time
- v2.0/v2.1 passports without `permission_windows` allow tools at any time
- Only passports with `permission_windows` enforce time restrictions

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

---

## v2.3 Delegation Chains (Agent-to-Agent Authorization)

Agent A can securely delegate limited work to Agent B using time-limited, scoped delegation tokens. B cannot escalate beyond A's permissions — this is enforced at the protocol level by the token structure itself.

### Quick Example

```python
from mcp_secure import generate_key_pair, create_passport, sign_passport
from langchain_mcps import MCPSCallbackHandler
from langchain_mcps.delegation import DelegationToken

# Agent A creates a delegation token for Agent B
delegator_caps = {
    "database_read": {
        "allowed": True,
        "constraints": {"allowed_tables": ["customers", "orders", "payments"]},
    }
}

# B gets access only to "customers" — subset of A's tables
token = DelegationToken.create(
    delegator_agent_id=agent_a_passport["passport_id"],
    delegatee_agent_id=agent_b_passport["passport_id"],
    delegator_capabilities=delegator_caps,
    requested_capabilities={
        "database_read": {
            "allowed": True,
            "constraints": {"allowed_tables": ["customers"]},
        }
    },
    ttl_seconds=1800,   # 30 min
)
token_jwt = token.to_jwt(agent_a_private_key)

# Agent B uses the delegation token
handler = MCPSCallbackHandler(
    passport=agent_b_passport,
    authority_public_key=authority_public_key,
    delegation_token_jwt=token_jwt,
    delegator_passport=agent_a_passport,   # provides A's public key
)
handler.on_tool_start({"name": "database_read"}, "SELECT * FROM customers")
# Tool executes — delegation verified, action audited
```

### 6-Step Verification Gate

Every tool call goes through six security checks:

| Step | Check | What it prevents |
|------|-------|-----------------|
| 1 | Delegatee passport (v1.0) | Unidentified agents |
| 2 | JWT structure + ES256 | Malformed tokens |
| 3 | ECDSA P-256 signature | Forged tokens |
| 4 | TTL + JTI nonce + revocation | Expired/replayed/revoked tokens |
| **5** | **Capability intersection** | **Privilege escalation** |
| 6 | Subject + parent ID + depth | Chain splicing |

Step 5 is the critical security guarantee: the token itself carries `intersection(A's caps, requested scope)`. If B requests a table A doesn't have, the intersection is empty and the request is denied — regardless of what B's own passport says.

### Shared Quota Pool

All of A's delegates share one rate-limit pool, preventing any single delegate from exhausting the parent's budget:

```python
# A has rate_limit=100/hour for database_read
# A delegates to B and C (both use parent pool key)

# B uses 60 calls  → 40 remaining in pool
# C uses 40 calls  → 0 remaining
# Any further calls by B or C are rejected
```

### Audit Trail

All delegation events are merkle-chained in the existing AuditChain:

```
delegation_verified  →  tool_start  →  chain_end
       │                    │               │
    entry_hash ──────── prev_hash    prev_hash
```

Call `handler.verify_audit_chain()` to prove the complete delegation trail is tamper-evident.

### Security Properties

| Threat | Defense |
|--------|---------|
| Privilege escalation | Token caps = intersection (protocol-level, not convention) |
| Token forgery | ECDSA P-256 — requires delegator's private key |
| Replay attack | JTI nonce cache + short TTL (default 30 min) |
| Quota bypass | Shared pool keyed by `(parent_id, tool_name)` |
| Non-repudiation | Merkle-chained audit events with delegation context |

### Design References

Built on proven authorization patterns:
- **AWS IAM policy intersection** — privilege escalation prevention
- **RFC 8693 Token Exchange** — standardized JWT delegation format (used by Azure AD, ZITADEL)
- **SAML AssertionID nonce cache** — replay prevention


