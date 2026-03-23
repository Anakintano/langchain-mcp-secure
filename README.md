# langchain-mcps

[![PyPI version](https://img.shields.io/pypi/v/langchain-mcpsecure.svg)](https://pypi.org/project/langchain-mcpsecure/)
[![OpenSSF Baseline](https://www.bestpractices.dev/projects/12236/baseline)](https://www.bestpractices.dev/projects/12236)

**MCPS (MCP Secure) integration for LangChain** -- cryptographic identity and trust verification for AI agents.

Add zero-trust identity verification to any LangChain agent or chain with one line of code.

## Install

```bash
pip install langchain-mcpsecure
```

## Build from Source

Requirements: Python 3.9+, `git`

```bash
# Clone the repository
git clone https://github.com/Anakintano/langchain-mcp-secure.git
cd langchain-mcp-secure

# Install in editable mode with all dependencies
pip install -e .

# Install development tools (testing, linting)
pip install pytest pytest-cov pylint mypy bandit

# Run tests to verify the build
pytest tests/ -v --cov=langchain_mcps
```

**Required libraries:**
- `mcp-secure>=1.0.0` — ECDSA P-256 passport signing (automatically installed)
- `langchain-core>=0.2.0` — LangChain callback hooks (automatically installed)

See [CONTRIBUTING.md](CONTRIBUTING.md) for dependency selection policy and contributor guide.

---

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

## Security Architecture

langchain-mcps provides 5 progressive security layers, each building on the previous:

```
┌─────────────────────────────────────────────────────┐
│  v2.3: Delegation Chains                            │
│  ↑ Transitive trust (Agent A → Agent B → Tool)      │
├─────────────────────────────────────────────────────┤
│  v2.2: Time-Bound Ephemeral Permissions             │
│  ↑ When can you act? (time windows + approval gates)│
├─────────────────────────────────────────────────────┤
│  v2.1: Merkle-Chain Audit Log                       │
│  ↑ What did you do? (tamper-proof, non-repudiation) │
├─────────────────────────────────────────────────────┤
│  v2.0: Capability-Scoped Passports                  │
│  ↑ What can you do? (least-privilege constraints)   │
├─────────────────────────────────────────────────────┤
│  v1.0: Passport Identity & Verification             │
│  ↑ Who are you? (ECDSA P-256 signature)             │
└─────────────────────────────────────────────────────┘
```

Each layer adds a security guarantee:
- **v1.0:** Authenticate — who are you?
- **v2.0:** Authorize — what can you do?
- **v2.1:** Audit — what did you do?
- **v2.2:** Time-bound — when can you do it?
- **v2.3:** Delegate — can you authorize others?

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

### `DelegationToken` (v2.3)

RFC 8693 JWT carrying agent-to-agent delegation authorization.

| Method | Signature | Description |
|--------|-----------|-------------|
| `create` | `(delegator_id, delegatee_id, delegator_caps, requested_caps, ttl=1800)` | Create token with capability intersection |
| `to_jwt` | `(private_key: str) → str` | Sign and encode as JWT string |
| `from_jwt` | `(token_str, public_key, verify_exp=True, current_time=None)` | Decode and validate JWT |
| `intersect_capabilities` | `(delegator_caps, requested_caps) → dict` | Compute capability intersection |

**Token fields:** `iss`, `sub`, `aud`, `iat`, `exp`, `jti`, `act`, `capabilities`, `parent_passport_id`, `delegation_depth`, `max_delegation_depth`

---

### `DelegationTokenValidator` (v2.3)

Stateful 6-step verification gate with replay prevention.

| Method | Signature | Description |
|--------|-----------|-------------|
| `verify` | `(token_jwt, delegator_public_key, delegatee_agent_id, delegator_passport_id, requested_tool, current_time=None) → DelegationVerificationResult` | Run full 6-step verification |
| `revoke_token` | `(jti: str)` | Add token JTI to revocation list |

**`DelegationVerificationResult` fields:** `valid: bool`, `reason: str`, `token: DelegationToken | None`

---

### `QuotaPool` (v2.3)

Shared sliding-window rate limiter. All delegates of a parent agent share one budget per tool.

| Method | Signature | Description |
|--------|-----------|-------------|
| `check_and_decrement` | `(parent_agent_id, tool_name, limit, window, current_time=None) → (bool, str, int)` | Check quota; returns `(allowed, reason, remaining)` |
| `get_remaining` | `(parent_agent_id, tool_name, limit, window, current_time=None) → int` | Get remaining calls in window |

---

### `intersect_capabilities(delegator_caps, requested_caps) → dict` (v2.3)

Computes capability intersection. The result is always a subset of `delegator_caps` — prevents escalation.

- `allowed_tables`: set intersection
- `rate_limit`: `min(delegator, requested)` per field
- Other constraints: delegator's value wins

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

### How Delegation Works

Token creation, presentation, verification, and execution across 4 phases:

```
PHASE 1: Creation          PHASE 2: Present           PHASE 3: Verify            PHASE 4: Execute & Audit
──────────────────         ─────────────────          ────────────────           ─────────────────────────
Agent A                    Agent B                    MCPSCallbackHandler        System
  │                          │                           │                           │
  ├─ Create JWT token        │                           │                           │
  │  ├─ iss: agent-a         │                           │                           │
  │  ├─ sub: agent-b         │                           │                           │
  │  ├─ exp: +30 min         │                           │                           │
  │  ├─ jti: abc123          │                           │                           │
  │  └─ capabilities:        │                           │                           │
  │     {database_read:      │                           │                           │
  │      [customers]}        │                           │                           │
  │                          │                           │                           │
  ├─ Sign (ECDSA P-256)      │                           │                           │
  │                          │                           │                           │
  └─────── token_jwt ───────→├─ Invoke tool with:       │                           │
                             │  ├─ B's passport         │                           │
                             │  ├─ delegation_token     │                           │
                             │  └─ tool_call            │                           │
                             │                          │                           │
                             └──────────────────────────┤                           │
                                                        ├─ STEP 1: B's passport ✓  │
                                                        ├─ STEP 2: JWT structure ✓  │
                                                        ├─ STEP 3: A's sig ✓        │
                                                        ├─ STEP 4: TTL/nonce ✓      │
                                                        ├─ STEP 5: caps ⊆ A's ✓     │
                                                        ├─ STEP 6: chain depth ✓    │
                                                        │  → ALLOW                  │
                                                        │                           ├─ Execute tool
                                                        │                           │  (database_read,
                                                        │                           │   customers)
                                                        │                           │
                                                        │                           ├─ Append to audit chain:
                                                        │                           │  {action: delegation_used,
                                                        │                           │   agent_b, delegated_from: a,
                                                        │                           │   jti: abc123,
                                                        │                           │   entry_hash: sha256(...)}
                                                        │                           │
                                                        │                           └─ Merkle linked to
                                                        │                              previous_hash
```

The verification gate (Phase 3) is the security-critical path: 6 sequential checks, any failure raises `PermissionError` and logs the rejection to the audit chain before the tool is ever invoked.

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

---

## Security Properties

Each layer prevents a distinct class of threat:

```
Layer              Threat Prevented         Mechanism                          Status
────────────────────────────────────────────────────────────────────────────────────
v1.0  Identity     Impersonation            ECDSA P-256 signature              ✅ Prevents
                                            Only the passport holder can
                                            produce a valid signature

v2.0  Capability   Privilege escalation     Implicit deny + constraints        ✅ Prevents
                                            Tool not listed → rejected
                                            allowed_tables enforced per call

v2.1  Audit        Tampering / denial       SHA256 merkle-chain linking        ✅ Prevents
                                            Modify any entry → chain breaks
                                            verify_chain() returns False

v2.2  Time-bound   Unauthorized timing      Time window + gate enforcement     ✅ Prevents
                                            Outside window → rejected
                                            Gate callback must approve

v2.3  Delegation   Over-delegation          Capability intersection            ✅ Prevents
                                            B's perms ⊆ A's perms (protocol)
                                            B cannot escalate beyond A
```

### Threat Model Coverage

- ✅ **Impersonation** — Agent cannot fake identity (ECDSA signature)
- ✅ **Privilege escalation** — Agent cannot exceed granted permissions (intersection)
- ✅ **Tampering** — Audit trail cannot be modified (merkle chain)
- ✅ **Unauthorized timing** — Agent cannot act outside allowed windows (time checks)
- ✅ **Over-delegation** — Delegatee cannot grant more than delegator has (constraint intersection)
- ✅ **Token forgery** — Delegation token requires delegator's private key (ECDSA P-256)
- ✅ **Replay attacks** — JTI nonce cache + TTL (passports + delegation tokens)

---

## Roadmap

### v2.4 — Enterprise-Scale Delegation

Deferred features for multi-process deployments and agent orchestration.

#### [v2.4.1] Distributed Quota & Nonce Storage (Redis backend) · [#9](https://github.com/Anakintano/langchain-mcp-secure/issues/9)

**Status:** Planned · **Effort:** 1–2 weeks

Current `QuotaPool` and `DelegationTokenValidator._nonce_cache` are in-memory and process-local.
In multi-replica deployments a replayed token can be accepted by a different process.

- Redis-backed `QuotaPool` (atomic `ZADD + ZCOUNT`, survives restarts)
- Redis-backed nonce cache (atomic `SET NX EX`, shared across processes)
- Automatic fallback to in-memory if Redis is unavailable

#### [v2.4.2] Multi-Hop Delegation (A→B→C chains) · [#10](https://github.com/Anakintano/langchain-mcp-secure/issues/10)

**Status:** Planned · **Effort:** 2–3 weeks · **Blocked by:** #9

Enables agent orchestration where Agent B can securely delegate a subset of its work to Agent C.

- Cycle detection — prevents A→B→A loops (DFS over `delegation_chain` field)
- Escalation prevention — B's caps when delegating to C must be ⊆ A's original grant to B
- Configurable max depth (default 1 for MVP, up to 3 hops planned)

### v2.5 — Token-Native Permissions & Async

Fine-grained per-token controls and non-blocking delegation verification.

#### [v2.5.1] Time Windows & Permission Gates in Tokens · [#11](https://github.com/Anakintano/langchain-mcp-secure/issues/11)

**Status:** Planned · **Effort:** 1–2 weeks

Allow A to embed explicit `permission_windows` and `permission_gates` inside the token itself, independent of A's passport. Example: "B may use `database_read` only between 02:00–04:00 tonight, and only if the approver webhook says yes."

- Intersection at token creation (B cannot get a wider window than A's passport allows)
- Window + gate checks added to Step 5 of the verification gate

#### [v2.5.2] Async Delegation Gate (ainvoke support) · [#12](https://github.com/Anakintano/langchain-mcp-secure/issues/12)

**Status:** Planned · **Effort:** 3–4 days

`MCPSChainWrapper.ainvoke()` currently calls synchronous `_gate()`, blocking the event loop.

- `DelegationTokenValidator.verify_async()` — non-blocking 6-step verification
- `QuotaPool.check_and_decrement_async()` — async quota accounting (benefits from v2.4.1 Redis)
- `MCPSChainWrapper._gate_async()` wired into `ainvoke()`, `astream()`, `abatch()`

### Contributing

All roadmap features are open for community contributions.

1. Comment on the linked issue to claim it
2. Open a draft PR early so we can align on approach
3. Reference the issue and this roadmap in your PR description

Current test baseline: **137 tests · 90% coverage** — new features should maintain or improve this.

---

## Project Governance

| Document | Purpose |
|----------|---------|
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributor guide, DCO sign-off, dependency policy, roles & responsibilities |
| [SECURITY.md](SECURITY.md) | CVD policy, private vulnerability reporting, disclosure process |
| [CHANGELOG.md](CHANGELOG.md) | Functional and security changes per release |


