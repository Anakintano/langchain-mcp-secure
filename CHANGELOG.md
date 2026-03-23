# Changelog

All notable changes to langchain-mcps are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] - 2026-03-22

### Added (Features)

#### v2.3: Delegation Chains - Agent-to-Agent Authorization
- **DelegationToken (RFC 8693)**: JWT-based delegation tokens with ECDSA P-256 signatures
  - Capability intersection: B's permissions = intersection(A's ∩ requested scope)
  - Prevents privilege escalation at protocol level
  - TTL-based expiry (configurable, default 30 minutes)
  - JTI (JWT ID) for token uniqueness

- **DelegationTokenValidator**: 6-step verification gate
  - Step 1: Delegatee (B) passport verification
  - Step 2: JWT structure validation
  - Step 3: ECDSA signature verification (using delegator's public key)
  - Step 4: Expiry, replay (JTI nonce cache), and revocation checks
  - Step 5: Capability intersection validation (escalation prevention)
  - Step 6: Delegation chain depth validation

- **QuotaPool**: Shared rate-limiting for delegated work
  - All delegates of agent A share A's quota for each tool
  - Sliding-window counting (configurable window size)
  - Fair allocation across concurrent delegations
  - Per-tool, per-parent-agent tracking

- **Integration with v2.0-v2.2 stack**: Delegation mode in MCPSCallbackHandler
  - When delegation token present: use 6-step verification instead of v2.0 passport checks
  - Audit logging of delegation events (merkle-chained via v2.1)
  - Time-window enforcement (if v2.2 gates configured)
  - Seamless fallback to v2.0/v2.2 when no token present

### Security Improvements

- **Protocol-level privilege escalation prevention**: Capability intersection enforced in token, not just application logic
- **Replay attack mitigation**: JTI nonce cache + TTL + timestamp validation (SAML pattern)
- **Delegation chain integrity**: Merkle-chained audit trail + delegation depth limits
- **Revocation support**: DTRL (Delegation Token Revocation List) for immediate token invalidation
- **Signature verification**: ECDSA P-256 prevents token forgery

### Changed

- `MCPSCallbackHandler.__init__()`: Added `delegation_token_jwt`, `delegator_passport`, `_delegation_validator`
- `MCPSCallbackHandler.on_tool_start()`: Routes to `_verify_delegation()` when token present
- `MCPSChainWrapper.__init__()`: Added delegation token fields
- `MCPSChainWrapper._gate()`: Integrated `_delegation_validator.verify()` per-invocation
- Audit chain: Now logs delegation events with action types (`delegation_verified`, `delegation_rejected`)

### Testing

- **51 new tests** in `tests/test_delegation.py`:
  - 9 tests: Token creation, capability intersection, escalation prevention
  - 4 tests: JWT encoding/decoding, cryptographic verification
  - 18 tests: 6-step verification logic (each step pass + fail cases)
  - 5 tests: Constraint intersection and permission propagation
  - 7 tests: QuotaPool functionality, fair allocation
  - 7 tests: Full callback integration, audit logging
  - 3 tests: Regression (v1.0/v2.0 unaffected, canary import)
- **90% code coverage** across all delegation components
- **137 total tests** (all passing)

### Documentation

- Added `### How Delegation Works` section to README (4-phase lifecycle diagram)
- Added `## Security Properties` section (threat model table, 7-item threat coverage)
- Added `## Roadmap` section with v2.4/v2.5 deferred features (#9-#12 GitHub issues)
- Added ASCII architecture diagram (5-layer stack)

---

## [0.1.0] - 2026-02-28

### Added (Features)

#### v1.0: Identity & Passport Verification
- ECDSA P-256 passport signing and verification
- Agent identity proven via cryptographic signature
- Public key distribution and trust establishment
- Prevents agent impersonation

#### v2.0: Capability-Scoped Permissions
- Passport-embedded capability declarations
- Implicit-deny authorization model (tool not in list = rejected)
- Constraint-based permissions (allowed_tables, rate_limits, etc.)
- Per-agent, per-tool access control
- Capability schema validation

#### v2.1: Merkle-Chain Audit Log
- SHA-256 merkle-linked audit trail
- Cryptographic linking prevents tampering (modify entry → chain breaks)
- Non-repudiation: agent cannot deny actions
- Tool invocation logging (timestamp, agent, tool, payload hash, result hash)
- Merkle root signable for forensics

#### v2.2: Time-Bound Ephemeral Permissions
- Temporary permission grants with time windows (start/end UTC)
- Approval gates: callback-based permission validation
- Time-window enforcement (outside window = rejected)
- Leeway for clock skew (configurable, default 5s)
- Integration with audit chain (time-window entries logged)

### Security Guarantees

- **v1.0**: Identity is cryptographically proven (ECDSA)
- **v2.0**: Agents cannot access tools they don't have permissions for (implicit deny)
- **v2.1**: Audit trail cannot be tampered with (merkle chain)
- **v2.2**: Time-bound permissions cannot be used outside their window
- **Together**: Least-privilege agents with accountability and temporal control

### Integration

- **MCPSCallbackHandler**: Wraps LangChain agent execution
- **MCPSChainWrapper**: Wraps any LangChain Runnable
- **CapabilityEnforcer**: Per-tool permission checks
- **AuditChain**: Event logging and merkle linking
- **Zero code changes** required to LangChain core

### Testing

- **86 tests** across all components:
  - Token creation and validation
  - Capability enforcement
  - Audit chain integrity
  - Time-window logic
  - Integration tests
- **90% code coverage**

### Documentation

- Comprehensive README with examples
- API documentation for all public classes
- Security properties documented
- Threat model outlined

---

## Security Advisories

### Known Limitations (by design)

- **v2.3 In-Memory State**: Nonce cache and quota pool are in-memory. Single-process only. Multi-process deployments need Redis backend (planned for v2.4.1).
- **No Async Support (yet)**: v2.2 approval gates are sync. Async support planned for v2.5.2.
- **Key Management Out of Scope**: Framework assumes agents have secure access to private keys. Use HSMs or key vaults in production.

### Mitigations in Place

- All 5 layers have cryptographic enforcement
- Protocol-level checks prevent application-level bypasses
- Comprehensive test coverage (90%) catches edge cases
- OWASP top 4 threats for agent systems explicitly tested and mitigated

---

## Roadmap

### v2.4: Enterprise Scale (Deferred - GitHub Issues #9-#10)
- Redis-backed QuotaPool + nonce cache (multi-process support)
- Multi-hop delegation (A→B→C chains with transitive trust)
- Effort: 4-6 weeks

### v2.5: Advanced Features (Deferred - GitHub Issues #11-#12)
- Time windows embedded in tokens (temporal scoping at token level)
- Async delegation gate (ainvoke support)
- Effort: 2-3 weeks

---

## Versioning Policy

- **Major (X.0.0)**: Breaking changes to security model or API
- **Minor (0.X.0)**: New security layers (v1.0→v2.0→v2.1, etc.) or features
- **Patch (0.0.X)**: Bug fixes, documentation

All releases are tested at 90%+ coverage and must pass 137+ tests before publication.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on submitting security findings, bug reports, and feature requests.

---

**Questions?** Open an issue on [GitHub](https://github.com/Anakintano/langchain-mcps).
