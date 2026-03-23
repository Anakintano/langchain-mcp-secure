# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✅ Active |
| 0.1.x   | ❌ No longer supported |

---

## Coordinated Vulnerability Disclosure (CVD) Policy

We take security seriously. If you discover a vulnerability in langchain-mcpsecure, please follow this process:

### Response Timeframe

| Action | Timeframe |
|--------|-----------|
| Acknowledgement of report | Within **48 hours** |
| Initial assessment | Within **7 days** |
| Fix or mitigation | Within **30 days** (critical: 7 days) |
| Public disclosure | After fix is released, coordinated with reporter |

We follow a **30-day responsible disclosure** window. We will not request extensions beyond 90 days total.

---

## How to Report a Vulnerability (Private)

**Do NOT open a public GitHub issue for security vulnerabilities.**

### Option 1: GitHub Private Security Advisory (Preferred)
Use GitHub's built-in private reporting:
1. Go to the [Security tab](https://github.com/Anakintano/langchain-mcp-secure/security)
2. Click **"Report a vulnerability"**
3. Fill in the advisory form with details

This keeps the report private until a fix is released.

### Option 2: Email
Send details to the maintainer directly via GitHub profile: [@Anakintano](https://github.com/Anakintano)

### What to Include in Your Report
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact
- Suggested fix (if any)

---

## Public Disclosure of Discovered Vulnerabilities

All confirmed and resolved vulnerabilities are publicly disclosed via:

1. **GitHub Security Advisories** — published after fix is released
   - View at: https://github.com/Anakintano/langchain-mcp-secure/security/advisories

2. **CHANGELOG.md** — security fixes are documented under each release with:
   - CVE number (if assigned)
   - Description of the vulnerability
   - Affected versions
   - Fix version

3. **Release notes** — GitHub release description includes security fix summaries

If a CVE is warranted, we will request one via [MITRE](https://cveform.mitre.org/) or coordinate with GitHub's advisory database.

---

## Security Contacts

| Role | Contact |
|------|---------|
| Maintainer / Security Contact | [@Anakintano](https://github.com/Anakintano) |

---

## Scope

This policy applies to the `langchain-mcpsecure` Python package and its source code at https://github.com/Anakintano/langchain-mcp-secure.

### In Scope
- Security vulnerabilities in `langchain_mcps` core code
- Vulnerabilities in delegation, capability, or audit logic
- Cryptographic implementation issues
- Dependency vulnerabilities that affect this package

### Out of Scope
- Vulnerabilities in upstream dependencies (report to those projects)
- Issues in your own application code that uses this library
- Theoretical attacks without a proof-of-concept

---

## Known Security Properties

langchain-mcpsecure is itself a security library. Its threat model is documented in [README.md](README.md#security-properties). The following properties are explicitly tested and enforced:

- No privilege escalation (capability intersection at protocol level)
- No replay attacks (JTI nonce cache + TTL)
- No token forgery (ECDSA P-256 signature verification)
- No audit log tampering (merkle chain)
