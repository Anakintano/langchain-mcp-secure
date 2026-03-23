# Contributing to langchain-mcpsecure

Thank you for your interest in contributing. This guide explains how to contribute code, documentation, and security fixes.

---

## Project Members & Roles

| Member | Role | Responsibilities | Access |
|--------|------|-----------------|--------|
| [@Anakintano](https://github.com/Anakintano) | Maintainer | Architecture, releases, security decisions, PyPI publishing, merge authority | GitHub Admin, PyPI Owner |

For a single-maintainer project, all sensitive access (PyPI token, GitHub admin) is held by the maintainer. Contributors do not receive sensitive resource access until explicitly granted by the maintainer.

---

## Acceptable Contributions

We welcome:
- Bug fixes with test coverage
- Security improvements (please follow [SECURITY.md](SECURITY.md) for vulnerabilities)
- Documentation improvements
- New test cases for edge cases
- v2.4/v2.5 roadmap features (see GitHub Issues [#9–#12](https://github.com/Anakintano/langchain-mcp-secure/issues))

We do not accept:
- Breaking changes to the security model without prior discussion
- Contributions that reduce test coverage below 90%
- Code that introduces external security dependencies without justification
- Changes that bypass the 6-step delegation verification

---

## How to Contribute

### 1. Open an Issue First
For non-trivial changes, open an issue to discuss the approach before writing code.

### 2. Fork & Branch
```bash
git clone https://github.com/Anakintano/langchain-mcp-secure.git
cd langchain-mcp-secure
git checkout -b feature/your-feature-name
```

### 3. Set Up Development Environment
```bash
pip install -e .
pip install pytest pytest-cov pylint mypy bandit
```

### 4. Write Tests
All contributions must include tests. Coverage must not drop below 90%:
```bash
pytest tests/ -v --cov=langchain_mcps --cov-report=term-missing
```

### 5. Run Linting
```bash
pylint langchain_mcps --disable=all --enable=E,F
bandit -r langchain_mcps -ll
```

### 6. Commit with DCO Sign-Off

Every commit MUST include a `Signed-off-by` line asserting that you are legally authorized to make the contribution under the project's MIT license.

```bash
git commit -s -m "your commit message"
```

This adds:
```
Signed-off-by: Your Name <your.email@example.com>
```

**By signing off, you certify that:**
> I have the right to submit this contribution under the open source license indicated in the file. I understand and agree that this project and the contribution are public and that a record of the contribution (including all personal information I submit with it, including my sign-off) is maintained indefinitely and may be redistributed consistent with this project or the open source license(s) involved.

This is the [Developer Certificate of Origin (DCO)](https://developercertificate.org/).

### 7. Open a Pull Request
- Target: `main` branch
- Include: description, motivation, test results
- CI must pass before review

---

## Code Standards

- Python 3.9+ compatible
- Follow existing patterns (no new external dependencies without discussion)
- Security-critical code requires 2 reviewers (if contributors are available)
- No use of `eval()`, `exec()`, or `pickle` in production code

---

## Dependency Policy (OSPS-DO-06.01)

### How Dependencies Are Selected
Dependencies are chosen based on:
1. **Security track record** — no known CVEs in supported versions
2. **Minimal footprint** — prefer stdlib over third-party where possible
3. **Active maintenance** — must have active upstream support
4. **Cryptographic soundness** — cryptographic deps must be audited libraries

### Current Dependencies
| Package | Purpose | Selection Rationale |
|---------|---------|-------------------|
| `mcp-secure>=1.0.0` | ECDSA passport signing | Core identity layer; provides P-256 key generation and signing |
| `langchain-core>=0.2.0` | LangChain integration | Required for callback hooks and chain wrapper |

### How Dependencies Are Obtained
- All dependencies are installed via `pip` from PyPI
- Pinned minimum versions in `pyproject.toml` (no unpinned `*` versions)
- Dependency hashes are tracked via `pip`'s built-in hash checking

### How Dependencies Are Tracked
- `pyproject.toml` declares all required dependencies
- GitHub Dependabot alerts are enabled for the repository
- Any new dependency must be added to `pyproject.toml` and documented in this table

---

## Release Process

Only the maintainer can cut releases. The process:
1. Update version in `pyproject.toml`
2. Update `CHANGELOG.md`
3. Commit and push to `main`
4. Create GitHub release with tag (triggers publish workflow)
5. Verify on PyPI

---

## Questions?

Open a [GitHub issue](https://github.com/Anakintano/langchain-mcp-secure/issues) or contact [@Anakintano](https://github.com/Anakintano).
