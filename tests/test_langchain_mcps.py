"""Tests for langchain-mcps integration."""

import time
import pytest
from unittest.mock import MagicMock, patch
from mcp_secure import (
    generate_key_pair,
    create_passport,
    sign_passport,
    TRUST_LEVELS,
)
from langchain_mcps import MCPSCallbackHandler, MCPSChainWrapper, with_mcps


# ── Fixtures ──


def _make_passport(trust_level=None, expired=False):
    """Create a signed passport for testing."""
    authority = generate_key_pair()
    agent = generate_key_pair()
    passport = create_passport(
        name="test-agent",
        version="1.0.0",
        public_key=agent["public_key"],
        ttl_days=-1 if expired else 365,
    )
    if trust_level is not None:
        passport["trust_level"] = trust_level
    signed = sign_passport(passport, authority["private_key"])
    return signed, authority, agent


# ── Callback Handler Tests ──


class TestMCPSCallbackHandler:

    def test_verified_passport_passes(self):
        passport, authority, agent = _make_passport()
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
        )
        handler.on_chain_start({"id": ["test_chain"]}, {"input": "hello"})
        assert handler.is_verified is True

    def test_invalid_signature_rejects(self):
        passport, authority, agent = _make_passport()
        other = generate_key_pair()
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=other["public_key"],  # wrong key
        )
        with pytest.raises(PermissionError, match="invalid_signature"):
            handler.on_chain_start({"id": ["test"]}, {})

    def test_expired_passport_rejects(self):
        passport, authority, agent = _make_passport(expired=True)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
        )
        with pytest.raises(PermissionError, match="expired"):
            handler.on_chain_start({"id": ["test"]}, {})

    def test_insufficient_trust_rejects(self):
        passport, authority, agent = _make_passport(trust_level=1)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            min_trust_level=TRUST_LEVELS["AUDITED"],  # level 4
        )
        with pytest.raises(PermissionError, match="insufficient_trust"):
            handler.on_chain_start({"id": ["test"]}, {})

    def test_tool_start_verifies(self):
        passport, authority, agent = _make_passport()
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
        )
        handler.on_tool_start({"name": "search"}, "query")
        assert handler.is_verified is True

    def test_agent_action_verifies(self):
        passport, authority, agent = _make_passport()
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
        )
        action = MagicMock()
        action.tool = "calculator"
        handler.on_agent_action(action)
        assert handler.is_verified is True

    def test_on_verified_callback_fires(self):
        passport, authority, agent = _make_passport()
        verified_calls = []
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            on_verified=lambda pid, evt: verified_calls.append((pid, evt)),
        )
        handler.on_chain_start({"id": ["test"]}, {})
        assert len(verified_calls) == 1
        assert verified_calls[0][1] == "chain_start"

    def test_on_rejected_callback_fires(self):
        passport, authority, agent = _make_passport()
        other = generate_key_pair()
        rejected_calls = []
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=other["public_key"],
            on_rejected=lambda pid, reason: rejected_calls.append(reason),
        )
        with pytest.raises(PermissionError):
            handler.on_chain_start({"id": ["test"]}, {})
        assert "invalid_signature" in rejected_calls

    def test_signing_actions(self):
        passport, authority, agent = _make_passport()
        actions = []
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            private_key=agent["private_key"],
            on_action=lambda env: actions.append(env),
        )
        handler.on_chain_start({"id": ["test"]}, {})
        assert len(actions) == 1
        assert actions[0]["mcps"] == "1.0.0"

    def test_audit_log_populated(self):
        passport, authority, agent = _make_passport()
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
            private_key=agent["private_key"],
        )
        handler.on_chain_start({"id": ["test"]}, {})
        handler.on_chain_end({"output": "done"})
        log = handler.audit_log
        assert len(log) >= 2
        assert log[-1]["action"] == "completed"

    def test_revocation_check(self):
        passport, authority, agent = _make_passport()
        with patch("langchain_mcps.callback.check_revocation") as mock_rev:
            mock_rev.return_value = {"revoked": True, "reason": "compromised"}
            handler = MCPSCallbackHandler(
                passport=passport,
                authority_public_key=authority["public_key"],
                verify_revocation=True,
            )
            with pytest.raises(PermissionError, match="revoked"):
                handler.on_chain_start({"id": ["test"]}, {})

    def test_skips_re_verification(self):
        """Once verified, subsequent calls don't re-verify."""
        passport, authority, agent = _make_passport()
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
        )
        handler.on_chain_start({"id": ["test"]}, {})
        # Second call should not raise even if we broke the passport
        handler.on_tool_start({"name": "tool"}, "input")
        assert handler.is_verified is True


# ── Middleware Tests ──


class TestMCPSChainWrapper:

    def test_invoke_passes_with_valid_passport(self):
        passport, authority, agent = _make_passport()
        mock_chain = MagicMock()
        mock_chain.invoke.return_value = "result"
        wrapped = MCPSChainWrapper(
            chain=mock_chain,
            passport=passport,
            authority_public_key=authority["public_key"],
        )
        result = wrapped.invoke({"input": "test"})
        assert result == "result"
        mock_chain.invoke.assert_called_once()

    def test_invoke_rejects_invalid_passport(self):
        passport, authority, agent = _make_passport()
        other = generate_key_pair()
        mock_chain = MagicMock()
        wrapped = MCPSChainWrapper(
            chain=mock_chain,
            passport=passport,
            authority_public_key=other["public_key"],
        )
        with pytest.raises(PermissionError):
            wrapped.invoke({"input": "test"})
        mock_chain.invoke.assert_not_called()

    def test_stream_passes_with_valid_passport(self):
        passport, authority, agent = _make_passport()
        mock_chain = MagicMock()
        mock_chain.stream.return_value = iter(["chunk1", "chunk2"])
        wrapped = MCPSChainWrapper(
            chain=mock_chain,
            passport=passport,
            authority_public_key=authority["public_key"],
        )
        chunks = list(wrapped.stream({"input": "test"}))
        assert chunks == ["chunk1", "chunk2"]

    def test_batch_passes_with_valid_passport(self):
        passport, authority, agent = _make_passport()
        mock_chain = MagicMock()
        mock_chain.batch.return_value = ["r1", "r2"]
        wrapped = MCPSChainWrapper(
            chain=mock_chain,
            passport=passport,
            authority_public_key=authority["public_key"],
        )
        results = wrapped.batch([{"input": "a"}, {"input": "b"}])
        assert results == ["r1", "r2"]

    def test_with_mcps_convenience(self):
        passport, authority, agent = _make_passport()
        mock_chain = MagicMock()
        mock_chain.invoke.return_value = "ok"
        wrapped = with_mcps(mock_chain, passport, authority["public_key"])
        assert isinstance(wrapped, MCPSChainWrapper)
        assert wrapped.invoke({"q": "test"}) == "ok"

    def test_caches_verification(self):
        passport, authority, agent = _make_passport()
        mock_chain = MagicMock()
        mock_chain.invoke.return_value = "ok"
        wrapped = MCPSChainWrapper(
            chain=mock_chain,
            passport=passport,
            authority_public_key=authority["public_key"],
        )
        wrapped.invoke({"q": "1"})
        wrapped.invoke({"q": "2"})
        assert mock_chain.invoke.call_count == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
