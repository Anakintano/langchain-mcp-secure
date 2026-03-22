"""
v2.3 delegation chain tests.

Covers:
  - DelegationToken creation + capability intersection
  - JWT encode / decode / signature verification
  - All 6 verification steps in DelegationTokenValidator
  - QuotaPool shared rate limiting
  - MCPSCallbackHandler integration (delegation mode)
  - Regression: v1.0-v2.2 paths unaffected
"""

import time
import pytest
import jwt as pyjwt

from mcp_secure import generate_key_pair, create_passport, sign_passport, TRUST_LEVELS

from langchain_mcps import MCPSCallbackHandler
from langchain_mcps.delegation import (
    DelegationToken,
    DelegationTokenValidator,
    DelegationVerificationResult,
    QuotaPool,
    intersect_capabilities,
)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_passport(trust_level=None, capabilities=None):
    """Create a signed passport, optionally with capabilities."""
    authority = generate_key_pair()
    agent = generate_key_pair()
    passport = create_passport(
        name="test-agent",
        version="1.0.0",
        public_key=agent["public_key"],
        ttl_days=365,
    )
    if trust_level is not None:
        passport["trust_level"] = trust_level
    if capabilities is not None:
        passport["capabilities"] = capabilities
    signed = sign_passport(passport, authority["private_key"])
    return signed, authority, agent


def _make_delegation_token(
    delegator_pair,
    delegatee_id,
    delegator_id,
    delegator_caps,
    requested_caps,
    ttl_seconds=1800,
):
    """Create and sign a delegation token."""
    token = DelegationToken.create(
        delegator_agent_id=delegator_id,
        delegatee_agent_id=delegatee_id,
        delegator_capabilities=delegator_caps,
        requested_capabilities=requested_caps,
        ttl_seconds=ttl_seconds,
    )
    return token, token.to_jwt(delegator_pair["private_key"])


_DELEGATOR_CAPS = {
    "database_read": {
        "allowed": True,
        "constraints": {"allowed_tables": ["customers", "orders", "payments"]},
    },
    "search": {"allowed": True, "constraints": {}},
}

_REQUESTED_SUBSET = {
    "database_read": {
        "allowed": True,
        "constraints": {"allowed_tables": ["customers"]},
    },
}


# ══ Token Creation ═══════════════════════════════════════════════════════════


class TestDelegationTokenCreation:

    def test_create_returns_token(self):
        delegator = generate_key_pair()
        token = DelegationToken.create(
            delegator_agent_id="agent-a",
            delegatee_agent_id="agent-b",
            delegator_capabilities=_DELEGATOR_CAPS,
            requested_capabilities=_REQUESTED_SUBSET,
        )
        assert token.iss == "agent-a"
        assert token.sub == "agent-b"
        assert token.aud == "langchain-mcps"
        assert token.delegation_depth == 1
        assert token.max_delegation_depth == 1
        assert token.parent_passport_id == "agent-a"

    def test_capability_intersection_restricts_tables(self):
        """B requests customers — gets only customers (subset of A's 3 tables)."""
        token = DelegationToken.create(
            delegator_agent_id="a",
            delegatee_agent_id="b",
            delegator_capabilities=_DELEGATOR_CAPS,
            requested_capabilities=_REQUESTED_SUBSET,
        )
        caps = token.capabilities
        assert "database_read" in caps
        assert caps["database_read"]["allowed"] is True
        assert caps["database_read"]["constraints"]["allowed_tables"] == ["customers"]

    def test_capability_intersection_blocks_escalation(self):
        """B requests a table A doesn't have — intersection is empty → escalation blocked."""
        requested = {
            "database_read": {
                "allowed": True,
                "constraints": {"allowed_tables": ["secrets"]},  # A doesn't have this
            }
        }
        token = DelegationToken.create(
            delegator_agent_id="a",
            delegatee_agent_id="b",
            delegator_capabilities=_DELEGATOR_CAPS,
            requested_capabilities=requested,
        )
        # Intersection of {"customers","orders","payments"} ∩ {"secrets"} = {}
        assert token.capabilities["database_read"]["constraints"]["allowed_tables"] == []

    def test_create_raises_for_tool_not_in_delegator(self):
        """Requesting a tool A doesn't have at all raises ValueError."""
        with pytest.raises(ValueError, match="not authorized"):
            DelegationToken.create(
                delegator_agent_id="a",
                delegatee_agent_id="b",
                delegator_capabilities=_DELEGATOR_CAPS,
                requested_capabilities={"admin_tool": {"allowed": True, "constraints": {}}},
            )

    def test_create_raises_for_denied_tool(self):
        """Requesting a tool that is allowed=False in delegator raises ValueError."""
        delegator_caps = {"secret_tool": {"allowed": False, "constraints": {}}}
        with pytest.raises(ValueError, match="denied"):
            DelegationToken.create(
                delegator_agent_id="a",
                delegatee_agent_id="b",
                delegator_capabilities=delegator_caps,
                requested_capabilities={"secret_tool": {"allowed": True, "constraints": {}}},
            )

    def test_rate_limit_intersection_takes_minimum(self):
        """Min(delegator, requested) rate limit wins."""
        delegator_caps = {
            "api": {"allowed": True, "constraints": {"rate_limit": {"value": 100, "window": "hour"}}}
        }
        requested = {
            "api": {"allowed": True, "constraints": {"rate_limit": {"value": 200, "window": "hour"}}}
        }
        token = DelegationToken.create("a", "b", delegator_caps, requested)
        rl = token.capabilities["api"]["constraints"]["rate_limit"]
        assert rl["value"] == 100  # min(100, 200) = 100

    def test_ttl_default_30_minutes(self):
        before = time.time()
        token = DelegationToken.create("a", "b", _DELEGATOR_CAPS, _REQUESTED_SUBSET)
        assert token.exp - token.iat == pytest.approx(1800, abs=2)

    def test_jti_unique_per_token(self):
        t1 = DelegationToken.create("a", "b", _DELEGATOR_CAPS, _REQUESTED_SUBSET)
        t2 = DelegationToken.create("a", "b", _DELEGATOR_CAPS, _REQUESTED_SUBSET)
        assert t1.jti != t2.jti

    def test_to_dict_roundtrip(self):
        token = DelegationToken.create("a", "b", _DELEGATOR_CAPS, _REQUESTED_SUBSET)
        d = token.to_dict()
        assert d["iss"] == "a"
        assert d["sub"] == "b"
        assert "capabilities" in d
        assert "jti" in d


# ══ JWT Encoding / Decoding ═══════════════════════════════════════════════════


class TestJWTEncoding:

    def test_encode_decode_roundtrip(self):
        pair = generate_key_pair()
        token = DelegationToken.create("a", "b", _DELEGATOR_CAPS, _REQUESTED_SUBSET)
        jwt_str = token.to_jwt(pair["private_key"])
        decoded = DelegationToken.from_jwt(jwt_str, pair["public_key"])
        assert decoded.iss == token.iss
        assert decoded.sub == token.sub
        assert decoded.jti == token.jti
        assert decoded.capabilities == token.capabilities

    def test_wrong_key_raises_invalid_signature(self):
        pair_a = generate_key_pair()
        pair_b = generate_key_pair()
        token = DelegationToken.create("a", "b", _DELEGATOR_CAPS, _REQUESTED_SUBSET)
        jwt_str = token.to_jwt(pair_a["private_key"])
        with pytest.raises(pyjwt.InvalidSignatureError):
            DelegationToken.from_jwt(jwt_str, pair_b["public_key"])

    def test_tampered_payload_raises(self):
        """Modifying the JWT payload invalidates the signature."""
        pair = generate_key_pair()
        token = DelegationToken.create("a", "b", _DELEGATOR_CAPS, _REQUESTED_SUBSET)
        jwt_str = token.to_jwt(pair["private_key"])
        # Tamper: flip a char in the payload (middle section)
        parts = jwt_str.split(".")
        payload_b64 = parts[1]
        tampered = payload_b64[:-4] + "XXXX"
        tampered_jwt = ".".join([parts[0], tampered, parts[2]])
        with pytest.raises(Exception):  # DecodeError or InvalidSignatureError
            DelegationToken.from_jwt(tampered_jwt, pair["public_key"])

    def test_uses_es256_algorithm(self):
        pair = generate_key_pair()
        token = DelegationToken.create("a", "b", _DELEGATOR_CAPS, _REQUESTED_SUBSET)
        jwt_str = token.to_jwt(pair["private_key"])
        header = pyjwt.get_unverified_header(jwt_str)
        assert header["alg"] == "ES256"


# ══ Verification Steps ════════════════════════════════════════════════════════


class TestVerificationSteps:
    """Two tests per step (pass + fail)."""

    def setup_method(self):
        self.delegator = generate_key_pair()
        self.delegatee = generate_key_pair()
        self.token = DelegationToken.create(
            delegator_agent_id="passport-a",
            delegatee_agent_id="passport-b",
            delegator_capabilities=_DELEGATOR_CAPS,
            requested_capabilities=_REQUESTED_SUBSET,
        )
        self.jwt_str = self.token.to_jwt(self.delegator["private_key"])
        self.validator = DelegationTokenValidator()

    def _verify(self, token_jwt=None, pub_key=None, delegatee_id=None,
                delegator_pid=None, tool=None, current_time=None):
        return self.validator.verify(
            token_jwt=token_jwt or self.jwt_str,
            delegator_public_key=pub_key or self.delegator["public_key"],
            delegatee_agent_id=delegatee_id or "passport-b",
            delegator_passport_id=delegator_pid or "passport-a",
            requested_tool=tool or "database_read",
            current_time=current_time or self.token.iat + 1,
        )

    # Step 2: JWT structure
    def test_step2_valid_jwt_passes(self):
        result = self._verify()
        assert result.valid is True

    def test_step2_malformed_jwt_rejected(self):
        result = self._verify(token_jwt="not.a.jwt")
        assert result.valid is False
        assert "jwt" in result.reason.lower()

    def test_step2_wrong_algorithm_rejected(self):
        # Create a token signed with HS256 instead of ES256
        hs_token = pyjwt.encode({"alg": "HS256", "sub": "x"}, "secret", algorithm="HS256")
        result = self._verify(token_jwt=hs_token)
        assert result.valid is False

    # Step 3: Signature
    def test_step3_valid_signature_passes(self):
        result = self._verify()
        assert result.valid is True

    def test_step3_invalid_signature_rejected(self):
        other = generate_key_pair()
        result = self._verify(pub_key=other["public_key"])
        assert result.valid is False
        assert "invalid_delegation_signature" in result.reason

    # Step 4a: TTL
    def test_step4_expired_token_rejected(self):
        # Create token that has already expired
        expired_token = DelegationToken.create(
            "passport-a", "passport-b", _DELEGATOR_CAPS, _REQUESTED_SUBSET, ttl_seconds=1
        )
        jwt_str = expired_token.to_jwt(self.delegator["private_key"])
        result = self.validator.verify(
            token_jwt=jwt_str,
            delegator_public_key=self.delegator["public_key"],
            delegatee_agent_id="passport-b",
            delegator_passport_id="passport-a",
            requested_tool="database_read",
            current_time=expired_token.exp + 10,  # 10 seconds after expiry
        )
        assert result.valid is False
        assert "expired" in result.reason

    def test_step4_future_dated_rejected(self):
        result = self._verify(current_time=self.token.iat - 100)  # 100s before iat
        assert result.valid is False
        assert "future_dated" in result.reason

    # Step 4b: Replay prevention
    def test_step4_first_use_allowed(self):
        v = DelegationTokenValidator()
        result = v.verify(
            token_jwt=self.jwt_str,
            delegator_public_key=self.delegator["public_key"],
            delegatee_agent_id="passport-b",
            delegator_passport_id="passport-a",
            requested_tool="database_read",
            current_time=self.token.iat + 1,
        )
        assert result.valid is True

    def test_step4_replay_rejected(self):
        v = DelegationTokenValidator()
        # First use consumes the JTI
        v.verify(
            token_jwt=self.jwt_str,
            delegator_public_key=self.delegator["public_key"],
            delegatee_agent_id="passport-b",
            delegator_passport_id="passport-a",
            requested_tool="database_read",
            current_time=self.token.iat + 1,
        )
        # Second use is a replay
        result = v.verify(
            token_jwt=self.jwt_str,
            delegator_public_key=self.delegator["public_key"],
            delegatee_agent_id="passport-b",
            delegator_passport_id="passport-a",
            requested_tool="database_read",
            current_time=self.token.iat + 2,
        )
        assert result.valid is False
        assert "replayed" in result.reason

    # Step 4c: Revocation
    def test_step4_revoked_token_rejected(self):
        v = DelegationTokenValidator()
        v.revoke_token(self.token.jti)
        result = v.verify(
            token_jwt=self.jwt_str,
            delegator_public_key=self.delegator["public_key"],
            delegatee_agent_id="passport-b",
            delegator_passport_id="passport-a",
            requested_tool="database_read",
            current_time=self.token.iat + 1,
        )
        assert result.valid is False
        assert "revoked" in result.reason

    # Step 5: Capability intersection
    def test_step5_allowed_tool_passes(self):
        result = self._verify(tool="database_read")
        assert result.valid is True

    def test_step5_tool_not_in_token_rejected(self):
        result = self._verify(tool="admin_panel")
        assert result.valid is False
        assert "tool_not_delegated" in result.reason

    # Step 6: Chain validation
    def test_step6_correct_subject_passes(self):
        result = self._verify(delegatee_id="passport-b")
        assert result.valid is True

    def test_step6_subject_mismatch_rejected(self):
        result = self._verify(delegatee_id="intruder-c")
        assert result.valid is False
        assert "subject_mismatch" in result.reason

    def test_step6_parent_id_mismatch_rejected(self):
        result = self._verify(delegator_pid="wrong-parent")
        assert result.valid is False
        assert "parent_id_mismatch" in result.reason

    def test_step6_depth_exceeded_rejected(self):
        """Token depth > max_delegation_depth is rejected."""
        token = DelegationToken(
            iss="passport-a",
            sub="passport-b",
            aud="langchain-mcps",
            iat=time.time(),
            exp=time.time() + 1800,
            jti="dt-depth-test",
            act={"sub": "passport-b"},
            capabilities={"database_read": {"allowed": True, "constraints": {}}},
            parent_passport_id="passport-a",
            delegation_depth=5,        # depth > max
            max_delegation_depth=1,
        )
        jwt_str = token.to_jwt(self.delegator["private_key"])
        result = self.validator.verify(
            token_jwt=jwt_str,
            delegator_public_key=self.delegator["public_key"],
            delegatee_agent_id="passport-b",
            delegator_passport_id="passport-a",
            requested_tool="database_read",
            current_time=token.iat + 1,
        )
        assert result.valid is False
        assert "depth_exceeded" in result.reason


# ══ Constraint Intersection ═══════════════════════════════════════════════════


class TestConstraintIntersection:

    def test_intersection_subset_tables(self):
        result = intersect_capabilities(
            {"db": {"allowed": True, "constraints": {"allowed_tables": ["a", "b", "c"]}}},
            {"db": {"allowed": True, "constraints": {"allowed_tables": ["b", "c", "d"]}}},
        )
        assert sorted(result["db"]["constraints"]["allowed_tables"]) == ["b", "c"]

    def test_intersection_empty_when_no_overlap(self):
        result = intersect_capabilities(
            {"db": {"allowed": True, "constraints": {"allowed_tables": ["a"]}}},
            {"db": {"allowed": True, "constraints": {"allowed_tables": ["z"]}}},
        )
        assert result["db"]["constraints"]["allowed_tables"] == []

    def test_intersection_rate_limit_min_wins(self):
        result = intersect_capabilities(
            {"api": {"allowed": True, "constraints": {"rate_limit": {"value": 10, "window": "hour"}}}},
            {"api": {"allowed": True, "constraints": {"rate_limit": {"value": 50, "window": "minute"}}}},
        )
        rl = result["api"]["constraints"]["rate_limit"]
        assert rl["value"] == 10
        assert rl["window"] == "hour"  # delegator's window wins

    def test_delegator_constraint_propagates_when_not_in_request(self):
        """Delegator's constraint propagates even if not in requested caps."""
        result = intersect_capabilities(
            {"tool": {"allowed": True, "constraints": {"max_rows_per_query": 100}}},
            {"tool": {"allowed": True, "constraints": {}}},
        )
        assert result["tool"]["constraints"]["max_rows_per_query"] == 100

    def test_multiple_tools_intersected(self):
        delegator = {
            "search": {"allowed": True, "constraints": {}},
            "db": {"allowed": True, "constraints": {"allowed_tables": ["x", "y"]}},
        }
        requested = {
            "search": {"allowed": True, "constraints": {}},
            "db": {"allowed": True, "constraints": {"allowed_tables": ["y", "z"]}},
        }
        result = intersect_capabilities(delegator, requested)
        assert "search" in result
        assert result["db"]["constraints"]["allowed_tables"] == ["y"]


# ══ Quota Pool ════════════════════════════════════════════════════════════════


class TestQuotaPool:

    def test_within_limit_allowed(self):
        pool = QuotaPool()
        ok, reason, remaining = pool.check_and_decrement("agent-a", "tool", 5, "hour", 1000.0)
        assert ok is True
        assert remaining == 4

    def test_exhaustion_rejected(self):
        pool = QuotaPool()
        for i in range(3):
            pool.check_and_decrement("agent-a", "tool", 3, "hour", 1000.0 + i)
        ok, reason, remaining = pool.check_and_decrement("agent-a", "tool", 3, "hour", 1003.0)
        assert ok is False
        assert remaining == 0
        assert "Quota exhausted" in reason

    def test_zero_limit_never_allows(self):
        pool = QuotaPool()
        ok, _, _ = pool.check_and_decrement("agent-a", "tool", 0, "hour", 1000.0)
        assert ok is False

    def test_shared_across_delegates(self):
        """Agent-b and agent-c share agent-a's quota pool."""
        pool = QuotaPool()
        # Both delegates use the SAME parent pool key
        pool.check_and_decrement("agent-a", "db", 3, "hour", 1000.0)  # delegate-b uses 1
        pool.check_and_decrement("agent-a", "db", 3, "hour", 1001.0)  # delegate-c uses 1
        # 2 used → 1 remaining
        ok, _, remaining = pool.check_and_decrement("agent-a", "db", 3, "hour", 1002.0)
        assert ok is True
        assert remaining == 0
        # 4th call exhausted
        ok2, _, _ = pool.check_and_decrement("agent-a", "db", 3, "hour", 1003.0)
        assert ok2 is False

    def test_window_reset(self):
        pool = QuotaPool()
        # Use up quota in first window
        for i in range(3):
            pool.check_and_decrement("a", "t", 3, "second", 1000.0 + i * 0.1)
        ok_before, _, _ = pool.check_and_decrement("a", "t", 3, "second", 1000.9)
        assert ok_before is False
        # Jump to next window (> 1 second later)
        ok_after, _, _ = pool.check_and_decrement("a", "t", 3, "second", 1002.0)
        assert ok_after is True

    def test_get_remaining_does_not_decrement(self):
        pool = QuotaPool()
        pool.check_and_decrement("a", "t", 10, "hour", 1000.0)
        remaining = pool.get_remaining("a", "t", 10, "hour", 1001.0)
        assert remaining == 9
        # Still 9 (not decremented again)
        remaining2 = pool.get_remaining("a", "t", 10, "hour", 1002.0)
        assert remaining2 == 9

    def test_different_tools_independent_pools(self):
        pool = QuotaPool()
        for i in range(2):
            pool.check_and_decrement("a", "tool_x", 2, "hour", float(i))
        # tool_x exhausted
        ok_x, _, _ = pool.check_and_decrement("a", "tool_x", 2, "hour", 3.0)
        assert ok_x is False
        # tool_y independent
        ok_y, _, _ = pool.check_and_decrement("a", "tool_y", 2, "hour", 3.0)
        assert ok_y is True


# ══ Callback Integration ══════════════════════════════════════════════════════


class TestCallbackIntegration:

    def _setup_delegation(self, delegatee_caps=None):
        """Build a delegator passport, delegatee passport, token, and handler."""
        delegator_passport, delegator_authority, delegator_agent = _make_passport(
            capabilities=_DELEGATOR_CAPS
        )
        delegatee_passport, delegatee_authority, delegatee_agent = _make_passport(
            capabilities=delegatee_caps
        )

        delegator_id = delegator_passport["passport_id"]
        delegatee_id = delegatee_passport["passport_id"]

        token = DelegationToken.create(
            delegator_agent_id=delegator_id,
            delegatee_agent_id=delegatee_id,
            delegator_capabilities=_DELEGATOR_CAPS,
            requested_capabilities=_REQUESTED_SUBSET,
        )
        token_jwt = token.to_jwt(delegator_agent["private_key"])

        handler = MCPSCallbackHandler(
            passport=delegatee_passport,
            authority_public_key=delegatee_authority["public_key"],
            delegation_token_jwt=token_jwt,
            delegator_passport=delegator_passport,
        )
        return handler, token, delegatee_passport

    def test_valid_delegation_allows_tool(self):
        """Valid token → on_tool_start succeeds."""
        handler, token, _ = self._setup_delegation()
        handler.on_tool_start({"name": "database_read"}, "query")
        assert handler.is_verified is True

    def test_valid_delegation_logged_in_audit(self):
        """Delegation verification logged in merkle chain."""
        handler, token, _ = self._setup_delegation()
        handler.on_tool_start({"name": "database_read"}, "query")
        log = handler.audit_log
        assert any("delegation_verified" in e.get("event", "") for e in log)
        assert handler.verify_audit_chain() is True

    def test_tool_not_in_token_raises(self):
        """Tool not covered by delegation token → PermissionError."""
        handler, token, _ = self._setup_delegation()
        with pytest.raises(PermissionError, match="tool_not_delegated"):
            handler.on_tool_start({"name": "admin_panel"}, "data")

    def test_expired_delegation_token_raises(self):
        """Expired delegation token → PermissionError."""
        delegator_passport, delegator_authority, delegator_agent = _make_passport(
            capabilities=_DELEGATOR_CAPS
        )
        delegatee_passport, delegatee_authority, _ = _make_passport()
        delegator_id = delegator_passport["passport_id"]
        delegatee_id = delegatee_passport["passport_id"]

        token = DelegationToken.create(
            delegator_agent_id=delegator_id,
            delegatee_agent_id=delegatee_id,
            delegator_capabilities=_DELEGATOR_CAPS,
            requested_capabilities=_REQUESTED_SUBSET,
            ttl_seconds=1,
        )
        token_jwt = token.to_jwt(delegator_agent["private_key"])

        handler = MCPSCallbackHandler(
            passport=delegatee_passport,
            authority_public_key=delegatee_authority["public_key"],
            delegation_token_jwt=token_jwt,
            delegator_passport=delegator_passport,
            current_time_provider=lambda: token.exp + 100,  # 100s after expiry
        )
        with pytest.raises(PermissionError, match="expired"):
            handler.on_tool_start({"name": "database_read"}, "q")

    def test_wrong_delegator_key_raises(self):
        """Token signed by unknown key → invalid_delegation_signature."""
        delegator_passport, delegator_authority, _ = _make_passport(capabilities=_DELEGATOR_CAPS)
        delegatee_passport, delegatee_authority, _ = _make_passport()
        impostor = generate_key_pair()

        token = DelegationToken.create(
            delegator_agent_id=delegator_passport["passport_id"],
            delegatee_agent_id=delegatee_passport["passport_id"],
            delegator_capabilities=_DELEGATOR_CAPS,
            requested_capabilities=_REQUESTED_SUBSET,
        )
        # Signed with impostor key but delegator_passport carries real public key
        token_jwt = token.to_jwt(impostor["private_key"])

        handler = MCPSCallbackHandler(
            passport=delegatee_passport,
            authority_public_key=delegatee_authority["public_key"],
            delegation_token_jwt=token_jwt,
            delegator_passport=delegator_passport,
        )
        with pytest.raises(PermissionError, match="invalid_delegation_signature"):
            handler.on_tool_start({"name": "database_read"}, "q")

    def test_delegation_rejected_logged_in_audit(self):
        """Rejection by delegation validator is still logged in audit chain."""
        delegator_passport, delegator_authority, _ = _make_passport(capabilities=_DELEGATOR_CAPS)
        delegatee_passport, delegatee_authority, _ = _make_passport()
        impostor = generate_key_pair()

        token = DelegationToken.create(
            delegator_agent_id=delegator_passport["passport_id"],
            delegatee_agent_id=delegatee_passport["passport_id"],
            delegator_capabilities=_DELEGATOR_CAPS,
            requested_capabilities=_REQUESTED_SUBSET,
        )
        token_jwt = token.to_jwt(impostor["private_key"])  # bad sig

        handler = MCPSCallbackHandler(
            passport=delegatee_passport,
            authority_public_key=delegatee_authority["public_key"],
            delegation_token_jwt=token_jwt,
            delegator_passport=delegator_passport,
        )
        with pytest.raises(PermissionError):
            handler.on_tool_start({"name": "database_read"}, "q")

        log = handler.audit_log
        assert any(e.get("action") == "rejected" for e in log)
        assert handler.verify_audit_chain() is True

    def test_delegation_merkle_root_signable(self):
        """Full delegation flow → merkle root is signable."""
        delegator_passport, _, delegator_agent = _make_passport(capabilities=_DELEGATOR_CAPS)
        delegatee_passport, delegatee_authority, delegatee_agent = _make_passport()
        delegator_id = delegator_passport["passport_id"]
        delegatee_id = delegatee_passport["passport_id"]

        token = DelegationToken.create(
            delegator_agent_id=delegator_id,
            delegatee_agent_id=delegatee_id,
            delegator_capabilities=_DELEGATOR_CAPS,
            requested_capabilities=_REQUESTED_SUBSET,
        )
        token_jwt = token.to_jwt(delegator_agent["private_key"])

        handler = MCPSCallbackHandler(
            passport=delegatee_passport,
            authority_public_key=delegatee_authority["public_key"],
            private_key=delegatee_agent["private_key"],
            delegation_token_jwt=token_jwt,
            delegator_passport=delegator_passport,
        )
        handler.on_chain_start({"id": ["test"]}, {})
        handler.on_tool_start({"name": "database_read"}, "q")
        handler.on_chain_end({"output": "done"})

        assert handler.verify_audit_chain() is True
        signed = handler.sign_merkle_root()
        assert signed is not None
        assert "mcps" in signed


# ══ Regression: v1.0-v2.2 paths unaffected ════════════════════════════════════


class TestRegression:

    def test_v1_passport_no_delegation_unaffected(self):
        """v1.0 passport without delegation_token_jwt still works normally."""
        passport, authority, _ = _make_passport()
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
        )
        handler.on_chain_start({"id": ["test"]}, {})
        handler.on_tool_start({"name": "any_tool"}, "query")
        assert handler.is_verified is True

    def test_v2_capabilities_without_delegation_unaffected(self):
        """v2.0 capability enforcement still works when no delegation token."""
        caps = {"search": {"allowed": True, "constraints": {}}}
        passport, authority, _ = _make_passport(capabilities=caps)
        handler = MCPSCallbackHandler(
            passport=passport,
            authority_public_key=authority["public_key"],
        )
        handler.on_tool_start({"name": "search"}, "q")
        assert handler.is_verified is True

        with pytest.raises(PermissionError, match="tool_not_allowed"):
            handler.on_tool_start({"name": "forbidden_tool"}, "q")

    def test_existing_86_tests_baseline(self):
        """Canary: ensure existing test infrastructure is intact."""
        from langchain_mcps import MCPSCallbackHandler, CapabilitySchema, CapabilityEnforcer
        assert MCPSCallbackHandler is not None
        assert CapabilitySchema is not None
        assert CapabilityEnforcer is not None
