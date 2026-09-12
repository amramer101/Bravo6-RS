#!/usr/bin/env python3
"""
DEFERRED (2026-09-12): the auth/quota/scan-job test classes moved here
verbatim from src/api/test_api_gateway.py when auth.py, quota.py, and
scan_job.py moved out of the active API Gateway package -- see
future-work/auth/README.md. Only the import paths changed (these three
modules now live alongside this file instead of in src/api/); the test
bodies are otherwise unmodified from their last active version.

Run directly: python3 test_auth_deferred.py [--test]

No real network or Cosmos DB call is made anywhere in this file: JWTs are
signed with a locally-generated RSA keypair and served through a
PyJWKClient subclass that overrides fetch_data() instead of hitting a
real JWKS endpoint; the Cosmos container is a unittest.mock object.
"""
import argparse
import json
import sys
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWKClient
from jwt.algorithms import RSAAlgorithm

sys.path.insert(0, str(Path(__file__).parent))

from auth import AuthError, extract_bearer_token, validate_jwt
from quota import MAX_SCANS_PER_WINDOW, WINDOW_SECONDS, check_quota
from scan_job import (
    ScanJobWriteError,
    count_recent_scans_for_user,
    new_scan_job,
    write_scan_job,
)
from azure.cosmos import exceptions as cosmos_exceptions


# ------------------------------------------------------------------------------
# Shared JWT test fixtures
# ------------------------------------------------------------------------------
ISSUER = "https://bravo6ciam.ciamlogin.com/test-tenant/v2.0"
AUDIENCE = "test-api-audience"
KID = "test-key-1"

_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_public_key = _private_key.public_key()


class _StaticJWKSClient(PyJWKClient):
    """Test-only PyJWKClient: returns a fixed JWKS document built from
    the module-level test keypair instead of making an HTTP request."""

    def __init__(self, jwks: dict):
        self._jwks = jwks
        super().__init__(uri="https://unused.invalid/jwks")

    def fetch_data(self):
        return self._jwks


def _build_jwks() -> dict:
    jwk = json.loads(RSAAlgorithm.to_jwk(_public_key))
    jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
    return {"keys": [jwk]}


_JWKS_CLIENT = _StaticJWKSClient(_build_jwks())


def _make_token(
    sub="user-123",
    iss=ISSUER,
    aud=AUDIENCE,
    expires_in=300,
    kid=KID,
    key=None,
    algorithm="RS256",
    extra_claims=None,
) -> str:
    now = int(time.time())
    claims = {"sub": sub, "iss": iss, "aud": aud, "exp": now + expires_in, "iat": now}
    if extra_claims:
        claims.update(extra_claims)
    headers = {"kid": kid} if kid else {}
    return jwt.encode(claims, key or _private_key, algorithm=algorithm, headers=headers)


# ------------------------------------------------------------------------------
# JWT validation
# ------------------------------------------------------------------------------
class TestAuth(unittest.TestCase):
    def test_valid_token_extracts_subject(self):
        token = _make_token()
        user = validate_jwt(token, _JWKS_CLIENT, ISSUER, AUDIENCE)
        self.assertEqual(user.subject, "user-123")

    def test_expired_token_rejected(self):
        token = _make_token(expires_in=-10)
        with self.assertRaises(AuthError):
            validate_jwt(token, _JWKS_CLIENT, ISSUER, AUDIENCE)

    def test_wrong_audience_rejected(self):
        token = _make_token(aud="someone-elses-app")
        with self.assertRaises(AuthError):
            validate_jwt(token, _JWKS_CLIENT, ISSUER, AUDIENCE)

    def test_wrong_issuer_rejected(self):
        token = _make_token(iss="https://not-our-tenant.example/v2.0")
        with self.assertRaises(AuthError):
            validate_jwt(token, _JWKS_CLIENT, ISSUER, AUDIENCE)

    def test_bad_signature_rejected(self):
        """Signed with a DIFFERENT keypair than the one in the JWKS --
        same kid claimed, wrong key entirely (a forged/tampered token)."""
        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        token = _make_token(key=other_key)
        with self.assertRaises(AuthError):
            validate_jwt(token, _JWKS_CLIENT, ISSUER, AUDIENCE)

    def test_malformed_token_rejected(self):
        with self.assertRaises(AuthError):
            validate_jwt("not-a-jwt-at-all", _JWKS_CLIENT, ISSUER, AUDIENCE)

    def test_missing_subject_claim_rejected(self):
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": AUDIENCE, "exp": now + 300, "iat": now}
        token = jwt.encode(claims, _private_key, algorithm="RS256", headers={"kid": KID})
        with self.assertRaises(AuthError):
            validate_jwt(token, _JWKS_CLIENT, ISSUER, AUDIENCE)

    def test_empty_token_rejected(self):
        with self.assertRaises(AuthError):
            validate_jwt("", _JWKS_CLIENT, ISSUER, AUDIENCE)

    def test_extract_bearer_token_happy_path(self):
        self.assertEqual(extract_bearer_token("Bearer abc.def.ghi"), "abc.def.ghi")

    def test_extract_bearer_token_missing_header(self):
        with self.assertRaises(AuthError):
            extract_bearer_token(None)

    def test_extract_bearer_token_wrong_scheme(self):
        with self.assertRaises(AuthError):
            extract_bearer_token("Basic abc.def.ghi")


# ------------------------------------------------------------------------------
# Quota enforcement
# ------------------------------------------------------------------------------
class TestQuota(unittest.TestCase):
    def test_under_limit_allowed(self):
        decision = check_quota("user-1", lambda uid, ws: MAX_SCANS_PER_WINDOW - 1)
        self.assertTrue(decision.allowed)

    def test_at_limit_blocked(self):
        """count == limit must already be blocked (limit is a ceiling on
        submissions allowed, not the (limit+1)th one)."""
        decision = check_quota("user-1", lambda uid, ws: MAX_SCANS_PER_WINDOW)
        self.assertFalse(decision.allowed)

    def test_over_limit_blocked(self):
        decision = check_quota("user-1", lambda uid, ws: MAX_SCANS_PER_WINDOW + 5)
        self.assertFalse(decision.allowed)

    def test_zero_count_allowed(self):
        decision = check_quota("user-1", lambda uid, ws: 0)
        self.assertTrue(decision.allowed)

    def test_window_start_is_within_configured_window(self):
        captured = {}

        def _count(uid, window_start):
            captured["window_start"] = window_start
            return 0

        check_quota("user-1", _count)
        age = datetime.now(timezone.utc) - captured["window_start"]
        self.assertAlmostEqual(age.total_seconds(), WINDOW_SECONDS, delta=5)

    def test_count_recent_scans_for_user_queries_cosmos_correctly(self):
        container = MagicMock()
        container.query_items.return_value = iter([3])
        window_start = datetime.now(timezone.utc) - timedelta(seconds=WINDOW_SECONDS)
        count = count_recent_scans_for_user("user-1", window_start, container)
        self.assertEqual(count, 3)
        container.query_items.assert_called_once()
        _, kwargs = container.query_items.call_args
        self.assertTrue(kwargs.get("enable_cross_partition_query"))


# ------------------------------------------------------------------------------
# Cosmos DB scan-job write (retry + local fallback)
# ------------------------------------------------------------------------------
class TestScanJobWrite(unittest.TestCase):
    def test_new_scan_job_has_matching_id_and_partition_key(self):
        job = new_scan_job("user-1", "https://example.com")
        self.assertEqual(job.id, job.scanId)
        self.assertEqual(job.status, "queued")

    def test_write_success_first_attempt(self):
        container = MagicMock()
        job = new_scan_job("user-1", "https://example.com")
        write_scan_job(job, container)
        container.create_item.assert_called_once()

    def test_write_retries_then_succeeds(self):
        container = MagicMock()
        container.create_item.side_effect = [
            cosmos_exceptions.CosmosHttpResponseError(status_code=503, message="transient"),
            None,
        ]
        job = new_scan_job("user-1", "https://example.com")
        write_scan_job(job, container)
        self.assertEqual(container.create_item.call_count, 2)

    def test_write_exhausts_retries_still_raises_but_saves_forensic_copy(self):
        """Even though a local forensic copy CAN be written, the write
        must still raise -- quota enforcement queries Cosmos DB directly,
        so a job invisible to Cosmos must not be treated as persisted
        (see write_scan_job()'s docstring for why this differs from the
        Worker's own local-fallback-is-success pattern)."""
        import tempfile

        container = MagicMock()
        container.create_item.side_effect = cosmos_exceptions.CosmosHttpResponseError(
            status_code=500, message="down"
        )
        job = new_scan_job("user-1", "https://example.com")
        with tempfile.TemporaryDirectory() as tmp:
            fallback_dir = Path(tmp)
            with self.assertRaises(ScanJobWriteError):
                write_scan_job(job, container, fallback_dir=fallback_dir)
            fallback_file = fallback_dir / f"scan_job_{job.id}.json"
            self.assertTrue(fallback_file.exists())
            saved = json.loads(fallback_file.read_text())
            self.assertEqual(saved["id"], job.id)
        self.assertEqual(container.create_item.call_count, 3)

    def test_write_fails_and_fallback_also_fails_still_raises(self):
        container = MagicMock()
        container.create_item.side_effect = cosmos_exceptions.CosmosHttpResponseError(
            status_code=500, message="down"
        )
        job = new_scan_job("user-1", "https://example.com")
        # A file (not a directory) at the fallback path forces mkdir() to
        # fail, simulating "the fallback write itself also fails".
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            blocked_path = Path(tmp) / "blocked"
            blocked_path.write_text("not a directory")
            with self.assertRaises(ScanJobWriteError):
                write_scan_job(job, container, fallback_dir=blocked_path)


def build_arg_parser():
    parser = argparse.ArgumentParser(description="Bravo6 deferred auth/quota/scan-job regression suite")
    parser.add_argument("--test", action="store_true", help="Accepted for CI-invocation consistency; always runs the suite.")
    return parser


if __name__ == "__main__":
    build_arg_parser().parse_args()
    sys.argv = [sys.argv[0]]
    unittest.main()
