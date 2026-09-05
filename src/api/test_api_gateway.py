#!/usr/bin/env python3
"""
Bravo6 API Gateway -- Regression Suite
=====================================================================
Matches the project's existing per-component convention (each scout and
main_scanner.py carries its own `--test` unittest suite). Run directly:

    python3 test_api_gateway.py [--test]

(--test is accepted for consistency with how the other suites are
invoked in CI; this file's only purpose is testing, so it runs the suite
either way.)

No real network, Cosmos DB, Service Bus, or Entra call is made anywhere
in this file: JWTs are signed with a locally-generated RSA keypair and
served through a PyJWKClient subclass that overrides fetch_data() instead
of hitting a real JWKS endpoint (mirrors the OCSP fix's "mock all
outcomes" pattern); Cosmos/Service Bus clients are unittest.mock objects.
"""
import argparse
import contextlib
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
from blocklist import is_blocklisted
from quota import MAX_SCANS_PER_WINDOW, WINDOW_SECONDS, check_quota
from scan_job import (
    ScanJob,
    ScanJobWriteError,
    count_recent_scans_for_user,
    new_scan_job,
    write_scan_job,
)
from servicebus_queue import EnqueueError, build_scan_message, enqueue_scan_job
from azure.cosmos import exceptions as cosmos_exceptions
from azure.servicebus.exceptions import ServiceBusError
import function_app


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
# Step 1 -- JWT validation
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
# Step 2 -- Blocklist enforcement
# ------------------------------------------------------------------------------
class TestBlocklist(unittest.TestCase):
    def test_government_domain_blocked(self):
        self.assertTrue(is_blocklisted("irs.gov"))
        self.assertTrue(is_blocklisted("sub.example.gov.uk"))

    def test_military_domain_blocked(self):
        self.assertTrue(is_blocklisted("defense.mil"))

    def test_educational_domain_blocked(self):
        self.assertTrue(is_blocklisted("mit.edu"))
        self.assertTrue(is_blocklisted("cs.ox.ac.uk"))

    def test_financial_specific_domain_blocked(self):
        self.assertTrue(is_blocklisted("www.jpmorganchase.com"))

    def test_healthcare_specific_domain_blocked(self):
        self.assertTrue(is_blocklisted("www.mayoclinic.org"))
        self.assertTrue(is_blocklisted("digital.nhs.uk"))

    def test_ordinary_domain_not_blocked(self):
        self.assertFalse(is_blocklisted("example.com"))
        self.assertFalse(is_blocklisted("github.com"))

    def test_lookalike_domain_not_falsely_blocked(self):
        """A domain that merely CONTAINS a blocked keyword as a substring
        (not a real suffix/subdomain match) must not be blocked."""
        self.assertFalse(is_blocklisted("notgov.com"))
        self.assertFalse(is_blocklisted("edufake.com"))

    def test_case_and_trailing_dot_insensitive(self):
        self.assertTrue(is_blocklisted("MIT.EDU."))


# ------------------------------------------------------------------------------
# Step 3 -- Quota enforcement
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
# Step 4a -- Cosmos DB scan-job write (retry + local fallback)
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


# ------------------------------------------------------------------------------
# Step 4b -- Service Bus enqueue (retry, worker schema match)
# ------------------------------------------------------------------------------
class TestServiceBusEnqueue(unittest.TestCase):
    def test_message_schema_matches_worker_expectations(self):
        """src/worker/function_app.py's process_scan() does:
        data = json.loads(body); target_url = data.get("url");
        config = data.get("config") if isinstance(data.get("config"), dict) else None.
        The enqueued message must satisfy that exactly."""
        job = new_scan_job("user-1", "https://example.com")
        message = build_scan_message(job)
        body = json.loads(b"".join(message.body).decode("utf-8"))
        self.assertEqual(body["url"], "https://example.com")
        self.assertIn("config", body)
        self.assertIsNone(body["config"])
        self.assertEqual(body["job_id"], job.id)

    def test_enqueue_success_first_attempt(self):
        sender = MagicMock()
        job = new_scan_job("user-1", "https://example.com")
        enqueue_scan_job(job, sender)
        sender.send_messages.assert_called_once()

    def test_enqueue_retries_then_succeeds(self):
        sender = MagicMock()
        sender.send_messages.side_effect = [ServiceBusError("transient"), None]
        job = new_scan_job("user-1", "https://example.com")
        enqueue_scan_job(job, sender)
        self.assertEqual(sender.send_messages.call_count, 2)

    def test_enqueue_persistent_failure_raises_after_retries(self):
        sender = MagicMock()
        sender.send_messages.side_effect = ServiceBusError("down")
        job = new_scan_job("user-1", "https://example.com")
        with self.assertRaises(EnqueueError):
            enqueue_scan_job(job, sender)
        self.assertEqual(sender.send_messages.call_count, 3)


# ------------------------------------------------------------------------------
# handle_scan_request() -- full status-code + side-effect matrix
# ------------------------------------------------------------------------------
class TestHandleScanRequest(unittest.TestCase):
    def _sender_factory(self, sender):
        return lambda: contextlib.nullcontext(sender)

    def test_401_missing_authorization_header_no_side_effects(self):
        container = MagicMock()
        sender = MagicMock()
        status, _ = function_app.handle_scan_request(
            authorization_header=None,
            url="https://example.com",
            jwks_client=_JWKS_CLIENT,
            issuer=ISSUER,
            audience=AUDIENCE,
            cosmos_container=container,
            get_service_bus_sender=self._sender_factory(sender),
        )
        self.assertEqual(status, 401)
        container.create_item.assert_not_called()
        sender.send_messages.assert_not_called()

    def test_401_invalid_token_no_side_effects(self):
        container = MagicMock()
        sender = MagicMock()
        status, _ = function_app.handle_scan_request(
            authorization_header="Bearer not-a-real-token",
            url="https://example.com",
            jwks_client=_JWKS_CLIENT,
            issuer=ISSUER,
            audience=AUDIENCE,
            cosmos_container=container,
            get_service_bus_sender=self._sender_factory(sender),
        )
        self.assertEqual(status, 401)
        container.create_item.assert_not_called()
        sender.send_messages.assert_not_called()

    def test_403_blocklisted_target_no_side_effects(self):
        container = MagicMock()
        sender = MagicMock()
        token = _make_token()
        status, _ = function_app.handle_scan_request(
            authorization_header=f"Bearer {token}",
            url="https://irs.gov",
            jwks_client=_JWKS_CLIENT,
            issuer=ISSUER,
            audience=AUDIENCE,
            cosmos_container=container,
            get_service_bus_sender=self._sender_factory(sender),
        )
        self.assertEqual(status, 403)
        container.create_item.assert_not_called()
        sender.send_messages.assert_not_called()

    def test_429_quota_exceeded_no_side_effects(self):
        container = MagicMock()
        container.query_items.return_value = iter([MAX_SCANS_PER_WINDOW])
        sender = MagicMock()
        token = _make_token()
        status, body = function_app.handle_scan_request(
            authorization_header=f"Bearer {token}",
            url="https://example.com",
            jwks_client=_JWKS_CLIENT,
            issuer=ISSUER,
            audience=AUDIENCE,
            cosmos_container=container,
            get_service_bus_sender=self._sender_factory(sender),
        )
        self.assertEqual(status, 429)
        container.create_item.assert_not_called()
        sender.send_messages.assert_not_called()

    def test_202_happy_path_writes_and_enqueues(self):
        container = MagicMock()
        container.query_items.return_value = iter([0])
        sender = MagicMock()
        token = _make_token()
        status, body = function_app.handle_scan_request(
            authorization_header=f"Bearer {token}",
            url="https://example.com",
            jwks_client=_JWKS_CLIENT,
            issuer=ISSUER,
            audience=AUDIENCE,
            cosmos_container=container,
            get_service_bus_sender=self._sender_factory(sender),
        )
        self.assertEqual(status, 202)
        self.assertIn("job_id", body)
        container.create_item.assert_called_once()
        sender.send_messages.assert_called_once()

    def test_503_cosmos_write_failure(self):
        container = MagicMock()
        container.query_items.return_value = iter([0])
        container.create_item.side_effect = cosmos_exceptions.CosmosHttpResponseError(
            status_code=500, message="down"
        )
        sender = MagicMock()
        token = _make_token()
        status, _ = function_app.handle_scan_request(
            authorization_header=f"Bearer {token}",
            url="https://example.com",
            jwks_client=_JWKS_CLIENT,
            issuer=ISSUER,
            audience=AUDIENCE,
            cosmos_container=container,
            get_service_bus_sender=self._sender_factory(sender),
        )
        self.assertEqual(status, 503)
        sender.send_messages.assert_not_called()

    def test_503_persistent_enqueue_failure_after_cosmos_write_succeeds(self):
        container = MagicMock()
        container.query_items.return_value = iter([0])
        sender = MagicMock()
        sender.send_messages.side_effect = ServiceBusError("down")
        token = _make_token()
        status, _ = function_app.handle_scan_request(
            authorization_header=f"Bearer {token}",
            url="https://example.com",
            jwks_client=_JWKS_CLIENT,
            issuer=ISSUER,
            audience=AUDIENCE,
            cosmos_container=container,
            get_service_bus_sender=self._sender_factory(sender),
        )
        self.assertEqual(status, 503)
        # The write DID happen (this is the documented orphaned-record
        # limitation noted in function_app.py, not a bug being masked).
        container.create_item.assert_called_once()

    def test_transient_enqueue_failure_recovers_to_202(self):
        container = MagicMock()
        container.query_items.return_value = iter([0])
        sender = MagicMock()
        sender.send_messages.side_effect = [ServiceBusError("transient"), None]
        token = _make_token()
        status, _ = function_app.handle_scan_request(
            authorization_header=f"Bearer {token}",
            url="https://example.com",
            jwks_client=_JWKS_CLIENT,
            issuer=ISSUER,
            audience=AUDIENCE,
            cosmos_container=container,
            get_service_bus_sender=self._sender_factory(sender),
        )
        self.assertEqual(status, 202)
        self.assertEqual(sender.send_messages.call_count, 2)

    def test_optional_ssrf_check_blocks_when_injected_and_unsafe(self):
        container = MagicMock()
        sender = MagicMock()
        token = _make_token()
        status, _ = function_app.handle_scan_request(
            authorization_header=f"Bearer {token}",
            url="http://169.254.169.254",
            jwks_client=_JWKS_CLIENT,
            issuer=ISSUER,
            audience=AUDIENCE,
            cosmos_container=container,
            get_service_bus_sender=self._sender_factory(sender),
            ssrf_check=lambda host: False,
        )
        self.assertEqual(status, 403)
        container.create_item.assert_not_called()
        sender.send_messages.assert_not_called()

    def test_optional_ssrf_check_error_does_not_block_request(self):
        """The secondary check erroring must not itself cause a false
        rejection -- only an actual unsafe-address verdict blocks."""
        container = MagicMock()
        container.query_items.return_value = iter([0])
        sender = MagicMock()
        token = _make_token()

        def _broken_check(host):
            raise RuntimeError("DNS resolver unavailable")

        status, _ = function_app.handle_scan_request(
            authorization_header=f"Bearer {token}",
            url="https://example.com",
            jwks_client=_JWKS_CLIENT,
            issuer=ISSUER,
            audience=AUDIENCE,
            cosmos_container=container,
            get_service_bus_sender=self._sender_factory(sender),
            ssrf_check=_broken_check,
        )
        self.assertEqual(status, 202)


def build_arg_parser():
    parser = argparse.ArgumentParser(description="Bravo6 API Gateway regression suite")
    parser.add_argument("--test", action="store_true", help="Accepted for CI-invocation consistency; always runs the suite.")
    return parser


if __name__ == "__main__":
    build_arg_parser().parse_args()
    sys.argv = [sys.argv[0]]
    unittest.main()
