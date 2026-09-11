#!/usr/bin/env python3
"""
Bravo6 Report Function -- Regression Suite
=====================================================================
Matches the project's existing per-component convention (each scout,
main_scanner.py, and src/api/test_api_gateway.py carry their own --test
unittest suite). Run directly:

    python3 test_report_function.py [--test]

No real network, Cosmos DB, or Entra call is made anywhere in this file:
JWTs are signed with a locally-generated RSA keypair and served through a
PyJWKClient subclass that overrides fetch_data() instead of hitting a
real JWKS endpoint (identical pattern to src/api/test_api_gateway.py);
the Cosmos container is a unittest.mock object.
"""
import argparse
import json
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt import PyJWKClient
from jwt.algorithms import RSAAlgorithm

sys.path.insert(0, str(Path(__file__).parent))

from azure.cosmos import exceptions as cosmos_exceptions
import function_app

# ------------------------------------------------------------------------------
# Shared JWT test fixtures (identical shape to test_api_gateway.py's)
# ------------------------------------------------------------------------------
ISSUER = "https://bravo6ciam.ciamlogin.com/test-tenant/v2.0"
AUDIENCE = "test-report-audience"
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


def _make_token(sub="user-123", iss=ISSUER, aud=AUDIENCE, expires_in=300):
    now = int(time.time())
    claims = {"sub": sub, "iss": iss, "aud": aud, "iat": now, "exp": now + expires_in}
    return jwt.encode(claims, _private_key, algorithm="RS256", headers={"kid": KID})


def _cosmos_not_found():
    """A CosmosResourceNotFoundError, close enough to the real SDK's
    shape for read_item's side_effect (matches how a real 404 from a
    point read is raised)."""
    return cosmos_exceptions.CosmosResourceNotFoundError(status_code=404, message="not found")


# ------------------------------------------------------------------------------
# Fixture documents -- one per _derive_status() input shape
# ------------------------------------------------------------------------------
def _job_doc(user_id="user-123", scan_id="scan-1", status="queued"):
    """Shape src/api/scan_job.py's ScanJob.to_dict() writes."""
    return {"id": scan_id, "scanId": scan_id, "user_id": user_id, "url": "https://example.com",
            "submitted_at": "2026-09-11T00:00:00+00:00", "status": status}


def _result_doc(user_id="user-123", scan_id="scan-1"):
    """Shape main_scanner.py's normal-completion final_result carries --
    deliberately includes "user_id" (see function_app.py's module
    docstring: this is the CORRECT intended shape once the upstream
    Worker/API scanId-correlation gap is fixed, not today's actual
    output verbatim)."""
    return {
        "id": scan_id, "scanId": scan_id, "user_id": user_id, "url": "https://example.com",
        "score": 85, "grade": "B", "total_findings": 2, "findings": [], "tests": {},
        "errors": [], "errors_count": 0, "waf": None, "page_is_representative": True,
    }


def _blocked_doc(user_id="user-123", scan_id="scan-1"):
    """Shape main_scanner.py's blocked_ssrf early exit carries."""
    return {"id": scan_id, "scanId": scan_id, "user_id": user_id, "url": "https://example.com",
            "status": "blocked_ssrf", "ssrf_block_reason": "private IP", "score": None,
            "findings": [], "tests": {}}


class ReportFunctionTests(unittest.TestCase):
    # -------------------- status route: all four states --------------------
    def test_status_pending_for_queued_doc(self):
        container = MagicMock()
        container.read_item.return_value = _job_doc(status="queued")
        status, body = function_app.handle_status_request(
            authorization_header=f"Bearer {_make_token()}", scan_id="scan-1",
            jwks_client=_JWKS_CLIENT, issuer=ISSUER, audience=AUDIENCE, cosmos_container=container,
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "Pending")

    def test_status_running_when_doc_says_so(self):
        container = MagicMock()
        container.read_item.return_value = _job_doc(status="running")
        status, body = function_app.handle_status_request(
            authorization_header=f"Bearer {_make_token()}", scan_id="scan-1",
            jwks_client=_JWKS_CLIENT, issuer=ISSUER, audience=AUDIENCE, cosmos_container=container,
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "Running")

    def test_status_complete_for_result_shaped_doc(self):
        container = MagicMock()
        container.read_item.return_value = _result_doc()
        status, body = function_app.handle_status_request(
            authorization_header=f"Bearer {_make_token()}", scan_id="scan-1",
            jwks_client=_JWKS_CLIENT, issuer=ISSUER, audience=AUDIENCE, cosmos_container=container,
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "Complete")

    def test_status_failed_for_blocked_ssrf_doc(self):
        container = MagicMock()
        container.read_item.return_value = _blocked_doc()
        status, body = function_app.handle_status_request(
            authorization_header=f"Bearer {_make_token()}", scan_id="scan-1",
            jwks_client=_JWKS_CLIENT, issuer=ISSUER, audience=AUDIENCE, cosmos_container=container,
        )
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "Failed")

    # -------------------- full-result route --------------------
    def test_result_owner_gets_200_html_when_complete(self):
        container = MagicMock()
        container.read_item.return_value = _result_doc(user_id="user-123")
        status, content_type, body = function_app.handle_result_request(
            authorization_header=f"Bearer {_make_token(sub='user-123')}", scan_id="scan-1",
            jwks_client=_JWKS_CLIENT, issuer=ISSUER, audience=AUDIENCE, cosmos_container=container,
        )
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "text/html")
        self.assertIn("example.com", body)
        self.assertIn("<html", body.lower())

    def test_result_different_user_gets_403(self):
        container = MagicMock()
        container.read_item.return_value = _result_doc(user_id="user-123")
        status, content_type, body = function_app.handle_result_request(
            authorization_header=f"Bearer {_make_token(sub='someone-else')}", scan_id="scan-1",
            jwks_client=_JWKS_CLIENT, issuer=ISSUER, audience=AUDIENCE, cosmos_container=container,
        )
        self.assertEqual(status, 403)
        self.assertEqual(content_type, "application/json")
        self.assertEqual(json.loads(body)["error"], "forbidden")

    def test_result_nonexistent_scan_gets_404(self):
        container = MagicMock()
        container.read_item.side_effect = _cosmos_not_found()
        status, content_type, body = function_app.handle_result_request(
            authorization_header=f"Bearer {_make_token()}", scan_id="does-not-exist",
            jwks_client=_JWKS_CLIENT, issuer=ISSUER, audience=AUDIENCE, cosmos_container=container,
        )
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body)["error"], "scan not found")

    def test_result_before_complete_gets_409_with_current_status(self):
        """Explicit assertion for the Step 2 decision: calling /report/result
        before status reaches Complete is a 409 carrying the current status,
        not a silent 200 or an unrelated error."""
        container = MagicMock()
        container.read_item.return_value = _job_doc(status="queued")
        status, content_type, body = function_app.handle_result_request(
            authorization_header=f"Bearer {_make_token()}", scan_id="scan-1",
            jwks_client=_JWKS_CLIENT, issuer=ISSUER, audience=AUDIENCE, cosmos_container=container,
        )
        self.assertEqual(status, 409)
        self.assertEqual(content_type, "application/json")
        parsed = json.loads(body)
        self.assertEqual(parsed["error"], "scan not complete")
        self.assertEqual(parsed["status"], "Pending")

    # -------------------- shared auth/validation gate --------------------
    def test_missing_auth_header_gets_401(self):
        container = MagicMock()
        status, body = function_app.handle_status_request(
            authorization_header=None, scan_id="scan-1",
            jwks_client=_JWKS_CLIENT, issuer=ISSUER, audience=AUDIENCE, cosmos_container=container,
        )
        self.assertEqual(status, 401)
        container.read_item.assert_not_called()

    def test_wrong_audience_gets_401(self):
        container = MagicMock()
        status, body = function_app.handle_status_request(
            authorization_header=f"Bearer {_make_token(aud='wrong-audience')}", scan_id="scan-1",
            jwks_client=_JWKS_CLIENT, issuer=ISSUER, audience=AUDIENCE, cosmos_container=container,
        )
        self.assertEqual(status, 401)
        container.read_item.assert_not_called()

    def test_missing_scan_id_gets_400(self):
        container = MagicMock()
        status, body = function_app.handle_status_request(
            authorization_header=f"Bearer {_make_token()}", scan_id=None,
            jwks_client=_JWKS_CLIENT, issuer=ISSUER, audience=AUDIENCE, cosmos_container=container,
        )
        self.assertEqual(status, 400)
        container.read_item.assert_not_called()

    def test_status_route_also_enforces_ownership(self):
        """Step 2's decision extends JWT + ownership to /report/status too,
        not just /report/result -- this is the regression test for that."""
        container = MagicMock()
        container.read_item.return_value = _job_doc(user_id="user-123")
        status, body = function_app.handle_status_request(
            authorization_header=f"Bearer {_make_token(sub='someone-else')}", scan_id="scan-1",
            jwks_client=_JWKS_CLIENT, issuer=ISSUER, audience=AUDIENCE, cosmos_container=container,
        )
        self.assertEqual(status, 403)


def build_arg_parser():
    parser = argparse.ArgumentParser(description="Bravo6 Report Function regression suite")
    parser.add_argument("--test", action="store_true", help="Accepted for CI-invocation consistency; always runs the suite.")
    return parser


if __name__ == "__main__":
    build_arg_parser().parse_args()
    sys.argv = [sys.argv[0]]
    unittest.main()
