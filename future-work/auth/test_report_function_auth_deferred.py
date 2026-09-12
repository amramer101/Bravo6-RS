#!/usr/bin/env python3
"""
DEFERRED (2026-09-12): the JWT/ownership-specific test cases moved here
verbatim from src/report/test_report_function.py when Report Function's
auth-gate (report_function_auth_gate.py) and JWT validation
(report_auth.py) moved out of the active package -- see
future-work/auth/README.md. Only the import paths and target functions
changed (these now call report_function_auth_gate's handle_status_request/
handle_result_request instead of the live function_app's); the test
bodies are otherwise unmodified from their last active version, including
the HTML-output assertion in test_result_owner_gets_200_html_when_complete
(auth and HTML output were both still active at the moment this was
deferred -- see report_function_auth_gate.py's own docstring on why
they're independent axes, not a bundle).

Run directly: python3 test_report_function_auth_deferred.py [--test]

No real network, Cosmos DB, or Entra call is made anywhere in this file.
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
import report_function_auth_gate as gate

ISSUER = "https://bravo6ciam.ciamlogin.com/test-tenant/v2.0"
AUDIENCE = "test-report-audience"
KID = "test-key-1"

_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_public_key = _private_key.public_key()


class _StaticJWKSClient(PyJWKClient):
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
    return cosmos_exceptions.CosmosResourceNotFoundError(status_code=404, message="not found")


def _job_doc(user_id="user-123", scan_id="scan-1", status="queued"):
    return {"id": scan_id, "scanId": scan_id, "user_id": user_id, "url": "https://example.com",
            "submitted_at": "2026-09-11T00:00:00+00:00", "status": status}


def _result_doc(user_id="user-123", scan_id="scan-1"):
    return {
        "id": scan_id, "scanId": scan_id, "user_id": user_id, "url": "https://example.com",
        "score": 85, "grade": "B", "total_findings": 2, "findings": [], "tests": {},
        "errors": [], "errors_count": 0, "waf": None, "page_is_representative": True,
    }


class ReportFunctionAuthGateTests(unittest.TestCase):
    def test_result_owner_gets_200_html_when_complete(self):
        container = MagicMock()
        container.read_item.return_value = _result_doc(user_id="user-123")
        status, content_type, body = gate.handle_result_request(
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
        status, content_type, body = gate.handle_result_request(
            authorization_header=f"Bearer {_make_token(sub='someone-else')}", scan_id="scan-1",
            jwks_client=_JWKS_CLIENT, issuer=ISSUER, audience=AUDIENCE, cosmos_container=container,
        )
        self.assertEqual(status, 403)
        self.assertEqual(content_type, "application/json")
        self.assertEqual(json.loads(body)["error"], "forbidden")

    def test_missing_auth_header_gets_401(self):
        container = MagicMock()
        status, body = gate.handle_status_request(
            authorization_header=None, scan_id="scan-1",
            jwks_client=_JWKS_CLIENT, issuer=ISSUER, audience=AUDIENCE, cosmos_container=container,
        )
        self.assertEqual(status, 401)
        container.read_item.assert_not_called()

    def test_wrong_audience_gets_401(self):
        container = MagicMock()
        status, body = gate.handle_status_request(
            authorization_header=f"Bearer {_make_token(aud='wrong-audience')}", scan_id="scan-1",
            jwks_client=_JWKS_CLIENT, issuer=ISSUER, audience=AUDIENCE, cosmos_container=container,
        )
        self.assertEqual(status, 401)
        container.read_item.assert_not_called()

    def test_status_route_also_enforces_ownership(self):
        container = MagicMock()
        container.read_item.return_value = _job_doc(user_id="user-123")
        status, body = gate.handle_status_request(
            authorization_header=f"Bearer {_make_token(sub='someone-else')}", scan_id="scan-1",
            jwks_client=_JWKS_CLIENT, issuer=ISSUER, audience=AUDIENCE, cosmos_container=container,
        )
        self.assertEqual(status, 403)

    def test_result_nonexistent_scan_gets_404(self):
        container = MagicMock()
        container.read_item.side_effect = _cosmos_not_found()
        status, content_type, body = gate.handle_result_request(
            authorization_header=f"Bearer {_make_token()}", scan_id="does-not-exist",
            jwks_client=_JWKS_CLIENT, issuer=ISSUER, audience=AUDIENCE, cosmos_container=container,
        )
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body)["error"], "scan not found")


def build_arg_parser():
    parser = argparse.ArgumentParser(description="Bravo6 deferred Report Function auth-gate regression suite")
    parser.add_argument("--test", action="store_true", help="Accepted for CI-invocation consistency; always runs the suite.")
    return parser


if __name__ == "__main__":
    build_arg_parser().parse_args()
    sys.argv = [sys.argv[0]]
    unittest.main()
