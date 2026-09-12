#!/usr/bin/env python3
"""
Bravo6 Report Function -- Regression Suite
=====================================================================
Matches the project's existing per-component convention (each scout,
main_scanner.py, and src/api/test_api_gateway.py carry their own --test
unittest suite). Run directly:

    python3 test_report_function.py [--test]

No real network or Cosmos DB call is made anywhere in this file -- the
Cosmos container is a unittest.mock object.

DEFERRED-AUTH NOTE (2026-09-12, see future-work/auth/README.md): the
JWT/ownership-specific test cases that used to live here (401 for a
missing/wrong-audience token, 403 for a cross-user request, and the
HTML-output assertion on /report/result) moved to
future-work/auth/test_report_function_auth_deferred.py along with the
auth-gate and JWT validation code they test. This file now only covers
what's actually active: status derivation (all four states), the
result route's JSON output, and 400/404/409.
"""
import argparse
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent))

from azure.cosmos import exceptions as cosmos_exceptions
import function_app


def _cosmos_not_found():
    """A CosmosResourceNotFoundError, close enough to the real SDK's
    shape for read_item's side_effect (matches how a real 404 from a
    point read is raised)."""
    return cosmos_exceptions.CosmosResourceNotFoundError(status_code=404, message="not found")


# ------------------------------------------------------------------------------
# Fixture documents -- one per _derive_status() input shape
# ------------------------------------------------------------------------------
def _job_doc(scan_id="scan-1", status="queued"):
    """Shape src/api/scan_job.py's ScanJob.to_dict() writes."""
    return {"id": scan_id, "scanId": scan_id, "url": "https://example.com",
            "submitted_at": "2026-09-11T00:00:00+00:00", "status": status}


def _result_doc(scan_id="scan-1"):
    """Shape main_scanner.py's normal-completion final_result carries."""
    return {
        "id": scan_id, "scanId": scan_id, "url": "https://example.com",
        "score": 85, "grade": "B", "total_findings": 2, "findings": [], "tests": {},
        "errors": [], "errors_count": 0, "waf": None, "page_is_representative": True,
    }


def _blocked_doc(scan_id="scan-1"):
    """Shape main_scanner.py's blocked_ssrf early exit carries."""
    return {"id": scan_id, "scanId": scan_id, "url": "https://example.com",
            "status": "blocked_ssrf", "ssrf_block_reason": "private IP", "score": None,
            "findings": [], "tests": {}}


class ReportFunctionTests(unittest.TestCase):
    # -------------------- status route: all four states --------------------
    def test_status_pending_for_queued_doc(self):
        container = MagicMock()
        container.read_item.return_value = _job_doc(status="queued")
        status, body = function_app.handle_status_request(scan_id="scan-1", cosmos_container=container)
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "Pending")

    def test_status_running_when_doc_says_so(self):
        container = MagicMock()
        container.read_item.return_value = _job_doc(status="running")
        status, body = function_app.handle_status_request(scan_id="scan-1", cosmos_container=container)
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "Running")

    def test_status_complete_for_result_shaped_doc(self):
        container = MagicMock()
        container.read_item.return_value = _result_doc()
        status, body = function_app.handle_status_request(scan_id="scan-1", cosmos_container=container)
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "Complete")

    def test_status_failed_for_blocked_ssrf_doc(self):
        container = MagicMock()
        container.read_item.return_value = _blocked_doc()
        status, body = function_app.handle_status_request(scan_id="scan-1", cosmos_container=container)
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "Failed")

    def test_status_missing_scan_id_gets_400(self):
        container = MagicMock()
        status, body = function_app.handle_status_request(scan_id=None, cosmos_container=container)
        self.assertEqual(status, 400)
        container.read_item.assert_not_called()

    def test_status_nonexistent_scan_gets_404(self):
        container = MagicMock()
        container.read_item.side_effect = _cosmos_not_found()
        status, body = function_app.handle_status_request(scan_id="does-not-exist", cosmos_container=container)
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "scan not found")

    # -------------------- full-result route --------------------
    def test_result_gets_200_json_when_complete(self):
        """No auth, no ownership check (see function_app.py's module
        docstring) -- any caller with the scanId gets the raw result
        document back as JSON, not rendered HTML."""
        container = MagicMock()
        container.read_item.return_value = _result_doc()
        status, body = function_app.handle_result_request(scan_id="scan-1", cosmos_container=container)
        self.assertEqual(status, 200)
        self.assertEqual(body["url"], "https://example.com")
        self.assertEqual(body["score"], 85)
        self.assertEqual(body["scanId"], "scan-1")

    def test_result_response_is_json_serializable(self):
        """Regression guard for the HTML-to-JSON switch: the handler's
        return value must be a plain dict the Azure Functions entry
        point can json.dumps() directly, not an HTML string."""
        container = MagicMock()
        container.read_item.return_value = _result_doc()
        status, body = function_app.handle_result_request(scan_id="scan-1", cosmos_container=container)
        self.assertIsInstance(body, dict)
        json.dumps(body)  # must not raise

    def test_result_nonexistent_scan_gets_404(self):
        container = MagicMock()
        container.read_item.side_effect = _cosmos_not_found()
        status, body = function_app.handle_result_request(scan_id="does-not-exist", cosmos_container=container)
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "scan not found")

    def test_result_before_complete_gets_409_with_current_status(self):
        """Explicit assertion for the Step 2 decision: calling /report/result
        before status reaches Complete is a 409 carrying the current status,
        not a silent 200 or an unrelated error."""
        container = MagicMock()
        container.read_item.return_value = _job_doc(status="queued")
        status, body = function_app.handle_result_request(scan_id="scan-1", cosmos_container=container)
        self.assertEqual(status, 409)
        self.assertEqual(body["error"], "scan not complete")
        self.assertEqual(body["status"], "Pending")

    def test_result_missing_scan_id_gets_400(self):
        container = MagicMock()
        status, body = function_app.handle_result_request(scan_id=None, cosmos_container=container)
        self.assertEqual(status, 400)
        container.read_item.assert_not_called()


def build_arg_parser():
    parser = argparse.ArgumentParser(description="Bravo6 Report Function regression suite")
    parser.add_argument("--test", action="store_true", help="Accepted for CI-invocation consistency; always runs the suite.")
    return parser


if __name__ == "__main__":
    build_arg_parser().parse_args()
    sys.argv = [sys.argv[0]]
    unittest.main()
