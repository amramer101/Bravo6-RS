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

No real network or Service Bus call is made anywhere in this file --
Service Bus clients are unittest.mock objects.

DEFERRED-AUTH NOTE (2026-09-12, see future-work/auth/README.md): the
TestAuth, TestQuota, and TestScanJobWrite classes that used to live here
moved to future-work/auth/test_auth_deferred.py along with the modules
they test (auth.py, quota.py, scan_job.py) -- run them from there if you
need to touch that code. This file now only covers what's actually
active: blocklist enforcement, Service Bus enqueue, and
handle_scan_request()'s (now three-step, no-auth) status-code matrix.
"""
import argparse
import contextlib
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent))

from blocklist import is_blocklisted
from servicebus_queue import EnqueueError, build_scan_message, enqueue_scan_job
from azure.servicebus.exceptions import ServiceBusError
import function_app


# ------------------------------------------------------------------------------
# Blocklist enforcement
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
# Service Bus enqueue (retry, worker schema match)
# ------------------------------------------------------------------------------
class TestServiceBusEnqueue(unittest.TestCase):
    def test_message_schema_matches_worker_expectations(self):
        """src/worker/function_app.py's process_scan() does:
        data = json.loads(body); target_url = data.get("url");
        job_id = data.get("job_id");
        config = data.get("config") if isinstance(data.get("config"), dict) else None.
        The enqueued message must satisfy that exactly. job_id is the
        Gap 3 correlation fix (DEPLOYMENT_NOTES.md) -- see
        src/worker/main_scanner.py's TestScanIdThreading for the Worker
        side of this same contract."""
        message = build_scan_message(url="https://example.com", job_id="job-abc-123")
        body = json.loads(b"".join(message.body).decode("utf-8"))
        self.assertEqual(body["url"], "https://example.com")
        self.assertIn("config", body)
        self.assertIsNone(body["config"])
        self.assertEqual(body["job_id"], "job-abc-123")

    def test_enqueue_success_first_attempt(self):
        sender = MagicMock()
        message = build_scan_message(url="https://example.com", job_id="job-1")
        enqueue_scan_job(message, sender, "job-1")
        sender.send_messages.assert_called_once()

    def test_enqueue_retries_then_succeeds(self):
        sender = MagicMock()
        sender.send_messages.side_effect = [ServiceBusError("transient"), None]
        message = build_scan_message(url="https://example.com", job_id="job-1")
        enqueue_scan_job(message, sender, "job-1")
        self.assertEqual(sender.send_messages.call_count, 2)

    def test_enqueue_persistent_failure_raises_after_retries(self):
        sender = MagicMock()
        sender.send_messages.side_effect = ServiceBusError("down")
        message = build_scan_message(url="https://example.com", job_id="job-1")
        with self.assertRaises(EnqueueError):
            enqueue_scan_job(message, sender, "job-1")
        self.assertEqual(sender.send_messages.call_count, 3)


# ------------------------------------------------------------------------------
# handle_scan_request() -- full status-code + side-effect matrix
# ------------------------------------------------------------------------------
class TestHandleScanRequest(unittest.TestCase):
    def _sender_factory(self, sender):
        return lambda: contextlib.nullcontext(sender)

    def test_403_blocklisted_target_no_side_effects(self):
        sender = MagicMock()
        status, _ = function_app.handle_scan_request(
            url="https://irs.gov",
            get_service_bus_sender=self._sender_factory(sender),
        )
        self.assertEqual(status, 403)
        sender.send_messages.assert_not_called()

    def test_202_happy_path_enqueues_and_returns_job_id(self):
        sender = MagicMock()
        status, body = function_app.handle_scan_request(
            url="https://example.com",
            get_service_bus_sender=self._sender_factory(sender),
        )
        self.assertEqual(status, 202)
        self.assertIn("job_id", body)
        self.assertEqual(body["status"], "queued")
        sender.send_messages.assert_called_once()

    def test_202_response_job_id_matches_enqueued_message(self):
        """The job_id returned to the caller must be the exact same one
        threaded through to the Worker via Service Bus -- otherwise the
        caller has no way to ever find their own scan's result."""
        sender = MagicMock()
        status, body = function_app.handle_scan_request(
            url="https://example.com",
            get_service_bus_sender=self._sender_factory(sender),
        )
        sent_message = sender.send_messages.call_args[0][0]
        sent_body = json.loads(b"".join(sent_message.body).decode("utf-8"))
        self.assertEqual(sent_body["job_id"], body["job_id"])

    def test_503_persistent_enqueue_failure(self):
        sender = MagicMock()
        sender.send_messages.side_effect = ServiceBusError("down")
        status, _ = function_app.handle_scan_request(
            url="https://example.com",
            get_service_bus_sender=self._sender_factory(sender),
        )
        self.assertEqual(status, 503)

    def test_transient_enqueue_failure_recovers_to_202(self):
        sender = MagicMock()
        sender.send_messages.side_effect = [ServiceBusError("transient"), None]
        status, _ = function_app.handle_scan_request(
            url="https://example.com",
            get_service_bus_sender=self._sender_factory(sender),
        )
        self.assertEqual(status, 202)
        self.assertEqual(sender.send_messages.call_count, 2)

    def test_optional_ssrf_check_blocks_when_injected_and_unsafe(self):
        sender = MagicMock()
        status, _ = function_app.handle_scan_request(
            url="http://169.254.169.254",
            get_service_bus_sender=self._sender_factory(sender),
            ssrf_check=lambda host: False,
        )
        self.assertEqual(status, 403)
        sender.send_messages.assert_not_called()

    def test_optional_ssrf_check_error_does_not_block_request(self):
        """The secondary check erroring must not itself cause a false
        rejection -- only an actual unsafe-address verdict blocks."""
        sender = MagicMock()

        def _broken_check(host):
            raise RuntimeError("DNS resolver unavailable")

        status, _ = function_app.handle_scan_request(
            url="https://example.com",
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
