import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKER_DIR = ROOT / "src" / "worker"
BENCHMARK_DIR = ROOT / "validation-benchmark"
if str(WORKER_DIR) not in sys.path:
    sys.path.insert(0, str(WORKER_DIR))
if str(BENCHMARK_DIR) not in sys.path:
    sys.path.insert(0, str(BENCHMARK_DIR))

from runner import summarize, run_case


def _load_cross_tool_calibration_summary_module():
    module_path = ROOT / "validation-benchmark" / "cross-tool-calibration" / "run_calibration.py"
    spec = __import__("importlib.util").util.spec_from_file_location("cross_tool_calibration", module_path)
    module = __import__("importlib.util").util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestBenchmarkRunner(unittest.TestCase):
    def test_summarize_counts(self):
        summary = summarize([
            {"tp": 1, "fp": 0, "fn": 0, "tn": 1},
            {"tp": 0, "fp": 1, "fn": 1, "tn": 0},
        ])
        self.assertEqual(summary["total_cases"], 2)
        self.assertEqual(summary["tp"], 1)
        self.assertEqual(summary["fp"], 1)
        self.assertEqual(summary["fn"], 1)
        self.assertEqual(summary["tn"], 1)
        self.assertAlmostEqual(summary["precision"], 0.5)
        self.assertAlmostEqual(summary["recall"], 0.5)

    def test_benchmark_secret_fixtures_are_not_live_looking(self):
        from app import create_app

        app = create_app()
        with app.test_client() as client:
            response = client.get("/secrets-positive")
            payload = response.get_data(as_text=True)
        self.assertNotIn("sk_live_", payload)
        self.assertNotIn("sk-", payload)
        self.assertNotIn("supersecretpass", payload)
        self.assertNotIn("postgresql://user:supersecretpass", payload)

    def test_run_case_uses_expected_titles(self):
        case = {
            "name": "fake-positive",
            "url": "http://127.0.0.1:5001/headers-missing",
            "expected_present": ["Missing Content-Security-Policy"],
            "expected_absent": [],
        }
        result = __import__("asyncio").run(run_case(case))
        self.assertIsInstance(result, dict)
        self.assertIn("name", result)
        self.assertIn("precision", result)

    def test_cross_tool_calibration_summary_uses_bravo6_and_mozilla_status(self):
        module = _load_cross_tool_calibration_summary_module()
        rows = [
            {
                "bravo6_status": "ok",
                "mozilla_status": "ok",
                "bravo6_signals": ["content-security-policy"],
                "mozilla_signals": ["content-security-policy", "redirection"],
                "overlap": ["content-security-policy"],
                "bravo6_only": [],
                "mozilla_only": ["redirection"],
            },
            {
                "bravo6_status": "ok",
                "mozilla_status": "error",
                "bravo6_signals": ["cookies"],
                "mozilla_signals": [],
                "overlap": [],
                "bravo6_only": ["cookies"],
                "mozilla_only": [],
            },
            {
                "bravo6_status": "error",
                "mozilla_status": "ok",
                "bravo6_signals": [],
                "mozilla_signals": ["strict-transport-security"],
                "overlap": [],
                "bravo6_only": [],
                "mozilla_only": ["strict-transport-security"],
            },
        ]
        summary = module.summarize(rows)
        self.assertEqual(summary["sites_scanned"], 3)
        self.assertEqual(summary["successful_sites"], 1)
        self.assertEqual(summary["overlap_sites"], 1)
        self.assertEqual(summary["disagreement_sites"], 1)
        self.assertAlmostEqual(summary["agreement_rate"], 0.5)


if __name__ == "__main__":
    unittest.main()
