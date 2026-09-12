import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKER_DIR = ROOT / "src" / "worker"
if str(WORKER_DIR) not in sys.path:
    sys.path.insert(0, str(WORKER_DIR))

from validation-benchmark.runner import summarize, run_case


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

    def test_run_case_uses_expected_titles(self):
        case = {
            "name": "fake-positive",
            "url": "http://127.0.0.1:5001/headers-missing",
            "expected_present": ["Missing Content-Security-Policy"],
            "expected_absent": [],
        }
        result = run_case(case)
        self.assertIsInstance(result, dict)
        self.assertIn("name", result)
        self.assertIn("precision", result)


if __name__ == "__main__":
    unittest.main()
