from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

ROOT = Path(__file__).resolve().parents[1]
WORKER_DIR = ROOT / "src" / "worker"
if str(ROOT / "validation-benchmark") not in sys.path:
    sys.path.insert(0, str(ROOT / "validation-benchmark"))
if str(WORKER_DIR) not in sys.path:
    sys.path.insert(0, str(WORKER_DIR))

from app import create_app

import main_scanner

BENCHMARK_OFFLINE_MOCK_ENV = "BRAVO6_VALIDATION_OFFLINE_MOCK"

try:
    import test_10_hallucinated_deps as hallucinated_deps_module
except Exception:  # pragma: no cover - benchmark-only support path
    hallucinated_deps_module = None


BENCHMARK_DIR = Path(__file__).resolve().parent
FIXTURES_DIR = BENCHMARK_DIR / "fixtures"
CVE_CSV_PATH = Path(__file__).resolve().parents[1] / "src" / "worker" / "cve_database_v2.csv"


BENCHMARK_PRIVATE_TARGETS_ENV = "BRAVO6_VALIDATION_ALLOW_PRIVATE_TARGETS"


def _offline_mock_requested(argv: Optional[List[str]] = None) -> bool:
    """Return True only for the explicit benchmark-only offline mock mode."""
    args = sys.argv[1:] if argv is None else argv
    if "--offline-mock" in args:
        return True
    value = os.environ.get(BENCHMARK_OFFLINE_MOCK_ENV, "").strip().lower()
    return value in {"1", "true", "yes", "on"}


@contextlib.contextmanager
def validation_private_targets_override() -> Iterable[None]:
    """Allow only the synthetic local benchmark to target loopback/private IPs.

    The environment variable is set here, inside the validation harness only, and
    then removed again immediately afterward. Real scans keep the default deny-
    private-targets behavior because the flag is off-by-default and never set in
    production deployment settings.
    """
    previous = os.environ.get(BENCHMARK_PRIVATE_TARGETS_ENV)
    os.environ[BENCHMARK_PRIVATE_TARGETS_ENV] = "1"
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop(BENCHMARK_PRIVATE_TARGETS_ENV, None)
        else:
            os.environ[BENCHMARK_PRIVATE_TARGETS_ENV] = previous


@contextlib.contextmanager
def validation_registry_mock_override() -> Iterable[None]:
    """Opt-in benchmark-only override for offline execution.

    This deliberately bypasses the real scout decision path for the hallucinated-
    dependency check by patching the lookup function in memory. It is intended
    only for environments with no internet access and must never be treated as a
    clean scanner-accuracy result. Any benchmark run executed with this override
    enabled must be reported as offline/mocked, not as the live scanner's real
    accuracy.
    """
    if hallucinated_deps_module is None:
        yield
        return

    original_lookup = hallucinated_deps_module._lookup_package

    async def fake_lookup(session, ecosystem, normalized_name, timeout_s):
        if normalized_name == "imaginary-not-published-package":
            return (hallucinated_deps_module.RegistryResult.ABSENT,
                    f"{normalized_name} -> mocked local benchmark result: registry 404")
        return await original_lookup(session, ecosystem, normalized_name, timeout_s)

    hallucinated_deps_module._lookup_package = fake_lookup
    try:
        yield
    finally:
        hallucinated_deps_module._lookup_package = original_lookup


def _start_server() -> threading.Thread:
    app = create_app()
    thread = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=5001, debug=False, use_reloader=False),
        daemon=True,
    )
    thread.start()
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", 5001), timeout=0.2):
                return thread
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("Benchmark app did not start on localhost:5001")


def _load_fixtures() -> List[Dict[str, Any]]:
    path = FIXTURES_DIR / "cases.json"
    with path.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)
    return payload["cases"]


def _collect_titles(result: Optional[Dict[str, Any]]) -> List[str]:
    if not result:
        return []
    findings = result.get("findings", []) or []
    return [str(f.get("title", "")) for f in findings if isinstance(f, dict)]


async def run_case(case: Dict[str, Any]) -> Dict[str, Any]:
    url = case["url"]
    expected_present = case.get("expected_present", [])
    expected_absent = case.get("expected_absent", [])
    mock_context = validation_registry_mock_override() if _offline_mock_requested() else contextlib.nullcontext()
    with validation_private_targets_override(), mock_context:
        result = await main_scanner.run_scout(
            url,
            scan_id=f"benchmark-{case['name']}",
            config={"cve_csv_url": str(CVE_CSV_PATH)},
        )
    titles = _collect_titles(result)
    present_hits = [kw for kw in expected_present if any(kw.lower() in title.lower() for title in titles)]
    absent_hits = [kw for kw in expected_absent if any(kw.lower() in title.lower() for title in titles)]
    predicted_positive = bool(present_hits)
    expected_positive = bool(expected_present)
    tp = 1 if expected_positive and predicted_positive else 0
    fp = 1 if (not expected_positive) and predicted_positive else 0
    fn = 1 if expected_positive and not predicted_positive else 0
    tn = 1 if (not expected_positive) and (not predicted_positive) else 0
    precision = (tp / (tp + fp)) if (tp + fp) else 1.0 if not expected_positive else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) else 1.0 if not expected_positive else 0.0
    return {
        "name": case["name"],
        "expected_positive": expected_positive,
        "predicted_positive": predicted_positive,
        "titles": titles,
        "expected_present": expected_present,
        "present_hits": present_hits,
        "expected_absent": expected_absent,
        "absent_hits": absent_hits,
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "result": result,
    }


def summarize(results: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = list(results)
    tp = sum(r["tp"] for r in rows)
    fp = sum(r["fp"] for r in rows)
    fn = sum(r["fn"] for r in rows)
    tn = sum(r["tn"] for r in rows)
    precision = (tp / (tp + fp)) if (tp + fp) else 1.0
    recall = (tp / (tp + fn)) if (tp + fn) else 1.0
    return {
        "total_cases": len(rows),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "precision": precision,
        "recall": recall,
        "f1": (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0,
        "rows": rows,
    }


def run_benchmark() -> Dict[str, Any]:
    _start_server()
    cases = _load_fixtures()
    mock_context = validation_registry_mock_override() if _offline_mock_requested() else contextlib.nullcontext()
    with validation_private_targets_override(), mock_context:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            rows = loop.run_until_complete(asyncio.gather(*(run_case(case) for case in cases)))
        finally:
            loop.close()
    return summarize(rows)


if __name__ == "__main__":
    report = run_benchmark()
    print(json.dumps({
        "total_cases": report["total_cases"],
        "tp": report["tp"],
        "fp": report["fp"],
        "fn": report["fn"],
        "tn": report["tn"],
        "precision": round(report["precision"], 4),
        "recall": round(report["recall"], 4),
        "f1": round(report["f1"], 4),
        "rows": [{
            "name": row["name"],
            "expected_positive": row["expected_positive"],
            "predicted_positive": row["predicted_positive"],
            "present_hits": row["present_hits"],
            "absent_hits": row["absent_hits"],
            "precision": round(row["precision"], 4),
            "recall": round(row["recall"], 4),
        } for row in report["rows"]],
    }, indent=2))
