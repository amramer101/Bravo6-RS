"""
main_scanner.py — Bravo6 Scout Worker
======================================
Orchestrates the 13 passive security tests against a target URL,
runs them in parallel (3 groups via asyncio.gather), aggregates
the results, and returns a single structured scan report.

Usage:
    result = asyncio.run(run_scout("example.com"))
"""

import asyncio
import time
from urllib.parse import urlparse

from scanner import (
    test_01_secrets,
    test_02_frontend_libs,
    test_03_mixed_content,
    test_04_ssl_tls,
    test_05_security_headers,
    test_06_info_disclosure,
    test_07_cookies,
    test_08_email_security,
    test_09_subdomain_takeover,
    test_10_robots_txt,
    test_11_cors,
    test_12_http_methods,
    test_13_cms_fingerprinting,
)

# --------------------------------------------------------------------------
# Severity config
# --------------------------------------------------------------------------

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# How many points each severity deducts from the score
SCORE_DEDUCTIONS = {
    "critical": 25,
    "high": 15,
    "medium": 7,
    "low": 3,
    "info": 0,
}


# --------------------------------------------------------------------------
# URL normalization
# --------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return url
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    return url


def _is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme and parsed.netloc)
    except Exception:
        return False


# --------------------------------------------------------------------------
# Score calculation
# --------------------------------------------------------------------------

def _calculate_score(findings: list) -> int:
    """
    Start at 100 and deduct points for each failed/warning finding
    based on its severity. Floor is 0.

    Only deducts once per test_name to avoid double-counting tests
    that return multiple findings (e.g. security_headers returns one
    finding per header).
    """
    score = 100
    seen_tests = set()

    # Sort by severity descending so the worst finding per test drives the deduction
    sorted_findings = sorted(
        findings,
        key=lambda f: SEVERITY_RANK.get(f.get("severity", "info"), 0),
        reverse=True,
    )

    for finding in sorted_findings:
        if finding.get("status") not in ("fail", "warning"):
            continue

        test_name = finding.get("test_name", "")
        if test_name in seen_tests:
            continue
        seen_tests.add(test_name)

        severity = finding.get("severity") or "info"
        score -= SCORE_DEDUCTIONS.get(severity, 0)

    return max(0, score)


# --------------------------------------------------------------------------
# Result aggregation
# --------------------------------------------------------------------------

def _severity_label(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _aggregate(raw_results: list, url: str, duration: float) -> dict:
    """
    Takes the raw list of results from asyncio.gather (may include
    Exception objects if return_exceptions=True) and builds the final
    scan report dict.
    """
    findings = []
    scan_errors = []

    for r in raw_results:
        if isinstance(r, Exception):
            scan_errors.append(str(r))
            continue
        if not isinstance(r, dict):
            scan_errors.append(f"Unexpected result type: {type(r).__name__}")
            continue
        findings.append(r)

    score = _calculate_score(findings)
    grade = _severity_label(score)

    summary = {
        "critical": sum(1 for f in findings if f.get("severity") == "critical" and f.get("status") in ("fail", "warning")),
        "high":     sum(1 for f in findings if f.get("severity") == "high"     and f.get("status") in ("fail", "warning")),
        "medium":   sum(1 for f in findings if f.get("severity") == "medium"   and f.get("status") in ("fail", "warning")),
        "low":      sum(1 for f in findings if f.get("severity") == "low"      and f.get("status") in ("fail", "warning")),
        "passed":   sum(1 for f in findings if f.get("status") == "pass"),
        "errors":   sum(1 for f in findings if f.get("status") == "error") + len(scan_errors),
    }

    # Overall status: fail if any critical/high, warning if only medium/low, pass otherwise
    if summary["critical"] > 0 or summary["high"] > 0:
        overall_status = "fail"
    elif summary["medium"] > 0 or summary["low"] > 0:
        overall_status = "warning"
    elif summary["errors"] == len(findings):
        overall_status = "error"
    else:
        overall_status = "pass"

    return {
        "url": url,
        "status": overall_status,
        "score": score,
        "grade": grade,
        "summary": summary,
        "findings": findings,
        "scan_errors": scan_errors,
        "meta": {
            "tests_run": len(findings),
            "tests_errored": len(scan_errors),
            "duration_seconds": round(duration, 2),
        },
    }


# --------------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------------

async def run_scout(url: str) -> dict:
    """
    Run all 13 passive security tests against the target URL in parallel.

    Groups:
        A — HTTP layer  (headers, CORS, methods, cookies, info disclosure)
        B — Content     (secrets, JS libs, mixed content, CMS/vibe)
        C — DNS/Network (SSL, email security, subdomain takeover, robots.txt)

    All 3 groups run concurrently via asyncio.gather.
    Within each group, tests also run concurrently.
    return_exceptions=True ensures one failing test never kills the others.

    Args:
        url: Target URL or domain, e.g. "example.com" or "https://example.com"

    Returns:
        Structured scan report dict with score, grade, summary, and findings.
    """
    target = _normalize_url(url)

    if not target or not _is_valid_url(target):
        return {
            "url": url,
            "status": "error",
            "score": 0,
            "grade": "F",
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "passed": 0, "errors": 1},
            "findings": [],
            "scan_errors": [f"Invalid or empty URL provided: '{url}'"],
            "meta": {"tests_run": 0, "tests_errored": 1, "duration_seconds": 0},
        }

    start = time.time()

    # Run all 13 tests concurrently
    # return_exceptions=True: if one test crashes, others keep running
    raw_results = await asyncio.gather(
        # ── Group A: HTTP layer ──────────────────────────────────────────
        test_05_security_headers.run(target),
        test_11_cors.run(target),
        test_12_http_methods.run(target),
        test_07_cookies.run(target),
        test_06_info_disclosure.run(target),
        # ── Group B: Content ─────────────────────────────────────────────
        test_01_secrets.run(target),
        test_02_frontend_libs.run(target),
        test_03_mixed_content.run(target),
        test_13_cms_fingerprinting.run(target),
        # ── Group C: DNS / Network ───────────────────────────────────────
        test_04_ssl_tls.run(target),
        test_08_email_security.run(target),
        test_09_subdomain_takeover.run(target),
        test_10_robots_txt.run(target),
        return_exceptions=True,
    )

    duration = time.time() - start
    return _aggregate(list(raw_results), target, duration)


# --------------------------------------------------------------------------
# Manual test harness
# --------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"

    print(f"[Bravo6] Scanning: {target}")
    result = asyncio.run(run_scout(target))

    # Pretty-print without findings detail for a quick overview
    overview = {k: v for k, v in result.items() if k != "findings"}
    print(json.dumps(overview, indent=2))
    print(f"\n[Bravo6] Total findings: {len(result['findings'])}")
    print(f"[Bravo6] Score: {result['score']}/100 (Grade {result['grade']})")
    print(f"[Bravo6] Duration: {result['meta']['duration_seconds']}s")