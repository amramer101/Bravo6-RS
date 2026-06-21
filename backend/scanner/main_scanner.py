"""
main_scanner.py — Bravo6 Scout Worker
======================================
Orchestrates the 16 passive security tests against a target URL,
runs them in parallel (4 groups via asyncio.gather), aggregates
the results, and returns a single structured scan report.

Usage:
    result = asyncio.run(run_scout("example.com"))
"""

import asyncio
import time
from urllib.parse import urlparse

import aiohttp

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
    test_14_subresource_integrity_sri,
    test_15_hallucinated_deps,
    test_16_ai_exposure,
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
# WAF / CDN detection (context only — informs report consumers that some
# findings, e.g. HTTP methods or rate-limit checks, may be false positives
# due to WAF interception. Not used to bypass or evade anything.)
# --------------------------------------------------------------------------

REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=10)
USER_AGENT = "Bravo6-Scanner/1.0"

# Each signature is either a bare header name (presence check) or a
# "header: value-substring" pair when the value itself is the tell.
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-cache-status"],
    "AWS CloudFront": ["x-amz-cf-id", "x-amz-request-id"],
    "Akamai": ["x-check-cacheable", "akamai-x-cache"],
    "Azure Front Door": ["x-azure-ref", "x-fd-healthprobe"],
    "Fastly": ["x-fastly-request-id", "fastly-restarts"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    "Imperva": ["x-iinfo", "x-cdn"],
    "Google Cloud CDN": ["x-goog-hash", "via: 1.1 google"],
}


async def _detect_waf(url: str, session: "aiohttp.ClientSession") -> str | None:
    """
    Detect a WAF/CDN from the response headers of a single GET request.

    This is purely informational/context-gathering for the report (so
    consumers understand why a finding like HTTP methods or rate-limiting
    might look like a false positive). It does not attempt to bypass,
    fingerprint version numbers, or probe for WAF weaknesses.

    Returns the WAF/CDN name on first match, or None if nothing matched
    or the request failed for any reason.
    """
    try:
        async with session.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            ssl=False,
            allow_redirects=True,
        ) as resp:
            headers_lower = {k.lower(): str(v).lower() for k, v in resp.headers.items()}

            for waf_name, signatures in WAF_SIGNATURES.items():
                for sig in signatures:
                    sig = sig.lower()
                    if ":" in sig:
                        header_name, _, value_substr = sig.partition(":")
                        header_name = header_name.strip()
                        value_substr = value_substr.strip()
                        actual_value = headers_lower.get(header_name, "")
                        if value_substr and value_substr in actual_value:
                            return waf_name
                    elif sig in headers_lower:
                        return waf_name
            return None
    except Exception:
        # Detection is best-effort context — never let it break the scan.
        return None


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


def _aggregate(raw_results: list, url: str, duration: float, waf_context: dict | None = None) -> dict:
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
        "waf_context": waf_context or {"detected": None, "note": None},
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
    Run all 16 passive security tests against the target URL in parallel.

    Groups:
        A — HTTP layer        (headers, CORS, methods, cookies, info disclosure)
        B — Content           (secrets, JS libs, mixed content, CMS/vibe)
        C — DNS/Network       (SSL, email security, subdomain takeover, robots.txt)
        D — AI & Supply Chain (SRI, hallucinated deps, AI exposure)

    All 4 groups run concurrently via asyncio.gather, alongside a
    lightweight WAF/CDN header check used only for report context.
    Within each group, tests also run concurrently.
    return_exceptions=True ensures one failing test never kills the others.

    Args:
        url: Target URL or domain, e.g. "example.com" or "https://example.com"

    Returns:
        Structured scan report dict with score, grade, summary, findings,
        and a non-scored "waf_context" field noting any detected WAF/CDN.
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
            "waf_context": {"detected": None, "note": None},
            "meta": {"tests_run": 0, "tests_errored": 1, "duration_seconds": 0},
        }

    start = time.time()

    # One lightweight GET to fingerprint a WAF/CDN from response headers.
    # This runs concurrently with the 16 tests rather than blocking them.
    async def _waf_lookup() -> str | None:
        async with aiohttp.ClientSession() as session:
            return await _detect_waf(target, session)

    # Run all 16 tests + WAF detection concurrently
    # return_exceptions=True: if one test crashes, others keep running
    *raw_results, waf_name = await asyncio.gather(
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
        # ── Group D: AI & Supply Chain ────────────────────────────────────
        test_14_subresource_integrity_sri.run(target),
        test_15_hallucinated_deps.run(target),
        test_16_ai_exposure.run(target),
        # ── WAF/CDN context (not a finding, not scored) ──────────────────
        _waf_lookup(),
        return_exceptions=True,
    )

    # If WAF detection itself raised, treat it the same as "not detected"
    # rather than letting it surface as a scan error.
    if isinstance(waf_name, Exception):
        waf_name = None

    waf_context = {
        "detected": waf_name,
        "note": (
            f"{waf_name} detected — some findings (HTTP methods, rate limiting) "
            "may show false positives due to WAF interception."
        ) if waf_name else None,
    }

    duration = time.time() - start
    return _aggregate(list(raw_results), target, duration, waf_context)


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