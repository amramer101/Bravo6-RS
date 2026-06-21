"""
main_scanner.py — Bravo6 Scout Worker
======================================
Orchestrates the 16 passive security tests against a target URL,
runs them in parallel (4 groups via asyncio.gather), aggregates
the results, and returns a single structured scan report.

Usage:
    result = asyncio.run(run_scout("example.com"))

    # With HTML report generation:
    python -m scanner.main_scanner https://example.com --html report.html
"""

import asyncio
import json
import sys
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

# Try to import the HTML report generator (optional)
try:
    from scanner.report_generator import generate_html_report
except ImportError:
    try:
        from report_generator import generate_html_report
    except ImportError:
        generate_html_report = None

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
# WAF / CDN detection (context only)
# --------------------------------------------------------------------------

REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=10)
USER_AGENT = "Bravo6-Scanner/1.0"

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
    score = 100
    seen_tests = set()

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

    async def _waf_lookup() -> str | None:
        async with aiohttp.ClientSession() as session:
            return await _detect_waf(target, session)

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
        # ── WAF/CDN context ──────────────────────────────────────────────
        _waf_lookup(),
        return_exceptions=True,
    )

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
# HTML Report Generation Helper
# --------------------------------------------------------------------------

def generate_report(result: dict, output_file: str = None) -> str:
    """Generate an HTML report from scan results."""
    if generate_html_report is None:
        print("[WARN] report_generator module not found. Install it to generate HTML reports.")
        return None

    html_content = generate_html_report(result)

    if output_file is None:
        # Default filename based on target domain
        import re
        target = result.get("url", "scan")
        safe_name = re.sub(r'[^a-zA-Z0-9]', '_', target)
        output_file = f"scan_report_{safe_name}.html"

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)

    return output_file


# --------------------------------------------------------------------------
# Command-line entry point
# --------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    import argparse

    # Simple argument parsing
    args = sys.argv[1:]
    target = None
    html_output = None

    # Parse --html flag
    if '--html' in args:
        idx = args.index('--html')
        if idx + 1 < len(args) and not args[idx+1].startswith('--'):
            html_output = args[idx+1]
            args.pop(idx)
            args.pop(idx)
        else:
            # --html without filename -> use default
            args.remove('--html')
            html_output = True  # will generate default name

    if args:
        target = args[0]
    else:
        target = "example.com"

    print(f"[Bravo6] Scanning: {target}")
    result = asyncio.run(run_scout(target))

    # Print overview to console
    overview = {k: v for k, v in result.items() if k != "findings"}
    print(json.dumps(overview, indent=2))
    print(f"\n[Bravo6] Total findings: {len(result['findings'])}")
    print(f"[Bravo6] Score: {result['score']}/100 (Grade {result['grade']})")
    print(f"[Bravo6] Duration: {result['meta']['duration_seconds']}s")

    # Generate HTML report if requested or if no specific output specified (optional)
    # Let's generate it by default unless --no-html is passed (we didn't add that, but we can)
    # For convenience, we'll generate if --html is present.
    if html_output is not None or '--html' in sys.argv:
        out = generate_report(result, html_output if isinstance(html_output, str) else None)
        if out:
            print(f"[Bravo6] HTML report saved to: {out}")
    else:
        # Optionally, user can enable by default; we'll keep it optional to avoid file clutter.
        print("[Bravo6] Use --html <filename> to generate HTML report.")