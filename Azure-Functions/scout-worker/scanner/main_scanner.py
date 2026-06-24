"""
main_scanner.py — Bravo6 Scout Worker (v2.0 – Shared Page Cache)
==================================================================
- Fetches the target homepage ONCE, caches it in memory.
- Passes the cached page (HTML, headers, soup) to all 16 tests.
- Tests can optionally use the shared page instead of re-fetching.
- Uses a single shared aiohttp.ClientSession for all network calls.
- Prevents duplicate fetches with asyncio.Event instead of a lock.
"""

import asyncio
import json
import sys
import time
from urllib.parse import urlparse
from typing import Dict, Optional

import aiohttp
from bs4 import BeautifulSoup

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

# Optional HTML report
try:
    from scanner.report_generator import generate_html_report
except ImportError:
    try:
        from report_generator import generate_html_report
    except ImportError:
        generate_html_report = None

# ── Constants ──────────────────────────────────────────────────────────────
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SCORE_DEDUCTIONS = {"critical": 25, "high": 15, "medium": 7, "low": 3, "info": 0}
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

# ── In‑memory cache for the main page ──────────────────────────────────────
_main_page_cache: Dict[str, dict] = {}

# ---- new: event-based single-flight pattern --------------------------------
_fetch_events: Dict[str, asyncio.Event] = {}

async def _fetch_main_page_cached(url: str, session: Optional[aiohttp.ClientSession] = None) -> dict:
    """Return cached page dict: {status, html, headers, soup, base_url, error}.
    Uses the provided session if given, otherwise creates a temporary one.
    Duplicate calls for the same URL are coalesced: only the first triggers a real fetch.
    """
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Fast path: already cached
    if url in _main_page_cache:
        return _main_page_cache[url]

    # If another coroutine is already fetching this URL, wait for its result
    if url in _fetch_events:
        await _fetch_events[url].wait()
        return _main_page_cache[url]

    # No cache, no in-flight fetch – we're the elected worker
    event = asyncio.Event()
    _fetch_events[url] = event

    result = {
        "status": 0, "html": "", "headers": {}, "soup": None,
        "base_url": url, "error": None
    }

    try:
        close_session = session is None
        if close_session:
            session = aiohttp.ClientSession(
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": USER_AGENT},
            )

        async with session.get(url) as resp:
            result["status"] = resp.status
            result["headers"] = dict(resp.headers)
            if resp.status == 200:
                html = await resp.text()
                result["html"] = html
                result["soup"] = BeautifulSoup(html, "html.parser")

        if close_session:
            await session.close()
    except Exception as e:
        result["error"] = str(e)
    finally:
        # Store result, wake any waiters, and clean up the event
        _main_page_cache[url] = result
        event.set()
        del _fetch_events[url]

    return result
# ---------------------------------------------------------------------------

# ── WAF detection (now accepts a session) ──────────────────────────────────
async def _detect_waf(url: str, session: aiohttp.ClientSession) -> Optional[str]:
    try:
        async with session.get(
            url, timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            ssl=False, allow_redirects=True,
        ) as resp:
            headers_lower = {k.lower(): str(v).lower() for k, v in resp.headers.items()}
            for waf, sigs in WAF_SIGNATURES.items():
                for sig in sigs:
                    sig_l = sig.lower()
                    if ":" in sig_l:
                        h, _, v = sig_l.partition(":")
                        if headers_lower.get(h.strip(), "") and v.strip() in headers_lower[h.strip()]:
                            return waf
                    elif sig_l in headers_lower:
                        return waf
    except Exception:
        pass
    return None

# ── Helpers ────────────────────────────────────────────────────────────────
def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    return url

def _is_valid_url(url: str) -> bool:
    try:
        p = urlparse(url)
        return bool(p.scheme and p.netloc)
    except Exception:
        return False

def _calculate_score(findings: list) -> int:
    score = 100
    seen = set()
    for f in sorted(findings, key=lambda x: SEVERITY_RANK.get(x.get("severity","info"),0), reverse=True):
        if f.get("status") not in ("fail","warning"): continue
        if f.get("test_name") in seen: continue
        seen.add(f.get("test_name"))
        score -= SCORE_DEDUCTIONS.get(f.get("severity","info"),0)
    return max(0, score)

def _severity_label(score: int) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"

def _aggregate(raw_results: list, url: str, duration: float, waf_context: dict | None = None) -> dict:
    all_findings = []
    errors = []
    for r in raw_results:
        if isinstance(r, Exception):
            errors.append(str(r)); continue
        if not isinstance(r, dict):
            errors.append(f"Bad type: {type(r).__name__}"); continue
        if "findings" in r and isinstance(r["findings"], list):
            tn = r.get("test_name", "unknown")
            for sf in r["findings"]:
                sf.setdefault("test_name", tn)
                if "overall_status" in sf and "status" not in sf:
                    sf["status"] = sf["overall_status"]
                all_findings.append(sf)
        else:
            r.setdefault("test_name", "unknown")
            all_findings.append(r)

    score = _calculate_score(all_findings)
    grade = _severity_label(score)

    def count(sev): return sum(1 for f in all_findings if f.get("severity")==sev and f.get("status") in ("fail","warning"))
    summary = {
        "critical": count("critical"), "high": count("high"),
        "medium": count("medium"), "low": count("low"),
        "passed": sum(1 for f in all_findings if f.get("status")=="pass"),
        "errors": sum(1 for f in all_findings if f.get("status")=="error") + len(errors),
    }
    if summary["critical"] or summary["high"]:
        overall = "fail"
    elif summary["medium"] or summary["low"]:
        overall = "warning"
    elif summary["errors"] == len(all_findings) and all_findings:
        overall = "error"
    else:
        overall = "pass"

    return {
        "url": url, "status": overall, "score": score, "grade": grade,
        "summary": summary, "findings": all_findings,
        "scan_errors": errors,
        "waf_context": waf_context or {"detected": None, "note": None},
        "meta": {
            "tests_run": len(raw_results),
            "findings_count": len(all_findings),
            "tests_errored": len(errors),
            "duration_seconds": round(duration,2),
        },
    }

# ── Main scan orchestrator ─────────────────────────────────────────────────
async def run_scout(url: str) -> dict:
    target = _normalize_url(url)
    if not target or not _is_valid_url(target):
        return {
            "url": url, "status": "error", "score": 0, "grade": "F",
            "summary": {"critical":0,"high":0,"medium":0,"low":0,"passed":0,"errors":1},
            "findings": [], "scan_errors": [f"Invalid URL: '{url}'"],
            "waf_context": {"detected":None,"note":None},
            "meta": {"tests_run":0,"findings_count":0,"tests_errored":1,"duration_seconds":0},
        }

    start = time.time()

    # ── Create one shared session for all network calls ─────────────────
    async with aiohttp.ClientSession(
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT}
    ) as shared_session:

        # 1. Fetch the homepage once (cached) – uses the shared session
        shared_page = await _fetch_main_page_cached(target, session=shared_session)

        # 2. Run all tests, each receiving the shared session
        async def _waf_lookup():
            return await _detect_waf(target, shared_session)

        *raw_results, waf_name = await asyncio.gather(
            # Group A – HTTP layer
            test_05_security_headers.run(target, shared_page=shared_page, session=shared_session),
            test_11_cors.run(target, shared_page=shared_page, session=shared_session),
            test_12_http_methods.run(target, shared_page=shared_page, session=shared_session),
            test_07_cookies.run(target, shared_page=shared_page, session=shared_session),
            test_06_info_disclosure.run(target, shared_page=shared_page, session=shared_session),
            # Group B – Content
            test_01_secrets.run(target, shared_page=shared_page, session=shared_session),
            test_02_frontend_libs.run(target, shared_page=shared_page, session=shared_session),
            test_03_mixed_content.run(target, shared_page=shared_page, session=shared_session),
            test_13_cms_fingerprinting.run(target, shared_page=shared_page, session=shared_session),
            # Group C – DNS / Network
            test_04_ssl_tls.run(target, shared_page=shared_page, session=shared_session),
            test_08_email_security.run(target, shared_page=shared_page, session=shared_session),
            test_09_subdomain_takeover.run(target, shared_page=shared_page, session=shared_session),
            test_10_robots_txt.run(target, shared_page=shared_page, session=shared_session),
            # Group D – AI & Supply Chain
            test_14_subresource_integrity_sri.run(target, shared_page=shared_page, session=shared_session),
            test_15_hallucinated_deps.run(target, shared_page=shared_page, session=shared_session),
            test_16_ai_exposure.run(target, shared_page=shared_page, session=shared_session),
            _waf_lookup(),
            return_exceptions=True,
        )

    if isinstance(waf_name, Exception):
        waf_name = None

    waf_context = {
        "detected": waf_name,
        "note": f"{waf_name} detected — findings may be affected." if waf_name else None,
    }

    duration = time.time() - start
    return _aggregate(list(raw_results), target, duration, waf_context)

# ── HTML report (unchanged) ────────────────────────────────────────────────
def generate_report(result: dict, output_file: str = None) -> str:
    # same as before...
    if generate_html_report is None:
        print("[WARN] report_generator not found.")
        return None
    html_content = generate_html_report(result)
    if output_file is None:
        import re
        safe = re.sub(r'[^a-zA-Z0-9]', '_', result.get("url","scan"))
        output_file = f"scan_report_{safe}.html"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    return output_file

# ── CLI ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("url", nargs="?", default="example.com")
    parser.add_argument("--html", nargs="?", const=True, default=False,
                        help="Output HTML report (optional filename)")
    args = parser.parse_args()

    target = args.url
    print(f"[Bravo6] Scanning: {target}")
    result = asyncio.run(run_scout(target))

    overview = {k: v for k, v in result.items() if k != "findings"}
    print(json.dumps(overview, indent=2))
    print(f"\n[Bravo6] Total findings: {len(result['findings'])}")
    print(f"[Bravo6] Score: {result['score']}/100 (Grade {result['grade']})")
    print(f"[Bravo6] Duration: {result['meta']['duration_seconds']}s")

    if args.html:
        out = generate_report(result, args.html if isinstance(args.html, str) else None)
        if out:
            print(f"[Bravo6] HTML report saved to: {out}")
    else:
        print("[Bravo6] Use --html <filename> for HTML report.")