#!/usr/bin/env python3
"""
main_scanner.py — Bravo6 Orchestrator (Robust)
==================================================
Improvements over the previous version:
- Retry logic with exponential backoff on failed HTTP requests
- Per‑test timeout (configurable) to prevent hanging
- Confidence‑based filtering of findings (reduces false positives)
- Accurate tests_run count (only successful, non‑error completions)
- Keeps per‑test structure AND a clean, filtered flat findings list
- Shared main page + shared JS cache across all tests
- Overall security score (0‑100) and letter grade (A‑F)
- Optional verbose mode (disables output suppression)
- All console output suppressed by default (redirect_stdout)
"""

import asyncio
import contextlib
import importlib
import inspect
import io
import json
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp
from bs4 import BeautifulSoup

# --- Import security tests -------------------------------------------------
import test_01_secrets
import test_02_frontend_libs
import test_04_ssl_tls
import test_05_security_headers
import test_06_info_disclosure

# --- Constants -------------------------------------------------------------
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=15)
USER_AGENT = "Bravo6-Scanner/2.0"
MAX_RETRIES = 3
RETRY_BACKOFF = 2          # seconds, exponential: 2^attempt
MIN_CONFIDENCE_DEFAULT = 50

# --- Per‑test timeouts (seconds) -------------------------------------------
TEST_TIMEOUTS = {
    "test_01_secrets": 60,
    "test_02_frontend_libs": 45,
    "test_04_ssl_tls": 30,
    "test_05_security_headers": 20,
    "test_06_info_disclosure": 120,
}

# --- Global caches for main page & JS files --------------------------------
_main_page_cache: Dict[str, Dict] = {}
_fetch_events: Dict[str, asyncio.Event] = {}

_js_cache: Dict[str, str] = {}
_js_fetch_events: Dict[str, asyncio.Event] = {}

# --- Helpers ----------------------------------------------------------------

def _normalize_url(url: str) -> str:
    """Ensure the URL has an http(s) scheme."""
    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


async def _fetch_with_retry(
    session: aiohttp.ClientSession,
    url: str,
    max_retries: int = MAX_RETRIES,
    backoff: int = RETRY_BACKOFF,
) -> aiohttp.ClientResponse:
    """
    Perform a GET request with exponential backoff on network‑level errors.
    Raises the last caught exception if all retries are exhausted.
    """
    last_exc = None
    for attempt in range(max_retries):
        try:
            resp = await session.get(url)
            return resp
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            last_exc = e
            if attempt < max_retries - 1:
                await asyncio.sleep(backoff ** attempt)
    raise last_exc


async def _fetch_main_page_cached(
    url: str, session: Optional[aiohttp.ClientSession] = None
) -> Dict:
    """
    Fetch the main page once, cache it, and return a dict with:
    status, html, headers, soup, base_url, error.
    Uses retry logic for the HTTP request.
    """
    url = _normalize_url(url)

    if url in _main_page_cache:
        return _main_page_cache[url]

    if url in _fetch_events:
        await _fetch_events[url].wait()
        return _main_page_cache[url]

    event = asyncio.Event()
    _fetch_events[url] = event

    result = {"status": 0, "html": "", "headers": {}, "soup": None, "base_url": url, "error": None}

    try:
        close_session = session is None
        if close_session:
            session = aiohttp.ClientSession(
                timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT}
            )

        resp = await _fetch_with_retry(session, url)
        result["status"] = resp.status
        result["headers"] = dict(resp.headers)
        if resp.status == 200:
            html = await resp.text()
            result["html"] = html
            result["soup"] = BeautifulSoup(html, "html.parser")
    except Exception as e:
        result["error"] = str(e)
    finally:
        _main_page_cache[url] = result
        event.set()
        _fetch_events.pop(url, None)

    return result


async def _detect_waf(url: str, session: aiohttp.ClientSession) -> Optional[str]:
    """Detect Cloudflare or Sucuri WAF via response headers."""
    try:
        resp = await _fetch_with_retry(session, url, max_retries=2)
        headers_lower = {k.lower(): str(v).lower() for k, v in resp.headers.items()}
        if "cf-ray" in headers_lower:
            return "Cloudflare"
        if "x-sucuri-id" in headers_lower:
            return "Sucuri"
    except Exception:
        pass
    return None


def _filter_findings(findings: List[Dict], min_confidence: int = MIN_CONFIDENCE_DEFAULT) -> List[Dict]:
    """
    Keep only findings with confidence >= min_confidence.
    If a finding lacks a 'confidence' key, it is included (assumed high confidence).
    """
    return [
        f for f in findings
        if f.get("confidence", 100) >= min_confidence
    ]


def _compute_score(findings: List[Dict]) -> Dict[str, Any]:
    """
    Calculate a numeric score (0‑100) and letter grade.
    Severity penalties:
        critical: -25
        high:     -15
        medium:    -5
        low:       -1
    """
    deductions = 0
    for f in findings:
        sev = f.get("severity", "").lower()
        if sev == "critical":
            deductions += 25
        elif sev == "high":
            deductions += 15
        elif sev == "medium":
            deductions += 5
        elif sev == "low":
            deductions += 1

    score = max(0, 100 - deductions)

    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    return {"score": score, "grade": grade}


# --- Main orchestrator ------------------------------------------------------

async def run_scout(
    url: str,
    verbose: bool = False,
    min_confidence: int = MIN_CONFIDENCE_DEFAULT,
) -> Dict[str, Any]:
    """
    Execute all security tests against `url`.
    - `verbose`: if True, console output is NOT suppressed.
    - `min_confidence`: threshold for filtering findings (inclusive).
    Returns a complete result dictionary and saves it to `result.json`.
    """
    target = _normalize_url(url)
    start_time = time.time()

    # --- Shared session ----------------------------------------------------
    async with aiohttp.ClientSession(
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    ) as shared_session:

        # Fetch the main page once and share it with all tests
        shared_page = await _fetch_main_page_cached(target, shared_session)

        # WAF detection (runs in parallel, is not a “test”)
        waf_task = asyncio.ensure_future(_detect_waf(target, shared_session))

        # ── Shared JS cache with retry ─────────────────────────────────
        async def fetch_js_cached(js_url: str) -> str:
            """Fetch a JS file, caching it in memory for the duration of the scan."""
            if js_url in _js_cache:
                return _js_cache[js_url]

            if js_url in _js_fetch_events:
                await _js_fetch_events[js_url].wait()
                return _js_cache[js_url]

            evt = asyncio.Event()
            _js_fetch_events[js_url] = evt

            try:
                resp = await _fetch_with_retry(shared_session, js_url)
                if resp.status == 200:
                    text = await resp.text()
                else:
                    text = ""
            except Exception:
                text = ""
            _js_cache[js_url] = text
            evt.set()
            _js_fetch_events.pop(js_url, None)
            return text

        # ── Test modules ───────────────────────────────────────────────
        TEST_MODULES = [
            test_01_secrets,
            test_02_frontend_libs,
            test_04_ssl_tls,
            test_05_security_headers,
            test_06_info_disclosure,
        ]

        # Build coroutines, injecting shared state and per‑test timeout
        test_coroutines = []
        for mod in TEST_MODULES:
            run_func = mod.run
            sig = inspect.signature(run_func)
            kwargs = {"shared_page": shared_page}
            if "js_cache" in sig.parameters:
                kwargs["js_cache"] = _js_cache
            if "fetch_js" in sig.parameters:
                kwargs["fetch_js"] = fetch_js_cached

            coro = run_func(target, **kwargs)

            # Wrap with timeout if configured
            test_name = mod.__name__
            timeout = TEST_TIMEOUTS.get(test_name)
            if timeout:
                coro = asyncio.wait_for(coro, timeout=timeout)

            test_coroutines.append(coro)

        all_tasks = test_coroutines + [waf_task]

        # ── Run everything, suppress stdout unless verbose ─────────────
        if verbose:
            raw_results = await asyncio.gather(*all_tasks, return_exceptions=True)
        else:
            with contextlib.redirect_stdout(io.StringIO()):
                raw_results = await asyncio.gather(*all_tasks, return_exceptions=True)

        # Separate WAF result
        waf_result = raw_results[-1]
        test_results = raw_results[:-1]

    duration = time.time() - start_time

    # ── Aggregation ─────────────────────────────────────────────────────
    tests: Dict[str, Any] = {}       # per‑test full result
    raw_findings: List[Dict] = []    # unfiltered security findings
    errors: List[str] = []
    tests_run = 0

    for mod, res in zip(TEST_MODULES, test_results):
        test_name = mod.__name__

        if isinstance(res, Exception):
            # Includes asyncio.TimeoutError
            errors.append(f"{test_name}: {res}")
            tests[test_name] = {"error": str(res)}
            continue

        if isinstance(res, dict):
            # A dict response is considered a successful run only if it does NOT contain an "error" key.
            if "error" in res:
                errors.append(f"{test_name}: {res['error']}")
                tests[test_name] = res
            else:
                tests_run += 1
                tests[test_name] = res
                findings = res.get("findings", [])
                if isinstance(findings, list):
                    raw_findings.extend(findings)
            continue

        # Unexpected return type → error
        errors.append(f"{test_name}: returned unexpected type {type(res)}")
        tests[test_name] = {"error": f"Unexpected return type: {type(res)}"}

    # WAF metadata
    waf = waf_result if isinstance(waf_result, str) else None

    # ── Confidence filtering ────────────────────────────────────────────
    flat_findings = _filter_findings(raw_findings, min_confidence)

    # ── Summary & score ─────────────────────────────────────────────────
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in flat_findings:
        sev = finding.get("severity", "").lower()
        if sev in summary:
            summary[sev] += 1

    total_findings = len(flat_findings)
    score_info = _compute_score(flat_findings)

    # ── Final result object ─────────────────────────────────────────────
    final_result = {
        "url": target,
        "scan_time": datetime.now().isoformat(),
        "duration_seconds": round(duration, 2),
        "tests_run": tests_run,
        "total_findings": total_findings,
        "findings": flat_findings,          # clean, filtered list
        "tests": tests,                     # per‑test raw data (including unfiltered findings)
        "waf": waf,
        "errors": errors,
        "summary": summary,
        "score": score_info["score"],
        "grade": score_info["grade"],
    }

    # Save to JSON
    with open("result.json", "w", encoding="utf-8") as f:
        json.dump(final_result, f, ensure_ascii=False, indent=2)

    return final_result


# ── CLI entry point ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Bravo6 Security Scanner")
    parser.add_argument(
        "url",
        nargs="?",
        default="https://example.com",
        help="Target URL to scan (default: https://example.com)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show console output (debugging)",
    )
    parser.add_argument(
        "--min-confidence",
        type=int,
        default=MIN_CONFIDENCE_DEFAULT,
        help=f"Minimum confidence threshold for findings (default: {MIN_CONFIDENCE_DEFAULT})",
    )
    args = parser.parse_args()

    asyncio.run(run_scout(args.url, verbose=args.verbose, min_confidence=args.min_confidence))