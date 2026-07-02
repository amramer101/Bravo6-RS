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

[FIXES APPLIED]
- JS cache race condition: only successful (200) responses are cached;
  empty responses are not stored, allowing automatic retries.
- skip_js_lib_scan is now True (test_02 handles frontend libs reliably;
  avoids duplicate / false-positive findings in test_06).
- WAF detection extended to AWS CloudFront, Akamai, Imperva/Incapsula.
- Scoring tuned: reduced medium severity penalty, adjusted grade thresholds
  (A>=85, B>=75, C>=65, D>=55) for more realistic ratings.

[AZURE FIXES]
- result.json now written to /tmp directory instead of current working directory
  to avoid PermissionError in Azure Functions Linux environment.
- Added Cosmos DB integration: results are stored persistently in Azure Cosmos DB
  if credentials are provided, falling back to /tmp otherwise.
"""

import asyncio
import contextlib
import inspect
import io
import json
import math
import os
import re
import sys
import tempfile
import time
import uuid
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp
from bs4 import BeautifulSoup

# Optional Cosmos DB import (gracefully handled if not installed)
try:
    from azure.cosmos import CosmosClient, exceptions
    COSMOS_AVAILABLE = True
except ImportError:
    COSMOS_AVAILABLE = False
    logging.warning("azure-cosmos not installed. Cosmos DB integration will be disabled.")

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
    "test_06_info_disclosure": 60,
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
    """GET with exponential backoff on network errors."""
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
    """Fetch main page once and cache."""
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
    """Detect WAF/CDN from response headers (Cloudflare, Sucuri, CloudFront, Akamai, Imperva)."""
    try:
        resp = await _fetch_with_retry(session, url, max_retries=2)
        headers_lower = {k.lower(): str(v).lower() for k, v in resp.headers.items()}
        if "cf-ray" in headers_lower:
            return "Cloudflare"
        if "x-sucuri-id" in headers_lower:
            return "Sucuri"
        if "x-amz-cf-id" in headers_lower or ("server" in headers_lower and "cloudfront" in headers_lower["server"]):
            return "AWS CloudFront"
        if "x-akamai-transformed" in headers_lower or "x-akamai-request-id" in headers_lower:
            return "Akamai"
        if "x-iinfo" in headers_lower or "x-cdn" in headers_lower:
            return "Imperva/Incapsula"
    except Exception:
        pass
    return None


def _normalize_title(title: str) -> str:
    """Normalize title for deduplication."""
    if not title:
        return ""
    cleaned = re.sub(r'[^\w\s]', '', title.lower())
    return re.sub(r'\s+', ' ', cleaned).strip()


_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _deduplicate_findings(findings: List[Dict]) -> List[Dict]:
    """Deduplicate by normalized title, keeping highest confidence/severity."""
    best: Dict[str, Dict] = {}
    for f in findings:
        title = f.get("title", "")
        norm = _normalize_title(title)
        if norm not in best:
            best[norm] = f
            continue
        existing = best[norm]
        conf_new = f.get("confidence", 100)
        conf_existing = existing.get("confidence", 100)
        if conf_new > conf_existing:
            best[norm] = f
        elif conf_new == conf_existing:
            sev_new = _SEVERITY_RANK.get(f.get("severity", "").lower(), 0)
            sev_existing = _SEVERITY_RANK.get(existing.get("severity", "").lower(), 0)
            if sev_new > sev_existing:
                best[norm] = f
    return list(best.values())


def _filter_findings(findings: List[Dict], min_confidence: int = MIN_CONFIDENCE_DEFAULT) -> List[Dict]:
    """Keep findings with confidence >= min_confidence (or missing key)."""
    return [f for f in findings if f.get("confidence", 100) >= min_confidence]


def _compute_score(findings: List[Dict], waf: Optional[str] = None) -> Dict[str, Any]:
    """Calculate score 0-100 and letter grade with realistic weightings."""
    BASE_PENALTY = {"critical": 25, "high": 15, "medium": 3, "low": 1}
    DIMINISHING_THRESHOLD = {"critical": 2, "high": 3, "medium": 5, "low": 7}
    MAX_DEDUCTION = {"critical": 50, "high": 45, "medium": 15, "low": 15}

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    sev_ded = {"critical": 0.0, "high": 0.0, "medium": 0.0, "low": 0.0}

    for f in findings:
        sev = f.get("severity", "").lower()
        if sev not in sev_counts:
            continue
        sev_counts[sev] += 1
        conf = f.get("confidence", 100) / 100.0
        base = BASE_PENALTY[sev]
        idx = sev_counts[sev]
        if idx <= DIMINISHING_THRESHOLD[sev]:
            penalty = base * conf
        else:
            extra = idx - DIMINISHING_THRESHOLD[sev]
            penalty = base * conf / (1 + math.sqrt(extra))
        sev_ded[sev] += penalty

    for sev in sev_ded:
        if sev_ded[sev] > MAX_DEDUCTION[sev]:
            sev_ded[sev] = MAX_DEDUCTION[sev]

    total_deductions = sum(sev_ded.values())
    score = max(0.0, 100.0 - total_deductions)
    if waf is not None:
        score = min(score + 5.0, 100.0)

    int_score = round(score)

    if int_score >= 85:
        grade = "A"
    elif int_score >= 75:
        grade = "B"
    elif int_score >= 65:
        grade = "C"
    elif int_score >= 55:
        grade = "D"
    else:
        grade = "F"

    return {"score": int_score, "grade": grade}


# --- Main orchestrator ------------------------------------------------------
async def run_scout(
    url: str,
    verbose: bool = False,
    min_confidence: int = MIN_CONFIDENCE_DEFAULT,
) -> Dict[str, Any]:
    """Execute all security tests, return aggregated result."""
    target = _normalize_url(url)
    start_time = time.time()

    async with aiohttp.ClientSession(
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
    ) as shared_session:

        shared_page = await _fetch_main_page_cached(target, shared_session)
        waf_task = asyncio.ensure_future(_detect_waf(target, shared_session))

        # JS cache: only cache successful (200) responses
        async def fetch_js_cached(js_url: str) -> str:
            if js_url in _js_cache:
                return _js_cache[js_url]
            if js_url in _js_fetch_events:
                await _js_fetch_events[js_url].wait()
                if js_url in _js_cache:
                    return _js_cache[js_url]

            evt = asyncio.Event()
            _js_fetch_events[js_url] = evt
            try:
                resp = await _fetch_with_retry(shared_session, js_url)
                if resp.status == 200:
                    text = await resp.text()
                    _js_cache[js_url] = text
                    return text
                return ""
            except Exception:
                return ""
            finally:
                evt.set()
                _js_fetch_events.pop(js_url, None)

        TEST_MODULES = [
            test_01_secrets,
            test_02_frontend_libs,
            test_04_ssl_tls,
            test_05_security_headers,
            test_06_info_disclosure,
        ]

        test_coroutines = []
        for mod in TEST_MODULES:
            run_func = mod.run
            sig = inspect.signature(run_func)
            kwargs = {"shared_page": shared_page}
            if "js_cache" in sig.parameters:
                kwargs["js_cache"] = _js_cache
            if "fetch_js" in sig.parameters:
                kwargs["fetch_js"] = fetch_js_cached
            # ** FINAL DECISION: skip JS lib scan in test_06 — test_02 handles it reliably **
            if "skip_js_lib_scan" in sig.parameters:
                kwargs["skip_js_lib_scan"] = True

            coro = run_func(target, **kwargs)
            test_name = mod.__name__
            timeout = TEST_TIMEOUTS.get(test_name)
            if timeout:
                coro = asyncio.wait_for(coro, timeout=timeout)
            test_coroutines.append(coro)

        all_tasks = test_coroutines + [waf_task]

        if verbose:
            raw_results = await asyncio.gather(*all_tasks, return_exceptions=True)
        else:
            with contextlib.redirect_stdout(io.StringIO()):
                raw_results = await asyncio.gather(*all_tasks, return_exceptions=True)

        waf_result = raw_results[-1]
        test_results = raw_results[:-1]

    duration = time.time() - start_time

    tests: Dict[str, Any] = {}
    raw_findings: List[Dict] = []
    errors: List[str] = []
    tests_run = 0

    for mod, res in zip(TEST_MODULES, test_results):
        test_name = mod.__name__
        if isinstance(res, Exception):
            errors.append(f"{test_name}: {res}")
            tests[test_name] = {"error": str(res)}
            continue
        if isinstance(res, dict):
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
        errors.append(f"{test_name}: returned unexpected type {type(res)}")
        tests[test_name] = {"error": f"Unexpected return type: {type(res)}"}

    waf = waf_result if isinstance(waf_result, str) else None

    original_findings_count = len(raw_findings)
    deduplicated_raw = _deduplicate_findings(raw_findings)
    deduplicated_count = original_findings_count - len(deduplicated_raw)

    flat_findings = _filter_findings(deduplicated_raw, min_confidence)

    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in flat_findings:
        sev = finding.get("severity", "").lower()
        if sev in summary:
            summary[sev] += 1

    total_findings = len(flat_findings)
    score_info = _compute_score(flat_findings, waf)

    final_result = {
        "url": target,
        "scan_time": datetime.now().isoformat(),
        "duration_seconds": round(duration, 2),
        "tests_run": tests_run,
        "total_findings": total_findings,
        "findings": flat_findings,
        "tests": tests,
        "waf": waf,
        "errors": errors,
        "errors_count": len(errors),
        "deduplicated_count": deduplicated_count,
        "summary": summary,
        "score": score_info["score"],
        "grade": score_info["grade"],
    }

    # --- Write result to Cosmos DB (if available) or fallback to /tmp ---
    try:
        if COSMOS_AVAILABLE:
            cosmos_url = os.environ.get("COSMOS_URL")
            cosmos_key = os.environ.get("COSMOS_KEY")
            database_name = os.environ.get("COSMOS_DATABASE", "Bravo6DB")
            container_name = os.environ.get("COSMOS_CONTAINER", "ScanResults")

            if not cosmos_url or not cosmos_key:
                logging.warning("Cosmos DB credentials not set. Falling back to /tmp file.")
                raise RuntimeError("Missing Cosmos DB credentials")
            else:
                client = CosmosClient(cosmos_url, credential=cosmos_key)
                database = client.get_database_client(database_name)
                container = database.get_container_client(container_name)

                # Generate a unique scanId if not already present
                scan_id = final_result.get("scanId") or str(uuid.uuid4())
                final_result["id"] = scan_id          # Cosmos DB requires 'id' field
                final_result["scanId"] = scan_id      # for querying

                container.create_item(body=final_result)
                logging.info(f"✅ Scan result saved to Cosmos DB with scanId: {scan_id}")
        else:
            raise RuntimeError("azure-cosmos module not installed")

    except Exception as e:
        # Fallback: write to /tmp (for local development or when Cosmos DB fails)
        logging.warning(f"Cosmos DB write failed ({e}). Falling back to /tmp/result.json")
        temp_dir = tempfile.gettempdir()
        result_path = os.path.join(temp_dir, "result.json")
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(final_result, f, ensure_ascii=False, indent=2)

    return final_result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Bravo6 Security Scanner")
    parser.add_argument("url", nargs="?", default="https://example.com", help="Target URL to scan")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show console output")
    parser.add_argument("--min-confidence", type=int, default=MIN_CONFIDENCE_DEFAULT,
                        help=f"Minimum confidence threshold (default: {MIN_CONFIDENCE_DEFAULT})")
    parser.add_argument("--html", action="store_true", help="Generate HTML security report after scan")
    args = parser.parse_args()

    # Run the scanner
    asyncio.run(run_scout(args.url, verbose=args.verbose, min_confidence=args.min_confidence))

    # Generate HTML report if requested (reads from /tmp)
    if args.html:
        try:
            from report_generator import build_html
            temp_dir = tempfile.gettempdir()
            result_path = os.path.join(temp_dir, "result.json")
            with open(result_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            html = build_html(data)
            with open("security_report.html", "w", encoding="utf-8") as f:
                f.write(html)
            print("✅ HTML report generated: security_report.html")
        except ImportError:
            print("❌ report_generator.py not found. Please ensure it is in the same folder.")
        except Exception as e:
            print(f"❌ Failed to generate report: {e}")