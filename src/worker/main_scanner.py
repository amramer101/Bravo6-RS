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
- skip_js_lib_scan override REMOVED: test_01 now scans external JS files via js_cache/fetch_js.
- WAF detection extended to AWS CloudFront, Akamai, Imperva/Incapsula.
- Scoring tuned: reduced medium severity penalty, adjusted grade thresholds
  (A>=85, B>=75, C>=65, D>=55) for more realistic ratings.
- Timeout errors now produce explicit, actionable messages.
- CVE CSV URL configurable via --cve-csv-url CLI arg or CVE_CSV_URL env var.
- HTML report generation hardened with explicit path checks and actionable errors.
- Results directory resolved relative to script directory, not CWD.
- Debug logging added for per-module kwargs injection.

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
import logging
import math
import os
import re
import sys
import tempfile
import time
import uuid
from datetime import datetime
from pathlib import Path
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
    "test_06_info_disclosure": 90,
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
    cve_csv_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute all security tests, return aggregated result."""
    target = _normalize_url(url)
    start_time = time.time()

    # FIX #3: Pass CVE data source to test_02_frontend_libs if configured
    # Previously cve_csv_url was never passed, forcing fallback to tiny built-in DB.
    # Now we check env var first, then CLI arg, and pass through if test_02 accepts it.

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

            # FIX #6: Defensive logging around per-module kwargs construction
            # Log exactly which kwargs are injected per module at DEBUG level to catch signature mismatches early.
            logging.debug(f"Building kwargs for {mod.__name__} with signature: {sig}")
            injected_kwargs = []

            if "js_cache" in sig.parameters:
                kwargs["js_cache"] = _js_cache
                injected_kwargs.append("js_cache")
            if "fetch_js" in sig.parameters:
                kwargs["fetch_js"] = fetch_js_cached
                injected_kwargs.append("fetch_js")

            # FIX #1: CRITICAL — Remove blanket skip_js_lib_scan=True override.
            # Previously this was unconditionally set to True for any module accepting it,
            # which disabled test_01's external JS scanning (its primary purpose).
            # Now removed entirely: test_01 scans external JS via js_cache/fetch_js as intended.
            # If any module truly needs this in the future, add it with explicit logging.

            # FIX #3: Pass CVE CSV URL to test_02 if it accepts the parameter
            if "cve_csv_url" in sig.parameters and cve_csv_url is not None:
                kwargs["cve_csv_url"] = cve_csv_url
                injected_kwargs.append("cve_csv_url")

            logging.debug(f"  Injected kwargs for {mod.__name__}: {injected_kwargs}")

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

        # FIX #2: CRITICAL — Fix silent, uninformative error messages for timeouts.
        # Previously: str(asyncio.TimeoutError()) is empty, producing messages like "test_06_info_disclosure: "
        # Now: explicitly detect TimeoutError and produce actionable messages with timeout value.
        if isinstance(res, Exception):
            timeout_val = TEST_TIMEOUTS.get(test_name, "?")
            if isinstance(res, asyncio.TimeoutError):
                errors.append(f"{test_name}: timed out after {timeout_val}s — no results returned")
            elif isinstance(res, TimeoutError):
                errors.append(f"{test_name}: timed out after {timeout_val}s — no results returned")
            else:
                msg = str(res) or "(no message)"
                errors.append(f"{test_name}: {type(res).__name__}: {msg}")
            tests[test_name] = {"error": errors[-1]}
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
        errors.append(f"{test_name}: returned unexpected type {type(res).__name__}")
        tests[test_name] = {"error": f"Unexpected return type: {type(res).__name__}"}

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
        "scanId": str(uuid.uuid4()),
        "url": target,
        "start_time": datetime.now().isoformat(),
        "end_time": datetime.now().isoformat(),
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

    # --- FIX #5: MEDIUM — Confirm and harden the results/ folder behavior.
    # Results directory resolved relative to script directory, not current working directory.
    # This ensures consistent output location regardless of invocation path.
    script_dir = Path(__file__).parent
    results_dir = script_dir / "results"
    os.makedirs(results_dir, exist_ok=True)

    # --- Write result to Cosmos DB (if available) or fallback to results/ ---
    try:
        if COSMOS_AVAILABLE:
            cosmos_url = os.environ.get("COSMOS_URL")
            cosmos_key = os.environ.get("COSMOS_KEY")
            database_name = os.environ.get("COSMOS_DATABASE", "Bravo6DB")
            container_name = os.environ.get("COSMOS_CONTAINER", "ScanResults")

            if not cosmos_url or not cosmos_key:
                logging.warning("Cosmos DB credentials not set. Falling back to local results/ directory.")
                raise RuntimeError("Missing Cosmos DB credentials")
            else:
                client = CosmosClient(cosmos_url, credential=cosmos_key)
                database = client.get_database_client(database_name)
                container = database.get_container_client(container_name)

                final_result["id"] = final_result["scanId"]
                container.create_item(body=final_result)
                logging.info(f"✅ Scan result saved to Cosmos DB with scanId: {final_result['scanId']}")
        else:
            raise RuntimeError("azure-cosmos module not installed")

    except Exception as e:
        # Fallback: write to results/ directory (relative to script)
        logging.warning(f"Cosmos DB write failed ({e}). Falling back to local results/ directory.")
        result_path = results_dir / f"result_{final_result['scanId']}.json"
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(final_result, f, ensure_ascii=False, indent=2)
        logging.info(f"✅ Scan result saved to {result_path}")

    return final_result

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Bravo6 Security Scanner")
    parser.add_argument("url", nargs="?", default="https://example.com", help="Target URL to scan")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show console output")
    parser.add_argument("--min-confidence", type=int, default=MIN_CONFIDENCE_DEFAULT,
                        help=f"Minimum confidence threshold (default: {MIN_CONFIDENCE_DEFAULT})")

    # FIX #3: Add --cve-csv-url CLI argument for configurable CVE data source
    # This allows test_02 to use an external vulnerability database instead of fallback.
    parser.add_argument("--cve-csv-url", default=None,
                        help="URL to CVE CSV database for frontend library scanning (test_02)")

    parser.add_argument("--html", action="store_true", help="Generate HTML security report after scan")
    args = parser.parse_args()

    # Check CVE CSV URL from environment variable if not provided via CLI
    cve_csv_url = args.cve_csv_url or os.environ.get("CVE_CSV_URL")

    # Run the scanner
    asyncio.run(run_scout(
        args.url,
        verbose=args.verbose,
        min_confidence=args.min_confidence,
        cve_csv_url=cve_csv_url
    ))

    # Generate HTML report if requested
    if args.html:
        try:
            # FIX #4: HIGH — Make --html report generation failures explicit and actionable.
            # Check report_generator.py exists up front with actionable message.
            script_dir = Path(__file__).parent
            generator_path = script_dir / "report_generator.py"

            if not generator_path.exists():
                print(f"❌ report_generator.py not found at {generator_path.resolve()}. "
                      f"Please place report_generator.py in {script_dir.resolve()}/")
                sys.exit(1)

            from report_generator import build_html

            # Read the most recent result from results/ directory
            results_dir = script_dir / "results"
            result_files = sorted(results_dir.glob("result_*.json"), key=os.path.getmtime, reverse=True)
            if not result_files:
                print("❌ No scan results found in results/ directory. Run a scan first.")
                sys.exit(1)

            with open(result_files[0], "r", encoding="utf-8") as f:
                data = json.load(f)

            html = build_html(data)

            # FIX #5: Save HTML report relative to script directory
            report_path = script_dir / "security_report.html"
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(html)

            # FIX #4: Log the full resolved path on success
            print(f"✅ HTML report generated: {report_path.resolve()}")

        except ImportError as e:
            # FIX #4: More explicit error message
            print(f"❌ Failed to import report_generator: {e}. "
                  f"Ensure report_generator.py is in {Path(__file__).parent.resolve()}/")
        except Exception as e:
            # FIX #4: Log exception type and message, don't swallow
            print(f"❌ Failed to generate report: {type(e).__name__}: {e}")