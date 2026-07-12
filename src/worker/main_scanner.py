#!/usr/bin/env python3
"""
Bravo6 Enterprise Orchestrator (v8.0 – Production Grade)
========================================================
- Dynamic plugin architecture (auto-discovers test_XX_*.py).
- Unified finding schema enforcement (CWE, OWASP, PoC, Evidence).
- Centralized dependency injection (Session, Caches, Context).
- Advanced metrics, tracing, and structured logging.
- Robust timeout, retry, and concurrency management.
- Deterministic, normalized scoring across all modules.
"""
import asyncio
import contextlib
import hashlib
import importlib.util
import inspect
import io
import json
import logging
import math
import os
import sys
import time
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import aiohttp
from bs4 import BeautifulSoup
# Optional Cosmos DB integration
try:
    from azure.cosmos import CosmosClient
    COSMOS_AVAILABLE = True
except ImportError:
    COSMOS_AVAILABLE = False

# ------------------------------------------------------------------------------
# Configuration & Constants
# ------------------------------------------------------------------------------
USER_AGENT = "Bravo6-Scanner/8.0"
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=15)
MAX_RETRIES = 3
RETRY_BACKOFF = 2
MIN_CONFIDENCE_DEFAULT = 50

# Default timeouts per module (seconds)
DEFAULT_TIMEOUTS = {
    "test_01_secrets": 60,
    "test_02_frontend_libs": 45,
    "test_03_sca_osv": 45,
    "test_04_ssl_tls": 30,
    "test_05_security_headers": 20,
    "test_06_info_disclosure": 90,
}

# ------------------------------------------------------------------------------
# Logging Configuration (Tracing)
# ------------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-7s | %(name)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("Bravo6-Orchestrator")

# ------------------------------------------------------------------------------
# Context & Dependency Injection
# ------------------------------------------------------------------------------
@dataclass
class ScannerContext:
    """Centralized context for dependency injection across all plugins."""
    url: str
    config: Dict[str, Any]
    session: Optional[aiohttp.ClientSession] = None
    main_page_cache: Dict[str, Dict] = field(default_factory=dict)
    js_cache: Dict[str, str] = field(default_factory=dict)
    fetch_events: Dict[str, asyncio.Event] = field(default_factory=dict)
    js_fetch_events: Dict[str, asyncio.Event] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=lambda: {
        "http_requests": 0,
        "cache_hits": 0,
        "modules_executed": 0,
        "errors": []
    })

# ------------------------------------------------------------------------------
# Plugin Architecture (Dynamic Discovery)
# ------------------------------------------------------------------------------
def discover_plugins() -> List[Any]:
    """Dynamically discover and load all test_XX_*.py modules in the same directory."""
    plugins = []
    current_dir = Path(__file__).parent
    for filepath in sorted(current_dir.glob("test_*.py")):
        module_name = filepath.stem
        try:
            spec = importlib.util.spec_from_file_location(module_name, filepath)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            if hasattr(module, "run") and inspect.iscoroutinefunction(module.run):
                plugins.append(module)
                logger.debug(f"Loaded plugin: {module_name}")
            else:
                logger.warning(f"Module {module_name} does not have an async 'run' function.")
        except Exception as e:
            logger.error(f"Failed to load plugin {module_name}: {e}")
    return plugins

# ------------------------------------------------------------------------------
# HTTP Helpers with Retry & Metrics
# ------------------------------------------------------------------------------
async def fetch_with_retry(ctx: ScannerContext, url: str, max_retries: int = MAX_RETRIES) -> aiohttp.ClientResponse:
    """GET with exponential backoff and metrics tracking."""
    last_exc = None
    for attempt in range(max_retries):
        try:
            ctx.metrics["http_requests"] += 1
            resp = await ctx.session.get(url)
            return resp
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            last_exc = e
            if attempt < max_retries - 1:
                await asyncio.sleep(RETRY_BACKOFF ** attempt)
    raise last_exc

async def fetch_main_page_cached(ctx: ScannerContext) -> Dict:
    """Fetch main page once and cache with event-based deduplication."""
    url = ctx.url
    if url in ctx.main_page_cache:
        ctx.metrics["cache_hits"] += 1
        return ctx.main_page_cache[url]

    if url in ctx.fetch_events:
        await ctx.fetch_events[url].wait()
        ctx.metrics["cache_hits"] += 1
        return ctx.main_page_cache[url]

    event = asyncio.Event()
    ctx.fetch_events[url] = event
    result = {"status": 0, "html": "", "headers": {}, "soup": None, "error": None}
    try:
        resp = await fetch_with_retry(ctx, url)
        result["status"] = resp.status
        result["headers"] = dict(resp.headers)
        if resp.status == 200:
            html = await resp.text()
            result["html"] = html
            result["soup"] = BeautifulSoup(html, "html.parser")
    except Exception as e:
        result["error"] = str(e)
        ctx.metrics["errors"].append(f"Main page fetch failed: {e}")
    finally:
        ctx.main_page_cache[url] = result
        event.set()
        ctx.fetch_events.pop(url, None)
    return result

async def fetch_js_cached(ctx: ScannerContext, js_url: str) -> str:
    """Fetch JS file with caching and deduplication."""
    if js_url in ctx.js_cache:
        ctx.metrics["cache_hits"] += 1
        return ctx.js_cache[js_url]

    if js_url in ctx.js_fetch_events:
        await ctx.js_fetch_events[js_url].wait()
        ctx.metrics["cache_hits"] += 1
        return ctx.js_cache.get(js_url, "")

    event = asyncio.Event()
    ctx.js_fetch_events[js_url] = event
    try:
        resp = await fetch_with_retry(ctx, js_url)
        if resp.status == 200:
            text = await resp.text()
            ctx.js_cache[js_url] = text
            return text
        return ""
    except Exception:
        return ""
    finally:
        event.set()
        ctx.js_fetch_events.pop(js_url, None)

# ------------------------------------------------------------------------------
# Finding Normalization & Schema Enforcement
# ------------------------------------------------------------------------------
def normalize_finding(raw: Dict[str, Any], module_name: str, index: int) -> Dict[str, Any]:
    """
    Enforce a unified schema for all findings across all modules.
    Ensures: id, title, severity, confidence, cwe, owasp, evidence, poc, remediation, detection_method.
    """
    # Compute normalized fields first for stable ID generation
    title = raw.get("title") or raw.get("type") or raw.get("cve") or raw.get("description") or "Unknown Finding"
    
    # Bug 5 Fix: Do not invent fake CWE/OWASP placeholders. Keep as empty string if missing.
    cwe = raw.get("cwe") or ""
    owasp = raw.get("owasp") or ""
    location = raw.get("location") or ""

    # Generate a deterministic ID based on stable fields only
    stable_fields = {
        "module": module_name,
        "title": title,
        "cwe": cwe,
        "owasp": owasp,
        "location": location
    }
    stable_str = json.dumps(stable_fields, sort_keys=True, default=str)
    finding_id = hashlib.sha256(stable_str.encode()).hexdigest()[:12]

    severity = (raw.get("severity") or "info").lower()
    if severity not in ["critical", "high", "medium", "low", "info"]:
        severity = "info"
    confidence = int(raw.get("confidence", 50))
    confidence = max(0, min(100, confidence))

    # Aggregate evidence from various possible fields
    evidence_parts = []
    if raw.get("context"): evidence_parts.append(f"Context: {raw['context']}")
    if raw.get("location"): evidence_parts.append(f"Location: {raw['location']}")
    if raw.get("value_masked"): evidence_parts.append(f"Value: {raw['value_masked']}")
    if raw.get("library") and raw.get("version_detected"): evidence_parts.append(f"Library: {raw['library']}@{raw['version_detected']}")
    if raw.get("sources"): evidence_parts.append(f"Sources: {', '.join(raw['sources'])}")
    if raw.get("url"): evidence_parts.append(f"URL: {raw['url']}")
    if raw.get("description"): evidence_parts.append(f"Description: {raw['description']}")
    evidence = "\n".join(evidence_parts) if evidence_parts else json.dumps(raw, default=str)[:500]

    # Map PoC and remediation fields
    poc = raw.get("poc") or raw.get("poc_curl") or raw.get("poc_js") or "Manual verification required."
    remediation = raw.get("remediation") or "Consult security team for remediation."
    detection_method = raw.get("detection_method") or raw.get("source") or module_name

    return {
        "id": finding_id,
        "module": module_name,
        "title": str(title)[:200],
        "severity": severity,
        "confidence": confidence,
        "cwe": str(cwe),
        "owasp": str(owasp),
        "evidence": str(evidence)[:1000],
        "poc": str(poc)[:500],
        "remediation": str(remediation)[:500],
        "detection_method": str(detection_method)[:100],
        "raw_data": raw  # Preserve raw data for deep-dive reporting
    }

def extract_findings_from_result(res: Dict[str, Any], module_name: str) -> List[Dict[str, Any]]:
    """Extract findings from various possible keys in the module result, avoiding duplicates."""
    raw_findings = []
    seen_ids = set()

    # Common keys for findings across different modules
    finding_keys = ["findings", "evidence", "vulnerabilities"]
    for key in finding_keys:
        if key in res and isinstance(res[key], list):
            for item in res[key]:
                if isinstance(item, dict):
                    # Use a quick hash to avoid adding the exact same dict twice
                    item_id = hashlib.md5(json.dumps(item, sort_keys=True, default=str).encode()).hexdigest()
                    if item_id not in seen_ids:
                        seen_ids.add(item_id)
                        raw_findings.append(item)

    normalized = []
    for i, f in enumerate(raw_findings):
        normalized.append(normalize_finding(f, module_name, i))
    return normalized

# ------------------------------------------------------------------------------
# Deduplication & Filtering
# ------------------------------------------------------------------------------
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate by normalized title + CWE + OWASP, keeping highest confidence/severity."""
    best: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        # Create a dedup key based on title and CWE/OWASP to avoid cross-module duplicates
        key = f"{f['title']}|{f['cwe']}|{f['owasp']}"
        if key not in best:
            best[key] = f
            continue
        existing = best[key]
        if f["confidence"] > existing["confidence"]:
            best[key] = f
        elif f["confidence"] == existing["confidence"]:
            if _SEVERITY_RANK.get(f["severity"], 0) > _SEVERITY_RANK.get(existing["severity"], 0):
                best[key] = f
    return list(best.values())

def filter_findings(findings: List[Dict[str, Any]], min_confidence: int) -> List[Dict[str, Any]]:
    """Keep findings with confidence >= min_confidence."""
    return [f for f in findings if f["confidence"] >= min_confidence]

# ------------------------------------------------------------------------------
# Unified Scoring Methodology
# ------------------------------------------------------------------------------
def compute_bravo6_score(findings: List[Dict[str, Any]], waf: Optional[str] = None) -> Dict[str, Any]:
    """
    Canonical scoring methodology for the Bravo6 project.
    Computes a 0-100 score and letter grade based on findings.
    """
    BASE_PENALTY = {"critical": 18, "high": 15, "medium": 3, "low": 1}
    DIMINISHING_THRESHOLD = {"critical": 4, "high": 3, "medium": 5, "low": 7}
    MAX_DEDUCTION = {"critical": 50, "high": 45, "medium": 15, "low": 15}

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    sev_ded = {"critical": 0.0, "high": 0.0, "medium": 0.0, "low": 0.0}

    for f in findings:
        sev = f["severity"]
        if sev not in sev_counts:
            continue
        sev_counts[sev] += 1
        conf = f["confidence"] / 100.0
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

    # Bug 2 Fix: Unjustified flat WAF bonus removed entirely.
    int_score = round(score)
    if int_score >= 85: grade = "A"
    elif int_score >= 75: grade = "B"
    elif int_score >= 65: grade = "C"
    elif int_score >= 55: grade = "D"
    else: grade = "F"

    return {
        "score": int_score,
        "grade": grade,
        "deductions": {k: round(v, 2) for k, v in sev_ded.items()},
        "waf_detected": waf is not None
    }

# ------------------------------------------------------------------------------
# WAF Detection
# ------------------------------------------------------------------------------
async def detect_waf(ctx: ScannerContext) -> Optional[str]:
    """Detect WAF/CDN from response headers."""
    try:
        resp = await fetch_with_retry(ctx, ctx.url, max_retries=2)
        headers_lower = {k.lower(): str(v).lower() for k, v in resp.headers.items()}
        if "cf-ray" in headers_lower: return "Cloudflare"
        if "x-sucuri-id" in headers_lower: return "Sucuri"
        if "x-amz-cf-id" in headers_lower or "cloudfront" in headers_lower.get("server", ""): return "AWS CloudFront"
        if "x-akamai-transformed" in headers_lower or "x-akamai-request-id" in headers_lower: return "Akamai"
        if "x-iinfo" in headers_lower or "x-cdn" in headers_lower: return "Imperva/Incapsula"
    except Exception:
        pass
    return None

# ------------------------------------------------------------------------------
# Main Orchestrator
# ------------------------------------------------------------------------------
async def run_scout(
    url: str,
    verbose: bool = False,
    min_confidence: int = MIN_CONFIDENCE_DEFAULT,
    cve_csv_url: Optional[str] = None,
    config: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Execute all security tests, return aggregated result."""
    start_time = time.time()
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    if config is None:
        config = {}

    ctx = ScannerContext(
        url=url,
        config={
            "min_confidence": min_confidence,
            "cve_csv_url": cve_csv_url,
            "verbose": verbose,
            **config
        }
    )

    logger.info(f"Starting Bravo6 Enterprise Scan for {url}")
    connector = aiohttp.TCPConnector(ssl=True, limit=20, limit_per_host=10)
    async with aiohttp.ClientSession(
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
        connector=connector
    ) as session:
        ctx.session = session

        # Pre-fetch main page and detect WAF concurrently
        shared_page_task = asyncio.ensure_future(fetch_main_page_cached(ctx))
        waf_task = asyncio.ensure_future(detect_waf(ctx))

        # Discover plugins dynamically
        plugins = discover_plugins()
        if not plugins:
            logger.error("No test plugins found. Exiting.")
            return {"error": "No test plugins found."}
        logger.info(f"Discovered {len(plugins)} plugins: {[p.__name__ for p in plugins]}")

        # Prepare coroutines for each plugin with Dependency Injection
        test_coroutines = []
        test_names = []
        plugin_start_times = {}
        shared_page_resolved = False
        shared_page_value = None

        for mod in plugins:
            module_name = mod.__name__
            test_names.append(module_name)
            plugin_start_times[module_name] = time.time()

            # Build kwargs via introspection
            sig = inspect.signature(mod.run)
            kwargs = {}

            # Inject shared page
            if "shared_page" in sig.parameters:
                if not shared_page_resolved:
                    shared_page_value = await shared_page_task
                    shared_page_resolved = True
                else:
                    ctx.metrics["cache_hits"] += 1
                kwargs["shared_page"] = shared_page_value

            # Inject caches and fetch functions
            if "js_cache" in sig.parameters:
                kwargs["js_cache"] = ctx.js_cache
            if "fetch_js" in sig.parameters:
                async def _fetch_js_wrapper(js_url: str, ctx=ctx) -> str:
                    return await fetch_js_cached(ctx, js_url)
                kwargs["fetch_js"] = _fetch_js_wrapper

            # Inject shared session for connection pooling
            if "session" in sig.parameters:
                kwargs["session"] = ctx.session

            # Inject specific config
            if "cve_csv_url" in sig.parameters and cve_csv_url:
                kwargs["cve_csv_url"] = cve_csv_url

            # Inject context if supported
            if "ctx" in sig.parameters or "context" in sig.parameters:
                param_name = "ctx" if "ctx" in sig.parameters else "context"
                kwargs[param_name] = ctx

            coro = mod.run(url, **kwargs)

            # Apply per-module timeout
            timeout_val = DEFAULT_TIMEOUTS.get(module_name, 60)
            coro = asyncio.wait_for(coro, timeout=timeout_val)
            test_coroutines.append(coro)

        # Execute all tests concurrently
        all_tasks = test_coroutines + [waf_task]
        if verbose:
            raw_results = await asyncio.gather(*all_tasks, return_exceptions=True)
        else:
            with contextlib.redirect_stdout(io.StringIO()):
                raw_results = await asyncio.gather(*all_tasks, return_exceptions=True)

        waf_result = raw_results[-1]
        test_results = raw_results[:-1]

        # Process results
        duration = time.time() - start_time
        tests = {}
        all_raw_findings = []
        errors = []
        tests_run = 0

        for mod_name, res in zip(test_names, test_results):
            if isinstance(res, Exception):
                duration_plugin = time.time() - plugin_start_times.get(mod_name, start_time)
                if isinstance(res, asyncio.TimeoutError):
                    err_msg = f"{mod_name}: timed out after {DEFAULT_TIMEOUTS.get(mod_name, 60)}s"
                else:
                    err_msg = f"{mod_name}: {type(res).__name__}: {res}"
                
                # Bug 4 Fix: Enhanced per-plugin failure diagnostics
                tb_str = "".join(traceback.format_exception(type(res), res, res.__traceback__))
                errors.append(err_msg)
                tests[mod_name] = {
                    "error": err_msg,
                    "exception_type": type(res).__name__,
                    "traceback": tb_str,
                    "duration_seconds": round(duration_plugin, 2)
                }
                continue

            if isinstance(res, dict):
                if "error" in res:
                    errors.append(f"{mod_name}: {res['error']}")
                    tests[mod_name] = res
                else:
                    tests_run += 1
                    ctx.metrics["modules_executed"] += 1
                    tests[mod_name] = res
                    
                    # Extract and normalize findings
                    findings = extract_findings_from_result(res, mod_name)
                    all_raw_findings.extend(findings)
            else:
                err_msg = f"{mod_name}: unexpected return type {type(res).__name__}"
                errors.append(err_msg)
                tests[mod_name] = {"error": err_msg}

        waf = waf_result if isinstance(waf_result, str) else None

        # Deduplicate and filter
        deduplicated = deduplicate_findings(all_raw_findings)
        final_findings = filter_findings(deduplicated, min_confidence)

        # Summary
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in final_findings:
            sev = f["severity"]
            if sev in summary:
                summary[sev] += 1

        # Bug 3 Fix: Top-level safety net around result assembly and persistence
        assembly_error = None
        try:
            score_info = compute_bravo6_score(final_findings, waf)
            score = score_info["score"]
            grade = score_info["grade"]
        except Exception as e:
            score = 0
            grade = "F"
            assembly_error = f"{type(e).__name__}: {e}"
            logger.error(f"Failed to compute score or assemble result: {assembly_error}")

        # Build final result
        final_result = {
            "scanId": str(uuid.uuid4()),
            "url": url,
            "start_time": datetime.now().isoformat(),
            "end_time": datetime.now().isoformat(),
            "duration_seconds": round(duration, 2),
            "tests_run": tests_run,
            "total_findings": len(final_findings),
            "findings": final_findings,
            "tests": tests,
            "waf": waf,
            "errors": errors,
            "errors_count": len(errors),
            "deduplicated_count": len(all_raw_findings) - len(deduplicated),
            "summary": summary,
            "score": score,
            "grade": grade,
            "metrics": ctx.metrics
        }
        if assembly_error:
            final_result["assembly_error"] = assembly_error

        # Save results
        script_dir = Path(__file__).parent
        results_dir = script_dir / "results"
        os.makedirs(results_dir, exist_ok=True)
        try:
            if COSMOS_AVAILABLE and os.environ.get("COSMOS_URL"):
                client = CosmosClient(os.environ["COSMOS_URL"], credential=os.environ.get("COSMOS_KEY"))
                db = client.get_database_client(os.environ.get("COSMOS_DATABASE", "Bravo6DB"))
                container = db.get_container_client(os.environ.get("COSMOS_CONTAINER", "ScanResults"))
                final_result["id"] = final_result["scanId"]
                container.create_item(body=final_result)
                logger.info(f"Saved to Cosmos DB: {final_result['scanId']}")
            else:
                result_path = results_dir / f"result_{final_result['scanId']}.json"
                with open(result_path, "w", encoding="utf-8") as f:
                    json.dump(final_result, f, ensure_ascii=False, indent=2)
                logger.info(f"Saved to {result_path}")
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
            
            # Fallback to local file if Cosmos DB write fails to ensure data isn't lost
            if COSMOS_AVAILABLE and os.environ.get("COSMOS_URL"):
                try:
                    result_path = results_dir / f"result_{final_result['scanId']}.json"
                    with open(result_path, "w", encoding="utf-8") as f:
                        json.dump(final_result, f, ensure_ascii=False, indent=2)
                    logger.info(f"Fallback: Saved to {result_path}")
                except Exception as local_e:
                    logger.error(f"Failed to save results locally: {local_e}")

        return final_result

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Bravo6 Enterprise Security Scanner")
    parser.add_argument("url", nargs="?", default="https://example.com", help="Target URL")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show console output")
    parser.add_argument("--min-confidence", type=int, default=MIN_CONFIDENCE_DEFAULT, help="Min confidence threshold")
    parser.add_argument("--cve-csv-url", default=None, help="URL to CVE CSV database")
    parser.add_argument("--html", action="store_true", help="Generate HTML report")
    args = parser.parse_args()

    cve_csv_url = args.cve_csv_url or os.environ.get("CVE_CSV_URL")
    result = asyncio.run(run_scout(
        args.url,
        verbose=args.verbose,
        min_confidence=args.min_confidence,
        cve_csv_url=cve_csv_url
    ))

    if args.html:
        try:
            script_dir = Path(__file__).parent
            generator_path = script_dir / "report_generator.py"
            if not generator_path.exists():
                print(f"❌ report_generator.py not found at {generator_path.resolve()}")
                sys.exit(1)
            from report_generator import build_html
            html = build_html(result)
            report_path = script_dir / "security_report.html"
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(html)
            print(f"✅ HTML report generated: {report_path.resolve()}")
        except Exception as e:
            print(f"❌ Failed to generate report: {type(e).__name__}: {e}")