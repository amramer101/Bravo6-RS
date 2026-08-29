#!/usr/bin/env python3
"""
Bravo6 Enterprise Orchestrator (v8.5)
========================================================
- Centralized caching, context sharing, and WAF detection
- Unified 12-field finding normalization with strict schemas
- Granular deduplication and Two-Tier Scoring
- Cosmos DB + JSON fallback persistence
- Unified comprehensive sensitive paths enumeration list
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
USER_AGENT = "Bravo6-Scanner/8.5"
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=15)
MAX_RETRIES = 3
RETRY_BACKOFF = 2

# Default timeouts per module (seconds)
DEFAULT_TIMEOUTS = {
    "test_01_secrets": 60,
    "test_02_frontend_libs": 45,
    "test_03_cookies": 15,
    "test_04_ssl_tls": 30,
    "test_05_security_headers": 20,
    "test_06_info_disclosure": 90,
    "test_07_email_security": 30,
}

# ------------------------------------------------------------------------------
# Logging Configuration
# ------------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-7s | %(name)s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("Bravo6-Orchestrator")

# Canonical, shared table of known sensitive paths, owned by Orchestrator
# Expanded to be a superset including all test_06_info_disclosure targets
COMMON_SENSITIVE_PATHS = [
    # Environment & Secrets
    "/.env", "/.aws/credentials", "/.npmrc", "/.htpasswd",
    # Version Control
    "/.git/config", "/.git/HEAD", "/.svn/entries",
    # Server & PHP Info
    "/server-status", "/phpinfo.php", "/info.php",
    # Config files & Backups
    "/config.php", "/config.php.bak", "/wp-config.php", "/wp-config.php.bak",
    "/web.config", "/docker-compose.yml",
    # DB Tools
    "/adminer.php", 
    # IDEs & OS files
    "/.vscode/settings.json", "/.DS_Store",
    # Package Managers
    "/composer.json", "/package.json"
]

# ------------------------------------------------------------------------------
# Context & Dependency Injection
# ------------------------------------------------------------------------------
@dataclass
class ScannerContext:
    """
    Centralized context for dependency injection across all plugins.
    Passed as a single explicit parameter to all scouts.
    """
    url: str
    session: aiohttp.ClientSession
    config: Dict[str, Any] = field(default_factory=dict)
    
    # Shared signal telling scouts if response is representative
    page_is_representative: bool = True
    waf_challenge_detected: Optional[str] = None
    
    # Path enumeration ownership belongs here
    sensitive_paths: List[str] = field(default_factory=lambda: COMMON_SENSITIVE_PATHS)
    
    metrics: Dict[str, Any] = field(default_factory=lambda: {
        "http_requests": 0,
        "cache_hits": 0,
        "modules_executed": 0,
        "errors": []
    })
    
    main_page_cache: Dict[str, Any] = field(default_factory=dict)
    
    # Centralized event-gated Cache
    js_cache: Dict[str, str] = field(default_factory=dict)
    _js_fetch_events: Dict[str, asyncio.Event] = field(default_factory=dict)

    async def fetch_js(self, js_url: str) -> str:
        """Fetch JS file with caching and asyncio Event deduplication."""
        if js_url in self.js_cache:
            self.metrics["cache_hits"] += 1
            logger.debug(f"Cache HIT for JS: {js_url}")
            return self.js_cache[js_url]
            
        if js_url in self._js_fetch_events:
            await self._js_fetch_events[js_url].wait()
            if js_url in self.js_cache:
                self.metrics["cache_hits"] += 1
                logger.debug(f"Cache HIT (waited) for JS: {js_url}")
                return self.js_cache[js_url]
                
        logger.debug(f"Cache MISS for JS: {js_url}")
        event = asyncio.Event()
        self._js_fetch_events[js_url] = event
        
        try:
            self.metrics["http_requests"] += 1
            async with self.session.get(js_url, timeout=10) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    self.js_cache[js_url] = text
                    return text
        except Exception as e:
            logger.debug(f"Failed to fetch JS {js_url}: {e}")
        finally:
            event.set()
            self._js_fetch_events.pop(js_url, None)
        return ""

# ------------------------------------------------------------------------------
# Initialization & Pre-Flight
# ------------------------------------------------------------------------------
async def fetch_main_page_and_analyze(ctx: ScannerContext):
    """Fetch main page once, store it, and analyze for WAF/Challenge Pages."""
    url = ctx.url
    ctx.main_page_cache = {"status": 0, "html": "", "headers": {}, "set_cookie_headers": [], "soup": None, "error": None}

    try:
        ctx.metrics["http_requests"] += 1
        async with ctx.session.get(url) as resp:
            status = resp.status
            headers = dict(resp.headers)
            # dict(resp.headers) keeps only ONE value per header name, so a response
            # setting multiple cookies (the common case) silently loses all but one
            # Set-Cookie header here. Cookie-auditing scouts need every cookie, not
            # just the last one, so also capture the raw multi-value list separately
            # -- additive only, "headers" above is untouched for existing consumers.
            set_cookie_headers = resp.headers.getall("Set-Cookie", [])
            html = await resp.text()

            ctx.main_page_cache["status"] = status
            ctx.main_page_cache["headers"] = headers
            ctx.main_page_cache["set_cookie_headers"] = set_cookie_headers
            ctx.main_page_cache["html"] = html
            ctx.main_page_cache["soup"] = BeautifulSoup(html, "html.parser")
            
            # WAF and Representative Page Gate
            headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}
            html_lower = html.lower()
            
            waf = None
            rep = True
            
            if "cf-ray" in headers_lower or "cloudflare" in headers_lower.get("server", ""):
                waf = "Cloudflare"
            elif "x-sucuri-id" in headers_lower: waf = "Sucuri"
            elif "x-amz-cf-id" in headers_lower: waf = "AWS CloudFront"
            elif "x-akamai-transformed" in headers_lower: waf = "Akamai"
            elif "x-iinfo" in headers_lower or "x-cdn" in headers_lower: waf = "Imperva/Incapsula"
            
            if status >= 400:
                rep = False
                
            if "cf-chl" in html_lower or "cf-mitigated" in html_lower or "just a moment..." in html_lower:
                waf = "Cloudflare"
                rep = False
            elif "akamai" in html_lower and "access denied" in html_lower:
                rep = False
                waf = "Akamai"
            elif "incapsula incident id" in html_lower:
                rep = False
                waf = "Imperva/Incapsula"
                
            ctx.waf_challenge_detected = waf
            ctx.page_is_representative = rep

    except Exception as e:
        ctx.main_page_cache["error"] = str(e)
        ctx.page_is_representative = False

def discover_plugins() -> List[Any]:
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
        except Exception as e:
            logger.error(f"Failed to load plugin {module_name}: {e}")
    return plugins

# ------------------------------------------------------------------------------
# Finding Normalization & Schema Enforcement
# ------------------------------------------------------------------------------
def get_confidence_tier(raw_conf: Any) -> str:
    """Map numeric values or unknown strings to the 4 strictly permitted tiers."""
    allowed = ["verified-live", "verified-static", "plausible-unconfirmed", "informational"]
    if isinstance(raw_conf, str) and raw_conf in allowed:
        return raw_conf
    try:
        val = int(raw_conf)
        if val >= 90: return "verified-live"
        if val >= 70: return "verified-static"
        if val >= 30: return "plausible-unconfirmed"
        return "informational"
    except (ValueError, TypeError):
        return "informational"

def normalize_finding(raw: Dict[str, Any], module_name: str, index: int) -> Dict[str, Any]:
    """
    Enforce strict 12+1-field schema and preserve location verbatim.
    """
    title = raw.get("title") or raw.get("type") or raw.get("cve") or "Unknown Finding"
    cwe = raw.get("cwe") or ""
    owasp = raw.get("owasp") or ""
    
    location = raw.get("location") or raw.get("header") or raw.get("exact_js_file") or ""
    
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
        
    confidence = get_confidence_tier(raw.get("confidence", 50))
    
    evidence_parts = []
    if raw.get("evidence"): evidence_parts.append(str(raw["evidence"]))
    if raw.get("context"): evidence_parts.append(f"Context: {raw['context']}")
    if raw.get("value_masked"): evidence_parts.append(f"Value: {raw['value_masked']}")
    
    evidence = "\n".join(evidence_parts) if evidence_parts else json.dumps(raw, default=str)[:500]
    poc = raw.get("poc") or raw.get("poc_curl") or raw.get("poc_js") or "Manual verification required."
    remediation = raw.get("remediation") or "Consult security team for remediation."
    detection_method = raw.get("detection_method") or raw.get("source") or module_name
    
    # Extract tier safely from raw or nested raw["raw_data"]
    raw_tier = raw.get("tier")
    if not raw_tier and isinstance(raw.get("raw_data"), dict):
        raw_tier = raw.get("raw_data").get("tier")
    
    return {
        "id": finding_id,
        "module": module_name,
        "title": str(title)[:200],
        "severity": severity,
        "confidence": confidence,
        "cwe": str(cwe),
        "owasp": str(owasp),
        "location": str(location)[:500],
        "evidence": str(evidence)[:1000],
        "poc": str(poc)[:500],
        "remediation": str(remediation)[:500],
        "detection_method": str(detection_method)[:100],
        "tier": str(raw_tier)[:50] if raw_tier else "",
        "raw_data": raw
    }

# ------------------------------------------------------------------------------
# Deduplication & Filtering
# ------------------------------------------------------------------------------
_CONF_RANK = {"verified-live": 4, "verified-static": 3, "plausible-unconfirmed": 2, "informational": 1}
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

def deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Location MUST be included in the deduplication key to preserve distinct resources."""
    best: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        loc = f.get("location", "").strip().lower()
        key = f"{f['module']}|{f['title']}|{f['cwe']}|{f['owasp']}|{loc}"
        
        if key not in best:
            best[key] = f
            continue
            
        existing = best[key]
        f_conf = _CONF_RANK.get(f["confidence"], 0)
        ex_conf = _CONF_RANK.get(existing["confidence"], 0)
        
        if f_conf > ex_conf:
            best[key] = f
        elif f_conf == ex_conf:
            if _SEV_RANK.get(f["severity"], 0) > _SEV_RANK.get(existing["severity"], 0):
                best[key] = f
    return list(best.values())

# ------------------------------------------------------------------------------
# Unified Scoring Methodology
# ------------------------------------------------------------------------------
def compute_bravo6_score(
    findings: List[Dict[str, Any]],
    waf: Optional[str] = None,
    tests_run: Optional[int] = None,
    modules_discovered: Optional[int] = None,
    page_is_representative: bool = True,
) -> Dict[str, Any]:
    """
    Two-Tier Scoring Calibration Fix:
    Prevent heavily weighing bleeding-edge headers like COOP, COEP, etc.
    (Bug 1 Fix: reads directly from raw_data tier).

    Coverage-awareness fix: `score`/`grade` are computed exactly as before
    (unchanged for any fully-covered scan, e.g. tests_run == modules_discovered
    and page_is_representative == True) so existing consumers reading those two
    fields keep seeing identical values. Additive-only: this also returns
    `grade_reliable` (False when the page wasn't representative -- e.g. a WAF/
    challenge page -- or when fewer modules ran than were discovered) and a
    human-readable `coverage_note` explaining why, so a confident-looking grade
    can no longer be produced from a scan that examined little of the target.

    Score-resolution fix: `score` stays clamped to [0, 100] as before (needed
    for the letter-grade thresholds and any consumer expecting a 0-100 value).
    A very small number of critical/high findings is enough to reach that
    floor, after which two sites with very different real-world risk (e.g. a
    site missing every baseline header outright vs. a mostly-solid site with
    a couple of inflated findings) become indistinguishable at "0/F". The
    additive `raw_score` field is NOT clamped at 0, so sites that both floor
    the visible `score` can still be told apart by how far below the floor
    their actual deduction total falls.
    """
    BASE_PENALTY = {"critical": 30, "high": 15, "medium": 5, "low": 2, "info": 0}
    
    tier1_deduction = 0.0
    tier2_deduction = 0.0
    
    for f in findings:
        sev = f["severity"].lower()
        penalty = BASE_PENALTY.get(sev, 0)
        
        # FIX 1: Read proper tier assigned natively by the scout
        raw_tier = f.get("tier", "")
        if not raw_tier:
            raw_tier = f.get("raw_data", {}).get("tier", "")
            
        is_tier2 = (raw_tier == "hardening")
        
        if is_tier2:
            tier2_deduction += penalty
        else:
            tier1_deduction += penalty
            
    # Tier 2 deduction capped so it never alone tanks a score
    tier2_deduction = min(tier2_deduction, 10.0)
    
    total_deduction = tier1_deduction + tier2_deduction
    raw_score = round(100.0 - total_deduction, 2)
    score = max(0.0, 100.0 - total_deduction)
    int_score = round(score)
    
    if int_score >= 85: grade = "A"
    elif int_score >= 75: grade = "B"
    elif int_score >= 65: grade = "C"
    elif int_score >= 55: grade = "D"
    else: grade = "F"

    coverage_gaps = []
    if not page_is_representative:
        coverage_gaps.append("page was not representative (WAF/challenge/error response detected)")
    if (
        tests_run is not None
        and modules_discovered is not None
        and tests_run < modules_discovered
    ):
        coverage_gaps.append(f"only {tests_run}/{modules_discovered} scan modules completed")

    grade_reliable = len(coverage_gaps) == 0
    coverage_note = ("Grade may be unreliable: " + "; ".join(coverage_gaps) + ".") if coverage_gaps else None

    return {
        "score": int_score,
        "raw_score": raw_score,
        "grade": grade,
        "deductions": {
            "tier1": round(tier1_deduction, 2),
            "tier2": round(tier2_deduction, 2)
        },
        "waf_detected": waf is not None,
        "grade_reliable": grade_reliable,
        "coverage_note": coverage_note
    }

# ------------------------------------------------------------------------------
# Main Orchestrator Execution
# ------------------------------------------------------------------------------
async def run_scout(url: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    start_time = time.time()
    start_time_iso = datetime.now().isoformat()
    
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
        
    config = config or {}
    logger.info(f"Starting Bravo6 Enterprise Scan for {url}")
    
    connector = aiohttp.TCPConnector(ssl=True, limit=20, limit_per_host=10)
    async with aiohttp.ClientSession(
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
        connector=connector
    ) as session:
        
        ctx = ScannerContext(url=url, session=session, config=config)
        await fetch_main_page_and_analyze(ctx)
        
        plugins = discover_plugins()
        if not plugins:
            return {"error": "No test plugins found."}
            
        # FIX 2: Wrapper function to measure time precisely for each coroutine
        async def _timed(coro, mod_name):
            t0 = time.time()
            try:
                result = await coro
                return mod_name, result, round(time.time() - t0, 2)
            except Exception as e:
                return mod_name, e, round(time.time() - t0, 2)
            except asyncio.CancelledError as e:
                return mod_name, e, round(time.time() - t0, 2)

        test_coroutines = []
        
        for mod in plugins:
            module_name = mod.__name__
            sig = inspect.signature(mod.run)
            
            if "ctx" in sig.parameters:
                coro = mod.run(url=url, ctx=ctx) if "url" in sig.parameters else mod.run(ctx)
            elif "url" in sig.parameters:
                coro = mod.run(url=url, ctx=ctx)
            else:
                coro = mod.run(ctx)
                
            timeout_val = DEFAULT_TIMEOUTS.get(module_name, 60)
            coro_with_timeout = asyncio.wait_for(coro, timeout=timeout_val)
            
            test_coroutines.append(_timed(coro_with_timeout, module_name))
            
        # Execute concurrently and fetch correctly tracked timings
        timed_results = await asyncio.gather(*test_coroutines)
        
        duration = time.time() - start_time
        tests = {}
        all_raw_findings = []
        errors = []
        tests_run = 0
        
        for mod_name, res, dur_plugin in timed_results:
            
            if isinstance(res, Exception) or isinstance(res, asyncio.CancelledError):
                err_msg = f"{type(res).__name__}: {res}"
                if isinstance(res, asyncio.TimeoutError):
                    err_msg = f"Timed out after {DEFAULT_TIMEOUTS.get(mod_name, 60)}s"
                    
                errors.append(f"{mod_name}: {err_msg}")
                tests[mod_name] = {
                    "status": "incomplete",
                    "fatal_error": err_msg,
                    "duration_seconds": dur_plugin
                }
                continue
                
            if isinstance(res, dict):
                if "fatal_error" in res:
                    errors.append(f"{mod_name}: {res['fatal_error']}")
                    tests[mod_name] = {
                        "status": "incomplete",
                        "fatal_error": res["fatal_error"],
                        "duration_seconds": dur_plugin
                    }
                else:
                    tests_run += 1
                    ctx.metrics["modules_executed"] += 1
                    res["status"] = "complete"
                    res["duration_seconds"] = dur_plugin
                    tests[mod_name] = res
                    
                    for key in ["findings", "evidence", "vulnerabilities"]:
                        if key in res and isinstance(res[key], list):
                            for idx, f in enumerate(res[key]):
                                if isinstance(f, dict):
                                    all_raw_findings.append(normalize_finding(f, mod_name, idx))
                                    
                    if "details" in res and isinstance(res["details"], dict):
                        ctx.metrics["http_requests"] += res["details"].get("requests_made", 0)
            else:
                err_msg = f"Unexpected return type {type(res).__name__}"
                errors.append(f"{mod_name}: {err_msg}")
                tests[mod_name] = {"status": "incomplete", "fatal_error": err_msg, "duration_seconds": dur_plugin}
                
        deduplicated = deduplicate_findings(all_raw_findings)
        
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in deduplicated:
            sev = f["severity"]
            if sev in summary: summary[sev] += 1
            
        try:
            score_info = compute_bravo6_score(
                deduplicated,
                ctx.waf_challenge_detected,
                tests_run=tests_run,
                modules_discovered=len(plugins),
                page_is_representative=ctx.page_is_representative,
            )
        except Exception as e:
            logger.error(f"Score computation failed: {e}")
            score_info = {
                "score": 0, "raw_score": 0, "grade": "F", "deductions": {}, "waf_detected": False,
                "grade_reliable": False, "coverage_note": f"Score computation failed: {e}"
            }

        final_result = {
            "scanId": str(uuid.uuid4()),
            "url": url,
            "start_time": start_time_iso,
            "end_time": datetime.now().isoformat(),
            "duration_seconds": round(duration, 2),
            "tests_run": tests_run,
            "total_findings": len(deduplicated),
            "findings": deduplicated,
            "tests": tests,
            "waf": ctx.waf_challenge_detected,
            "page_is_representative": ctx.page_is_representative,
            "errors": errors,
            "errors_count": len(errors),
            "deduplicated_count": len(all_raw_findings) - len(deduplicated),
            "summary": summary,
            "score": score_info.get("score"),
            "raw_score": score_info.get("raw_score"),
            "grade": score_info.get("grade"),
            "grade_reliable": score_info.get("grade_reliable", True),
            "coverage_note": score_info.get("coverage_note"),
            "metrics": ctx.metrics
        }
        
        # Save results Logic
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
            
        return final_result

# ------------------------------------------------------------------------------
# CLI argument parsing (module-level so regression tests can exercise it
# without spawning a subprocess)
# ------------------------------------------------------------------------------
def build_arg_parser():
    import argparse
    parser = argparse.ArgumentParser(description="Bravo6 Enterprise Security Scanner")
    parser.add_argument("url", nargs="?", default="https://example.com", help="Target URL")
    parser.add_argument("--test", action="store_true", help="Run Orchestrator Integration Tests")
    parser.add_argument(
        "--cve-csv-url", dest="cve_csv_url", default=None,
        help="HTTP(S) URL or local filesystem path to a CVE dataset CSV, forwarded to "
             "test_02_frontend_libs.py's fetch_cve_dataset() for CVE correlation."
    )
    return parser


def build_run_config(args) -> Optional[Dict[str, Any]]:
    """Build the config dict passed to run_scout() from parsed CLI args."""
    if args.cve_csv_url:
        return {"cve_csv_url": args.cve_csv_url}
    return None


# ------------------------------------------------------------------------------
# Test Execution blocks mandated by Spec
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    args = build_arg_parser().parse_args()

    if args.test:
        import unittest
        class TestOrchestrator(unittest.IsolatedAsyncioTestCase):
            def test_bug1_location_preservation(self):
                """Bug 1: Assert the normalized output's location is identical to raw finding."""
                raw = {"title": "Exposed Creds", "location": "Header: X-Token"}
                norm = normalize_finding(raw, "test_01", 0)
                self.assertEqual(norm["location"], "Header: X-Token", "Location was dropped during normalization.")
                self.assertIn("id", norm, "Missing schema fields")
                self.assertIn("cwe", norm, "Missing schema fields")

            def test_bug2_dedup_distinct_locations(self):
                """Bug 2: Assert deduplication doesn't merge same-titled findings on different paths."""
                f1 = {"module": "test", "title": "File Exposed", "cwe": "200", "owasp": "A5", "location": "/api/v1/users", "confidence": "verified-live", "severity": "high"}
                f2 = {"module": "test", "title": "File Exposed", "cwe": "200", "owasp": "A5", "location": "/api/v2/admin", "confidence": "verified-live", "severity": "high"}
                res = deduplicate_findings([f1, f2])
                self.assertEqual(len(res), 2, "Deduplication incorrectly collapsed findings with different locations.")

            def test_bug3_tier_flattening_and_scoring(self):
                """Bug 3: Assert nested tier is flattened and Tier 2 deduction is capped at 10."""
                raw_findings = [
                    {"title": "Missing COOP", "severity": "medium", "raw_data": {"tier": "hardening"}},
                    {"title": "Missing COEP", "severity": "medium", "raw_data": {"tier": "hardening"}},
                    {"title": "Missing Permissions-Policy", "severity": "medium", "raw_data": {"tier": "hardening"}}
                ]
                
                normalized = [normalize_finding(f, "test_05", idx) for idx, f in enumerate(raw_findings)]
                
                for n in normalized:
                    self.assertEqual(n.get("tier"), "hardening", "Tier was not flattened correctly.")
                    
                score_info = compute_bravo6_score(normalized)
                self.assertEqual(score_info["deductions"]["tier2"], 10.0, "Tier 2 deduction was not capped at 10.")
                self.assertEqual(score_info["score"], 90, "Score calculation is incorrect.")
                self.assertTrue(
                    score_info["grade_reliable"],
                    "A fully-covered scan (no tests_run/modules_discovered/representativeness "
                    "gap supplied) must default to grade_reliable=True for backward compatibility."
                )
                self.assertIsNone(score_info["coverage_note"])
                self.assertEqual(score_info["raw_score"], 90.0, "raw_score must match the clamped score when nothing floors.")

            def test_raw_score_is_not_clamped_when_score_floors_at_zero(self):
                """Score-resolution fix: two sites that both floor score/grade at 0/F
                must still be distinguishable via the uncapped raw_score. Mirrors the
                audit's real-world case: gs.alexu.edu.eg (missing essentially every
                baseline header) and facebook.com (a mostly-solid site whose deduction
                was inflated by the test_05 boost bug) both landed on an identical
                0/F under the old scoring, losing all signal about which was worse."""
                many_criticals = [
                    {"title": f"Critical issue {i}", "severity": "critical", "raw_data": {}}
                    for i in range(6)  # 6 * 30 = 180 points of deduction
                ]
                normalized = [normalize_finding(f, "test_05", idx) for idx, f in enumerate(many_criticals)]
                score_info = compute_bravo6_score(normalized)

                self.assertEqual(score_info["score"], 0, "Clamped score must still floor at 0 as before.")
                self.assertEqual(score_info["grade"], "F")
                self.assertEqual(
                    score_info["raw_score"], -80.0,
                    "raw_score must reflect the true, uncapped deduction total (100 - 180 = -80)."
                )

            def test_raw_score_distinguishes_two_sites_that_both_floor_at_zero(self):
                mildly_bad = [{"title": f"Critical issue {i}", "severity": "critical", "raw_data": {}} for i in range(4)]
                catastrophic = [{"title": f"Critical issue {i}", "severity": "critical", "raw_data": {}} for i in range(10)]

                mild_info = compute_bravo6_score([normalize_finding(f, "m", i) for i, f in enumerate(mildly_bad)])
                bad_info = compute_bravo6_score([normalize_finding(f, "m", i) for i, f in enumerate(catastrophic)])

                self.assertEqual(mild_info["score"], 0)
                self.assertEqual(bad_info["score"], 0)
                self.assertEqual(mild_info["grade"], "F")
                self.assertEqual(bad_info["grade"], "F")
                # Both floor identically on the clamped fields, but raw_score still
                # tells them apart.
                self.assertGreater(
                    mild_info["raw_score"], bad_info["raw_score"],
                    "raw_score must distinguish a less-catastrophic 0/F from a more-catastrophic 0/F."
                )

            def test_coverage_gap_from_non_representative_page_marks_grade_unreliable(self):
                """Coverage-awareness fix: a WAF/challenge-blocked scan must not produce a
                confident grade. Mirrors the real gammal.tech scan (page_is_representative
                False, only 2/5 modules ran, yet the old code emitted score=96/grade=A)."""
                findings = [{"title": "Missing DNS CAA Record", "severity": "low", "raw_data": {}}]
                normalized = [normalize_finding(f, "test_04", 0) for f in findings]

                score_info = compute_bravo6_score(
                    normalized, tests_run=2, modules_discovered=5, page_is_representative=False
                )
                self.assertFalse(score_info["grade_reliable"])
                self.assertIsNotNone(score_info["coverage_note"])
                self.assertIn("not representative", score_info["coverage_note"])
                self.assertIn("2/5", score_info["coverage_note"])
                # The numeric score/grade themselves must still be computed normally --
                # this is an additive signal, not a replacement for the existing fields.
                self.assertEqual(score_info["score"], 98)
                self.assertEqual(score_info["grade"], "A")

            def test_coverage_gap_from_partial_module_completion_alone(self):
                """Even with a representative page, fewer completed modules than were
                discovered must also mark the grade unreliable."""
                score_info = compute_bravo6_score([], tests_run=3, modules_discovered=5, page_is_representative=True)
                self.assertFalse(score_info["grade_reliable"])
                self.assertIn("3/5", score_info["coverage_note"])
                self.assertNotIn("not representative", score_info["coverage_note"])

            def test_full_coverage_with_explicit_counts_stays_reliable(self):
                """tests_run == modules_discovered and a representative page must NOT be
                flagged, even when the counts are explicitly supplied (not defaulted)."""
                score_info = compute_bravo6_score([], tests_run=5, modules_discovered=5, page_is_representative=True)
                self.assertTrue(score_info["grade_reliable"])
                self.assertIsNone(score_info["coverage_note"])

            async def test_bug4_cache_hits(self):
                """Bug 4: Integration test running 3 simulated concurrent checks. Assert cache_hits >= 1."""
                class MockResponse:
                    status = 200
                    async def text(self): return "mock_js_content"
                    async def __aenter__(self): return self
                    async def __aexit__(self, *a): pass

                class MockSession:
                    def get(self, *a, **kw): return MockResponse()

                ctx = ScannerContext("http://example.com", session=MockSession())
                
                async def mock_scout_task(c):
                    await c.fetch_js("http://example.com/shared.js")
                
                # Fire concurrently to verify Event-gating
                await asyncio.gather(mock_scout_task(ctx), mock_scout_task(ctx), mock_scout_task(ctx))
                
                self.assertEqual(ctx.metrics["http_requests"], 1, "Should only make one HTTP request due to Event locking.")
                self.assertGreaterEqual(ctx.metrics["cache_hits"], 1, "Cache hits should be >= 1 for shared fetching.")

            def test_bug5_cve_csv_url_cli_flag_reaches_config(self):
                """Issue 3: --cve-csv-url must be parsed and forwarded into the config
                dict that run_scout() passes into ScannerContext, so
                test_02_frontend_libs.py's ctx.config.get('cve_csv_url') sees it."""
                parser = build_arg_parser()
                args = parser.parse_args(["https://example.com", "--cve-csv-url", "path/to/some.csv"])
                self.assertEqual(args.cve_csv_url, "path/to/some.csv")

                config = build_run_config(args)
                self.assertEqual(config, {"cve_csv_url": "path/to/some.csv"})

                ctx = ScannerContext(url="https://example.com", session=None, config=config)
                self.assertEqual(ctx.config.get("cve_csv_url"), "path/to/some.csv")

            def test_bug5_no_cve_csv_url_flag_preserves_default_behavior(self):
                """Without --cve-csv-url, config must stay empty/None just like before this fix."""
                parser = build_arg_parser()
                args = parser.parse_args(["https://example.com"])
                self.assertIsNone(args.cve_csv_url)

                config = build_run_config(args)
                self.assertIsNone(config)

                ctx = ScannerContext(url="https://example.com", session=None, config=config or {})
                self.assertIsNone(ctx.config.get("cve_csv_url"))

        sys.argv = [sys.argv[0]]
        unittest.main()
    else:
        config = build_run_config(args)
        result = asyncio.run(run_scout(args.url, config=config))