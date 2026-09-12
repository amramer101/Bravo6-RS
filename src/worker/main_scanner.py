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
import ipaddress
import json
import logging
import math
import os
import socket
import sys
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp
from aiohttp.resolver import ThreadedResolver
from bs4 import BeautifulSoup

# Optional Cosmos DB integration.
#
# DefaultAzureCredential is imported inside the SAME guarded block on purpose:
# the Worker now authenticates to Cosmos DB with its Function App's Managed
# Identity (the identity block in terraform/modules/function_app/main.tf), not
# an account key, so azure-identity is exactly as much a hard prerequisite of
# the Cosmos path as azure-cosmos is. If either import fails, COSMOS_AVAILABLE
# stays False and persistence goes straight to the local-JSON path -- the same
# degraded-but-never-lossy behaviour as having no COSMOS_URL configured.
try:
    from azure.cosmos import CosmosClient
    from azure.identity import DefaultAzureCredential
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
    "test_08_cors": 15,
    # test_09_sri intentionally has no entry: it makes zero network requests
    # (pure reparse of already-cached HTML), so the 60s default is never hit.
    # test_10_hallucinated_deps has TWO distinct outbound hops with different
    # hosts/latency/failure modes, so it carries a per-hop budget for each in
    # addition to the whole-scout cap the orchestrator reads below:
    #   *_manifest_fetch  - one GET to the TARGET site per well-known manifest path
    #   *_registry_lookup - one GET per package to npm/PyPI (a DIFFERENT host);
    #                       a slow registry must not block/corrupt the target portion
    "test_10_hallucinated_deps": 45,
    "test_10_hallucinated_deps_manifest_fetch": 8,
    "test_10_hallucinated_deps_registry_lookup": 6,
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

# ------------------------------------------------------------------------------
# SSRF / Target Safety
# ------------------------------------------------------------------------------
class SSRFBlockedError(Exception):
    """Raised when a target hostname/IP resolves to (or is) a non-public
    address -- private, loopback, link-local (which includes the cloud
    metadata endpoint 169.254.169.254), reserved, or multicast."""

    def __init__(self, host: str, address: str):
        self.host = host
        self.address = address
        super().__init__(
            f"Refusing to connect to '{host}' -- resolves to non-public address {address}"
        )


def _is_ip_safe(ip: "ipaddress._BaseAddress") -> bool:
    """Stdlib classification only -- deliberately not hand-rolled CIDR
    checks. is_private already subsumes loopback/link-local/reserved for
    both address families in Python's ipaddress module, but each is listed
    explicitly here so the intent (and the metadata-endpoint case
    specifically) is legible without reading CPython's source."""
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def is_target_address_safe(hostname_or_ip: str) -> bool:
    """True if it's safe to issue an outbound scan request to hostname_or_ip.

    A bare IP literal is checked directly. A hostname is resolved (A and
    AAAA) and EVERY returned address must be safe -- one unsafe answer
    among several fails the whole lookup, since a scanning HTTP client has
    no reliable way to force which of several returned addresses it will
    actually connect to.

    An unresolvable hostname returns True: nothing unsafe has been proven,
    and the connection attempt will simply fail on its own right after.
    """
    try:
        return _is_ip_safe(ipaddress.ip_address(hostname_or_ip))
    except ValueError:
        pass  # not a literal IP -- resolve it below

    try:
        infos = socket.getaddrinfo(hostname_or_ip, None)
    except socket.gaierror:
        return True

    addresses = {info[4][0] for info in infos}
    if not addresses:
        return True

    return all(_is_ip_safe(ipaddress.ip_address(addr)) for addr in addresses)


class SSRFSafeConnector(aiohttp.TCPConnector):
    """Closes a gap SSRFSafeResolver alone can't cover: aiohttp's own
    TCPConnector._resolve_host() special-cases a literal IP host and
    returns it directly WITHOUT ever calling the resolver (verified against
    aiohttp 3.14.1's source -- `if is_ip_address(host): return [...]`, no
    resolver call at all on that branch). A target given as a bare IP, or
    an HTTP redirect Location pointing at one, would sail straight past
    SSRFSafeResolver on that path. _resolve_host() is called uniformly
    for the initial connection and every redirect hop, so overriding it
    here covers a literal-IP host the same way the resolver covers a
    hostname. Hostnames are deliberately NOT re-checked here (left to
    SSRFSafeResolver): checking them again with a second, independent
    getaddrinfo() call here would open a TOCTOU/DNS-rebinding gap between
    what this check saw and what the resolver actually connects to.
    """

    async def _resolve_host(self, host, port, traces=None):
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if ip is not None and not _is_ip_safe(ip):
            raise SSRFBlockedError(host, host)
        return await super()._resolve_host(host, port, traces)


class SSRFSafeResolver(ThreadedResolver):
    """Drop-in replacement for aiohttp's default resolver that rejects any
    DNS answer pointing at a non-public address, wired into the single
    aiohttp.TCPConnector every scout's requests share (see run_scout()).

    This is also what makes the check apply to redirects, not just the
    initial hostname: aiohttp opens a fresh connection -- and therefore
    performs a fresh resolve() through this same connector/resolver -- for
    every redirect hop, including a hop to a different host. A publicly
    resolving hostname that 302s to an internal address is blocked here,
    at the redirect target, the same way the initial target would be.
    """

    async def resolve(self, host, port=0, family=socket.AF_INET):
        hosts = await super().resolve(host, port, family)
        for h in hosts:
            if not _is_ip_safe(ipaddress.ip_address(h["host"])):
                raise SSRFBlockedError(host, h["host"])
        return hosts


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

    # Set when the pre-flight fetch was refused by SSRFSafeResolver -- the
    # target (or something it redirected to) resolved to a non-public
    # address. run_scout() checks this immediately after the pre-flight
    # fetch and aborts the scan before any scout runs.
    ssrf_blocked: bool = False
    ssrf_block_reason: Optional[str] = None
    
    # Path enumeration ownership belongs here
    sensitive_paths: List[str] = field(default_factory=lambda: COMMON_SENSITIVE_PATHS)
    
    metrics: Dict[str, Any] = field(default_factory=lambda: {
        "http_requests": 0,
        "cache_hits": 0,
        "modules_executed": 0,
        "errors": [],
        # Additive instrumentation only (no scoring/detection impact):
        # base_url_gets  -- actual HTTP GETs issued against ctx.url itself
        #                   (expected: exactly 1, the pre-flight fetch).
        # cache_reads    -- number of cache-consuming scouts (test_01/02/03/
        #                   05/06/09) that served their main-page needs from
        #                   ctx.main_page_cache instead of issuing a fetch.
        "base_url_gets": 0,
        "cache_reads": 0
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
def detect_waf_and_representativeness(status: int, headers: Dict[str, Any], html: str) -> tuple:
    """Pure WAF/challenge-page detection, factored out of
    fetch_main_page_and_analyze() so it's directly unit-testable without
    mocking an HTTP session. Returns (waf_name_or_None, page_is_representative).
    """
    headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}
    html_lower = html.lower()

    waf = None
    rep = True

    if "cf-ray" in headers_lower or "cloudflare" in headers_lower.get("server", ""):
        waf = "Cloudflare"
    elif "x-sucuri-id" in headers_lower: waf = "Sucuri"
    elif "x-amz-cf-id" in headers_lower: waf = "AWS CloudFront"
    # Live-confirmed regression: elcorteingles.es's real Akamai block page
    # ("Access Denied", Server: AkamaiGHost) has neither the
    # x-akamai-transformed header nor the literal word "akamai" anywhere in
    # its 374-byte body -- only in the Server header value ("AkamaiGHost").
    # Check that too, mirroring how the Cloudflare branch above already
    # checks the Server header's content, not just specific header names.
    elif "x-akamai-transformed" in headers_lower or "akamai" in headers_lower.get("server", ""): waf = "Akamai"
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

    return waf, rep


async def fetch_main_page_and_analyze(ctx: ScannerContext):
    """Fetch main page once, store it, and analyze for WAF/Challenge Pages."""
    url = ctx.url
    ctx.main_page_cache = {"status": 0, "html": "", "headers": {}, "set_cookie_headers": [], "soup": None, "error": None}

    try:
        ctx.metrics["http_requests"] += 1
        ctx.metrics["base_url_gets"] = ctx.metrics.get("base_url_gets", 0) + 1
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
            waf, rep = detect_waf_and_representativeness(status, headers, html)
            ctx.waf_challenge_detected = waf
            ctx.page_is_representative = rep

    except SSRFBlockedError as e:
        ctx.main_page_cache["error"] = str(e)
        ctx.page_is_representative = False
        ctx.ssrf_blocked = True
        ctx.ssrf_block_reason = str(e)
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

    # NOTE: the scout's raw finding dict is deliberately NOT echoed back into
    # the normalized finding. The 12 explicit fields above (plus `tier`) are
    # the single source of truth; keeping a verbatim `raw_data` copy only
    # duplicated every field, roughly doubled the persisted result size, and
    # re-stored free-text evidence/context that a scout might have failed to
    # redact (see test_01_secrets._redact_secrets). `tier` is preserved as a
    # first-class field so compute_bravo6_score() still has everything it
    # needs.
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
        
        # Read the tier assigned natively by the scout. normalize_finding()
        # flattens both the top-level and the nested raw_data["tier"] form
        # into this single field; the nested-dict fallback is kept only for
        # callers that pass un-normalized findings straight in (some tests).
        raw_tier = f.get("tier", "")
        if not raw_tier and isinstance(f.get("raw_data"), dict):
            raw_tier = f["raw_data"].get("tier", "")

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
# Result Persistence (Cosmos DB first, local JSON as the never-lose-it fallback)
# ------------------------------------------------------------------------------
# Three attempts with exponential backoff, matching the API Gateway's write
# path (src/api/scan_job.py's COSMOS_WRITE_MAX_ATTEMPTS) in retry COUNT but
# deliberately NOT in failure semantics:
#
#   Gateway (write_scan_job): a scan-job record that never reaches Cosmos DB
#   raises -- the caller must return 503. It has to, because quota enforcement
#   counts a user's recent jobs by querying Cosmos DB, so a job recorded only
#   in a local file would silently escape every future quota count.
#
#   Worker (persist_scan_result, below): a scan RESULT that never reaches
#   Cosmos DB falls through to a local JSON file and the scan is still
#   reported as a success. Nothing else in the system reads back a result to
#   make a control decision, and the scan itself -- minutes of network work
#   across ten scouts -- is far more expensive to redo than a Gateway
#   submission. Losing it because the database blipped is the worse outcome.
#
# That difference is why these two retry loops are not factored into one
# shared helper: the retry mechanics are ~8 lines, while what happens on
# exhaustion (raise vs. fall through) is the entire point of each call site.
# The two Function Apps are also separate deployment roots -- src/api/ and
# src/worker/ are each packaged and deployed on their own, with no shared
# importable package between them -- so a common helper would have to be
# vendored into both anyway.
COSMOS_WRITE_MAX_ATTEMPTS = 3
COSMOS_WRITE_RETRY_BACKOFF_SECONDS = 1.0

# Fallback values only -- COSMOS_DATABASE / COSMOS_CONTAINER are now set
# explicitly on the Worker's Function App
# (terraform/modules/function_app/main.tf). They match what Terraform actually
# provisions (modules/cosmos_db/main.tf: database var.db_name = "bravo6-db",
# container "scans") and what the Gateway already targets. The previous
# defaults here, "Bravo6DB" and "ScanResults", named a database and a
# container that exist nowhere in the Terraform, so even a correctly
# authenticated client would have 404'd against them.
COSMOS_DEFAULT_DATABASE = "bravo6-db"
COSMOS_DEFAULT_CONTAINER = "scans"


def build_cosmos_container():
    """Build the Cosmos container client the Worker writes scan results to.

    Managed Identity via DefaultAzureCredential, the platform-wide standard --
    src/api/function_app.py._get_cosmos_container() constructs its client the
    same way, and the Worker's Function App has a system-assigned identity with
    a Cosmos SQL data-plane role assignment (terraform/iam.tf).

    This replaces the previous account-key credential, read from a COSMOS_KEY
    environment variable. No Terraform ever set COSMOS_KEY, so that lookup
    resolved to None on every deployed invocation; combined with COSMOS_URL
    also being unset, the Cosmos branch was unreachable in the deployed
    configuration and every scan result went to local JSON on an ephemeral
    Flex Consumption instance.
    """
    client = CosmosClient(os.environ["COSMOS_URL"], credential=DefaultAzureCredential())
    db = client.get_database_client(os.environ.get("COSMOS_DATABASE", COSMOS_DEFAULT_DATABASE))
    return db.get_container_client(os.environ.get("COSMOS_CONTAINER", COSMOS_DEFAULT_CONTAINER))


def write_result_locally(final_result: Dict[str, Any], results_dir) -> Optional[Path]:
    """Write final_result to results_dir as JSON. Returns the path written, or
    None if even this failed (logged, never raised -- run_scout must still
    return the result to its caller either way)."""
    try:
        results_dir = Path(results_dir)
        results_dir.mkdir(parents=True, exist_ok=True)
        result_path = results_dir / f"result_{final_result['scanId']}.json"
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(final_result, f, ensure_ascii=False, indent=2)
        logger.info(f"Saved to {result_path}")
        return result_path
    except Exception as e:
        logger.error(f"Failed to save results locally: {e}")
        return None


def persist_scan_result(
    final_result: Dict[str, Any],
    results_dir,
    container_factory=None,
    sleep=None,
) -> str:
    """Persist a finished scan result. Returns "cosmos", "local", or "none".

    Cosmos DB is attempted only when it is both importable and configured;
    otherwise this goes straight to local JSON, as before. A Cosmos write is
    retried COSMOS_WRITE_MAX_ATTEMPTS times with exponential backoff, and if
    every attempt fails the result STILL lands in local JSON. That last part
    is the invariant this function exists to protect: a scan result must never
    be lost because Cosmos DB was unavailable.

    (Before this pass there was no such fallback: the Cosmos write and the
    local write were the two arms of one if/else inside a single try, so an
    exception from the Cosmos arm was caught, logged, and dropped -- the local
    arm never ran. The design intent was already documented; the wiring wasn't
    there.)

    Exceptions are caught broadly rather than as CosmosHttpResponseError -- the
    Gateway's narrower catch is right for a path that re-raises, but here
    anything that escapes (auth failure, DNS, a client-construction error)
    must end in the local-JSON fallback, not propagate out of run_scout.

    container_factory and sleep are injection points for the regression suite;
    production callers pass neither.
    """
    container_factory = container_factory or build_cosmos_container
    sleep = sleep or time.sleep

    if not (COSMOS_AVAILABLE and os.environ.get("COSMOS_URL")):
        return "local" if write_result_locally(final_result, results_dir) else "none"

    last_error = None
    for attempt in range(1, COSMOS_WRITE_MAX_ATTEMPTS + 1):
        try:
            container = container_factory()
            final_result["id"] = final_result["scanId"]
            container.create_item(body=final_result)
            logger.info(f"Saved to Cosmos DB: {final_result['scanId']}")
            return "cosmos"
        except Exception as e:
            last_error = e
            logger.warning(
                f"Cosmos DB write attempt {attempt}/{COSMOS_WRITE_MAX_ATTEMPTS} "
                f"failed for scan {final_result.get('scanId')}: {e}"
            )
            if attempt < COSMOS_WRITE_MAX_ATTEMPTS:
                sleep(COSMOS_WRITE_RETRY_BACKOFF_SECONDS * (2 ** (attempt - 1)))

    logger.error(
        f"Cosmos DB write failed after {COSMOS_WRITE_MAX_ATTEMPTS} attempts for scan "
        f"{final_result.get('scanId')}; falling back to local JSON. Last error: {last_error}"
    )
    return "local" if write_result_locally(final_result, results_dir) else "none"


# ------------------------------------------------------------------------------
# Main Orchestrator Execution
# ------------------------------------------------------------------------------
async def run_scout(url: str, scan_id: str, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    start_time = time.time()
    start_time_iso = datetime.now().isoformat()
    
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
        
    config = config or {}
    logger.info(f"Starting Bravo6 Enterprise Scan for {url}")
    
    # SSRFSafeResolver is shared by every request this session makes --
    # the pre-flight fetch below, every scout's ctx.session.get/head/
    # options() call, and (critically) any redirect hop any of those
    # requests follows -- since it's installed on the one connector the
    # whole session uses, not called ad hoc per request.
    connector = SSRFSafeConnector(ssl=True, limit=20, limit_per_host=10, resolver=SSRFSafeResolver())
    async with aiohttp.ClientSession(
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT},
        connector=connector
    ) as session:

        ctx = ScannerContext(url=url, session=session, config=config)
        await fetch_main_page_and_analyze(ctx)

        if ctx.ssrf_blocked:
            logger.warning(f"Blocked unsafe target {url}: {ctx.ssrf_block_reason}")
            return {
                "scanId": scan_id,
                "url": url,
                "status": "blocked_ssrf",
                "ssrf_block_reason": ctx.ssrf_block_reason,
                "start_time": start_time_iso,
                "end_time": datetime.now().isoformat(),
                "duration_seconds": round(time.time() - start_time, 2),
                "tests_run": 0,
                "total_findings": 0,
                "findings": [],
                "tests": {},
                "waf": None,
                "page_is_representative": False,
                "errors": [ctx.ssrf_block_reason],
                "errors_count": 1,
                "deduplicated_count": 0,
                "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "score": None,
                "raw_score": None,
                "grade": None,
                "grade_reliable": False,
                "coverage_note": "Scan aborted before any scout ran: target blocked by SSRF safety check.",
                "metrics": ctx.metrics,
            }

        plugins = discover_plugins()
        if not plugins:
            return {"error": "No test plugins found."}
            
        # FIX 2: Wrapper function to measure time precisely for each coroutine
        #
        # Deliberately does NOT catch asyncio.CancelledError: a caller
        # cancelling this scan (e.g. run_evaluation.py's outer
        # asyncio.wait_for(run_scout(...), OUTER_TIMEOUT_SECONDS) firing on a
        # genuine hang) must actually be able to cancel it. Catching
        # CancelledError here and returning it as an ordinary value made
        # gather() below complete "normally" instead of propagating the
        # cancellation, so run_scout() would return a partial result rather
        # than actually stopping -- defeating the one mechanism meant to
        # catch a hang above the per-module timeouts already enforced by
        # asyncio.wait_for(coro, timeout=timeout_val) below.
        async def _timed(coro, mod_name):
            t0 = time.time()
            try:
                result = await coro
                return mod_name, result, round(time.time() - t0, 2)
            except Exception as e:
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
            "scanId": scan_id,
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
        
        # Save results Logic -- Cosmos DB (Managed Identity, 3 attempts with
        # exponential backoff), then local JSON if that never succeeds. See
        # persist_scan_result() for why the fallback is unconditional here and
        # not in the Gateway's equivalent writer.
        results_dir = Path(__file__).parent / "results"
        persist_scan_result(final_result, results_dir)

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

            def test_akamai_detected_via_server_header_on_real_block_page(self):
                """Live-confirmed regression: elcorteingles.es's real Akamai
                'Access Denied' block page has neither the
                x-akamai-transformed header nor the literal word "akamai" in
                its body -- only Server: AkamaiGHost. Must still be detected."""
                status = 403
                headers = {"Server": "AkamaiGHost", "Content-Type": "text/html"}
                html = '<HTML><HEAD>\n<TITLE>Access Denied</TITLE>\n</HEAD><BODY>\n<H1>Access Denied</H1>\nYou don\'t have permission...\n</BODY></HTML>'
                waf, rep = detect_waf_and_representativeness(status, headers, html)
                self.assertEqual(waf, "Akamai")
                self.assertFalse(rep)

            def test_akamai_still_detected_via_legacy_header_name(self):
                """Regression guard: the pre-existing x-akamai-transformed
                header path must keep working after the fix."""
                waf, rep = detect_waf_and_representativeness(
                    200, {"X-Akamai-Transformed": "9 - 0 pmb=mtr"}, "<html>ok</html>"
                )
                self.assertEqual(waf, "Akamai")

            def test_akamai_still_detected_via_body_marker(self):
                """Regression guard: the pre-existing body-based
                'akamai' + 'access denied' path must keep working too."""
                waf, rep = detect_waf_and_representativeness(
                    200, {}, "<html>Access Denied by Akamai edge server</html>"
                )
                self.assertEqual(waf, "Akamai")
                self.assertFalse(rep)

            def test_unrelated_server_header_not_misdetected_as_akamai(self):
                waf, rep = detect_waf_and_representativeness(200, {"Server": "nginx"}, "<html>ok</html>")
                self.assertIsNone(waf)
                self.assertTrue(rep)

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

            def test_ssrf_public_ip_and_hostname_allowed(self):
                self.assertTrue(is_target_address_safe("8.8.8.8"))
                self.assertTrue(is_target_address_safe("1.1.1.1"))

            def test_ssrf_rfc1918_ip_blocked(self):
                self.assertFalse(is_target_address_safe("10.0.0.5"))
                self.assertFalse(is_target_address_safe("172.16.0.1"))
                self.assertFalse(is_target_address_safe("192.168.1.1"))

            def test_ssrf_loopback_and_localhost_blocked(self):
                self.assertFalse(is_target_address_safe("127.0.0.1"))
                self.assertFalse(is_target_address_safe("localhost"))

            def test_ssrf_cloud_metadata_endpoint_blocked(self):
                """169.254.169.254 -- the Azure/AWS/GCP metadata endpoint --
                falls under link-local, but is asserted by its literal
                address specifically since this is the concrete target the
                threat model names, not just the CIDR block it happens to
                sit in."""
                self.assertFalse(is_target_address_safe("169.254.169.254"))

            def test_ssrf_unresolvable_hostname_not_blocked(self):
                """Nothing unsafe is proven for a hostname that doesn't
                resolve at all -- the connection attempt fails on its own
                right after. This must not be conflated with a blocked
                target in aggregate.csv/per-site JSON."""
                self.assertTrue(is_target_address_safe("this-should-not-exist-bravo6-test.invalid"))

            async def test_ssrf_resolver_blocks_unsafe_dns_answer(self):
                import unittest.mock as mock
                resolver = SSRFSafeResolver()
                with mock.patch.object(
                    ThreadedResolver, "resolve",
                    new=mock.AsyncMock(return_value=[
                        {"hostname": "evil.example.com", "host": "10.1.2.3", "port": 443,
                         "family": socket.AF_INET, "proto": 0, "flags": 0}
                    ]),
                ):
                    with self.assertRaises(SSRFBlockedError):
                        await resolver.resolve("evil.example.com")

            async def test_ssrf_resolver_blocks_redirect_target_not_only_initial_host(self):
                """Simulates the classic SSRF bypass: a publicly-resolving
                hostname's HTTP redirect target is a DIFFERENT host that
                resolves internally. aiohttp performs a fresh resolve() per
                redirect hop through this same connector/resolver, so two
                calls to the same resolver instance with different
                hostnames models exactly what happens at that second hop."""
                import unittest.mock as mock

                async def fake_resolve(self_, host, port=0, family=socket.AF_INET):
                    if host == "public.example.com":
                        return [{"hostname": host, "host": "93.184.216.34", "port": port,
                                 "family": family, "proto": 0, "flags": 0}]
                    return [{"hostname": host, "host": "127.0.0.1", "port": port,
                             "family": family, "proto": 0, "flags": 0}]

                resolver = SSRFSafeResolver()
                with mock.patch.object(ThreadedResolver, "resolve", new=fake_resolve):
                    hosts = await resolver.resolve("public.example.com")
                    self.assertEqual(hosts[0]["host"], "93.184.216.34")

                    with self.assertRaises(SSRFBlockedError):
                        await resolver.resolve("internal.example.com")

        class TestResultPersistence(unittest.TestCase):
            """Regression suite for persist_scan_result() -- the Worker's
            Cosmos-DB-then-local-JSON write path.

            Three things are pinned here, in decreasing order of how bad it
            would be to regress them:

              1. A Cosmos failure that exhausts every retry STILL writes the
                 result to local JSON. This is the Worker's whole design
                 intent -- never lose a scan result -- and it is the one
                 behaviour that must never regress, however the retry or auth
                 code above it is rewritten.
              2. The Cosmos client authenticates with Managed Identity
                 (DefaultAzureCredential), never an account key.
              3. A failing write is attempted exactly COSMOS_WRITE_MAX_ATTEMPTS
                 times, with a growing (exponential) backoff between attempts.
            """

            def setUp(self):
                import tempfile
                import unittest.mock as mock
                self.mock = mock
                self.module = sys.modules[__name__]
                self._tmp = tempfile.TemporaryDirectory()
                self.results_dir = Path(self._tmp.name)
                self.result = {"scanId": "scan-abc-123", "url": "https://example.com", "score": 90}
                self.slept = []

            def tearDown(self):
                self._tmp.cleanup()

            def _cosmos_env(self, **extra):
                env = {
                    "COSMOS_URL": "https://bravo6-cosmosdb-12345.documents.azure.com:443/",
                    "COSMOS_DATABASE": "bravo6-db",
                    "COSMOS_CONTAINER": "scans",
                }
                env.update(extra)
                return self.mock.patch.dict(os.environ, env, clear=False)

            def _local_files(self):
                return sorted(pth.name for pth in self.results_dir.glob("*.json"))

            def _persist(self, container_factory):
                """Run persist_scan_result with Cosmos considered available,
                capturing every backoff sleep instead of actually sleeping."""
                with self.mock.patch.object(self.module, "COSMOS_AVAILABLE", True), self._cosmos_env():
                    return persist_scan_result(
                        self.result,
                        self.results_dir,
                        container_factory=container_factory,
                        sleep=self.slept.append,
                    )

            # --- 2. Managed Identity, not an account key -------------------
            def test_cosmos_client_uses_managed_identity_not_account_key(self):
                """build_cosmos_container() must pass a DefaultAzureCredential
                instance, not the value of a COSMOS_KEY account key. The
                pre-fix code read that key straight out of the environment;
                COSMOS_KEY is set by no Terraform anywhere, so it resolved to
                None in every deployed invocation. COSMOS_KEY is deliberately
                set to a sentinel value here: if it ever leaks back into the
                credential, this test fails."""
                sentinel_key = "SENTINEL-ACCOUNT-KEY-MUST-NOT-BE-USED"
                captured = {}

                class FakeCredential:
                    pass

                class FakeContainer:
                    pass

                class FakeDatabase:
                    def get_container_client(self, name):
                        captured["container"] = name
                        return FakeContainer()

                class FakeCosmosClient:
                    def __init__(self, url, credential=None, **kwargs):
                        captured["url"] = url
                        captured["credential"] = credential

                    def get_database_client(self, name):
                        captured["database"] = name
                        return FakeDatabase()

                with self.mock.patch.object(self.module, "CosmosClient", FakeCosmosClient), \
                     self.mock.patch.object(self.module, "DefaultAzureCredential", FakeCredential), \
                     self._cosmos_env(COSMOS_KEY=sentinel_key):
                    container = build_cosmos_container()

                self.assertIsInstance(container, FakeContainer)
                self.assertIsInstance(
                    captured["credential"], FakeCredential,
                    "Cosmos client must authenticate with DefaultAzureCredential (Managed Identity)."
                )
                self.assertNotEqual(
                    captured["credential"], sentinel_key,
                    "Cosmos client must NOT authenticate with an account key from COSMOS_KEY."
                )
                self.assertIsNotNone(
                    captured["credential"],
                    "credential=None was the real-world effect of the old COSMOS_KEY lookup."
                )
                self.assertEqual(captured["database"], "bravo6-db")
                self.assertEqual(captured["container"], "scans")

            def test_cosmos_key_is_not_read_anywhere_in_the_source(self):
                """Belt-and-braces companion to the test above: no COSMOS_KEY
                lookup may survive anywhere in this module, including in a code
                path the unit tests happen not to exercise."""
                import re
                source = Path(__file__).read_text(encoding="utf-8")
                lookups = re.findall(
                    r"os\.environ(?:\.get)?\(\s*[\"']COSMOS\_KEY[\"']", source
                )
                self.assertEqual(
                    lookups, [],
                    "COSMOS_KEY must not be read anywhere: the Worker authenticates "
                    "to Cosmos DB with Managed Identity, not an account key."
                )

            # --- 3. Retry count and backoff --------------------------------
            def test_transient_cosmos_failure_is_retried_three_times(self):
                attempts = {"n": 0}

                class AlwaysFailingContainer:
                    def create_item(self, body):
                        attempts["n"] += 1
                        raise RuntimeError("transient Cosmos DB failure")

                outcome = self._persist(lambda: AlwaysFailingContainer())

                self.assertEqual(
                    attempts["n"], COSMOS_WRITE_MAX_ATTEMPTS,
                    f"Cosmos write must be attempted {COSMOS_WRITE_MAX_ATTEMPTS} times before giving up."
                )
                self.assertEqual(attempts["n"], 3, "The agreed retry count is 3, matching the API Gateway's writer.")
                self.assertEqual(outcome, "local")

            def test_backoff_between_attempts_is_exponential(self):
                class AlwaysFailingContainer:
                    def create_item(self, body):
                        raise RuntimeError("transient Cosmos DB failure")

                self._persist(lambda: AlwaysFailingContainer())

                self.assertEqual(
                    len(self.slept), COSMOS_WRITE_MAX_ATTEMPTS - 1,
                    "Backoff must be applied between attempts, not after the final one."
                )
                self.assertEqual(self.slept, [1.0, 2.0], "Backoff must double each attempt (1s, then 2s).")

            def test_write_that_succeeds_on_second_attempt_does_not_fall_back(self):
                """A retry that eventually works must land in Cosmos DB and
                leave no local file behind -- the fallback is for genuine
                unavailability, not for a single blip."""
                attempts = {"n": 0}

                class FlakyContainer:
                    def create_item(self, body):
                        attempts["n"] += 1
                        if attempts["n"] < 2:
                            raise RuntimeError("first attempt blip")

                outcome = self._persist(lambda: FlakyContainer())

                self.assertEqual(outcome, "cosmos")
                self.assertEqual(attempts["n"], 2, "Should stop retrying as soon as a write succeeds.")
                self.assertEqual(self._local_files(), [], "A successful Cosmos write must not also write local JSON.")
                self.assertEqual(len(self.slept), 1, "Exactly one backoff between attempt 1 and attempt 2.")

            def test_retry_also_covers_client_construction_failure(self):
                """The retry wraps container construction too, so a credential
                or DNS failure while building the client is retried rather than
                skipping straight to the fallback."""
                attempts = {"n": 0}

                def failing_factory():
                    attempts["n"] += 1
                    raise RuntimeError("could not acquire Managed Identity token")

                outcome = self._persist(failing_factory)

                self.assertEqual(attempts["n"], COSMOS_WRITE_MAX_ATTEMPTS)
                self.assertEqual(outcome, "local")

            # --- 1. The invariant: never lose a scan result ----------------
            def test_cosmos_failure_after_all_retries_still_writes_local_json(self):
                """THE regression guard. Cosmos DB is configured and reachable
                enough to try, every attempt fails, and the scan result must
                still end up on disk. Before this pass the Cosmos write and
                the local write were the two arms of a single if/else inside
                one try block, so this case wrote nothing at all."""
                class AlwaysFailingContainer:
                    def create_item(self, body):
                        raise RuntimeError("Cosmos DB is unavailable")

                outcome = self._persist(lambda: AlwaysFailingContainer())

                self.assertEqual(outcome, "local", "Exhausted retries must fall through to the local JSON write.")
                self.assertEqual(self._local_files(), ["result_scan-abc-123.json"])

                written = json.loads((self.results_dir / "result_scan-abc-123.json").read_text(encoding="utf-8"))
                self.assertEqual(written["scanId"], "scan-abc-123")
                self.assertEqual(written["url"], "https://example.com")
                self.assertEqual(written["score"], 90, "The fallback copy must be the complete result, not a stub.")

            def test_persist_never_raises_when_everything_fails(self):
                """run_scout() must still return its result to the caller even
                if BOTH Cosmos DB and the local write fail -- persistence is
                never allowed to turn a completed scan into an exception."""
                class AlwaysFailingContainer:
                    def create_item(self, body):
                        raise RuntimeError("Cosmos DB is unavailable")

                unwritable = self.results_dir / "a-file-not-a-directory"
                unwritable.write_text("blocks mkdir", encoding="utf-8")

                with self.mock.patch.object(self.module, "COSMOS_AVAILABLE", True), self._cosmos_env():
                    outcome = persist_scan_result(
                        self.result,
                        unwritable,
                        container_factory=lambda: AlwaysFailingContainer(),
                        sleep=self.slept.append,
                    )
                self.assertEqual(outcome, "none")

            def test_unconfigured_cosmos_goes_straight_to_local_json(self):
                """Unchanged pre-existing behaviour: with no COSMOS_URL the
                Cosmos path is never attempted at all (no wasted retries, no
                backoff) and the result is written locally."""
                attempts = {"n": 0}

                def factory():
                    attempts["n"] += 1
                    raise AssertionError("Cosmos must not be attempted without COSMOS_URL")

                env = {k: v for k, v in os.environ.items() if k != "COSMOS_URL"}
                with self.mock.patch.object(self.module, "COSMOS_AVAILABLE", True), \
                     self.mock.patch.dict(os.environ, env, clear=True):
                    outcome = persist_scan_result(
                        self.result, self.results_dir, container_factory=factory, sleep=self.slept.append
                    )

                self.assertEqual(attempts["n"], 0)
                self.assertEqual(self.slept, [])
                self.assertEqual(outcome, "local")
                self.assertEqual(self._local_files(), ["result_scan-abc-123.json"])

            def test_missing_azure_sdk_goes_straight_to_local_json(self):
                """Same for a deployment where azure-cosmos / azure-identity
                aren't importable: COSMOS_AVAILABLE is False and persistence
                degrades to local JSON rather than blowing up on a missing
                DefaultAzureCredential symbol."""
                with self.mock.patch.object(self.module, "COSMOS_AVAILABLE", False), self._cosmos_env():
                    outcome = persist_scan_result(self.result, self.results_dir, sleep=self.slept.append)

                self.assertEqual(outcome, "local")
                self.assertEqual(self._local_files(), ["result_scan-abc-123.json"])

            def test_cosmos_document_carries_id_matching_scan_id(self):
                """The 'scans' container is partitioned on /scanId and Cosmos
                requires an 'id' -- the written document must carry both."""
                captured = {}

                class RecordingContainer:
                    def create_item(self, body):
                        captured.update(body)

                outcome = self._persist(lambda: RecordingContainer())

                self.assertEqual(outcome, "cosmos")
                self.assertEqual(captured["id"], "scan-abc-123")
                self.assertEqual(captured["scanId"], captured["id"])

        class TestScanIdThreading(unittest.IsolatedAsyncioTestCase):
            """Gap 3 fix (DEPLOYMENT_NOTES.md): run_scout() must use the
            caller-supplied scan_id -- the API's own job_id, threaded
            through by src/worker/function_app.py's process_scan() -- as
            the result's scanId on BOTH the blocked_ssrf early-exit path
            and the normal-completion path, and never mint its own
            uuid4(). Without this, the queued job document the API writes
            and the finished result document the Worker writes never
            share an id, and no Report Function read can ever observe a
            real Pending -> Complete transition for a given scanId."""

            def setUp(self):
                import unittest.mock as mock
                self.mock = mock
                self.module = sys.modules[__name__]
                self.persisted = []
                patch_persist = self.mock.patch.object(
                    self.module,
                    "persist_scan_result",
                    lambda final_result, results_dir: (self.persisted.append(final_result), "local")[1],
                )
                patch_persist.start()
                self.addCleanup(patch_persist.stop)

            async def test_blocked_ssrf_path_uses_given_scan_id(self):
                job_id = "job-9f2c-blocked"

                async def fake_fetch(ctx):
                    ctx.ssrf_blocked = True
                    ctx.ssrf_block_reason = "target resolves to a private IP"

                with self.mock.patch.object(self.module, "fetch_main_page_and_analyze", fake_fetch):
                    result = await run_scout("http://169.254.169.254", scan_id=job_id)

                self.assertEqual(result["status"], "blocked_ssrf")
                self.assertEqual(
                    result["scanId"], job_id,
                    "blocked_ssrf early-exit must use the caller's scan_id, not a fresh uuid4()."
                )

            async def test_normal_completion_path_uses_given_scan_id(self):
                import types
                job_id = "job-9f2c-complete"

                async def fake_fetch(ctx):
                    ctx.ssrf_blocked = False

                async def fake_scout_run(ctx):
                    return {"findings": []}

                fake_plugin = types.SimpleNamespace(__name__="fake_scout", run=fake_scout_run)

                with self.mock.patch.object(self.module, "fetch_main_page_and_analyze", fake_fetch), \
                     self.mock.patch.object(self.module, "discover_plugins", lambda: [fake_plugin]):
                    result = await run_scout("https://example.com", scan_id=job_id)

                self.assertEqual(
                    result["scanId"], job_id,
                    "normal-completion path must use the caller's scan_id, not a fresh uuid4()."
                )
                self.assertEqual(
                    self.persisted[-1]["scanId"], job_id,
                    "persist_scan_result must receive the exact same scanId returned to the caller."
                )

        sys.argv = [sys.argv[0]]
        unittest.main()
    else:
        import uuid  # CLI-only scan id -- doesn't correlate with any API job_id.
        config = build_run_config(args)
        result = asyncio.run(run_scout(args.url, scan_id=str(uuid.uuid4()), config=config))