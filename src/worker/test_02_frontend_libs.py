#!/usr/bin/env python3
r"""
Bravo6 Enterprise SCA Engine (v8.5 – Local Cache, Signature Aware, Context-Bound)
=============================================================================
- Complies strictly with Bravo6 Unified Plugin Contract v8.5.
- Fixed Critical Bug: Library version cross-contamination in bundled/concatenated JS files
  by applying tight horizontal-only regex scoping (`[ \t]` instead of `\s`) and
  implementing rigorous version-history bounding limits.
- Supports comprehensive deduplication and context-aware confidence scoring:
  (`verified-live`, `verified-static`, `plausible-unconfirmed`, `informational`).
- Enforces strict 12-field finding schemas.
- Enhanced detection with CDN URL parsing and Fingerprint-based fallbacks for bundlers (Webpack/Vite).
"""

import asyncio
import csv
import io
import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple, Set
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from packaging.version import InvalidVersion, Version
import aiohttp

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------
# Orchestrator Contract (Stub for local execution/typing)
# ------------------------------------------------------------------------------
@dataclass
class ScannerContext:
    url: str
    session: aiohttp.ClientSession
    config: Dict[str, Any]
    page_is_representative: bool
    waf_challenge_detected: Optional[str]
    sensitive_paths: List[str]
    main_page_cache: Dict[str, Any]

    async def fetch_js(self, js_url: str) -> str:
        """Mock fallback in case orchestrator doesn't natively supply it."""
        try:
            async with self.session.get(js_url, timeout=10, ssl=False) as resp:
                if resp.status == 200:
                    data = await resp.read()
                    return data.decode("utf-8", errors="replace")
        except Exception:
            pass
        return ""


# ------------------------------------------------------------------------------
# Constants & Sandbox Limits
# ------------------------------------------------------------------------------
MAX_FILE_BYTES = 2_097_152  # 2 MB max to scan for regex
REGEX_TIMEOUT_PROXY = 500_000  # Cap signature checks to first 500k chars to avoid ReDoS

# ------------------------------------------------------------------------------
# Version Extraction & Validation Definitions
# ------------------------------------------------------------------------------
# Tighten scoping: `\s` crosses newlines. We MUST use `[ \t]` to ensure
# the library name anchor and the version string are tightly bound horizontally.
_VERSION = r"(\d+\.\d+\.\d+(?:[-.][0-9A-Za-z.]+)?)"

LIB_URL = {
    "jquery": re.compile(r"jquery[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "bootstrap": re.compile(r"bootstrap[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "vue": re.compile(r"vue[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "react": re.compile(r"react[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "lodash": re.compile(r"lodash[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "axios": re.compile(r"axios[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "moment": re.compile(r"moment[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
}

LIB_URL_FILENAME = {
    "jquery": re.compile(r"jquery[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)(?:\.min)?(?:\.[a-f0-9]+)?\.js", re.I),
    "bootstrap": re.compile(r"bootstrap[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)(?:\.min)?(?:\.[a-f0-9]+)?\.js", re.I),
    "vue": re.compile(r"vue[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)(?:\.min)?(?:\.[a-f0-9]+)?\.js", re.I),
    "react": re.compile(r"react[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)(?:\.min)?(?:\.[a-f0-9]+)?\.js", re.I),
}

# New CDN patterns that may optionally include the version string
LIB_URL_CDN = {
    "jquery": re.compile(r"(?:cdn\.jsdelivr\.net/npm/|unpkg\.com/|cdnjs\.cloudflare\.com/ajax/libs/)jquery(?:[/@])(?:v?" + _VERSION + r")?", re.I),
    "bootstrap": re.compile(r"(?:cdn\.jsdelivr\.net/npm/|unpkg\.com/|cdnjs\.cloudflare\.com/ajax/libs/)bootstrap(?:[/@])(?:v?" + _VERSION + r")?", re.I),
    "vue": re.compile(r"(?:cdn\.jsdelivr\.net/npm/|unpkg\.com/|cdnjs\.cloudflare\.com/ajax/libs/)vue(?:[/@])(?:v?" + _VERSION + r")?", re.I),
    "react": re.compile(r"(?:cdn\.jsdelivr\.net/npm/|unpkg\.com/|cdnjs\.cloudflare\.com/ajax/libs/)react(?:-dom)?[/@](?:v?" + _VERSION + r")?", re.I),
    "lodash": re.compile(r"(?:cdn\.jsdelivr\.net/npm/|unpkg\.com/|cdnjs\.cloudflare\.com/ajax/libs/)lodash(?:[/@])(?:v?" + _VERSION + r")?", re.I),
    "axios": re.compile(r"(?:cdn\.jsdelivr\.net/npm/|unpkg\.com/|cdnjs\.cloudflare\.com/ajax/libs/)axios(?:[/@])(?:v?" + _VERSION + r")?", re.I),
    "moment": re.compile(r"(?:cdn\.jsdelivr\.net/npm/|unpkg\.com/|cdnjs\.cloudflare\.com/ajax/libs/)moment(?:[/@])(?:v?" + _VERSION + r")?", re.I),
}

# Strong evidence: explicit assignments (No bare \s across lines!)
LIB_CONTENT_SIGNATURE = {
    "jquery": re.compile(r"jQuery\.fn\.jquery[ \t]*=[ \t]*[\"']" + _VERSION + r"[\"']", re.I),
    "react": re.compile(r"React\.version[ \t]*=[ \t]*[\"']" + _VERSION + r"[\"']", re.I),
    "vue": re.compile(r"Vue\.version[ \t]*=[ \t]*[\"']" + _VERSION + r"[\"']", re.I),
    "bootstrap": re.compile(r"Bootstrap\.VERSION[ \t]*=[ \t]*[\"']" + _VERSION + r"[\"']", re.I),
    "moment": re.compile(r"moment\.version[ \t]*=[ \t]*[\"']" + _VERSION + r"[\"']", re.I),
    "lodash": re.compile(r"(?:lodash\.version|_\.VERSION)[ \t]*=[ \t]*[\"']" + _VERSION + r"[\"']", re.I),
    "axios": re.compile(r"axios\.VERSION[ \t]*=[ \t]*[\"']" + _VERSION + r"[\"']", re.I),
}

# Plausible evidence: inline comments/headers (Limited to 20 spaces horizontally)
LIB_CONTENT_GENERAL = {
    "jquery": re.compile(r"jQuery[ \t]{1,20}v?" + _VERSION, re.I),
    "bootstrap": re.compile(r"Bootstrap[ \t]{1,20}v?" + _VERSION, re.I),
    "vue": re.compile(r"Vue\.js[ \t]{1,20}v?" + _VERSION, re.I),
    "react": re.compile(r"React[ \t]{1,20}v?" + _VERSION, re.I),
    "lodash": re.compile(r"lodash[ \t]{1,20}v?" + _VERSION, re.I),
    "moment": re.compile(r"Moment\.js[ \t]{1,20}v?" + _VERSION, re.I),
    "axios": re.compile(r"axios[ \t]{1,20}v?" + _VERSION, re.I),
}

# Fingerprints for when version is stripped out entirely by modern bundlers (Webpack/Vite/Rollup)
LIB_CONTENT_FINGERPRINT = {
    "react": re.compile(r"__REACT_DEVTOOLS_GLOBAL_HOOK__|react_devtools_backend|Warning: React|React current owner", re.I),
    "vue": re.compile(r"__VUE_DEVTOOLS_GLOBAL_HOOK__|__VUE__|_isVue", re.I),
    "jquery": re.compile(r"jQuery\.fn\.init|jQuery\.extend", re.I),
    "bootstrap": re.compile(r"bootstrap\.Dropdown|bootstrap\.Modal|bootstrap\.Tooltip", re.I),
    "lodash": re.compile(r"__lodash_hash_undefined__|lodash\.isEqual", re.I),
    "moment": re.compile(r"moment\.isMoment|moment\.duration", re.I),
    "axios": re.compile(r"axios\.interceptors\.request|axios\.create", re.I),
}

# ------------------------------------------------------------------------------
# Known Real Version Bounds Check
# ------------------------------------------------------------------------------
# To fix the Lodash/Moment 2.30.1 cross-contamination bug fundamentally, we
# define valid major version ranges per library. If a version falls completely
# outside these real-world release brackets, it is demoted to informational.
LIBRARY_VERSION_RANGES = {
    "lodash": [("0.1.0", "0.2.2"), ("1.0.0", "1.3.1"), ("2.0.0", "2.4.2"),
               ("3.0.0", "3.10.1"), ("4.0.0", "4.17.21"), ("5.0.0", "5.9.9")],
    "jquery": [("1.0.0", "1.12.4"), ("2.0.0", "2.2.4"), ("3.0.0", "3.7.1"), ("4.0.0", "4.9.9")],
    "react": [("0.13.0", "0.14.8"), ("15.0.0", "15.6.2"), ("16.0.0", "16.14.0"),
              ("17.0.0", "17.0.2"), ("18.0.0", "18.3.1"), ("19.0.0", "19.9.9")],
    "vue": [("1.0.0", "1.0.28"), ("2.0.0", "2.7.16"), ("3.0.0", "3.4.21")],
    "bootstrap": [("2.0.0", "2.3.2"), ("3.0.0", "3.4.1"), ("4.0.0", "4.6.2"), ("5.0.0", "5.3.3")],
    "moment": [("1.0.0", "1.7.2"), ("2.0.0", "2.30.1")],
    "axios": [("0.15.0", "0.27.2"), ("1.0.0", "1.7.0")],
}


def is_version_valid(lib: str, v_str: Optional[str]) -> bool:
    """Verifies if the extracted version is within the known real release bounds."""
    if not v_str:
        return True # If no version is found, we consider range check "valid" (skip bounding)
        
    ranges = LIBRARY_VERSION_RANGES.get(lib.lower())
    if not ranges:
        return True  # If library not tracked with strict ranges, assume valid

    try:
        cleaned = re.sub(r'^[\^~>=<]', '', v_str.strip())
        v = Version(cleaned)
        for (min_v, max_v) in ranges:
            if Version(min_v) <= v <= Version(max_v):
                return True
        return False
    except InvalidVersion:
        return False


def _version_in_cve_range(detected_version: str, min_affected: str, fixed_in: str) -> bool:
    """True if `detected_version` falls within a CVE's vulnerable range
    [min_affected, fixed_in) from cve_database_v2.csv, using real semantic-
    version comparison instead of exact string equality against one pinned
    version. An empty/blank min_affected means the range has no lower bound
    (vulnerable from the earliest release); an empty/blank fixed_in means
    the CVE is still unfixed (no upper bound) -- every version from
    min_affected onward matches. `fixed_in` itself is NOT included in the
    vulnerable range (fixed means fixed, not vulnerable at the boundary).
    Any value that fails to parse as a version causes this to return False
    rather than raise, so a garbage/partial string from a noisy signature
    match is skipped for CVE correlation instead of crashing the scout or
    producing a false match.
    """
    try:
        detected = Version(re.sub(r'^[\^~>=<]', '', detected_version.strip()))
    except InvalidVersion:
        return False

    if min_affected and str(min_affected).strip():
        try:
            if detected < Version(str(min_affected).strip()):
                return False
        except InvalidVersion:
            return False

    if fixed_in and str(fixed_in).strip():
        try:
            if detected >= Version(str(fixed_in).strip()):
                return False
        except InvalidVersion:
            return False

    return True


def _general_pattern_confirms_version(lib: str, js_content: str, ver_str: Optional[str]) -> bool:
    """Fallback CVE-confirmation check for real-world minified CDN bundles.

    cve_database_v2.csv's own `signature` regex expects a literal un-minified
    assignment (e.g. `jQuery.fn.jquery = "3.3.1"`). Confirmed live against the
    actual jquery@3.3.1 and bootstrap@4.1.3 CDN builds that neither contains
    that text -- both carry the version in a banner comment instead (e.g.
    `/*! jQuery v3.3.1 | ... */`), which is exactly what LIB_CONTENT_GENERAL
    already detects (that's how ver_str was found for these in the first
    place when is_sig=False). Relying only on the strict signature here is a
    false negative: the version was already independently bounded and
    validated by is_version_valid() before this check ever runs.

    Re-checks with the SAME tightly-scoped, per-library LIB_CONTENT_GENERAL
    pattern already used for detection, scoped to this specific script's
    content, and requires the captured version to equal `ver_str` EXACTLY --
    not "any version mentioned" -- so this doesn't reopen the historical
    Lodash/Moment cross-contamination bug and can't be tricked by a banner
    comment for a different version than the one actually being reported.
    """
    if not js_content or not ver_str:
        return False
    general_pat = LIB_CONTENT_GENERAL.get(lib.lower())
    if not general_pat:
        return False
    gm = general_pat.search(js_content)
    return bool(gm and gm.group(1) == ver_str)


# ------------------------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------------------------
def _unified_version_extraction(text: str, patterns_sig: Dict, patterns_gen: Dict) -> Dict[str, tuple]:
    result = {}
    for lib, pat in patterns_sig.items():
        m = pat.search(text)
        if m and m.group(1):
            result[lib] = (m.group(1), True)
    for lib, pat in patterns_gen.items():
        if lib in result:
            continue
        m = pat.search(text)
        if m and m.group(1):
            result[lib] = (m.group(1), False)
    return result

def _extract_from_cdn_url(url: str, patterns: Dict) -> Dict[str, Optional[str]]:
    result = {}
    for lib, pat in patterns.items():
        m = pat.search(url)
        if m:
            try:
                ver = m.group(1)
            except IndexError:
                ver = None
            result[lib] = ver
    return result

def _extract_fingerprints(text: str, patterns: Dict) -> List[str]:
    result = []
    for lib, pat in patterns.items():
        if pat.search(text):
            result.append(lib)
    return result

def _build_poc(location: str, lib: str, version: Optional[str], is_signature: bool) -> str:
    if location.startswith("inline_script"):
        return f"Inspect HTML source at inline script block for {lib} declaration or fingerprint."
    if location == "Header: Context":
        return "Manual verification required."
    
    v_str = version if version else ""
    if is_signature and v_str:
        return f"curl -s '{location}' | grep -ioE '{lib}.{{0,20}}{v_str}' | head -n 1"
    if not v_str:
        return f"curl -s '{location}' | grep -i '{lib}' # (Version unknown, look for fingerprint)"
    return f"curl -s '{location}' | grep -ioE '{lib}'"


async def fetch_cve_dataset(ctx: ScannerContext, cve_csv_url: str) -> Tuple[List[Dict], int]:
    reqs = 0
    cache = []
    try:
        if cve_csv_url.startswith("http://") or cve_csv_url.startswith("https://"):
            reqs += 1
            async with ctx.session.get(cve_csv_url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    reader = csv.DictReader(io.StringIO(text))
                    cache = list(reader)
        else:
            with open(cve_csv_url, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                cache = list(reader)
    except Exception as e:
        logger.warning(f"[SCA] Failed to load CVE CSV: {e}")
    return cache, reqs


async def fetch_cve_dataset_from_table(
    table_endpoint: str,
    table_name: str = "cveCache",
    table_service_client_factory=None,
) -> Tuple[List[Dict], int]:
    """Reads the CVE/version-range dataset from the Table Storage cache
    osv_cve_sync.py's Timer Function populates on a schedule, instead of
    fetch_cve_dataset()'s CSV path. Returns the SAME List[Dict] shape
    (library/min_affected/fixed_in/cve/cvss/cwe/summary/signature/
    upgrade_rec) that fetch_cve_dataset() does, so every downstream CVE-
    correlation line in run() below (the 7a/7b steps) is unchanged
    regardless of which loader supplied cve_cache -- only run()'s "which
    loader do I call" step differs.

    table_service_client_factory is an injection point for tests (a
    zero-arg callable returning an async context-manager-compatible fake
    TableServiceClient) so this never needs real Azure Table Storage or
    Managed Identity credentials to exercise in the regression suite --
    the same injected-client pattern this project already uses for
    Cosmos DB (main_scanner.py's persist_scan_result) and Service Bus
    (src/api's handle_scan_request).

    CACHE-READ-FAILURE DESIGN NOTE: any failure here (network, auth, the
    table not existing yet on a fresh deployment before the Timer
    Function's first run) returns an empty cache -- exactly the same
    "no CVE data this run" outcome as fetch_cve_dataset() failing or
    cve_csv_url being unset entirely. This scout already treats "no CVE
    data" as fail-safe/skip, not fail the scan (see run()'s CVE
    correlation step: a library with no cve_cache match simply falls
    through to the existing informational/plausible-unconfirmed finding
    instead of a vulnerability finding) -- so a cache miss or read
    failure degrades gracefully to the same place, never blocks the scan
    on a live OSV call, and never raises out of this function.
    """
    from azure.data.tables.aio import TableServiceClient
    from azure.identity.aio import DefaultAzureCredential

    def _default_factory():
        return TableServiceClient(endpoint=table_endpoint, credential=DefaultAzureCredential())

    factory = table_service_client_factory or _default_factory

    cache: List[Dict] = []
    try:
        async with factory() as service:
            table_client = service.get_table_client(table_name)
            async for entity in table_client.list_entities():
                cache.append({
                    "library": entity.get("Library", ""),
                    "min_affected": entity.get("MinAffected", ""),
                    "fixed_in": entity.get("FixedIn", ""),
                    "cve": entity.get("CveId", ""),
                    "cvss": entity.get("Cvss", 0.0),
                    "cwe": entity.get("Cwe", ""),
                    "summary": entity.get("Summary", ""),
                    "signature": entity.get("Signature", ""),
                    "upgrade_rec": entity.get("UpgradeRec", ""),
                })
    except Exception as e:
        logger.warning(f"[SCA] Failed to load CVE dataset from Table Storage cache: {e}")
        return [], 1
    return cache, 1


# ------------------------------------------------------------------------------
# Main Scout Entry Point
# ------------------------------------------------------------------------------
async def run(ctx: ScannerContext) -> dict:
    """
    Entry point for the SCA scout matching the Bravo6 v8.5 contract.
    """
    # 1. Representative Page Gatekeeper
    if not ctx.page_is_representative:
        return {"fatal_error": "Page is not representative (e.g. WAF block/error). Skipping SCA."}

    requests_made = 0
    findings = []
    raw_findings = []
    script_contents: Dict[str, str] = {}
    
    html = ctx.main_page_cache.get("html", "")
    soup = ctx.main_page_cache.get("soup")
    if not soup and html:
        soup = BeautifulSoup(html, "html.parser")
        
    if not soup:
        return {"fatal_error": "Failed to parse main page HTML."}

    _m = getattr(ctx, "metrics", None)
    if isinstance(_m, dict):
        _m["cache_reads"] = _m.get("cache_reads", 0) + 1

    # 2. Extract scripts & process URLs
    script_urls = []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            abs_url = urljoin(ctx.url, src)
            if abs_url not in script_urls:
                script_urls.append(abs_url)
                
            # Pattern check on URL itself
            for lib, (ver, _) in _unified_version_extraction(abs_url, {}, LIB_URL).items():
                raw_findings.append({"library": lib, "version": ver, "source": "script_src_url", "url": abs_url})
            for lib, (ver, _) in _unified_version_extraction(abs_url, {}, LIB_URL_FILENAME).items():
                raw_findings.append({"library": lib, "version": ver, "source": "script_src_filename", "url": abs_url})
            # CDN checks (Can extract libraries with or without version strings)
            for lib, ver in _extract_from_cdn_url(abs_url, LIB_URL_CDN).items():
                raw_findings.append({"library": lib, "version": ver, "source": "cdn_url", "url": abs_url})

    # 3. Fetch remote JS content & scan via tightly-scoped regex
    for u in script_urls[:40]:  # Cap to prevent scanner saturation
        if getattr(ctx, "fetch_js", None):
            js_text = await ctx.fetch_js(u)
        else:
            js_text = ""
            
        if not js_text:
            continue
            
        script_contents[u] = js_text
        scan_text = js_text[:MAX_FILE_BYTES]
        content_versions = _unified_version_extraction(scan_text, LIB_CONTENT_SIGNATURE, LIB_CONTENT_GENERAL)
        
        for lib, (ver, is_sig) in content_versions.items():
            raw_findings.append({
                "library": lib, "version": ver, "source": "script_content", 
                "url": u, "is_signature": is_sig,
                "evidence": f"Matched {'signature' if is_sig else 'general pattern'} in {u}"
            })
            
        # Fingerprint fallback
        for lib in _extract_fingerprints(scan_text, LIB_CONTENT_FINGERPRINT):
            if lib not in content_versions:
                raw_findings.append({
                    "library": lib, "version": None, "source": "script_content_fingerprint", 
                    "url": u, "is_signature": False,
                    "evidence": f"Matched library fingerprint in {u}"
                })

    # 4. Inline Script scanning
    inline_idx = 0
    for tag in soup.find_all("script"):
        if not tag.get("src") and tag.string:
            inline_text = tag.string.strip()
            loc_name = f"inline_script_block_{inline_idx}"
            script_contents[loc_name] = inline_text
            inline_idx += 1
            
            inline_versions = _unified_version_extraction(inline_text, LIB_CONTENT_SIGNATURE, LIB_CONTENT_GENERAL)
            for lib, (ver, is_sig) in inline_versions.items():
                raw_findings.append({
                    "library": lib, "version": ver, "source": "inline",
                    "url": loc_name, "is_signature": is_sig,
                    "evidence": "Matched signature in inline script block."
                })
                
            for lib in _extract_fingerprints(inline_text, LIB_CONTENT_FINGERPRINT):
                if lib not in inline_versions:
                    raw_findings.append({
                        "library": lib, "version": None, "source": "inline_fingerprint",
                        "url": loc_name, "is_signature": False,
                        "evidence": "Matched library fingerprint in inline script block."
                    })

    # 5. Group and Deduplicate Findings by Library
    lib_groups = {}
    for f in raw_findings:
        lib = f["library"].lower()
        lib_groups.setdefault(lib, []).append(f)
        
    # Highest priority is script content signatures
    SOURCE_PRIORITY = {
        "script_content": 10, "inline": 9, "cdn_url": 8, "script_src_filename": 5, "script_src_url": 4, 
        "script_content_fingerprint": 3, "inline_fingerprint": 2, "fallback": 0
    }

    # 6. Load CVE Dataset. Table Storage (osv_cve_sync.py's Timer
    # Function keeps it fresh, see DEPLOYMENT_NOTES.md/README.md Future
    # Work) is the production path, set via CVE_TABLE_ENDPOINT -- a
    # deployment-level app setting, not per-request config, since which
    # cache to read from doesn't vary per scan. cve_csv_url (per-request
    # config) stays supported unchanged for local/CLI/evaluation-harness
    # runs that don't set that env var. If both are absent, cve_cache
    # stays empty -- the existing, unchanged fail-safe behavior.
    cve_table_endpoint = os.environ.get("CVE_TABLE_ENDPOINT")
    cve_csv_url = ctx.config.get("cve_csv_url") if ctx.config else None
    cve_cache = []
    if cve_table_endpoint:
        cve_cache, reqs = await fetch_cve_dataset_from_table(
            cve_table_endpoint, os.environ.get("CVE_TABLE_NAME", "cveCache")
        )
        requests_made += reqs
    elif cve_csv_url:
        cve_cache, reqs = await fetch_cve_dataset(ctx, cve_csv_url)
        requests_made += reqs

    # 7. Evaluate and Validate Version Claims
    for lib, entries in lib_groups.items():
        # Sort by priority, then by having a version
        entries_sorted = sorted(
            entries, 
            key=lambda e: (
                SOURCE_PRIORITY.get(e["source"], 0) + (2 if e.get("is_signature") else 0), 
                1 if e.get("version") else 0
            ), 
            reverse=True
        )
        best = next((e for e in entries_sorted if e.get("version")), entries_sorted[0])
        ver_str = best.get("version")
        location = best.get("url", "inline")
        is_sig = best.get("is_signature", False)
        
        cve_reported = False
        
        # 7a. The Sanity Check (Fix for the LODASH 2.30.1 bug)
        is_valid_range = True
        if ver_str and not is_version_valid(lib, ver_str):
            is_valid_range = False
            
        if ver_str and is_valid_range:
            # 7b. CVE Correlation (range-based: cve_database_v2.csv's min_affected/
            # fixed_in columns describe a vulnerable RANGE per CVE, not one pinned
            # version -- exact string equality would only ever catch a detected
            # version that happens to match a CSV row character-for-character.
            cve_matches = [
                row for row in cve_cache
                if str(row.get("library", "")).lower() == lib.lower()
                and _version_in_cve_range(str(ver_str), row.get("min_affected", ""), row.get("fixed_in", ""))
            ]
            
            js_content = script_contents.get(location, "")[:REGEX_TIMEOUT_PROXY]

            for cve_row in cve_matches:
                signature = str(cve_row.get("signature", "")).strip()
                signature_found = False
                matched_via = "strict"

                if signature and js_content:
                    try:
                        # Sandbox regex to avoid ReDoS on main thread
                        if re.search(signature, js_content):
                            signature_found = True
                    except re.error:
                        signature_found = False
                elif not signature:
                    signature_found = True  # Blind version trust if dataset lacks signature

                # Fallback for real-world minified CDN bundles: the CVE CSV's own
                # `signature` regex expects a literal un-minified assignment (e.g.
                # `jQuery.fn.jquery = "3.3.1"`). Confirmed live against the actual
                # jquery@3.3.1 and bootstrap@4.1.3 CDN builds that neither contains
                # that text -- both carry the version in a banner comment instead
                # (e.g. `/*! jQuery v3.3.1 | ... */`), which is exactly what
                # LIB_CONTENT_GENERAL already detects (that's how ver_str was found
                # for these in the first place when is_sig=False). Falling through
                # to "no CVE reported" here is a false negative: the version was
                # already independently bounded and validated by is_version_valid()
                # before reaching this step. Re-check with LIB_CONTENT_GENERAL and
                # require its captured version to equal ver_str EXACTLY (not blind
                # trust -- it's the same tightly-scoped per-library pattern
                # re-verified against this specific script's content, so it doesn't
                # reopen the historical cross-contamination bug).
                if not signature_found and _general_pattern_confirms_version(lib, js_content, ver_str):
                    signature_found = True
                    matched_via = "general"

                if signature_found:
                    cve_reported = True
                    cve_id = cve_row.get("cve", "Unknown CVE")
                    cvss_score = float(cve_row.get("cvss", 0.0))
                    
                    if cvss_score >= 9.0:
                        severity = "critical"
                    elif cvss_score >= 7.0:
                        severity = "high"
                    elif cvss_score >= 4.0:
                        severity = "medium"
                    else:
                        severity = "low"
                        
                    findings.append({
                        "title": f"Vulnerable {lib.title()} Component: {cve_id}",
                        "severity": severity,
                        "confidence": "verified-live" if matched_via == "strict" else "verified-static",
                        "cwe": cve_row.get("cwe", "CWE-1035"),
                        "owasp": "A06:2021-Vulnerable and Outdated Components",
                        "location": location,
                        "evidence": (
                            f"Detected {lib}@{ver_str} in {best['source']}. CVE: {cve_id} matched "
                            f"via {'strict assignment signature' if matched_via == 'strict' else 'version-banner fallback signature (minified CDN build)'}. "
                            f"Summary: {cve_row.get('summary', 'Known vulnerability')}."
                        ),
                        "poc": _build_poc(location, lib, ver_str, is_sig),
                        "remediation": f"Upgrade {lib} to version {cve_row.get('upgrade_rec', 'latest')} or later.",
                        "detection_method": "SCA + Local Cache + Signature Verification"
                    })

        # 7c. Fallback / Standard Finding Emission
        if not cve_reported:
            if not is_valid_range:
                # Demoted informational finding due to bounding box failure
                findings.append({
                    "title": f"Detected {lib.title()} v{ver_str} (Misattributed?)",
                    "severity": "info",
                    "confidence": "informational",
                    "cwe": "CWE-1035",
                    "owasp": "A06:2021-Vulnerable and Outdated Components",
                    "location": location,
                    "evidence": f"Version string extracted ({ver_str}) is outside {lib}'s known release history. Likely misattributed from a concatenated file; suppressed pending manual review.",
                    "poc": _build_poc(location, lib, ver_str, is_sig),
                    "remediation": "Review the concatenated JS file for overlapping library versions.",
                    "detection_method": "Library Fingerprinting (Suppressed)"
                })
            else:
                # Normal valid version, or no version, but no CVE
                if is_sig:
                    confidence = "verified-static"
                elif best["source"] in ["script_src_filename", "script_src_url", "cdn_url"]:
                    confidence = "plausible-unconfirmed"
                elif best["source"] in ["script_content_fingerprint", "inline_fingerprint"]:
                    confidence = "informational"
                else:
                    confidence = "informational"
                    
                v_disp = ver_str if ver_str else "unknown"
                
                if not ver_str:
                    title_text = f"Detected {lib.title()} Component (Version Unknown)"
                    severity_text = "info"
                    evidence_text = f"Detected {lib} via {best['source']} but could not determine its version."
                    remediation_text = "Ensure the library is kept up-to-date."
                else:
                    title_text = f"Detected {lib.title()} Component v{v_disp}"
                    severity_text = "info"
                    evidence_text = f"Detected {lib}@{v_disp} via {best['source']}."
                    remediation_text = "Monitor for updates and ensure libraries are patched regularly."

                findings.append({
                    "title": title_text,
                    "severity": severity_text,
                    "confidence": confidence,
                    "cwe": "CWE-1035",
                    "owasp": "A06:2021-Vulnerable and Outdated Components",
                    "location": location,
                    "evidence": evidence_text,
                    "poc": _build_poc(location, lib, ver_str, is_sig),
                    "remediation": remediation_text,
                    "detection_method": "Library Fingerprinting"
                })

    return {
        "findings": findings,
        "details": {
            "requests_made": requests_made,
            "libraries_detected": len(lib_groups),
            "cve_cache_loaded": len(cve_cache) > 0
        }
    }

# ------------------------------------------------------------------------------
# Calibration & Integration Test (Fix Validation)
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    import sys

    _parser = argparse.ArgumentParser(description="Bravo6 SCA Engine (frontend libs)")
    _parser.add_argument("--test", action="store_true", help="Run Scout Regression Tests")
    _args, _ = _parser.parse_known_args()

    if _args.test:
        import unittest

        class TestCveRangeMatching(unittest.TestCase):
            """Regression tests for range-based CVE correlation. cve_database_v2.csv's
            min_affected/fixed_in columns describe a vulnerable RANGE per CVE (from
            OSV.dev), not a single pinned version string -- _version_in_cve_range()
            replaces the old exact-string-equality match with real semantic-version
            comparison via packaging.version."""

            def test_version_strictly_inside_range_matches(self):
                self.assertTrue(_version_in_cve_range("3.3.1", "1.1.4", "3.4.0"))

            def test_version_equal_to_fixed_in_does_not_match(self):
                # Fixed means fixed -- not vulnerable at the boundary.
                self.assertFalse(_version_in_cve_range("3.4.0", "1.1.4", "3.4.0"))

            def test_version_below_min_affected_does_not_match(self):
                self.assertFalse(_version_in_cve_range("1.0.0", "1.1.4", "3.4.0"))

            def test_open_ended_range_matches_any_version_at_or_above_floor(self):
                # fixed_in == "" means the CVE is still unfixed -- no upper bound,
                # so even a version far newer than anything in the dataset matches.
                self.assertTrue(_version_in_cve_range("1.4.0", "1.4.0", ""))
                self.assertTrue(_version_in_cve_range("99.0.0", "1.4.0", ""))
                self.assertFalse(_version_in_cve_range("1.3.9", "1.4.0", ""))

            def test_unparseable_detected_version_is_skipped_not_crashed(self):
                self.assertFalse(_version_in_cve_range("not-a-version", "1.0.0", "2.0.0"))
                self.assertFalse(_version_in_cve_range("", "1.0.0", "2.0.0"))

            def test_real_world_gap_jquery_331_and_bootstrap_413(self):
                # Concrete real-world case from the audit: jQuery 3.3.1 and
                # Bootstrap 4.1.3 were both correctly detected on a live target but
                # produced zero CVE matches under exact-string matching, even
                # though real OSV.dev ranges cover them. Values below are taken
                # directly from the regenerated cve_database_v2.csv.
                self.assertTrue(_version_in_cve_range("3.3.1", "1.1.4", "3.4.0"))   # CVE-2019-11358
                self.assertTrue(_version_in_cve_range("4.1.3", "4.0.0", "4.3.0"))   # CVE-2019-8331
                # ...and must still correctly EXCLUDE Bootstrap 4.1.3 from CVEs it
                # had already fixed (4.1.3 shipped after the 4.1.2 fix).
                self.assertFalse(_version_in_cve_range("4.1.3", "4.0.0", "4.1.2"))  # CVE-2018-14040/14041

            def test_lodash_cross_contamination_fix_still_holds_with_range_matching(self):
                # The historical Lodash/Moment cross-contamination fix (tight
                # horizontal-only regex scoping) is orthogonal to CVE range
                # matching -- confirm range matching doesn't reintroduce it by
                # running the same bundled-JS scenario as the file's own
                # integration self-test, with a range-shaped CVE row.
                mock_bundled_js = (
                    "/* Lodash source */\nvar lodash = {};\nlodash.VERSION = '4.17.15';\n"
                    "/* Moment source */\nvar moment = {};\nmoment.version = '2.30.1';\n"
                )
                mock_html = '<html><head><script src="/js/bundle.js"></script></head><body></body></html>'
                ctx = ScannerContext(
                    url="https://example.com", session=None, config={"cve_csv_url": "mock"},
                    page_is_representative=True, waf_challenge_detected=None, sensitive_paths=[],
                    main_page_cache={"html": mock_html, "soup": BeautifulSoup(mock_html, "html.parser"), "status": 200},
                )

                async def mock_fetch_js(js_url: str) -> str:
                    return mock_bundled_js if "bundle.js" in js_url else ""
                ctx.fetch_js = mock_fetch_js

                async def mock_fetch_cve_dataset(c_ctx, url):
                    return [{
                        "library": "lodash", "min_affected": "4.0.0", "fixed_in": "4.17.21",
                        "cve": "CVE-2019-10744", "cvss": "7.3", "cwe": "CWE-400",
                        "signature": r"lodash\.VERSION\s*=\s*['\"]4\.17\.15['\"]",
                        "summary": "Prototype Pollution in lodash", "upgrade_rec": "4.17.21",
                    }], 0

                global fetch_cve_dataset
                original_fetch = fetch_cve_dataset
                globals()['fetch_cve_dataset'] = mock_fetch_cve_dataset
                try:
                    result = asyncio.run(run(ctx))
                finally:
                    globals()['fetch_cve_dataset'] = original_fetch

                lodash_finding = next((f for f in result["findings"] if "lodash" in f["title"].lower()), None)
                self.assertIsNotNone(lodash_finding)
                self.assertEqual(
                    lodash_finding["confidence"], "verified-live",
                    "The strict assignment signature (lodash.VERSION = '4.17.15') is present in "
                    "the mock content, so it must confirm the CVE on its own -- the new general-"
                    "pattern fallback must not downgrade or interfere with the already-working "
                    "strict path."
                )
                self.assertIn("strict assignment signature", lodash_finding["evidence"])
                self.assertNotIn("2.30.1", lodash_finding["evidence"],
                                  "Lodash must not steal Moment's 2.30.1 version string.")

        class TestCveGeneralPatternFallback(unittest.TestCase):
            """Regression tests for the general-pattern CVE-confirmation fallback.
            Live-confirmed root cause: cve_database_v2.csv's `signature` column
            expects a literal un-minified assignment (e.g. `jQuery.fn.jquery =
            "3.3.1"`), but real CDN builds (jquery@3.3.1 slim, bootstrap@4.1.3) only
            carry the version in a banner comment -- the exact shape
            LIB_CONTENT_GENERAL already matches during initial detection. Without
            this fallback, a correctly-detected, correctly-range-matched vulnerable
            component silently produces no "Vulnerable Component" finding at all.
            """

            async def _run_single_script_scan(self, script_url: str, js_content: str, cve_rows: list):
                mock_html = f'<html><head><script src="{script_url}"></script></head></html>'
                ctx = ScannerContext(
                    url="https://example.com", session=None, config={"cve_csv_url": "mock"},
                    page_is_representative=True, waf_challenge_detected=None, sensitive_paths=[],
                    main_page_cache={"html": mock_html, "soup": BeautifulSoup(mock_html, "html.parser"), "status": 200},
                )

                async def mock_fetch_js(js_url: str) -> str:
                    return js_content if js_url == script_url else ""
                ctx.fetch_js = mock_fetch_js

                async def mock_fetch_cve_dataset(c_ctx, url):
                    return cve_rows, 0

                global fetch_cve_dataset
                original_fetch = fetch_cve_dataset
                globals()['fetch_cve_dataset'] = mock_fetch_cve_dataset
                try:
                    return await run(ctx)
                finally:
                    globals()['fetch_cve_dataset'] = original_fetch

            def test_real_world_jquery_331_minified_banner_confirms_cve(self):
                # Live-confirmed real content shape: no `jQuery.fn.jquery =` assignment
                # anywhere, only the version-banner comment.
                js_content = "/*! jQuery v3.3.1 | (c) JS Foundation and other contributors | jquery.org/license */"
                cve_rows = [{
                    "library": "jquery", "min_affected": "1.1.4", "fixed_in": "3.4.0",
                    "cve": "CVE-2019-11358", "cvss": "6.1", "cwe": "CWE-1321",
                    "signature": r"jQuery\.fn\.jquery",
                    "summary": "XSS in jQuery", "upgrade_rec": "3.4.0",
                }]
                result = asyncio.run(self._run_single_script_scan(
                    "https://code.jquery.com/jquery-3.3.1.slim.min.js", js_content, cve_rows
                ))
                finding = next((f for f in result["findings"] if "vulnerable" in f["title"].lower()), None)
                self.assertIsNotNone(finding, "Expected a Vulnerable Jquery Component finding via the fallback.")
                self.assertEqual(finding["confidence"], "verified-static")
                self.assertIn("version-banner fallback", finding["evidence"])

            def test_real_world_bootstrap_413_minified_banner_confirms_cve(self):
                js_content = (
                    "/*!\n  * Bootstrap v4.1.3 (https://getbootstrap.com/)\n"
                    "  * Copyright 2011-2018 The Bootstrap Authors\n  */"
                )
                cve_rows = [{
                    "library": "bootstrap", "min_affected": "4.0.0", "fixed_in": "4.3.0",
                    "cve": "CVE-2019-8331", "cvss": "6.1", "cwe": "CWE-79",
                    "signature": r"Bootstrap\.VERSION",
                    "summary": "XSS in Bootstrap tooltip/popover", "upgrade_rec": "4.3.0",
                }]
                result = asyncio.run(self._run_single_script_scan(
                    "https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/js/bootstrap.min.js", js_content, cve_rows
                ))
                finding = next((f for f in result["findings"] if "vulnerable" in f["title"].lower()), None)
                self.assertIsNotNone(finding, "Expected a Vulnerable Bootstrap Component finding via the fallback.")
                self.assertEqual(finding["confidence"], "verified-static")
                self.assertIn("version-banner fallback", finding["evidence"])

            def test_fallback_rejects_content_confirming_a_different_version(self):
                # Direct unit-level test of the exact-match guard: a banner comment
                # for a DIFFERENT version than the one actually being reported must
                # not confirm the CVE -- "any version mentioned" is not enough.
                self.assertFalse(
                    _general_pattern_confirms_version("jquery", "jQuery v3.4.0", "3.3.1"),
                    "The fallback must require an EXACT match to ver_str, not just any version string."
                )
                self.assertTrue(
                    _general_pattern_confirms_version("jquery", "jQuery v3.3.1", "3.3.1")
                )

            def test_fallback_handles_library_with_no_general_pattern_entry(self):
                # A library not present in LIB_CONTENT_GENERAL must not crash --
                # general_pat is None and the fallback cleanly returns False.
                self.assertFalse(
                    _general_pattern_confirms_version("not-a-real-library", "anything v1.0.0", "1.0.0")
                )

            def test_fallback_returns_false_on_empty_content_or_version(self):
                self.assertFalse(_general_pattern_confirms_version("jquery", "", "3.3.1"))
                self.assertFalse(_general_pattern_confirms_version("jquery", "jQuery v3.3.1", None))

        class TestCveTableStorageCache(unittest.IsolatedAsyncioTestCase):
            """fetch_cve_dataset_from_table() -- the read side of the OSV
            Table Storage cache osv_cve_sync.py's Timer Function
            populates (see that file's own regression suite for the
            write side). No real Azure Table Storage or Managed Identity
            credential is ever touched here -- table_service_client_factory
            injects a fake async context manager instead."""

            def _fake_entity(self, **overrides):
                entity = {
                    "Library": "jquery", "MinAffected": "1.2.0", "FixedIn": "3.5.0",
                    "CveId": "CVE-2020-11022", "Cvss": 6.1, "Cwe": "CWE-79",
                    "Summary": "jQuery XSS", "Signature": r"jQuery\.fn\.jquery",
                    "UpgradeRec": "3.5.0",
                }
                entity.update(overrides)
                return entity

            def _factory_returning(self, entities):
                class _FakeTableClient:
                    async def list_entities(_self):
                        for e in entities:
                            yield e

                class _FakeService:
                    async def __aenter__(_self):
                        return _self

                    async def __aexit__(_self, *a):
                        return False

                    def get_table_client(_self, name):
                        return _FakeTableClient()

                return lambda: _FakeService()

            def _factory_raising(self, exc):
                class _FakeService:
                    async def __aenter__(_self):
                        raise exc

                    async def __aexit__(_self, *a):
                        return False

                return lambda: _FakeService()

            async def test_reads_entities_into_the_same_shape_as_csv_loader(self):
                factory = self._factory_returning([self._fake_entity()])
                cache, reqs = await fetch_cve_dataset_from_table(
                    "https://fake.table.core.windows.net", table_service_client_factory=factory
                )
                self.assertEqual(reqs, 1)
                self.assertEqual(len(cache), 1)
                row = cache[0]
                # Exactly the keys fetch_cve_dataset() (the CSV loader)
                # produces -- run()'s CVE-correlation code (7a/7b) reads
                # these by name regardless of which loader supplied them.
                for key in ["library", "min_affected", "fixed_in", "cve", "cvss", "cwe", "summary", "signature", "upgrade_rec"]:
                    self.assertIn(key, row)
                self.assertEqual(row["library"], "jquery")
                self.assertEqual(row["cve"], "CVE-2020-11022")
                self.assertEqual(row["cvss"], 6.1)

            async def test_multiple_entities_all_returned(self):
                factory = self._factory_returning([
                    self._fake_entity(Library="jquery", CveId="CVE-1"),
                    self._fake_entity(Library="lodash", CveId="CVE-2"),
                ])
                cache, _ = await fetch_cve_dataset_from_table("https://fake", table_service_client_factory=factory)
                self.assertEqual(len(cache), 2)
                self.assertEqual({r["library"] for r in cache}, {"jquery", "lodash"})

            async def test_empty_table_returns_empty_cache_not_error(self):
                """A freshly-provisioned table the Timer Function hasn't
                populated yet must degrade to 'no CVE data', not crash."""
                factory = self._factory_returning([])
                cache, reqs = await fetch_cve_dataset_from_table("https://fake", table_service_client_factory=factory)
                self.assertEqual(cache, [])
                self.assertEqual(reqs, 1)

            async def test_read_failure_returns_empty_cache_not_raise(self):
                """Cache-miss/read-failure design (see this function's own
                docstring): a Table Storage error must degrade to the
                same 'no CVE data this run' outcome as a missing
                cve_csv_url, never raise out of this function and never
                fall back to a live per-scan OSV call."""
                factory = self._factory_raising(RuntimeError("simulated auth failure"))
                cache, reqs = await fetch_cve_dataset_from_table("https://fake", table_service_client_factory=factory)
                self.assertEqual(cache, [])

            async def test_run_prefers_table_cache_over_csv_when_both_configured(self):
                """run()'s step 6: CVE_TABLE_ENDPOINT (deployment-level env
                var, the production path) takes priority over cve_csv_url
                (per-request config, the local/CLI/evaluation-harness
                path) when both are present -- and reading from the table
                cache actually feeds the same downstream CVE-correlation
                logic (same pattern as the existing mock_fetch_cve_dataset
                tests above, just patching the table loader instead)."""

                async def mock_fetch_from_table(endpoint, table_name):
                    return [{
                        "library": "bootstrap", "min_affected": "2.0.0", "fixed_in": "3.4.0",
                        "cve": "CVE-TABLE-1", "cvss": "7.0", "cwe": "CWE-79",
                        "signature": r"Bootstrap\.VERSION\s*=\s*['\"]3\.0\.0['\"]",
                        "summary": "Table-sourced CVE", "upgrade_rec": "3.4.0",
                    }], 1

                html = '<html><body><script>Bootstrap.VERSION = "3.0.0"</script></body></html>'
                ctx = ScannerContext(
                    url="https://example.com", session=None, config={"cve_csv_url": "should_not_be_used"},
                    page_is_representative=True, waf_challenge_detected=None, sensitive_paths=[],
                    main_page_cache={"html": html},
                )

                global fetch_cve_dataset_from_table
                original_fetch = fetch_cve_dataset_from_table
                globals()["fetch_cve_dataset_from_table"] = mock_fetch_from_table
                os.environ["CVE_TABLE_ENDPOINT"] = "https://fake.table.core.windows.net"
                try:
                    result = await run(ctx)
                finally:
                    globals()["fetch_cve_dataset_from_table"] = original_fetch
                    del os.environ["CVE_TABLE_ENDPOINT"]

                bootstrap_finding = next(
                    (f for f in result["findings"] if "bootstrap" in f["title"].lower() and "CVE-TABLE-1" in f["title"]), None
                )
                self.assertIsNotNone(
                    bootstrap_finding,
                    "CVE_TABLE_ENDPOINT being set must route CVE correlation through the "
                    "table-cache loader, not the CSV loader -- the CSV path's mock CVE "
                    "('should_not_be_used', which isn't a real file so fetch_cve_dataset "
                    "would just log a warning and return an empty cache) must never run."
                )

        sys.argv = [sys.argv[0]]
        unittest.main()  # exits the process on completion (default behavior)

    # Provides proof of the CVE dataset capability and the cross-contamination fix.
    async def run_test():
        print("[*] Running Integration Test for SCA Scout...")
        
        # 1. Set up a fake session
        session = aiohttp.ClientSession()
        
        # 2. Mock a concatenated JS file mimicking the real-world bug.
        #    Notice Lodash and Moment are next to each other.
        mock_bundled_js = """
        /* Lodash source */
        var lodash = {};
        lodash.VERSION = '4.17.15';
        
        /* Moment source */
        var moment = {};
        moment.version = '2.30.1';
        """

        # 3. Create a mock ScannerContext
        mock_html = '<html><head><script src="/js/bundle.js"></script></head><body></body></html>'
        ctx = ScannerContext(
            url="https://example.com",
            session=session,
            config={"cve_csv_url": "mock_cve_dataset"},
            page_is_representative=True,
            waf_challenge_detected=None,
            sensitive_paths=[],
            main_page_cache={
                "html": mock_html,
                "soup": BeautifulSoup(mock_html, "html.parser"),
                "status": 200
            }
        )

        # Mock the fetch_js function to return our bundled payload
        async def mock_fetch_js(js_url: str) -> str:
            if "bundle.js" in js_url:
                return mock_bundled_js
            return ""
        ctx.fetch_js = mock_fetch_js
        
        # Override the CSV fetch globally for the test
        global fetch_cve_dataset
        async def mock_fetch_cve_dataset(c_ctx, url):
            # Deliberately mock CVE-2019-10744 for lodash 4.17.15
            mock_data = [{
                "library": "lodash",
                "version": "4.17.15",
                "cve": "CVE-2019-10744",
                "cvss": "7.3",
                "cwe": "CWE-400",
                "signature": r"lodash\.VERSION\s*=\s*['\"]4\.17\.15['\"]",
                "summary": "Prototype Pollution in lodash",
                "upgrade_rec": "4.17.21"
            }]
            return mock_data, 0
        
        # Inject mock
        original_fetch = fetch_cve_dataset
        globals()['fetch_cve_dataset'] = mock_fetch_cve_dataset
        
        try:
            # 4. Execute the scout
            result = await run(ctx)
            
            # 5. Output Results
            print(json.dumps(result, indent=2))
            
            # Assertions purely for visual confirmation
            print("\n[*] Self-Test Assertions:")
            lodash_finding = next((f for f in result["findings"] if "lodash" in f["title"].lower()), None)
            moment_finding = next((f for f in result["findings"] if "moment" in f["title"].lower()), None)
            
            if lodash_finding and lodash_finding["confidence"] == "verified-live":
                print("  [PASS] Lodash 4.17.15 detected and successfully correlated with CVE dataset.")
            else:
                print("  [FAIL] Lodash CVE correlation failed.")
                
            if moment_finding and "2.30.1" in moment_finding["title"]:
                print("  [PASS] Moment 2.30.1 accurately detected independently.")
                
            # Verify cross-contamination didn't happen
            bad_finding = next((f for f in result["findings"] if "lodash" in f["title"].lower() and "2.30.1" in f["evidence"]), None)
            if not bad_finding:
                print("  [PASS] Cross-contamination bug averted. Lodash did NOT steal Moment's 2.30.1 version string.")
            else:
                print("  [FAIL] Cross-contamination detected!")
                
        finally:
            globals()['fetch_cve_dataset'] = original_fetch
            await session.close()

    asyncio.run(run_test())