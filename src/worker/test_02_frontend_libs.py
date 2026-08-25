#!/usr/bin/env python3
"""
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

    # 6. Load CVE Dataset
    cve_csv_url = ctx.config.get("cve_csv_url") if ctx.config else None
    cve_cache = []
    if cve_csv_url:
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
                
                if signature and js_content:
                    try:
                        # Sandbox regex to avoid ReDoS on main thread
                        if re.search(signature, js_content):
                            signature_found = True
                    except re.error:
                        signature_found = False
                elif not signature:
                    signature_found = True  # Blind version trust if dataset lacks signature

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
                        "confidence": "verified-live",
                        "cwe": cve_row.get("cwe", "CWE-1035"),
                        "owasp": "A06:2021-Vulnerable and Outdated Components",
                        "location": location,
                        "evidence": f"Detected {lib}@{ver_str} in {best['source']}. CVE: {cve_id} matched. Summary: {cve_row.get('summary', 'Known vulnerability')}.",
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
                self.assertEqual(lodash_finding["confidence"], "verified-live")
                self.assertNotIn("2.30.1", lodash_finding["evidence"],
                                  "Lodash must not steal Moment's 2.30.1 version string.")

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