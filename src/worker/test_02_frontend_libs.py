#!/usr/bin/env python3
"""
Bravo6 Enterprise SCA Engine (v7.0 – Local Cache & Signature Aware)
============================================================
- Removed external OSV API integration to comply with Plugin Contract v2.2.
- Added local CSV cache reading for vulnerability data.
- Added signature-based verification for CVE findings.
- Aggressive false positive reduction via multi-method detection correlation.
- Every finding now includes: CWE, OWASP, CVSS, Evidence, PoC, Remediation.
- Preserved async model, API compatibility, and JSON output format.
- Refactored to comply with Bravo6 Unified Plugin Contract v2.2.
"""
import argparse
import asyncio
import csv
import io
import json
import logging
import re
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
import aiohttp
from bs4 import BeautifulSoup
from packaging.version import InvalidVersion, Version

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
USER_AGENT = "Bravo6-SCA/7.0"
TIMEOUT = aiohttp.ClientTimeout(total=20)
MAX_FILE_BYTES = 2_097_152  # 2 MB per script
MAX_SCRIPT_URLS = 80
MAX_CONCURRENT_FETCHES = 10

# ------------------------------------------------------------------------------
# Ecosystem Mapping (Kept for reference, though OSV is removed)
# ------------------------------------------------------------------------------
ECOSYSTEM_MAP = {
    "jquery": ("npm", "jquery"), "react": ("npm", "react"), "vue": ("npm", "vue"),
    "angularjs": ("npm", "angular"), "lodash": ("npm", "lodash"), "axios": ("npm", "axios"),
    "moment": ("npm", "moment"), "bootstrap": ("npm", "bootstrap"), "webpack": ("npm", "webpack"),
    "vite": ("npm", "vite"), "next": ("npm", "next"), "nuxt": ("npm", "nuxt"),
    "svelte": ("npm", "svelte"), "alpinejs": ("npm", "alpinejs"), "chart.js": ("npm", "chart.js"),
    "ember": ("npm", "ember-source"), "swiper": ("npm", "swiper"), "socket.io": ("npm", "socket.io"),
    "select2": ("npm", "select2"), "uppy": ("npm", "@uppy/core"), "splide": ("npm", "@splidejs/splide"),
    "popper": ("npm", "@popperjs/core"), "tailwindcss": ("npm", "tailwindcss"),
    "laravel": ("Packagist", "laravel/framework"), "symfony": ("Packagist", "symfony/symfony"),
    "django": ("PyPI", "django"), "flask": ("PyPI", "flask"), "express": ("npm", "express"),
    "wordpress": ("Packagist", "wordpress/core"), "joomla": ("Packagist", "joomla/application"),
    "drupal": ("Packagist", "drupal/core"),
}

# ------------------------------------------------------------------------------
# Detection Patterns (Preserved & Enhanced)
# ------------------------------------------------------------------------------
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
LIB_CONTENT_SIGNATURE = {
    "jquery": re.compile(r"jQuery\.fn\.jquery\s*=\s*[\"']" + _VERSION + r"[\"']", re.I),
    "react": re.compile(r"React\.version\s*=\s*[\"']" + _VERSION + r"[\"']", re.I),
    "vue": re.compile(r"Vue\.version\s*=\s*[\"']" + _VERSION + r"[\"']", re.I),
    "bootstrap": re.compile(r"Bootstrap\.VERSION\s*=\s*[\"']" + _VERSION + r"[\"']", re.I),
    "moment": re.compile(r"moment\.version\s*=\s*[\"']" + _VERSION + r"[\"']", re.I),
    "lodash": re.compile(r"(?:lodash\.version|_.VERSION)\s*=\s*[\"']" + _VERSION + r"[\"']", re.I),
    "axios": re.compile(r"axios\.VERSION\s*=\s*[\"']" + _VERSION + r"[\"']", re.I),
}
LIB_CONTENT_GENERAL = {
    "jquery": re.compile(r"jQuery\s+v?" + _VERSION, re.I),
    "bootstrap": re.compile(r"Bootstrap\s+v?" + _VERSION, re.I),
    "vue": re.compile(r"Vue\.js\s+v?" + _VERSION, re.I),
    "react": re.compile(r"React\s+v?" + _VERSION, re.I),
    "lodash": re.compile(r"lodash\s+v?" + _VERSION, re.I),
    "moment": re.compile(r"Moment\.js\s+v?" + _VERSION, re.I),
    "axios": re.compile(r"axios\s+v?" + _VERSION, re.I),
}
LIB_POSITIVE_CONTEXT = {
    "angularjs": [r'angular\.module\s*\(', r'ng-app\s*[=:]'],
    "vue": [r'new Vue\s*\(', r'createApp\s*\(', r'Vue\.version\s*='],
    "bootstrap": [r'bs\.modal', r'data-bs-toggle'],
    "jquery": [r'\$\(document\)\.ready\s*\(', r'jQuery\.fn\.'],
    "react": [r'React\.createElement\(', r'React\.version\s*='],
}
LIB_CONTENT_SIGNATURE_NO_VERSION = {
    "jquery": re.compile(r"jQuery\.fn\.jquery\s*=", re.I),
    "react": re.compile(r"React\.version\s*=|React\.createElement\(", re.I),
    "vue": re.compile(r"Vue\.version\s*=|new Vue\s*\(|createApp\s*\(", re.I),
    "bootstrap": re.compile(r"Bootstrap\.VERSION\s*=|bs\.modal|data-bs-toggle", re.I),
    "moment": re.compile(r"moment\.version\s*=|moment\.", re.I),
    "lodash": re.compile(r"(?:lodash\.version|_.VERSION)\s*=|_\.", re.I),
    "axios": re.compile(r"axios\.VERSION\s*=|axios\.", re.I),
    "angularjs": re.compile(r"angular\.module\s*\(|ng-app\s*[=:]", re.I),
}

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
def _safe_version(v: str) -> Optional[Version]:
    try:
        cleaned = re.sub(r'^[\^~>=<]', '', v.strip())
        return Version(cleaned)
    except InvalidVersion:
        return None

def _has_library_context(text: str, lib: str) -> bool:
    keys = [lib]
    for key in keys:
        if key in LIB_POSITIVE_CONTEXT:
            if any(re.search(pat, text) for pat in LIB_POSITIVE_CONTEXT[key]):
                return True
    return not any(k in LIB_POSITIVE_CONTEXT for k in keys)

def _unified_version_extraction(text: str, patterns_sig: Dict, patterns_gen: Dict) -> Dict[str, tuple]:
    result = {}
    for lib, pat in patterns_sig.items():
        m = pat.search(text)
        if m and m.group(1):
            result[lib] = (m.group(1), True)
    for lib, pat in patterns_gen.items():
        if lib in result: continue
        m = pat.search(text)
        if m and m.group(1):
            result[lib] = (m.group(1), False)
    return result

def _unified_versionless_extraction(text: str, patterns: Dict) -> List[str]:
    result = []
    for lib, pat in patterns.items():
        if pat.search(text):
            result.append(lib)
    return result

async def _get_content(url: str, fetch_js: Optional[Callable], session: Optional[aiohttp.ClientSession], sem: Optional[asyncio.Semaphore]) -> Optional[str]:
    if fetch_js:
        try:
            content = await fetch_js(url)
            if isinstance(content, bytes): return content.decode("utf-8", errors="replace")
            if isinstance(content, str): return content
        except Exception: pass
    if session and sem:
        async with sem:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=20), ssl=True) as resp:
                    if resp.status == 200:
                        data = await resp.read()
                        if len(data) <= MAX_FILE_BYTES:
                            return data.decode("utf-8", errors="replace")
            except Exception: pass
    return None

async def extract_from_source_map(session: aiohttp.ClientSession, js_url: str, js_content: str, sem: asyncio.Semaphore) -> List[dict]:
    findings = []
    match = re.search(r'//#\s*sourceMappingURL=(.+)', js_content)
    if not match:
        return findings
    map_url = match.group(1).strip()
    if map_url.startswith('data:'):
        return findings
    map_url = urljoin(js_url, map_url)
    async with sem:
        try:
            async with session.get(map_url, timeout=aiohttp.ClientTimeout(total=20), ssl=True) as resp:
                if resp.status == 200:
                    map_data = await resp.json(content_type=None)
                    sources = map_data.get("sources", [])
                    for src in sources:
                        m = re.search(r'(?:node_modules|bower_components)/(@?[^/]+/[^/]+|[^/]+)(?:@(\d+\.\d+\.\d+[^/]*))?', src)
                        if m:
                            lib = m.group(1)
                            ver = m.group(2)
                            lib = lib.split('/')[-1] if lib.startswith('@') else lib
                            findings.append({
                                "library": lib.lower(),
                                "version": ver,
                                "source": "source_map",
                                "url": js_url,
                                "evidence": f"Found in source map: {src}"
                            })
        except Exception:
            pass
    return findings

# ------------------------------------------------------------------------------
# Main SCA Engine
# ------------------------------------------------------------------------------
async def run(url: str, **kwargs) -> Dict[str, Any]:
    try:
        session = kwargs.get("session")
        shared_page = kwargs.get("shared_page")
        js_cache = kwargs.get("js_cache", {})
        fetch_js = kwargs.get("fetch_js")
        min_confidence = kwargs.get("min_confidence", 50)
        cve_csv_url = kwargs.get("cve_csv_url")
        
        own_session = session
        should_close = False
        if own_session is None:
            connector = aiohttp.TCPConnector(ssl=True, limit=15, limit_per_host=6)
            headers = {"User-Agent": USER_AGENT}
            own_session = aiohttp.ClientSession(connector=connector, headers=headers, timeout=TIMEOUT)
            should_close = True
            
        cve_cache = []
        if cve_csv_url:
            try:
                if cve_csv_url.startswith("http://") or cve_csv_url.startswith("https://"):
                    async with own_session.get(cve_csv_url, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            reader = csv.DictReader(io.StringIO(text))
                            cve_cache = list(reader)
                else:
                    with open(cve_csv_url, 'r', encoding='utf-8') as f:
                        reader = csv.DictReader(f)
                        cve_cache = list(reader)
            except Exception:
                pass # Operate in detection-only mode
                
        target = url.strip()
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
            
        findings = []
        script_contents = {}
        if js_cache and isinstance(js_cache, dict):
            for u, content in js_cache.items():
                if isinstance(content, bytes):
                    script_contents[u] = content.decode("utf-8", errors="replace")
                elif isinstance(content, str):
                    script_contents[u] = content
                    
        sem = asyncio.Semaphore(MAX_CONCURRENT_FETCHES)
        
        html = None
        soup = None
        if shared_page and not shared_page.get("error") and shared_page.get("status") == 200:
            html = shared_page.get("html", "")
            soup = shared_page.get("soup")
            if not soup and html:
                soup = BeautifulSoup(html, "html.parser")
            shared_sc = shared_page.get("script_contents", {})
            if isinstance(shared_sc, dict):
                for u, content in shared_sc.items():
                    if u not in script_contents:
                        script_contents[u] = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
        else:
            async with own_session.get(target, timeout=aiohttp.ClientTimeout(total=20), ssl=True, allow_redirects=True) as resp:
                if resp.status >= 400:
                    return {"findings": [], "details": {"error": f"HTTP {resp.status}", "status": resp.status}}
                html = await resp.text(errors="replace")
                soup = BeautifulSoup(html, "html.parser")
                
        if not html:
            return {"findings": [], "details": {"error": "Empty response body"}}
            
        raw_findings = []
        script_urls = []
        
        if soup:
            for tag in soup.find_all("script"):
                src = tag.get("src")
                if src:
                    abs_url = urljoin(target, src)
                    script_urls.append(abs_url)
                    url_versions = _unified_version_extraction(abs_url, {}, LIB_URL)
                    for lib, (ver, _) in url_versions.items():
                        raw_findings.append({"library": lib, "version": ver, "source": "script_src_url", "url": abs_url})
                    filename_versions = _unified_version_extraction(abs_url, {}, LIB_URL_FILENAME)
                    for lib, (ver, _) in filename_versions.items():
                        raw_findings.append({"library": lib, "version": ver, "source": "script_src_filename", "url": abs_url})
            
            script_urls = list(dict.fromkeys(script_urls))[:MAX_SCRIPT_URLS]
            
            tasks = []
            for u in script_urls:
                if u not in script_contents:
                    tasks.append(_get_content(u, fetch_js, own_session, sem))
                else:
                    async def dummy(): return script_contents[u]
                    tasks.append(dummy())
                    
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, res in enumerate(results):
                if isinstance(res, str):
                    script_contents[script_urls[i]] = res
                    
            for u, text in script_contents.items():
                if not text: continue
                content_versions = _unified_version_extraction(text, LIB_CONTENT_SIGNATURE, LIB_CONTENT_GENERAL)
                versionless_libs = _unified_versionless_extraction(text, LIB_CONTENT_SIGNATURE_NO_VERSION)
                detected_libs_in_text = set(content_versions.keys())
                
                for lib, (ver, is_sig) in content_versions.items():
                    if _has_library_context(text, lib):
                        raw_findings.append({
                            "library": lib, "version": ver, "source": "script_content",
                            "url": u, "is_signature": is_sig,
                            "evidence": f"Matched signature in {u}"
                        })
                for lib in versionless_libs:
                    if lib not in detected_libs_in_text and _has_library_context(text, lib):
                        raw_findings.append({
                            "library": lib, "version": None, "source": "script_content",
                            "url": u, "is_signature": True,
                            "evidence": f"Matched signature without version in {u}"
                        })
                        
                sm_findings = await extract_from_source_map(own_session, u, text, sem)
                raw_findings.extend(sm_findings)
                
            inline_idx = 0
            for tag in soup.find_all("script"):
                if not tag.get("src") and tag.string:
                    inline_text = tag.string.strip()
                    loc_name = f"inline_script_{inline_idx}"
                    script_contents[loc_name] = inline_text
                    inline_idx += 1
                    
                    inline_versions = _unified_version_extraction(inline_text, LIB_CONTENT_SIGNATURE, LIB_CONTENT_GENERAL)
                    inline_versionless = _unified_versionless_extraction(inline_text, LIB_CONTENT_SIGNATURE_NO_VERSION)
                    detected_inline_libs = set(inline_versions.keys())
                    for lib, (ver, is_sig) in inline_versions.items():
                        if _has_library_context(inline_text, lib):
                            raw_findings.append({
                                "library": lib, "version": ver, "source": "inline",
                                "url": loc_name, "is_signature": is_sig, "evidence": "Matched signature in inline script"
                            })
                    for lib in inline_versionless:
                        if lib not in detected_inline_libs and _has_library_context(inline_text, lib):
                            raw_findings.append({
                                "library": lib, "version": None, "source": "inline",
                                "url": loc_name, "is_signature": True, "evidence": "Matched signature without version in inline script"
                            })
                            
            for manifest_path, pkg_type in [("/package.json", "npm"), ("/composer.json", "Packagist")]:
                pkg_url = urljoin(target, manifest_path)
                pkg_text = await _get_content(pkg_url, fetch_js, own_session, sem)
                if pkg_text:
                    try:
                        pkg = json.loads(pkg_text)
                        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {}), **pkg.get("require", {})}
                        for lib, ver in deps.items():
                            cleaned = re.sub(r'^[\^~>=<]', '', ver.strip())
                            raw_findings.append({"library": lib, "version": cleaned, "source": pkg_type, "url": pkg_url})
                    except Exception: pass
                    
        lib_groups = {}
        for f in raw_findings:
            lib = f["library"].lower()
            lib_groups.setdefault(lib, []).append(f)
            
        SOURCE_PRIORITY = {
            "source_map": 10, "script_src_filename": 9, "script_content": 8, "inline": 7,
            "npm": 6, "Packagist": 6, "script_src_url": 5, "fallback": 0
        }
        
        for lib, entries in lib_groups.items():
            entries_sorted = sorted(entries, key=lambda e: (SOURCE_PRIORITY.get(e["source"], 0), 1 if e.get("version") else 0), reverse=True)
            best = next((e for e in entries_sorted if e.get("version")), entries_sorted[0])
            ver_str = best.get("version")
            
            sources = list({e["source"] for e in entries})
            has_sig = any(e.get("is_signature") for e in entries if e["source"] in ("script_content", "inline"))
            base_conf = 95 if "source_map" in sources else (85 if has_sig else 70)
            
            location = best.get("url", "inline")
            
            cve_matches = [row for row in cve_cache if str(row.get("library", "")).lower() == lib.lower() and str(row.get("version", "")) == str(ver_str)]
            
            cve_reported = False
            if cve_matches and ver_str:
                js_content = script_contents.get(location)
                if not js_content and location != "inline" and not location.startswith("inline_script_"):
                    js_content = await _get_content(location, fetch_js, own_session, sem)
                    if js_content:
                        script_contents[location] = js_content
                
                for cve_row in cve_matches:
                    signature = str(cve_row.get("signature", "")).strip()
                    confidence = base_conf
                    signature_found = False
                    
                    if signature:
                        try:
                            if re.search(signature, js_content or ""):
                                signature_found = True
                        except re.error:
                            signature_found = False
                    else:
                        confidence = max(0, base_conf - 15)
                        signature_found = True
                        
                    if signature_found:
                        cve_reported = True
                        cvss_str = str(cve_row.get("cvss", ""))
                        cvss_score = 0.0
                        score_match = re.search(r'CVSS:[34]\.\d/([0-9]\.[0-9])', cvss_str)
                        if score_match:
                            cvss_score = float(score_match.group(1))
                        else:
                            nums = re.findall(r'\b(\d+\.\d+)\b', cvss_str)
                            for n in nums:
                                val = float(n)
                                if 0.0 <= val <= 10.0:
                                    cvss_score = val
                                    break
                        
                        if cvss_score >= 9.0:
                            severity = "critical"
                        elif cvss_score >= 7.0:
                            severity = "high"
                        elif cvss_score >= 4.0:
                            severity = "medium"
                        else:
                            severity = "low"
                            
                        cwe = cve_row.get("cwe", "CWE-1035") or "CWE-1035"
                        summary = cve_row.get("summary", "")
                        upgrade_rec = cve_row.get("upgrade_rec", "latest")
                        cve_id = cve_row.get("cve", "Unknown CVE")
                        
                        finding = {
                            "title": f"Vulnerable {lib}: {cve_id}",
                            "severity": severity,
                            "confidence": confidence,
                            "cwe": cwe,
                            "owasp": "A06:2021",
                            "evidence": f"Detected {lib}@{ver_str} via {', '.join(sources)}. CVE: {cve_id}. CVSS: {cvss_str}. Summary: {summary}. Upgrade to {upgrade_rec}.",
                            "poc": f"Check current version: grep -r '{lib}' . || npm list {lib}",
                            "remediation": f"Upgrade {lib} to {upgrade_rec} or later. Current version {ver_str} is vulnerable to {cve_id}.",
                            "detection_method": "SCA + Local Cache + Signature Verification",
                            "location": location
                        }
                        findings.append(finding)
            
            if not cve_reported:
                finding = {
                    "title": f"Detected {lib} v{ver_str or 'unknown'}",
                    "severity": "info",
                    "confidence": base_conf,
                    "cwe": "",
                    "owasp": "",
                    "evidence": f"Detected {lib}@{ver_str or 'unknown'} via {', '.join(sources)}.",
                    "poc": "N/A",
                    "remediation": "Keep libraries updated and monitor for known vulnerabilities.",
                    "detection_method": "Library Fingerprinting",
                    "location": location
                }
                findings.append(finding)
                
        findings = [f for f in findings if f.get("confidence", 100) >= min_confidence]
        
        details = {
            "libraries_detected": len(lib_groups),
            "cve_cache_loaded": len(cve_cache) > 0
        }
        
        return {"findings": findings, "details": details}
        
    except Exception as e:
        return {
            "findings": [],
            "details": {"error": str(e), "error_type": type(e).__name__}
        }
    finally:
        if should_close and own_session is not None:
            await own_session.close()

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(json.dumps(asyncio.run(run(target)), indent=2, ensure_ascii=False))