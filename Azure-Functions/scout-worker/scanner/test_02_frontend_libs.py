#!/usr/bin/env python3
"""
Bravo6 Ultimate Frontend Library Auditor (v4.3 – Enhanced + filename‑aware + multi‑CVE)
============================================================
- Accepts shared_page from main_scanner to avoid re-fetching the homepage.
- All header keys are normalized to lowercase for case‑insensitive matching.
- Vulnerabilities are no longer truncated – **all** matching CVEs per library are reported.
- URL parsing now also extracts versions from filenames (e.g., jquery-3.6.0.min.js).
"""

import asyncio
import json
import os
import random
import re
from typing import Dict, List, Optional, Any
from urllib.parse import urljoin

import aiohttp
from bs4 import BeautifulSoup
from packaging.version import Version, InvalidVersion

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────
USER_AGENT = "Bravo6-LibAudit/4.3"
TIMEOUT = aiohttp.ClientTimeout(total=20)
MAX_FILE_BYTES = 1_048_576          # 1 MB per script
MAX_SCRIPT_URLS = 40
MAX_CONCURRENT_FETCHES = 8

# ──────────────────────────────────────────────────────────────────────────────
# Version patterns
# ──────────────────────────────────────────────────────────────────────────────
_VERSION = r"(\d+\.\d+\.\d+(?:[-.][0-9A-Za-z.]+)?)"

# Original patterns that rely on a query string (?v=...)
LIB_URL = {
    "jquery":           re.compile(r"jquery[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "jquery-ui":        re.compile(r"jquery[.\-]?ui[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "jquery-ui-alt":    re.compile(r"jquery/ui/.*?\.js\?.*v?" + _VERSION, re.I),
    "bootstrap":        re.compile(r"bootstrap[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "angularjs":        re.compile(r"angular[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "lodash":           re.compile(r"lodash[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "moment":           re.compile(r"moment[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "axios":            re.compile(r"axios[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "vue":              re.compile(r"vue[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "vue-router":       re.compile(r"vue-router[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "react":            re.compile(r"react[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "react-dom":        re.compile(r"react-dom[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "react-router":     re.compile(r"react-router[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "next":             re.compile(r"next[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "svelte":           re.compile(r"svelte[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "alpinejs":         re.compile(r"alpine(?:js)?[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "chart.js":         re.compile(r"chart(?:\.min)?\.js\?.*v?" + _VERSION, re.I),
    "ember":            re.compile(r"ember[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "swiper":           re.compile(r"swiper(?:/v?\d+)?[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "socket.io":        re.compile(r"socket\.io[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "select2":          re.compile(r"select2[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "bootstrap-datepicker": re.compile(r"bootstrap-datepicker[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "vite":             re.compile(r"vite[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "webpack":          re.compile(r"webpack[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "elementor":        re.compile(r"elementor[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
}

# **NEW** – patterns that directly match a version embedded in the filename
# e.g., jquery-3.6.0.min.js, bootstrap-5.1.3.bundle.min.js
LIB_URL_FILENAME = {
    "jquery":           re.compile(r"jquery[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
    "jquery-ui":        re.compile(r"jquery[.\-]?ui[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
    "bootstrap":        re.compile(r"bootstrap[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
    "angularjs":        re.compile(r"angular[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
    "lodash":           re.compile(r"lodash[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
    "moment":           re.compile(r"moment[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
    "axios":            re.compile(r"axios[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
    "vue":              re.compile(r"vue[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
    "react":            re.compile(r"react[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
    "react-dom":        re.compile(r"react-dom[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
    "swiper":           re.compile(r"swiper[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
    "select2":          re.compile(r"select2[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
    "chart.js":         re.compile(r"chart[.-](\d+\.\d+\.\d+)(?:\.min)?\.js", re.I),
    # add others as needed
}

LIB_CONTENT = {
    "jquery":           re.compile(r"(?:jQuery\s+v?" + _VERSION + r"|jquery\.fn\.jquery\s*=\s*[\"']" + _VERSION + r"[\"'])", re.I),
    "jquery-ui":        re.compile(r"jQuery UI\s+v?" + _VERSION, re.I),
    "bootstrap":        re.compile(r"Bootstrap\s+v?" + _VERSION, re.I),
    "angularjs":        re.compile(r"angular[.\-]v?" + _VERSION, re.I),
    "lodash":           re.compile(r"lodash\s+v?" + _VERSION, re.I),
    "moment":           re.compile(r"moment\.version\s*=\s*[\"']" + _VERSION + r"[\"']", re.I),
    "axios":            re.compile(r"axios\s+v?" + _VERSION, re.I),
    "vue":              re.compile(r"Vue\.js\s+v?" + _VERSION, re.I),
    "react":            re.compile(r"React\s+v?" + _VERSION, re.I),
    "next":             re.compile(r"Next\.js\s+v?" + _VERSION, re.I),
    "svelte":           re.compile(r"svelte\s+v?" + _VERSION, re.I),
    "alpinejs":         re.compile(r"Alpine\.js\s+v?" + _VERSION, re.I),
    "chart.js":         re.compile(r"Chart\.js\s+v?" + _VERSION, re.I),
    "ember":            re.compile(r"Ember\s+v?" + _VERSION, re.I),
    "swiper":           re.compile(r"Swiper\s+v?" + _VERSION, re.I),
    "tailwindcss":      re.compile(r"tailwindcss\s+v?" + _VERSION, re.I),
    "elementor":        re.compile(r"Elementor\s+v?" + _VERSION, re.I),
    "select2":          re.compile(r"Select2\s+v?" + _VERSION, re.I),
    "popper":           re.compile(r"Popper\s+v?" + _VERSION, re.I),
    "slicknav":         re.compile(r"SlickNav\s+v?" + _VERSION, re.I),
}

META_GENERATOR = {
    "wordpress": re.compile(r"WordPress\s+" + _VERSION, re.I),
    "joomla":    re.compile(r"Joomla!\s+" + _VERSION, re.I),
    "drupal":    re.compile(r"Drupal\s+" + _VERSION, re.I),
    "laravel":   re.compile(r"Laravel\s+v?" + _VERSION, re.I),
}

HEADER_NAMES = ["server", "x-powered-by", "x-generator"]

HEADER_PATTERNS = {
    "php":      re.compile(r"PHP/(\d+\.\d+\.\d+)"),
    "nginx":    re.compile(r"nginx/(\d+\.\d+\.\d+)"),
    "apache":   re.compile(r"Apache/(\d+\.\d+\.\d+)"),
    "aspnet":   re.compile(r"ASP\.NET\s+v?(\d+\.\d+\.\d+)"),
    "express":  re.compile(r"Express\s+v?(\d+\.\d+\.\d+)", re.I),
}

COOKIE_HINTS = {
    "php":          "PHPSESSID",
    "laravel":      "laravel_session",
    "wordpress":    "wp-settings-",
    "django":       "csrftoken",
    "express":      "connect.sid",
    "aspnet":       "ASP.NET_SessionId",
    "java":         "JSESSIONID",
}

GLOBAL_VAR = {
    "jquery":   re.compile(r"window\.jQuery\s*=", re.I),
    "react":    re.compile(r"window\.React\s*=", re.I),
    "vue":      re.compile(r"window\.Vue\s*=", re.I),
    "angularjs":re.compile(r"window\.angular\s*=", re.I),
    "lodash":   re.compile(r"window\._\s*=", re.I),
    "axios":    re.compile(r"window\.axios\s*=", re.I),
    "moment":   re.compile(r"window\.moment\s*=", re.I),
    "swiper":   re.compile(r"window\.Swiper\s*=", re.I),
    "alpinejs": re.compile(r"window\.Alpine\s*=", re.I),
    "elementor": re.compile(r"window\.elementor\s*=", re.I),
    "popper":   re.compile(r"window\.Popper\s*=", re.I),
    "select2":  re.compile(r"window\.jQuery\.fn\.select2\s*=", re.I),
}

CSS_LINKS = {
    "bootstrap":        re.compile(r"bootstrap[.\-]v?" + _VERSION, re.I),
    "font-awesome":     re.compile(r"font-awesome[.\-]v?" + _VERSION, re.I),
    "bulma":            re.compile(r"bulma[.\-]v?" + _VERSION, re.I),
    "tailwindcss":      re.compile(r'(?:tailwindcss[.\-]v?' + _VERSION + r'|data-tailwind)', re.I),
    "swiper":           re.compile(r"swiper[.\-]v?" + _VERSION, re.I),
    "select2":          re.compile(r"select2[.\-]v?" + _VERSION, re.I),
    "slicknav":         re.compile(r"slicknav[.\-]v?" + _VERSION, re.I),
}

VERSION_FALLBACK = re.compile(r'(?:window\.)?(?:__VERSION__|\.version)\s*=\s*["\']' + _VERSION + r'["\']', re.I)

# ──────────────────────────────────────────────────────────────────────────────
# Load CVE database from external file (with fallback)
# ──────────────────────────────────────────────────────────────────────────────
def _load_cve_db() -> Dict[str, List[Dict]]:
    db_path = os.path.join(os.path.dirname(__file__), "cve_db.json")
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {
            "jquery": [{"range": ["1.0.0","3.5.0"], "cve":"CVE-2020-11022","desc":"XSS via jQuery.html()","severity":"high","patch":"3.5.0","sig":"(?:jQuery\\.htmlPrefilter|\\.htmlPrefilter\\s*[=:])"}]
        }

VULNERABILITIES = _load_cve_db()

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────
def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    return url

def _safe_version(v: str) -> Optional[Version]:
    try:
        cleaned = re.sub(r'^[\^~>=<]', '', v.strip())
        return Version(cleaned)
    except InvalidVersion:
        return None

def _version_in_range(ver: Version, min_str: str, max_str: str) -> bool:
    min_v = _safe_version(min_str)
    max_v = _safe_version(max_str)
    return min_v is not None and max_v is not None and min_v <= ver < max_v

def _unified_version_extraction(text: str, patterns: Dict[str, re.Pattern]) -> Dict[str, str]:
    result = {}
    for lib, pat in patterns.items():
        m = pat.search(text)
        if m and m.group(1):
            result[lib] = m.group(1)
    return result

def _best_url(urls: List[str], lib: str) -> Optional[str]:
    for url in urls:
        if lib.lower() in url.lower():
            return url
    return urls[0] if urls else None

async def _fetch_script(session, url: str, sem: asyncio.Semaphore, retries=3) -> Optional[bytes]:
    async with sem:
        for attempt in range(retries):
            try:
                async with session.get(url, timeout=TIMEOUT, ssl=True) as resp:
                    if resp.status == 200:
                        data = await resp.read()
                        if len(data) <= MAX_FILE_BYTES:
                            return data
            except Exception:
                if attempt < retries - 1:
                    backoff = 2 ** attempt + random.uniform(0, 1)
                    await asyncio.sleep(backoff)
    return None

# ──────────────────────────────────────────────────────────────────────────────
# Main audit (accepts shared_page)
# ──────────────────────────────────────────────────────────────────────────────
async def run(url: str, shared_page: dict = None) -> Dict[str, Any]:
    target = _normalize_url(url)
    if not target:
        return {"test_name": "frontend_libs_audit", "status": "error", "title": "Invalid URL"}

    print(f"[*] Starting frontend audit for {target}")
    connector = aiohttp.TCPConnector(ssl=True, limit=15, limit_per_host=6)
    headers = {"User-Agent": USER_AGENT}
    all_findings = []
    script_contents = {}
    sem = asyncio.Semaphore(MAX_CONCURRENT_FETCHES)

    try:
        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            if shared_page and not shared_page.get("error") and shared_page.get("status") == 200:
                html = shared_page.get("html", "")
                raw_headers = shared_page.get("headers", {})
                resp_headers = {k.lower(): v for k, v in raw_headers.items()}
                soup = shared_page.get("soup")
                if soup is None:
                    soup = BeautifulSoup(html, "html.parser")
            else:
                async with session.get(target, timeout=TIMEOUT, ssl=True, allow_redirects=True) as resp:
                    if resp.status >= 400:
                        return {"test_name": "frontend_libs_audit", "status": "warning", "title": f"HTTP {resp.status}"}
                    html = await resp.text(errors="replace")
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    soup = BeautifulSoup(html, "html.parser")

            if not html or len(html) < 500:
                print(f"[!] Warning: Received very short HTML ({len(html) if html else 0} chars) – possible captcha/block")

            # ── 1. Meta generator tags ───────────────────────────────
            for meta in soup.find_all("meta", attrs={"name": "generator"}):
                content = meta.get("content", "")
                if content:
                    for lib, pat in META_GENERATOR.items():
                        m = pat.search(content)
                        if m:
                            all_findings.append({"library": lib, "version": m.group(1), "source": "meta"})

            # ── 2. HTTP headers ─────────────────────────────────────
            for hdr_name in HEADER_NAMES:
                hdr_val = resp_headers.get(hdr_name, "")
                if not hdr_val:
                    continue
                for lib, pat in HEADER_PATTERNS.items():
                    m = pat.search(hdr_val)
                    if m:
                        all_findings.append({"library": lib, "version": m.group(1), "source": "header"})

            # ── 3. Cookies ───────────────────────────────────────────
            set_cookie = resp_headers.get("set-cookie", "")
            for lib, hint in COOKIE_HINTS.items():
                if hint.lower() in set_cookie.lower():
                    all_findings.append({"library": lib, "version": None, "source": "cookie"})

            # ── 4. External script tags ──────────────────────────────
            script_urls = []
            for tag in soup.find_all("script"):
                src = tag.get("src")
                if src:
                    abs_url = urljoin(target, src)
                    script_urls.append(abs_url)

                    # Original query‑string based extraction
                    extracted_url = _unified_version_extraction(abs_url, LIB_URL)
                    # **NEW** – filename‑based extraction
                    extracted_filename = _unified_version_extraction(abs_url, LIB_URL_FILENAME)

                    # Merge results (filename overrides query if both present)
                    all_extracted = {**extracted_url, **extracted_filename}
                    for lib, ver in all_extracted.items():
                        if lib == "jquery-ui-alt":
                            lib = "jquery-ui"
                        all_findings.append({"library": lib, "version": ver, "source": "script_src", "url": abs_url})

            script_urls = list(dict.fromkeys(script_urls))[:MAX_SCRIPT_URLS]

            # ── 5. Fetch external scripts ────────────────────────────
            fetched = await asyncio.gather(*[_fetch_script(session, u, sem) for u in script_urls])
            for url, data in zip(script_urls, fetched):
                if data:
                    text = data.decode("utf-8", errors="replace")
                    script_contents[url] = text
                    content_versions = _unified_version_extraction(text, LIB_CONTENT)
                    for lib, ver in content_versions.items():
                        if lib == "jquery" and "jquery" not in url.lower():
                            continue
                        all_findings.append({"library": lib, "version": ver, "source": "script_content", "url": url})
                    for lib, pat in GLOBAL_VAR.items():
                        if pat.search(text):
                            all_findings.append({"library": lib, "version": None, "source": "global_var", "url": url})
                    fallback = VERSION_FALLBACK.search(text)
                    if fallback:
                        all_findings.append({"library": "unknown", "version": fallback.group(1), "source": "fallback", "url": url})

            print(f"[+] Fetched {len(script_contents)} external scripts (total {len(script_urls)} links)")

            # ── 6. Inline scripts ────────────────────────────────────
            for tag in soup.find_all("script"):
                if not tag.get("src") and tag.string:
                    inline_vers = _unified_version_extraction(tag.string.strip(), LIB_CONTENT)
                    for lib, ver in inline_vers.items():
                        all_findings.append({"library": lib, "version": ver, "source": "inline"})

            # ── 7. CSS links ─────────────────────────────────────────
            for link in soup.find_all("link", rel="stylesheet"):
                href = link.get("href")
                if href:
                    full_href = urljoin(target, href)
                    css_vers = _unified_version_extraction(full_href, CSS_LINKS)
                    for lib, ver in css_vers.items():
                        all_findings.append({"library": lib, "version": ver, "source": "css", "url": full_href})

            # ── 8. /package.json ─────────────────────────────────────
            pkg_url = urljoin(target, "/package.json")
            pkg_data = await _fetch_script(session, pkg_url, sem)
            if pkg_data:
                try:
                    pkg = json.loads(pkg_data)
                    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
                    for lib, ver in deps.items():
                        cleaned = re.sub(r'^[\^~>=<]', '', ver.strip())
                        all_findings.append({"library": lib, "version": cleaned, "source": "package.json"})
                except:
                    pass

    except Exception as e:
        return {"test_name": "frontend_libs_audit", "status": "error", "title": f"Error: {e}"}

    # Merge findings (same as before)
    merged = {}
    for f in all_findings:
        lib = f["library"]
        ver = f["version"]
        url = f.get("url")
        key = (lib, ver)
        if key not in merged:
            merged[key] = f.copy()
            merged[key]["sources"] = [f["source"]]
            merged[key]["urls"] = [url] if url else []
        else:
            if f["source"] not in merged[key]["sources"]:
                merged[key]["sources"].append(f["source"])
            if url and url not in merged[key]["urls"]:
                merged[key]["urls"].append(url)

    unknown_keys = [(lib, ver) for (lib, ver) in merged if lib == "unknown"]
    for ulib, uver in unknown_keys:
        unknown_entry = merged.get((ulib, uver))
        if not unknown_entry:
            continue
        unknown_urls = set(unknown_entry.get("urls", []))
        for (klib, kver), kentry in merged.items():
            if klib == "unknown" or kver != uver:
                continue
            known_urls = set(kentry.get("urls", []))
            if known_urls & unknown_urls:
                for src in unknown_entry["sources"]:
                    if src not in kentry["sources"]:
                        kentry["sources"].append(src)
                merged.pop((ulib, uver), None)
                break

    merged = {k: v for k, v in merged.items() if k[0] != "unknown"}

    for entry in merged.values():
        urls = entry.get("urls", [])
        entry["url"] = _best_url(urls, entry["library"]) if urls else None

    findings = list(merged.values())

    # ─────────────────────────────────────────────────────────────────
    # Vulnerability assessment – **ALL** matching CVEs are now collected
    # ─────────────────────────────────────────────────────────────────
    evidence = []
    vuln_count = 0

    for entry in findings:
        lib = entry["library"]
        ver_str = entry.get("version")
        if not ver_str:
            entry["vulnerable"] = False
            entry["confidence"] = 0
            evidence.append(entry)
            continue

        parsed = _safe_version(ver_str)
        if not parsed:
            entry["vulnerable"] = False
            entry["confidence"] = 0
            evidence.append(entry)
            continue

        # **CHANGE**: Collect **all** matching CVEs instead of breaking
        matched_vulns = []
        for vuln in VULNERABILITIES.get(lib, []):
            if _version_in_range(parsed, *vuln["range"]):
                matched_vulns.append(vuln)

        if not matched_vulns:
            entry["vulnerable"] = False
            entry["confidence"] = 80 if "script" in entry.get("sources", []) else 50
            evidence.append(entry)
            continue

        # For each CVE found, create a dedicated evidence entry
        for vuln in matched_vulns:
            sig_present = False
            if entry.get("url") and entry["url"] in script_contents:
                script_text = script_contents[entry["url"]]
                sig_present = bool(re.search(vuln["sig"], script_text, re.IGNORECASE | re.DOTALL))

            confidence = 95 if sig_present else 70 if entry.get("url") else 50
            cve_link = f"https://nvd.nist.gov/vuln/detail/{vuln['cve']}"
            curl_cmd = f"curl -s {entry['url']} -o vulnerable-{lib}-{ver_str}.js" if entry.get("url") else "No direct file URL available"

            evidence.append({
                "library": lib,
                "version_detected": ver_str,
                "vulnerable": True,
                "cve": vuln["cve"],
                "cve_link": cve_link,
                "description": vuln["desc"],
                "severity": vuln["severity"],
                "patch_version": vuln["patch"],
                "sources": entry.get("sources", [entry.get("source")]),
                "signature_verified": sig_present,
                "confidence": confidence,
                "poc_js": f"// {lib}@{ver_str}: {vuln['desc']}\n// Exploitable via {vuln['sig']}",
                "poc_curl": curl_cmd,
                "remediation": f"Upgrade {lib} to >= {vuln['patch']}"
            })
            vuln_count += 1

    criticals = [e for e in evidence if e.get("severity") == "critical"]
    highs = [e for e in evidence if e.get("severity") == "high"]
    mediums = [e for e in evidence if e.get("severity") == "medium"]

    sev_summary = f"[!] {len(criticals)} CRITICAL | {len(highs)} HIGH | {len(mediums)} MEDIUM"
    print(sev_summary)

    if criticals:
        status, sev = "fail", "critical"
        title = f"{len(criticals)} CRITICAL vulnerable libraries"
    elif highs:
        status, sev = "fail", "high"
        title = f"{len(highs)} HIGH vulnerable libraries"
    elif vuln_count:
        status, sev = "warning", "medium"
        title = f"{vuln_count} vulnerable libraries (medium/low)"
    else:
        status, sev = "pass", "info"
        title = "No vulnerable libraries detected"

    print(f"[+] Analysis complete. Findings: {len(findings)}, Vulnerable: {vuln_count}")

    return {
        "test_name": "frontend_libs_audit",
        "status": status,
        "severity": sev,
        "title": title,
        "libraries_detected": len(findings),
        "vulnerable_count": vuln_count,
        "severity_breakdown": {
            "critical": len(criticals),
            "high": len(highs),
            "medium": len(mediums),
            "low": len(evidence) - len(criticals) - len(highs) - len(mediums)
        },
        "evidence": evidence,
        "remediation": "Update all identified libraries to the recommended versions. Use provided PoC commands and CVE links for verification."
    }

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(json.dumps(asyncio.run(run(target)), indent=2, ensure_ascii=False))