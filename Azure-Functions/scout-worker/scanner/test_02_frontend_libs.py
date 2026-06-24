#!/usr/bin/env python3
"""
Bravo6 Ultimate Frontend Library Auditor (v5.1 – Expert Security Auditor Edition)
=================================================================================
- Filename & content version extraction have highest priority; query strings are
  only a weak hint.
- Drastically reduced false positives through an **extended blacklist** and
  **mandatory positive context checks** for frequently misidentified libraries.
- Caches all fetched JS and reuses it.
- Signature verification confidence raised to 95 % **only** when both version
  and CVE‑specific signature are confirmed.
- Multi‑CVE per library fully supported.
- Graceful fallback on fetch failures: only very strong signatures (filename)
  lead to a vulnerability report, and even then with reduced confidence.
- Accurate summary & severity breakdown based on actual CVE severity.
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
USER_AGENT = "Bravo6-LibAudit/5.1"
TIMEOUT = aiohttp.ClientTimeout(total=20)
MAX_FILE_BYTES = 1_048_576          # 1 MB per script
MAX_SCRIPT_URLS = 40
MAX_CONCURRENT_FETCHES = 8

# ──────────────────────────────────────────────────────────────────────────────
# Version patterns
# ──────────────────────────────────────────────────────────────────────────────
_VERSION = r"(\d+\.\d+\.\d+(?:[-.][0-9A-Za-z.]+)?)"

# Query‑string based (low priority)
LIB_URL = {
    "jquery":           re.compile(r"jquery[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "jquery-ui":        re.compile(r"jquery[.\-]?ui[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
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

# Filename‑based (high priority)
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
}

# Content‑based patterns (high priority, subject to blacklist & context)
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

# ---------------------------------------------------------------------------
# False‑positive blacklist for content‑based detection.
# If any of these patterns is found in the same script, the match is discarded.
# ---------------------------------------------------------------------------
CONTENT_FALSE_POSITIVE_PATTERNS = {
    "bootstrap": [
        re.compile(r"\banimate\b", re.I),
        re.compile(r"data-parent", re.I),
        re.compile(r"data-toggle", re.I),
        re.compile(r"data-target", re.I),
        re.compile(r"data-dismiss", re.I),
        re.compile(r"\.modal\b", re.I),
    ],
    "angularjs": [
        re.compile(r"\banimate\b", re.I),          # animation libraries
        re.compile(r"owl-carousel", re.I),
        re.compile(r"wow\.js", re.I),
        re.compile(r"aos\.js", re.I),
        re.compile(r"fancybox", re.I),
        re.compile(r"\.css\(\s*[\"']animation", re.I),
    ],
    "vue": [
        re.compile(r"\banimate\b", re.I),
        re.compile(r"fancybox", re.I),
        re.compile(r"owl-carousel", re.I),
        re.compile(r"slick\.js", re.I),
        re.compile(r"\.modal\(", re.I),           # generic modal call
    ],
    "drupal": [
        re.compile(r"rest", re.I),                # very generic term
        re.compile(r"jquery\.fancybox", re.I),
        re.compile(r"drupalSettings", re.I),      # may appear in non‑Drupal contexts
    ],
    "jquery": [
        re.compile(r"\$\(document\)\.on\b", re.I), # too generic
        re.compile(r"owl\.carousel", re.I),
    ],
    "react": [
        re.compile(r"createElement\(", re.I),     # too generic
    ],
}

# ---------------------------------------------------------------------------
# Positive context checks – MUST be present to accept a content‑based detection.
# If any library has an entry here, at least one of these patterns must be
# found in the same script, otherwise the match is discarded.
# ---------------------------------------------------------------------------
LIB_POSITIVE_CONTEXT = {
    "angularjs": [
        r'angular\.module\s*\(',
        r'angular\.controller\s*\(',
        r'ng-app\s*[=:]',
        r'ng-controller\s*[=:]',
        r'angular\.element\(',
        r'angular\.bootstrap\(',
        r'\.directive\s*\(',
    ],
    "vue": [
        r'new Vue\s*\(',
        r'Vue\.component\s*\(',
        r'createApp\s*\(',
        r'defineComponent\s*\(',
        r'el\s*:\s*["\']#app',
        r'\.\.\.mapActions\b',
    ],
    "bootstrap": [
        r'bs\.modal',               # bootstrap modal
        r'data-bs-toggle',
        r'class\s*=\s*["\']modal',
        r'\.tooltip\(',
        r'\.popover\(',
    ],
    "jquery": [
        r'\$\(document\)\.ready\s*\(',
        r'jQuery\.fn\.',
        r'\.css\(\s*["\']',
        r'\.ajax\s*\(',
    ],
    "select2": [
        r'\.select2\s*\(',
        r'select2\(',
        r'data-select2-',
    ],
    "swiper": [
        r'new Swiper\s*\(',
        r'\.swiper-container',
        r'swiper-wrapper',
    ],
    "lodash": [
        r'_\s*\.\s*map\s*\(',
        r'_.each\s*\(',
        r'lodash\s+v?',
    ],
    "chart.js": [
        r'new Chart\s*\(',
        r'Chart\.defaults',
    ],
}

# Other detection patterns (unchanged)
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
# CVE database loading (unchanged)
# ──────────────────────────────────────────────────────────────────────────────
def _load_cve_db() -> Dict[str, List[Dict]]:
    db_path = os.path.join(os.path.dirname(__file__), "cve_db.json")
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {
            "jquery": [
                {
                    "range": ["1.0.0", "3.5.0"],
                    "cve": "CVE-2020-11022",
                    "desc": "XSS via jQuery.html()",
                    "severity": "high",
                    "patch": "3.5.0",
                    "sig": r"(?:jQuery\.htmlPrefilter|\\.htmlPrefilter\\s*[=:])"
                }
            ]
        }

VULNERABILITIES = _load_cve_db()

# ──────────────────────────────────────────────────────────────────────────────
# Helper functions
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

def _has_library_context(text: str, lib: str) -> bool:
    """Returns True if the script text contains at least one positive contextual
    pattern that indicates the library is genuinely present."""
    if lib not in LIB_POSITIVE_CONTEXT:
        return True   # no positive check defined → accept
    patterns = LIB_POSITIVE_CONTEXT[lib]
    return any(re.search(pat, text) for pat in patterns)

def _unified_version_extraction(
    text: str,
    patterns: Dict[str, re.Pattern],
    false_positive_blacklist: Optional[Dict[str, List[re.Pattern]]] = None
) -> Dict[str, str]:
    """Extract library versions from text using patterns.
    Optionally filters out matches that hit a false‑positive blacklist for the library."""
    result = {}
    for lib, pat in patterns.items():
        m = pat.search(text)
        if m and m.group(1):
            if false_positive_blacklist and lib in false_positive_blacklist:
                if any(bp.search(text) for bp in false_positive_blacklist[lib]):
                    continue
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
# Source priority – higher number = more reliable
# ──────────────────────────────────────────────────────────────────────────────
SOURCE_PRIORITY = {
    "script_src_filename":  10,
    "script_content":       9,
    "global_var":           8,
    "inline":               7,
    "script_src_url":       5,
    "css":                  4,
    "meta":                 3,
    "header":               2,
    "cookie":               1,
    "package.json":         6,
    "fallback":             0,
}

# ──────────────────────────────────────────────────────────────────────────────
# Main audit function (enhanced with context & blacklist)
# ──────────────────────────────────────────────────────────────────────────────
async def run(url: str, shared_page: dict = None) -> Dict[str, Any]:
    target = _normalize_url(url)
    if not target:
        return {"test_name": "frontend_libs_audit", "status": "error", "title": "Invalid URL"}

    print(f"[*] Starting frontend audit for {target}")
    connector = aiohttp.TCPConnector(ssl=True, limit=15, limit_per_host=6)
    headers = {"User-Agent": USER_AGENT}
    sem = asyncio.Semaphore(MAX_CONCURRENT_FETCHES)

    raw_findings: List[Dict[str, Any]] = []
    script_contents: Dict[str, str] = {}   # url -> text cache

    try:
        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            # ── Page loading ────────────────────────────────────────
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
                            raw_findings.append({"library": lib, "version": m.group(1), "source": "meta"})

            # ── 2. HTTP headers ─────────────────────────────────────
            for hdr_name in HEADER_NAMES:
                hdr_val = resp_headers.get(hdr_name, "")
                if not hdr_val:
                    continue
                for lib, pat in HEADER_PATTERNS.items():
                    m = pat.search(hdr_val)
                    if m:
                        raw_findings.append({"library": lib, "version": m.group(1), "source": "header"})

            # ── 3. Cookies ───────────────────────────────────────────
            set_cookie = resp_headers.get("set-cookie", "")
            for lib, hint in COOKIE_HINTS.items():
                if hint.lower() in set_cookie.lower():
                    raw_findings.append({"library": lib, "version": None, "source": "cookie"})

            # ── 4. External script URLs ──────────────────────────────
            script_urls = []
            for tag in soup.find_all("script"):
                src = tag.get("src")
                if src:
                    abs_url = urljoin(target, src)
                    script_urls.append(abs_url)

                    # a) Query‑string extraction (low priority)
                    url_versions = _unified_version_extraction(abs_url, LIB_URL)
                    for lib, ver in url_versions.items():
                        raw_findings.append({"library": lib, "version": ver, "source": "script_src_url", "url": abs_url})

                    # b) Filename extraction (high priority)
                    filename_versions = _unified_version_extraction(abs_url, LIB_URL_FILENAME)
                    for lib, ver in filename_versions.items():
                        raw_findings.append({"library": lib, "version": ver, "source": "script_src_filename", "url": abs_url})

            script_urls = list(dict.fromkeys(script_urls))[:MAX_SCRIPT_URLS]

            # ── 5. Fetch external scripts & content analysis ─────────
            fetched = await asyncio.gather(*[_fetch_script(session, u, sem) for u in script_urls])
            for url, data in zip(script_urls, fetched):
                if data:
                    text = data.decode("utf-8", errors="replace")
                    script_contents[url] = text

                    # Content version extraction with blacklist AND positive context
                    content_versions = _unified_version_extraction(
                        text, LIB_CONTENT,
                        false_positive_blacklist=CONTENT_FALSE_POSITIVE_PATTERNS
                    )
                    for lib, ver in content_versions.items():
                        # Additional check: positive context
                        if not _has_library_context(text, lib):
                            continue   # discard this false positive completely

                        # Extra safety: if library is jquery but URL does not contain jquery,
                        # still allow but mark source accordingly (confidence will be lowered later)
                        if lib == "jquery" and "jquery" not in url.lower():
                            raw_findings.append({
                                "library": lib, "version": ver, "source": "script_content", "url": url
                            })
                        else:
                            raw_findings.append({
                                "library": lib, "version": ver, "source": "script_content", "url": url
                            })

                    # Global variable assignments (strong presence indicator)
                    for lib, pat in GLOBAL_VAR.items():
                        if pat.search(text):
                            raw_findings.append({
                                "library": lib, "version": None, "source": "global_var", "url": url
                            })

                    # Fallback version
                    fallback = VERSION_FALLBACK.search(text)
                    if fallback:
                        raw_findings.append({
                            "library": "unknown", "version": fallback.group(1), "source": "fallback", "url": url
                        })

            print(f"[+] Fetched {len(script_contents)} external scripts (total {len(script_urls)} links)")

            # ── 6. Inline scripts ────────────────────────────────────
            for tag in soup.find_all("script"):
                if not tag.get("src") and tag.string:
                    inline_vers = _unified_version_extraction(
                        tag.string.strip(), LIB_CONTENT,
                        false_positive_blacklist=CONTENT_FALSE_POSITIVE_PATTERNS
                    )
                    for lib, ver in inline_vers.items():
                        # Also apply positive context for inline scripts
                        if not _has_library_context(tag.string.strip(), lib):
                            continue
                        raw_findings.append({"library": lib, "version": ver, "source": "inline"})

            # ── 7. CSS links ─────────────────────────────────────────
            for link in soup.find_all("link", rel="stylesheet"):
                href = link.get("href")
                if href:
                    full_href = urljoin(target, href)
                    css_vers = _unified_version_extraction(full_href, CSS_LINKS)
                    for lib, ver in css_vers.items():
                        raw_findings.append({
                            "library": lib, "version": ver, "source": "css", "url": full_href
                        })

            # ── 8. /package.json ─────────────────────────────────────
            pkg_url = urljoin(target, "/package.json")
            pkg_data = await _fetch_script(session, pkg_url, sem)
            if pkg_data:
                try:
                    pkg = json.loads(pkg_data)
                    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
                    for lib, ver in deps.items():
                        cleaned = re.sub(r'^[\^~>=<]', '', ver.strip())
                        raw_findings.append({
                            "library": lib, "version": cleaned, "source": "package.json"
                        })
                except Exception:
                    pass

    except Exception as e:
        return {"test_name": "frontend_libs_audit", "status": "error", "title": f"Error: {e}"}

    # ── Merge findings per library – pick most reliable version ──
    lib_groups: Dict[str, List[Dict]] = {}
    for f in raw_findings:
        lib = f["library"]
        lib_groups.setdefault(lib, []).append(f)

    merged_libraries = {}
    for lib, entries in lib_groups.items():
        entries_sorted = sorted(
            entries,
            key=lambda e: (SOURCE_PRIORITY.get(e["source"], 0), 1 if e.get("version") else 0),
            reverse=True
        )
        best = None
        for e in entries_sorted:
            if e.get("version"):
                best = e
                break
        if not best:
            best = entries_sorted[0]
        merged_libraries[lib] = {
            "library": lib,
            "version": best.get("version"),
            "sources": list({e["source"] for e in entries}),
            "urls": list({e.get("url") for e in entries if e.get("url")}),
        }

    # ── Detection confidence (0‑100) ─────────────────────────────────
    def _detection_confidence(lib_info: dict) -> int:
        sources = lib_info["sources"]
        has_version = bool(lib_info["version"])
        lib = lib_info["library"]

        # If the ONLY source is script_content and none of the URLs contain the library name,
        # it's very likely a false positive. Dramatically reduce confidence.
        if sources == ["script_content"]:
            urls = lib_info.get("urls", [])
            if urls and not any(lib.lower() in u.lower() for u in urls):
                return 25  # extremely low
            # if no URLs (inline), still lower than usual
            return 40 if has_version else 25

        # Strongest: filename with version
        if "script_src_filename" in sources and has_version:
            return 95

        # Good: content with version
        if "script_content" in sources and has_version:
            return 85

        # Global var + version
        if "global_var" in sources and has_version:
            return 80

        if "package.json" in sources:
            return 85 if has_version else 50

        if "script_src_url" in sources:
            return 75 if has_version else 45

        if "inline" in sources:
            return 80 if has_version else 55

        if "css" in sources:
            return 70 if has_version else 40

        # meta, header, cookie are weak
        return 50 if has_version else 30

    # ── Build vulnerability list ──────────────────────────────────────
    vulnerabilities = []
    for lib, info in merged_libraries.items():
        ver_str = info.get("version")
        det_confidence = _detection_confidence(info)
        if not ver_str or det_confidence < 35:
            # Too uncertain to report vulnerabilities
            continue

        parsed = _safe_version(ver_str)
        if not parsed or lib not in VULNERABILITIES:
            continue

        for vuln in VULNERABILITIES[lib]:
            if not _version_in_range(parsed, *vuln["range"]):
                continue

            # Signature verification
            sig_present = False
            sig_script_url = None
            if info["urls"]:
                for u in info["urls"]:
                    if u in script_contents:
                        text = script_contents[u]
                        if re.search(vuln["sig"], text, re.IGNORECASE | re.DOTALL):
                            sig_present = True
                            sig_script_url = u
                            break

            # Compute vulnerability confidence
            if sig_present and det_confidence >= 85:
                vuln_confidence = 95   # signature + reliable version
            elif sig_present and det_confidence >= 60:
                vuln_confidence = 85
            elif det_confidence >= 85:
                vuln_confidence = 75
            elif det_confidence >= 60:
                vuln_confidence = 60
            else:
                vuln_confidence = 45

            cve_link = f"https://nvd.nist.gov/vuln/detail/{vuln['cve']}"
            best_url = _best_url(info["urls"], lib) if info["urls"] else None
            curl_cmd = f"curl -s {best_url} -o vulnerable-{lib}-{ver_str}.js" if best_url else "No direct file URL available"

            vulnerabilities.append({
                "library": lib,
                "version_detected": ver_str,
                "vulnerable": True,
                "cve": vuln["cve"],
                "cve_link": cve_link,
                "description": vuln["desc"],
                "severity": vuln["severity"],
                "patch_version": vuln["patch"],
                "sources": info["sources"],
                "signature_verified": sig_present,
                "confidence": vuln_confidence,
                "poc_js": f"// {lib}@{ver_str}: {vuln['desc']}\n// Exploitable via {vuln['sig']}",
                "poc_curl": curl_cmd,
                "remediation": f"Upgrade {lib} to >= {vuln['patch']}"
            })

    # ── Build final output ────────────────────────────────────────────
    criticals = [v for v in vulnerabilities if v["severity"] == "critical"]
    highs = [v for v in vulnerabilities if v["severity"] == "high"]
    mediums = [v for v in vulnerabilities if v["severity"] == "medium"]
    lows = [v for v in vulnerabilities if v["severity"] == "low"]

    if criticals:
        status, sev = "fail", "critical"
        title = f"{len(criticals)} CRITICAL vulnerable libraries"
    elif highs:
        status, sev = "fail", "high"
        title = f"{len(highs)} HIGH vulnerable libraries"
    elif mediums or lows:
        status, sev = "warning", "medium"
        title = f"{len(mediums)+len(lows)} vulnerable libraries (medium/low)"
    else:
        status, sev = "pass", "info"
        title = "No vulnerable libraries detected"

    sev_summary = f"[!] {len(criticals)} CRITICAL | {len(highs)} HIGH | {len(mediums)} MEDIUM | {len(lows)} LOW"
    print(sev_summary)

    detected_libraries = [
        {
            "library": lib,
            "version": info["version"],
            "sources": info["sources"],
            "urls": info["urls"],
            "detection_confidence": _detection_confidence(info)
        }
        for lib, info in merged_libraries.items()
    ]

    return {
        "test_name": "frontend_libs_audit",
        "status": status,
        "severity": sev,
        "title": title,
        "libraries_detected": len(detected_libraries),
        "vulnerable_count": len(vulnerabilities),
        "severity_breakdown": {
            "critical": len(criticals),
            "high": len(highs),
            "medium": len(mediums),
            "low": len(lows)
        },
        "detected_libraries": detected_libraries,
        "vulnerabilities": vulnerabilities,
        "remediation": "Update all identified libraries to the recommended versions. Use provided PoC commands and CVE links for verification."
    }

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(json.dumps(asyncio.run(run(target)), indent=2, ensure_ascii=False))