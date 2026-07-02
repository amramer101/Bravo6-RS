#!/usr/bin/env python3
"""
Bravo6 Ultimate Frontend Library Auditor (v6.0 – Cache‑Aware & Modern JS Ready)
================================================================================
- Fully leverages the engine’s `js_cache` and `fetch_js` for zero‑redundant fetching.
- Extremely flexible version extraction from filenames (hashes, @‑sign, -alpha/beta/rc).
- Content signatures for minified/bundled code (e.g. jQuery.fn.jquery).
- Auto‑detects Next.js, Nuxt.js, plus modern libs (Uppy, Splide, Alpine, Svelte, Tailwind).
- Composer.json support for PHP/Laravel projects.
- Confidence 85+ for immutable signatures, 80 for others; MIN_CONFIDENCE=70 kept.
- Positive context expanded for Vue/React/JSX, preventing false positives.
- Output structure identical to main scanner expectations.
"""

import asyncio
import json
import logging
import os
import random
import re
import sys
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin

import aiohttp
from bs4 import BeautifulSoup
from packaging.version import InvalidVersion, Version

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
USER_AGENT = "Bravo6-LibAudit/6.0"
TIMEOUT = aiohttp.ClientTimeout(total=20)
MAX_FILE_BYTES = 1_048_576          # 1 MB per script
MAX_SCRIPT_URLS = 40
MAX_CONCURRENT_FETCHES = 8
MIN_CONFIDENCE = 70                # drop detections below this

# ------------------------------------------------------------------------------
# Version pattern (captures pre‑releases like 3.0.0-alpha1)
# ------------------------------------------------------------------------------
_VERSION = r"(\d+\.\d+\.\d+(?:[-.][0-9A-Za-z.]+)?)"

# ------------------------------------------------------------------------------
# Flexible URL/filename/path patterns
# ------------------------------------------------------------------------------
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
    "uppy":             re.compile(r"uppy[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
    "splide":           re.compile(r"splide[.\-]?(?:min\.)?js\?.*v?" + _VERSION, re.I),
}

# Filename patterns – now allow hashes, @, and pre‑release suffixes
LIB_URL_FILENAME = {
    "jquery":           re.compile(r"jquery[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)(?:\.min)?(?:\.[a-f0-9]+)?\.js", re.I),
    "jquery-ui":        re.compile(r"jquery[.\-]?ui[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)(?:\.min)?(?:\.[a-f0-9]+)?\.js", re.I),
    "bootstrap":        re.compile(r"bootstrap[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)(?:\.min)?(?:\.[a-f0-9]+)?\.js", re.I),
    "angularjs":        re.compile(r"angular[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)(?:\.min)?(?:\.[a-f0-9]+)?\.js", re.I),
    "lodash":           re.compile(r"lodash[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)(?:\.min)?(?:\.[a-f0-9]+)?\.js", re.I),
    "moment":           re.compile(r"moment[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)(?:\.min)?(?:\.[a-f0-9]+)?\.js", re.I),
    "axios":            re.compile(r"axios[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)(?:\.min)?(?:\.[a-f0-9]+)?\.js", re.I),
    "vue":              re.compile(r"vue[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)(?:\.min)?(?:\.[a-f0-9]+)?\.js", re.I),
    "react":            re.compile(r"react[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)(?:\.min)?(?:\.[a-f0-9]+)?\.js", re.I),
    "react-dom":        re.compile(r"react-dom[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)(?:\.min)?(?:\.[a-f0-9]+)?\.js", re.I),
    "swiper":           re.compile(r"swiper[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)(?:\.min)?(?:\.[a-f0-9]+)?\.js", re.I),
    "select2":          re.compile(r"select2[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)(?:\.min)?(?:\.[a-f0-9]+)?\.js", re.I),
    "chart.js":         re.compile(r"chart[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)(?:\.min)?(?:\.[a-f0-9]+)?\.js", re.I),
    "uppy":             re.compile(r"uppy[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)(?:\.min)?(?:\.[a-f0-9]+)?\.js", re.I),
    "splide":           re.compile(r"splide[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)(?:\.min)?(?:\.[a-f0-9]+)?\.js", re.I),
}

# Path‑based extraction for libraries using @ or slashes
LIB_PATH_VERSIONS = {
    "select2":          re.compile(r'(?:^|/)select2[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)[\-/]', re.I),
    "jquery":           re.compile(r'(?:^|/)jquery[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)[\-/]', re.I),
    "bootstrap":        re.compile(r'(?:^|/)bootstrap[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)[\-/]', re.I),
    "angularjs":        re.compile(r'(?:^|/)angular[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)[\-/]', re.I),
    "lodash":           re.compile(r'(?:^|/)lodash[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)[\-/]', re.I),
    "moment":           re.compile(r'(?:^|/)moment[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)[\-/]', re.I),
    "swiper":           re.compile(r'(?:^|/)swiper[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)[\-/]', re.I),
    "chart.js":         re.compile(r'(?:^|/)chart[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)[\-/]', re.I),
    "react":            re.compile(r'(?:^|/)react[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)[\-/]', re.I),
    "react-dom":        re.compile(r'(?:^|/)react-dom[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)[\-/]', re.I),
    "vue":              re.compile(r'(?:^|/)vue[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)[\-/]', re.I),
    "uppy":             re.compile(r'(?:^|/)uppy[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)[\-/]', re.I),
    "splide":           re.compile(r'(?:^|/)splide[.\-@](\d+\.\d+\.\d+(?:[-.][0-9A-Za-z]+)*)[\-/]', re.I),
}

# ------------------------------------------------------------------------------
# Content signatures – split into immutable (property) and generic (string)
# ------------------------------------------------------------------------------
LIB_CONTENT_SIGNATURE = {
    "jquery":       re.compile(r"jQuery\.fn\.jquery\s*=\s*[\"']" + _VERSION + r"[\"']", re.I),
    "react":        re.compile(r"React\.version\s*=\s*[\"']" + _VERSION + r"[\"']", re.I),
    "vue":          re.compile(r"Vue\.version\s*=\s*[\"']" + _VERSION + r"[\"']", re.I),
    "bootstrap":    re.compile(r"Bootstrap\.VERSION\s*=\s*[\"']" + _VERSION + r"[\"']", re.I),
    "moment":       re.compile(r"moment\.version\s*=\s*[\"']" + _VERSION + r"[\"']", re.I),
    "lodash":       re.compile(r"(?:lodash\.version|_.VERSION)\s*=\s*[\"']" + _VERSION + r"[\"']", re.I),
    "angularjs":    re.compile(r"angular\.version\.full\s*=\s*[\"']" + _VERSION + r"[\"']", re.I),
    "axios":        re.compile(r"axios\.VERSION\s*=\s*[\"']" + _VERSION + r"[\"']", re.I),
    "uppy":         re.compile(r"Uppy\.VERSION\s*=\s*[\"']" + _VERSION + r"[\"']", re.I),
    "splide":       re.compile(r"Splide\.version\s*=\s*[\"']" + _VERSION + r"[\"']", re.I),
}

LIB_CONTENT_GENERAL = {
    "jquery":           re.compile(r"jQuery\s+v?" + _VERSION, re.I),
    "jquery-ui":        re.compile(r"jQuery UI\s+v?" + _VERSION, re.I),
    "bootstrap":        re.compile(r"Bootstrap\s+v?" + _VERSION, re.I),
    "angularjs":        re.compile(r"angular[.\-]v?" + _VERSION, re.I),
    "lodash":           re.compile(r"lodash\s+v?" + _VERSION, re.I),
    "moment":           re.compile(r"Moment\.js\s+v?" + _VERSION, re.I),
    "axios":            re.compile(r"axios\s+v?" + _VERSION, re.I),
    "vue":              re.compile(r"Vue\.js\s+v?" + _VERSION, re.I),
    "react":            re.compile(r"React\s+v?" + _VERSION, re.I),
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

# ------------------------------------------------------------------------------
# Blacklist patterns for content false positives
# ------------------------------------------------------------------------------
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
        re.compile(r"\banimate\b", re.I),
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
        re.compile(r"\.modal\(", re.I),
    ],
    "drupal": [
        re.compile(r"rest", re.I),
        re.compile(r"jquery\.fancybox", re.I),
        re.compile(r"drupalSettings", re.I),
    ],
    "jquery": [
        re.compile(r"\$\(document\)\.on\b", re.I),
        re.compile(r"owl\.carousel", re.I),
    ],
    "react": [
        re.compile(r"createElement\(", re.I),
    ],
}

# ------------------------------------------------------------------------------
# Positive context (must be present for content‑based detection)
# ------------------------------------------------------------------------------
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
        r'Vue\.version\s*=',
        r'Vue\.createApp\s*\(',
        r'createVNode\s*\(',
        r'_jsx\s*\(',
        r'h\s*\(',
        r'resolveComponent\s*\(',
    ],
    "bootstrap": [
        r'bs\.modal',
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
        r'_.VERSION\s*=',
    ],
    "chart.js": [
        r'new Chart\s*\(',
        r'Chart\.defaults',
    ],
    "react": [
        r'React\.createElement\(',
        r'React\.version\s*=',
        r'__REACT_DEVTOOLS_GLOBAL_HOOK__',
        r'jsx\s*\(',
        r'jsxs\s*\(',
    ],
}

# ------------------------------------------------------------------------------
# Meta / headers / cookies (server‑side tech)
# ------------------------------------------------------------------------------
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

# ------------------------------------------------------------------------------
# Global variables (window.*)
# ------------------------------------------------------------------------------
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
    "uppy":     re.compile(r"window\.Uppy\s*=", re.I),
    "splide":   re.compile(r"window\.Splide\s*=", re.I),
}

# ------------------------------------------------------------------------------
# CSS hints
# ------------------------------------------------------------------------------
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

# ------------------------------------------------------------------------------
# CVE database loader
# ------------------------------------------------------------------------------
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

# ------------------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------------------
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
    aliases = {
        "angularjs": ["angularjs", "angular"],
        "chart.js": ["chart.js", "chartjs"],
    }
    keys = aliases.get(lib, [lib])
    for key in keys:
        if key in LIB_POSITIVE_CONTEXT:
            if any(re.search(pat, text) for pat in LIB_POSITIVE_CONTEXT[key]):
                return True
    # If no context rules exist for this lib, we accept it
    return not any(k in LIB_POSITIVE_CONTEXT for k in keys)

def _unified_version_extraction_with_type(
    text: str,
    patterns_signature: Dict[str, re.Pattern],
    patterns_general: Dict[str, re.Pattern],
    false_positive_blacklist: Optional[Dict[str, List[re.Pattern]]] = None
) -> Dict[str, tuple]:
    """
    Returns dict: lib -> (version, is_signature)
    Signature patterns have priority.
    """
    result = {}
    # first signature patterns
    for lib, pat in patterns_signature.items():
        m = pat.search(text)
        if m and m.group(1):
            if false_positive_blacklist and lib in false_positive_blacklist:
                if any(bp.search(text) for bp in false_positive_blacklist[lib]):
                    continue
            result[lib] = (m.group(1), True)
    # general patterns, skip already found
    for lib, pat in patterns_general.items():
        if lib in result:
            continue
        m = pat.search(text)
        if m and m.group(1):
            if false_positive_blacklist and lib in false_positive_blacklist:
                if any(bp.search(text) for bp in false_positive_blacklist[lib]):
                    continue
            result[lib] = (m.group(1), False)
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

async def _get_content(
    url: str,
    fetch_js: Optional[Callable] = None,
    session: Optional[aiohttp.ClientSession] = None,
    sem: Optional[asyncio.Semaphore] = None
) -> Optional[str]:
    """Unified content fetcher: uses fetch_js if available, else session."""
    if fetch_js:
        try:
            content = await fetch_js(url)
            if isinstance(content, bytes):
                return content.decode("utf-8", errors="replace")
            if isinstance(content, str):
                return content
        except Exception:
            pass
    # fallback to direct HTTP via session
    if session and sem:
        data = await _fetch_script(session, url, sem)
        if data:
            return data.decode("utf-8", errors="replace")
    return None

# Source priorities for merging
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
    "composer.json":        6,
    "framework":            9,
    "fallback":             0,
}

def _self_test():
    ver = _safe_version("3.6.0")
    assert ver is not None
    assert not _version_in_range(ver, "1.0.0", "3.5.0")
    assert not _version_in_range(ver, "1.0.0", "3.6.0")
    # test immutable signature
    assert re.search(r"jQuery\.fn\.jquery\s*=\s*[\"']" + _VERSION + r"[\"']",
                     "jQuery.fn.jquery=\"3.5.1\"")
    # test flexible filename
    assert re.search(LIB_URL_FILENAME["jquery"], "jquery-3.5.1.min.dc5e7f18c8.js")
    assert re.search(LIB_URL_FILENAME["bootstrap"], "bootstrap@5.3.0-alpha1/dist/js/bootstrap.min.js")
    print("[+] Self-test passed")

# ------------------------------------------------------------------------------
# Main audit function
# ------------------------------------------------------------------------------
async def run(
    url: str,
    shared_page: dict = None,
    js_cache: dict = None,
    fetch_js: callable = None
) -> Dict[str, Any]:
    target = _normalize_url(url)
    if not target:
        return {"test_name": "frontend_libs_audit", "status": "error", "title": "Invalid URL"}

    logging.basicConfig(level=logging.WARNING)
    logger = logging.getLogger(__name__)
    logger.info("Starting frontend audit for %s", target)

    connector = aiohttp.TCPConnector(ssl=True, limit=15, limit_per_host=6)
    headers = {"User-Agent": USER_AGENT}
    sem = asyncio.Semaphore(MAX_CONCURRENT_FETCHES)

    raw_findings: List[Dict[str, Any]] = []
    script_contents: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # 1. Pre-populate script_contents from js_cache and shared_page
    # ------------------------------------------------------------------
    if js_cache and isinstance(js_cache, dict):
        for u, content in js_cache.items():
            if u in script_contents:
                continue
            if isinstance(content, bytes):
                try:
                    script_contents[u] = content.decode("utf-8", errors="replace")
                except Exception:
                    pass
            elif isinstance(content, str):
                script_contents[u] = content

    try:
        async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
            # ------------------------------------------------------------------
            # 2. Obtain HTML, headers, cookies (shared_page or live fetch)
            # ------------------------------------------------------------------
            if shared_page and not shared_page.get("error") and shared_page.get("status") == 200:
                html = shared_page.get("html", "")
                raw_headers = shared_page.get("headers", {})
                resp_headers = {k.lower(): v for k, v in raw_headers.items()}
                set_cookie = ""
                if "cookies" in shared_page:
                    if isinstance(shared_page["cookies"], str):
                        set_cookie = shared_page["cookies"]
                    elif isinstance(shared_page["cookies"], dict):
                        set_cookie = "; ".join(f"{k}={v}" for k, v in shared_page["cookies"].items())
                else:
                    set_cookie = resp_headers.get("set-cookie", "")
                soup = shared_page.get("soup")
                if soup is None:
                    soup = BeautifulSoup(html, "html.parser")

                # Merge shared_page script_contents if present
                shared_sc = shared_page.get("script_contents", {})
                if isinstance(shared_sc, dict):
                    for u, content in shared_sc.items():
                        if u not in script_contents:
                            if isinstance(content, bytes):
                                try:
                                    script_contents[u] = content.decode("utf-8", errors="replace")
                                except Exception:
                                    pass
                            elif isinstance(content, str):
                                script_contents[u] = content
            else:
                async with session.get(target, timeout=TIMEOUT, ssl=True, allow_redirects=True) as resp:
                    if resp.status >= 400:
                        return {"test_name": "frontend_libs_audit", "status": "warning", "title": f"HTTP {resp.status}"}
                    html = await resp.text(errors="replace")
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    set_cookie = resp_headers.get("set-cookie", "")
                    soup = BeautifulSoup(html, "html.parser")

            if not html or len(html) < 500:
                logger.warning("Very short HTML (%s chars) – possible captcha/block", len(html) if html else 0)

            # ------------------------------------------------------------------
            # 3. Meta generator
            # ------------------------------------------------------------------
            for meta in soup.find_all("meta", attrs={"name": "generator"}):
                content = meta.get("content", "")
                if content:
                    for lib, pat in META_GENERATOR.items():
                        m = pat.search(content)
                        if m:
                            raw_findings.append({"library": lib, "version": m.group(1), "source": "meta"})

            # ------------------------------------------------------------------
            # 4. HTTP headers
            # ------------------------------------------------------------------
            for hdr_name in HEADER_NAMES:
                hdr_val = resp_headers.get(hdr_name, "")
                if hdr_val:
                    for lib, pat in HEADER_PATTERNS.items():
                        m = pat.search(hdr_val)
                        if m:
                            raw_findings.append({"library": lib, "version": m.group(1), "source": "header"})

            # ------------------------------------------------------------------
            # 5. Cookies
            # ------------------------------------------------------------------
            for lib, hint in COOKIE_HINTS.items():
                if hint.lower() in set_cookie.lower():
                    raw_findings.append({"library": lib, "version": None, "source": "cookie"})

            # ------------------------------------------------------------------
            # 6. Next.js / Nuxt.js framework detection
            # ------------------------------------------------------------------
            # HTML clues
            if re.search(r'/_next/static/', html) or re.search(r'__NEXT_DATA__', html):
                raw_findings.append({"library": "next", "version": None, "source": "framework"})
            if re.search(r'/_nuxt/', html) or re.search(r'__NUXT__', html):
                raw_findings.append({"library": "nuxt", "version": None, "source": "framework"})
            # Header clues
            powered = resp_headers.get("x-powered-by", "")
            if "next.js" in powered.lower():
                raw_findings.append({"library": "next", "version": None, "source": "framework"})

            # ------------------------------------------------------------------
            # 7. External scripts – URL and filename analysis
            # ------------------------------------------------------------------
            script_urls = []
            for tag in soup.find_all("script"):
                src = tag.get("src")
                if src:
                    abs_url = urljoin(target, src)
                    script_urls.append(abs_url)

                    # URL query‑string versions
                    url_versions = _unified_version_extraction_with_type(abs_url, {}, LIB_URL)
                    for lib, (ver, _) in url_versions.items():
                        raw_findings.append({"library": lib, "version": ver, "source": "script_src_url", "url": abs_url})

                    # Filename versions
                    filename_versions = _unified_version_extraction_with_type(abs_url, {}, LIB_URL_FILENAME)
                    for lib, (ver, _) in filename_versions.items():
                        raw_findings.append({"library": lib, "version": ver, "source": "script_src_filename", "url": abs_url})

                    # Path‑based versions (handles @, slashes)
                    for lib, pat in LIB_PATH_VERSIONS.items():
                        m = pat.search(abs_url)
                        if m and m.group(1):
                            raw_findings.append({"library": lib, "version": m.group(1), "source": "script_src_filename", "url": abs_url})

            script_urls = list(dict.fromkeys(script_urls))[:MAX_SCRIPT_URLS]

            # ------------------------------------------------------------------
            # 8. Fetch missing scripts (via fetch_js or direct)
            # ------------------------------------------------------------------
            for url in script_urls:
                if url not in script_contents:
                    text = await _get_content(url, fetch_js, session, sem)
                    if text:
                        script_contents[url] = text

            # Analyse every script content
            for url, text in script_contents.items():
                if not text:
                    continue

                # Content‑based version extraction with signature flag
                content_versions = _unified_version_extraction_with_type(
                    text,
                    LIB_CONTENT_SIGNATURE,
                    LIB_CONTENT_GENERAL,
                    false_positive_blacklist=CONTENT_FALSE_POSITIVE_PATTERNS
                )
                for lib, (ver, is_sig) in content_versions.items():
                    if _has_library_context(text, lib):
                        raw_findings.append({
                            "library": lib,
                            "version": ver,
                            "source": "script_content",
                            "url": url,
                            "is_signature": is_sig
                        })

                # Global variable detection
                for lib, pat in GLOBAL_VAR.items():
                    if pat.search(text):
                        raw_findings.append({"library": lib, "version": None, "source": "global_var", "url": url})

                # Generic fallback version
                fallback = VERSION_FALLBACK.search(text)
                if fallback:
                    raw_findings.append({"library": "unknown", "version": fallback.group(1), "source": "fallback", "url": url})

            # ------------------------------------------------------------------
            # 9. Inline scripts
            # ------------------------------------------------------------------
            for tag in soup.find_all("script"):
                if not tag.get("src") and tag.string:
                    inline_text = tag.string.strip()
                    inline_versions = _unified_version_extraction_with_type(
                        inline_text,
                        LIB_CONTENT_SIGNATURE,
                        LIB_CONTENT_GENERAL,
                        false_positive_blacklist=CONTENT_FALSE_POSITIVE_PATTERNS
                    )
                    for lib, (ver, is_sig) in inline_versions.items():
                        if _has_library_context(inline_text, lib):
                            raw_findings.append({
                                "library": lib,
                                "version": ver,
                                "source": "inline",
                                "is_signature": is_sig
                            })

            # ------------------------------------------------------------------
            # 10. CSS links
            # ------------------------------------------------------------------
            for link in soup.find_all("link", rel="stylesheet"):
                href = link.get("href")
                if href:
                    full_href = urljoin(target, href)
                    css_versions = _unified_version_extraction_with_type(full_href, {}, CSS_LINKS)
                    for lib, (ver, _) in css_versions.items():
                        raw_findings.append({"library": lib, "version": ver, "source": "css", "url": full_href})

            # ------------------------------------------------------------------
            # 11. /package.json
            # ------------------------------------------------------------------
            pkg_url = urljoin(target, "/package.json")
            pkg_text = await _get_content(pkg_url, fetch_js, session, sem)
            if pkg_text:
                try:
                    pkg = json.loads(pkg_text)
                    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
                    for lib, ver in deps.items():
                        cleaned = re.sub(r'^[\^~>=<]', '', ver.strip())
                        raw_findings.append({"library": lib, "version": cleaned, "source": "package.json"})
                except Exception:
                    pass

            # ------------------------------------------------------------------
            # 12. /composer.json (PHP/Laravel)
            # ------------------------------------------------------------------
            composer_url = urljoin(target, "/composer.json")
            composer_text = await _get_content(composer_url, fetch_js, session, sem)
            if composer_text:
                try:
                    composer = json.loads(composer_text)
                    req = composer.get("require", {})
                    req_dev = composer.get("require-dev", {})
                    for lib, ver in {**req, **req_dev}.items():
                        cleaned = re.sub(r'^[\^~>=<]', '', ver.strip())
                        raw_findings.append({"library": lib, "version": cleaned, "source": "composer.json"})
                except Exception:
                    pass

    except Exception as e:
        return {"test_name": "frontend_libs_audit", "status": "error", "title": f"Error: {e}"}

    # ------------------------------------------------------------------
    # Merge findings per library
    # ------------------------------------------------------------------
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

        # Determine if any content detection came from an immutable signature
        content_sig = any(
            e.get("is_signature") for e in entries
            if e["source"] in ("script_content", "inline")
        )

        merged_libraries[lib] = {
            "library": lib,
            "version": best.get("version"),
            "sources": list({e["source"] for e in entries}),
            "urls": list({e.get("url") for e in entries if e.get("url")}),
            "content_urls": list({e["url"] for e in entries if e.get("url") and e["source"] == "script_content"}),
            "content_has_signature": content_sig,
        }

    # ------------------------------------------------------------------
    # Detection confidence calculation
    # ------------------------------------------------------------------
    def _detection_confidence(lib_info: dict) -> int:
        sources = lib_info["sources"]
        has_version = bool(lib_info["version"])
        lib = lib_info["library"]

        # Highest priority: filename
        if "script_src_filename" in sources and has_version:
            return 95
        # Framework detection (Next/Nuxt)
        if "framework" in sources:
            return 85
        # Package managers
        if "package.json" in sources or "composer.json" in sources:
            return 85 if has_version else 50
        # Content with immutable signature
        if ("script_content" in sources or "inline" in sources) and has_version:
            if lib_info.get("content_has_signature"):
                return 85
            return 80
        # Other content without version
        if "script_content" in sources or "inline" in sources:
            return 40
        if "global_var" in sources and has_version:
            return 80
        if "global_var" in sources:
            return 50
        if "script_src_url" in sources:
            return 75 if has_version else 45
        if "css" in sources:
            return 70 if has_version else 40
        if "meta" in sources:
            return 60 if has_version else 30
        if "header" in sources:
            return 50 if has_version else 20
        if "cookie" in sources:
            return 20
        return 50 if has_version else 30

    # ------------------------------------------------------------------
    # Vulnerability matching with tiered confidence
    # ------------------------------------------------------------------
    vulnerabilities = []
    for lib, info in merged_libraries.items():
        ver_str = info.get("version")
        det_confidence = _detection_confidence(info)
        if not ver_str or det_confidence < MIN_CONFIDENCE:
            continue

        parsed = _safe_version(ver_str)
        if not parsed or lib not in VULNERABILITIES:
            continue

        for vuln in VULNERABILITIES[lib]:
            if "range" in vuln:
                if not _version_in_range(parsed, *vuln["range"]):
                    continue
            elif "min" in vuln and "max" in vuln:
                if not _version_in_range(parsed, vuln["min"], vuln["max"]):
                    continue
            else:
                continue

            # Signature verification restricted to content scripts
            sig_present = False
            content_urls = info.get("content_urls", [])
            if not content_urls:
                content_urls = [u for u in info.get("urls", []) if lib.lower() in u.lower()]

            for u in content_urls:
                if u in script_contents:
                    if re.search(vuln.get("sig", ""), script_contents[u], re.IGNORECASE | re.DOTALL):
                        sig_present = True
                        break

            # Tiered confidence based on detection method + signature presence
            if sig_present and det_confidence >= 85:
                vuln_confidence = 95
            elif sig_present and det_confidence >= 60:
                vuln_confidence = 85
            elif det_confidence >= 95:
                vuln_confidence = 65
            elif det_confidence >= 85:
                vuln_confidence = 55
            elif det_confidence >= 60:
                vuln_confidence = 45
            else:
                vuln_confidence = 30

            if vuln_confidence < MIN_CONFIDENCE:
                continue

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

    # ------------------------------------------------------------------
    # Build final output
    # ------------------------------------------------------------------
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

    detected_libraries = [
        {
            "library": lib,
            "version": info["version"],
            "sources": info["sources"],
            "urls": info["urls"],
            "detection_confidence": conf
        }
        for lib, info in merged_libraries.items()
        if (conf := _detection_confidence(info)) >= MIN_CONFIDENCE
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
        "severity_summary": sev_summary,
        "detected_libraries": detected_libraries,
        "vulnerabilities": vulnerabilities,
        "findings": vulnerabilities,
        "remediation": "Update all identified libraries to the recommended versions. Use provided PoC commands and CVE links for verification."
    }

if __name__ == "__main__":
    _self_test()
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(json.dumps(asyncio.run(run(target)), indent=2, ensure_ascii=False))