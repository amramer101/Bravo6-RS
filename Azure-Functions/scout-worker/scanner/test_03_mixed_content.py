"""
test_03_mixed_content.py — Advanced Mixed Content Scanner (Full Exploit-Oriented)

Comprehensive detection with active verification and deep analysis of external resources.
Detects:
- All HTML tags with HTTP/WS resources (script, link, img, iframe, form, object, embed, audio, video, source)
- srcset, CSS @import, CSS url(), JavaScript fetch/XHR/WebSocket (including external JS files)
- base tag with HTTP href
- Service Worker registration over HTTP
- Import maps with HTTP URLs
- CSP headers: upgrade-insecure-requests and block-all-mixed-content to adjust severity
- WebSocket (ws://) in HTML, JS, and external scripts
- Cookie security context (Secure, HttpOnly)
- Actively verifies each resource does NOT redirect to HTTPS
- Provides PoC curl commands for each confirmed mixed content resource
- Correlates findings with CSP directives to reduce false positives
"""

import asyncio
import re
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

TEST_NAME = "mixed_content"
USER_AGENT = "Bravo6-Scanner/1.0"
REQUEST_TIMEOUT_SECONDS = 12
MAX_VERIFY_CONCURRENCY = 5
MAX_EXTERNAL_FILES = 10  # Limit external files to analyse to avoid timeouts

# ── Tag/attribute patterns ──────────────────────────────────────────────
RESOURCE_TAGS = [
    ("img", "src", "image", "passive"),
    ("script", "src", "script", "active"),
    ("link", "href", "stylesheet", "active"),
    ("iframe", "src", "iframe", "active"),
    ("audio", "src", "audio", "passive"),
    ("video", "src", "video", "passive"),
    ("source", "src", "source", "passive"),
    ("object", "data", "object", "active"),
    ("embed", "src", "embed", "active"),
    ("form", "action", "form-action", "high"),
]

LINK_REL_ACTIVE = {"stylesheet", "preload", "prefetch", "preconnect", "manifest"}
LINK_REL_PASSIVE = {"dns-prefetch", "icon", "shortcut icon", "apple-touch-icon"}

# ── Regular expressions for extraction ─────────────────────────────────
WEBSOCKET_URL_RE = re.compile(r'ws://[^\s"\']+', re.IGNORECASE)
JS_FETCH_RE = re.compile(r'''(?:fetch|XMLHttpRequest|WebSocket)\s*\(\s*["']([^"']+)["']''', re.VERBOSE | re.IGNORECASE)
CSS_IMPORT_RE = re.compile(r'@import\s+["\']([^"\']+)["\']', re.IGNORECASE)
CSS_URL_RE = re.compile(r'url\(\s*["\']?(http://[^"\')\s]+)["\']?\s*\)', re.IGNORECASE)
SRCSET_URL_RE = re.compile(r'(https?://[^\s,]+)', re.IGNORECASE)
BASE_TAG_RE = re.compile(r'<base\s+[^>]*href\s*=\s*["\'](http://[^"\']+)["\']', re.IGNORECASE)
SERVICE_WORKER_RE = re.compile(r'navigator\.serviceWorker\.register\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE)
IMPORT_MAP_RE = re.compile(r'<script\s+type\s*=\s*["\']importmap["\']>(.*?)</script>', re.DOTALL | re.IGNORECASE)
IMPORT_MAP_URL_RE = re.compile(r'"url"\s*:\s*["\'](http://[^"\']+)["\']', re.IGNORECASE)


def _normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return raw
    parsed = urlparse(raw)
    if not parsed.scheme:
        raw = f"https://{raw}"
    return raw


def _is_http_url(url: str) -> bool:
    return url.strip().lower().startswith("http://")


def _is_ws_url(url: str) -> bool:
    return url.strip().lower().startswith("ws://")


def _extract_css_http_urls(css_text: str) -> list:
    urls = []
    if not css_text:
        return urls
    for match in CSS_IMPORT_RE.findall(css_text):
        if _is_http_url(match):
            urls.append(match)
    for match in CSS_URL_RE.findall(css_text):
        if _is_http_url(match):
            urls.append(match)
    return urls


def _extract_srcset_http_urls(srcset: str) -> list:
    urls = []
    if not srcset:
        return urls
    for match in SRCSET_URL_RE.findall(srcset):
        if _is_http_url(match):
            urls.append(match)
    return urls


def _extract_js_urls(js_text: str) -> list:
    urls = []
    if not js_text:
        return urls
    for match in JS_FETCH_RE.findall(js_text):
        if _is_http_url(match) or _is_ws_url(match):
            urls.append(match)
    return urls


def _extract_ws_from_text(text: str) -> list:
    return [url for url in WEBSOCKET_URL_RE.findall(text) if _is_ws_url(url)]


async def _fetch_and_parse_external(session, url: str, resource_type: str) -> list:
    """Fetch and extract HTTP resources from external JS/CSS."""
    try:
        async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            if resp.status != 200:
                return []
            text = await resp.text(errors="replace")
            extracted = []
            if resource_type == "script":
                # Extract fetch/XHR/WebSocket
                for u in _extract_js_urls(text):
                    extracted.append(u)
                # Also extract WebSocket plain
                for u in _extract_ws_from_text(text):
                    extracted.append(u)
            elif resource_type == "stylesheet":
                # Extract @import and url()
                for u in _extract_css_http_urls(text):
                    extracted.append(u)
            # Return as relative to original URL
            return [urljoin(url, u.strip()) for u in extracted if u]
    except:
        return []


def _collect_resources(html: str, base_url: str, session, external_limit: int = MAX_EXTERNAL_FILES) -> list:
    """Collect all potential mixed content resources, including from external files."""
    findings = []
    soup = BeautifulSoup(html, "html.parser")

    # ── 1) HTML tags ──────────────────────────────────────────────────
    for tag_name, attr_name, category, activity in RESOURCE_TAGS:
        for tag in soup.find_all(tag_name):
            attr_value = tag.get(attr_name)
            if not attr_value:
                continue
            if tag_name == "link":
                rel = tag.get("rel") or []
                if isinstance(rel, str):
                    rel = [rel]
                rel_lower = {r.lower() for r in rel}
                if not (rel_lower & (LINK_REL_ACTIVE | LINK_REL_PASSIVE)):
                    continue
                if rel_lower & LINK_REL_ACTIVE:
                    activity = "active"
                else:
                    activity = "passive"
                category = "link-" + next(iter(rel_lower), "unknown")
            resolved = urljoin(base_url, attr_value.strip())
            if _is_http_url(resolved):
                findings.append({
                    "type": category,
                    "url": resolved,
                    "is_active": (activity == "active"),
                    "severity": "critical" if activity == "active" else "high" if activity == "high" else "medium"
                })

    # ── 2) srcset ──────────────────────────────────────────────────────
    for tag in soup.find_all("img", srcset=True):
        for url in _extract_srcset_http_urls(tag["srcset"]):
            resolved = urljoin(base_url, url.strip())
            if _is_http_url(resolved):
                findings.append({"type": "srcset-image", "url": resolved, "is_active": False, "severity": "medium"})

    # ── 3) Inline style tags ─────────────────────────────────────────
    for style_tag in soup.find_all("style"):
        css_text = style_tag.string or style_tag.get_text() or ""
        for raw_url in _extract_css_http_urls(css_text):
            resolved = urljoin(base_url, raw_url.strip())
            findings.append({"type": "css-url", "url": resolved, "is_active": True, "severity": "critical"})

    # ── 4) Inline style attributes ────────────────────────────────────
    for tag in soup.find_all(style=True):
        style_attr = tag.get("style") or ""
        for raw_url in _extract_css_http_urls(style_attr):
            resolved = urljoin(base_url, raw_url.strip())
            findings.append({"type": "css-url", "url": resolved, "is_active": True, "severity": "critical"})

    # ── 5) WebSocket in HTML ──────────────────────────────────────────
    for ws_url in _extract_ws_from_text(html):
        resolved = urljoin(base_url, ws_url)
        findings.append({"type": "websocket", "url": resolved, "is_active": True, "severity": "critical"})

    # ── 6) JavaScript inline ──────────────────────────────────────────
    for script_tag in soup.find_all("script", string=True):
        if script_tag.string:
            js_text = script_tag.string
            for u in _extract_js_urls(js_text):
                resolved = urljoin(base_url, u)
                if _is_http_url(resolved) or _is_ws_url(resolved):
                    findings.append({"type": "js-fetch", "url": resolved, "is_active": True, "severity": "critical"})

    # ── 7) External scripts and stylesheets analysis ──────────────────
    external_scripts = []
    external_styles = []
    for script_tag in soup.find_all("script", src=True):
        src = script_tag["src"]
        if _is_http_url(src):
            # This is already detected as a resource, but we also want to parse its content
            external_scripts.append(urljoin(base_url, src))
        elif src.startswith("/") or src.startswith("./"):
            external_scripts.append(urljoin(base_url, src))
    for link_tag in soup.find_all("link", rel="stylesheet", href=True):
        href = link_tag["href"]
        if _is_http_url(href):
            external_styles.append(urljoin(base_url, href))
        elif href.startswith("/") or href.startswith("./"):
            external_styles.append(urljoin(base_url, href))

    # Limit to avoid heavy load
    external_scripts = external_scripts[:external_limit]
    external_styles = external_styles[:external_limit]

    # Parse each external file (asynchronously later)
    # We'll store the URLs to be fetched later
    external_files_to_check = []
    for url in external_scripts:
        external_files_to_check.append((url, "script"))
    for url in external_styles:
        external_files_to_check.append((url, "stylesheet"))

    # ── 8) Base tag ────────────────────────────────────────────────────
    base_match = BASE_TAG_RE.search(html)
    if base_match:
        base_url = base_match.group(1)
        findings.append({"type": "base-tag", "url": base_url, "is_active": True, "severity": "critical"})

    # ── 9) Service Worker registration ──────────────────────────────
    for sw_match in SERVICE_WORKER_RE.findall(html):
        sw_url = sw_match
        if not _is_http_url(sw_url):
            sw_url = urljoin(base_url, sw_url)
        if _is_http_url(sw_url):
            findings.append({"type": "service-worker", "url": sw_url, "is_active": True, "severity": "critical"})

    # ── 10) Import map ──────────────────────────────────────────────────
    import_maps = IMPORT_MAP_RE.findall(html)
    for map_json in import_maps:
        for match in IMPORT_MAP_URL_RE.findall(map_json):
            import_url = match
            if not _is_http_url(import_url):
                import_url = urljoin(base_url, import_url)
            if _is_http_url(import_url):
                findings.append({"type": "import-map", "url": import_url, "is_active": True, "severity": "critical"})

    return findings, external_files_to_check


async def _verify_resource(session: aiohttp.ClientSession, url: str) -> dict:
    try:
        async with session.get(url, ssl=False, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            final_url = str(resp.url)
            if final_url.startswith("https://"):
                return {"url": url, "status": "redirected_to_https", "final_url": final_url}
            if resp.status >= 400:
                return {"url": url, "status": "failed", "status_code": resp.status}
            if resp.status < 400:
                return {"url": url, "status": "confirmed_http", "status_code": resp.status}
            return {"url": url, "status": "unknown"}
    except Exception:
        return {"url": url, "status": "error"}


async def run(url: str) -> dict:
    try:
        target_url = _normalize_url(url)
        if not target_url:
            return {"test_name": TEST_NAME, "status": "error", "title": "Invalid URL", "evidence": []}

        parsed = urlparse(target_url)
        if parsed.scheme != "https":
            return {"test_name": TEST_NAME, "status": "warning", "title": "Skipped (Not HTTPS)", "evidence": []}

        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
        headers = {"User-Agent": USER_AGENT}

        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            # Fetch page
            async with session.get(target_url, ssl=True, allow_redirects=True) as resp:
                if resp.status >= 400:
                    return {"test_name": TEST_NAME, "status": "warning", "title": f"HTTP {resp.status}", "evidence": []}
                final_url = str(resp.url)
                if not final_url.startswith("https://"):
                    return {"test_name": TEST_NAME, "status": "warning", "title": "Redirected to HTTP", "evidence": []}
                html = await resp.text(errors="replace")
                # Capture CSP headers
                csp = resp.headers.get("Content-Security-Policy", "")
                upgrade = "upgrade-insecure-requests" in csp
                block = "block-all-mixed-content" in csp
                # Capture cookies to check Secure flag
                set_cookie = resp.headers.get("Set-Cookie", "")
                cookies_secure = "Secure" in set_cookie if set_cookie else None
                cookies_httponly = "HttpOnly" in set_cookie if set_cookie else None

            # Collect resources and external files to parse
            raw_resources, external_files = _collect_resources(html, final_url, session)

            # ── Fetch external files and extract resources ──────────────
            external_findings = []
            semaphore = asyncio.Semaphore(MAX_VERIFY_CONCURRENCY)

            async def _fetch_external(ext_url, ext_type):
                async with semaphore:
                    extracted = await _fetch_and_parse_external(session, ext_url, ext_type)
                    return [(u, ext_type) for u in extracted if u]

            tasks = [_fetch_external(url, typ) for url, typ in external_files]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, list):
                    for u, typ in res:
                        if _is_http_url(u) or _is_ws_url(u):
                            # Determine if active (usually JS fetch is active)
                            is_active = (typ == "script")
                            sev = "critical" if is_active else "medium"
                            external_findings.append({
                                "type": f"external-{typ}-fetch",
                                "url": u,
                                "is_active": is_active,
                                "severity": sev,
                                "from_external": True
                            })

            # Merge external findings into raw_resources
            all_resources = raw_resources + external_findings

            if not all_resources:
                return {"test_name": TEST_NAME, "status": "pass", "title": "No Mixed Content Found", "evidence": []}

            # ── Active verification ──────────────────────────────────────
            semaphore_verify = asyncio.Semaphore(MAX_VERIFY_CONCURRENCY)

            async def _verify_with_semaphore(res):
                async with semaphore_verify:
                    return await _verify_resource(session, res["url"])

            tasks = [_verify_with_semaphore(r) for r in all_resources]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Combine results
            verified_findings = []
            for idx, result in enumerate(results):
                if isinstance(result, Exception) or not isinstance(result, dict):
                    continue
                raw = all_resources[idx]
                if result.get("status") == "confirmed_http":
                    verified_findings.append({
                        "type": raw["type"],
                        "url": raw["url"],
                        "is_active": raw["is_active"],
                        "severity": raw["severity"],
                        "status": "confirmed",
                        "status_code": result.get("status_code"),
                        "poc": f"curl -v {raw['url']}",
                        "risk": "This resource loads over unencrypted HTTP. Active resources can be intercepted to execute malicious code. Passive resources may leak data."
                    })
                elif result.get("status") == "redirected_to_https":
                    # NOT a vulnerability, ignore
                    continue

            if not verified_findings:
                return {"test_name": TEST_NAME, "status": "pass", "title": "No Active Mixed Content Confirmed", "evidence": []}

            # ── Adjust severity based on CSP and cookie context ──────────
            # If upgrade-insecure-requests is present, downgrade severity
            if upgrade:
                for f in verified_findings:
                    # Still report but lower severity
                    if f["severity"] == "critical":
                        f["severity"] = "high"
                    elif f["severity"] == "high":
                        f["severity"] = "medium"
                    f["note"] = "CSP upgrade-insecure-requests present, browser will auto-upgrade."
            if block:
                # block-all-mixed-content means browsers will block everything, so the risk is mitigated.
                for f in verified_findings:
                    f["severity"] = "info"
                    f["note"] = "CSP block-all-mixed-content present, browser blocks mixed content."
                # If block is present, we can return pass/info
                return {
                    "test_name": TEST_NAME,
                    "status": "pass",
                    "severity": "info",
                    "title": "Mixed content found but blocked by CSP",
                    "description": "CSP block-all-mixed-content prevents loading of HTTP resources.",
                    "evidence": verified_findings,
                    "remediation": "No action needed; CSP handles it."
                }

            # Count active vs passive
            active_count = sum(1 for f in verified_findings if f["is_active"])
            passive_count = len(verified_findings) - active_count

            # Overall severity
            if active_count > 0:
                severity = "critical"
                status = "fail"
                title = f"{active_count} active mixed content resources confirmed"
            else:
                severity = "medium"
                status = "warning"
                title = f"{passive_count} passive mixed content resources confirmed"

            # Additional context: cookies
            cookie_warning = ""
            if cookies_secure is False:
                cookie_warning = " Additionally, session cookies are not Secure, making them vulnerable to interception over HTTP."
            if cookies_httponly is False:
                cookie_warning += " Cookies are not HttpOnly, increasing XSS risk."

            remediation = (
                "Replace all HTTP URLs with HTTPS. "
                "Implement Content-Security-Policy with 'upgrade-insecure-requests' "
                "to automatically upgrade requests. "
                "Consider using 'block-all-mixed-content' for strict enforcement. "
                "Set Secure and HttpOnly flags on session cookies."
            )

            return {
                "test_name": TEST_NAME,
                "status": status,
                "severity": severity,
                "title": title,
                "description": f"Found {len(verified_findings)} confirmed mixed content resources ({active_count} active, {passive_count} passive).{cookie_warning}",
                "active_count": active_count,
                "passive_count": passive_count,
                "evidence": verified_findings,
                "remediation": remediation,
                "csp_context": {"upgrade": upgrade, "block": block},
                "cookie_context": {"secure": cookies_secure, "httponly": cookies_httponly}
            }

    except Exception as e:
        return {"test_name": TEST_NAME, "status": "error", "title": f"Error: {e}", "evidence": []}