"""
test_03_mixed_content.py — Advanced Mixed Content Scanner (Active Verification)

Upgraded:
- Fetches each detected HTTP resource to check if it actually loads.
- Skips resources that redirect to HTTPS (safe) or return 404 (dead links).
- Adds PoC curl command for confirmed active mixed content.
- Confidence 100% for confirmed resources.
"""

import asyncio
import re
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

TEST_NAME = "mixed_content"
USER_AGENT = "Bravo6-Scanner/1.0"
REQUEST_TIMEOUT_SECONDS = 8
MAX_VERIFY_CONCURRENCY = 15  # Limit parallel checks to avoid overwhelming target

RESOURCE_TAGS = [
    ("img", "src", "image"),
    ("script", "src", "script"),
    ("link", "href", "stylesheet"),
    ("iframe", "src", "iframe"),
    ("audio", "src", "audio"),
    ("video", "src", "video"),
    ("source", "src", "source"),
]

ACTIVE_CATEGORIES = {"script", "iframe", "stylesheet"}
CSS_URL_HTTP_RE = re.compile(r"""url\(\s*['"]?(http://[^'")\s]+)['"]?\s*\)""", re.IGNORECASE)


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


def _extract_css_http_urls(css_text: str) -> list:
    return CSS_URL_HTTP_RE.findall(css_text or "")


def _collect_resources(html: str, base_url: str) -> list:
    """Collect all potential mixed content URLs without filtering."""
    findings = []
    soup = BeautifulSoup(html, "html.parser")

    # 1) Tags
    for tag_name, attr_name, category in RESOURCE_TAGS:
        for tag in soup.find_all(tag_name):
            attr_value = tag.get(attr_name)
            if not attr_value:
                continue
            if tag_name == "link":
                rel = tag.get("rel") or []
                if isinstance(rel, str):
                    rel = [rel]
                relevant_rels = {"stylesheet", "preload", "prefetch", "icon", "shortcut icon", "apple-touch-icon"}
                if not (set(r.lower() for r in rel) & relevant_rels):
                    continue

            resolved = urljoin(base_url, attr_value.strip())
            if _is_http_url(resolved):
                findings.append({"type": category, "url": resolved, "is_active": category in ACTIVE_CATEGORIES})

    # 2) Inline style tags
    for style_tag in soup.find_all("style"):
        css_text = style_tag.string or style_tag.get_text() or ""
        for raw_url in _extract_css_http_urls(css_text):
            resolved = urljoin(base_url, raw_url.strip())
            findings.append({"type": "css-url", "url": resolved, "is_active": True})

    # 3) Inline style attributes
    for tag in soup.find_all(style=True):
        style_attr = tag.get("style") or ""
        for raw_url in _extract_css_http_urls(style_attr):
            resolved = urljoin(base_url, raw_url.strip())
            findings.append({"type": "css-url", "url": resolved, "is_active": True})

    return findings


async def _verify_resource(session: aiohttp.ClientSession, url: str) -> dict:
    """Check if the resource loads over HTTP and does NOT redirect to HTTPS."""
    try:
        async with session.get(url, ssl=False, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            # Check final URL
            final_url = str(resp.url)
            if final_url.startswith("https://"):
                return {"url": url, "status": "redirected_to_https", "final_url": final_url}
            if resp.status >= 400:
                return {"url": url, "status": "failed", "status_code": resp.status}
            # If it loads successfully over HTTP
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

            # Collect resources
            raw_resources = _collect_resources(html, final_url)
            if not raw_resources:
                return {"test_name": TEST_NAME, "status": "pass", "title": "No Mixed Content Found", "evidence": []}

            # Active verification
            semaphore = asyncio.Semaphore(MAX_VERIFY_CONCURRENCY)

            async def _verify_with_semaphore(res):
                async with semaphore:
                    return await _verify_resource(session, res["url"])

            tasks = [_verify_with_semaphore(r) for r in raw_resources]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Combine results
            verified_findings = []
            for idx, result in enumerate(results):
                if isinstance(result, Exception) or not isinstance(result, dict):
                    continue
                raw = raw_resources[idx]
                if result.get("status") == "confirmed_http":
                    verified_findings.append({
                        "type": raw["type"],
                        "url": raw["url"],
                        "is_active": raw["is_active"],
                        "status_code": result.get("status_code"),
                        "severity": "critical" if raw["is_active"] else "medium",
                        "status": "confirmed",
                        "poc": f"curl -v {raw['url']}",
                        "risk": "This resource loads over unencrypted HTTP. Active resources (scripts/stylesheets) can be intercepted to execute malicious code."
                    })
                elif result.get("status") == "redirected_to_https":
                    # NOT a vulnerability, ignore
                    continue

            if not verified_findings:
                return {"test_name": TEST_NAME, "status": "pass", "title": "No Active Mixed Content Confirmed", "evidence": []}

            active_count = sum(1 for f in verified_findings if f["is_active"])
            severity = "critical" if active_count > 0 else "medium"
            status = "fail" if active_count > 0 else "warning"

            return {
                "test_name": TEST_NAME,
                "status": status,
                "severity": severity,
                "title": f"{len(verified_findings)} Confirmed Mixed Content Resources",
                "active_count": active_count,
                "passive_count": len(verified_findings) - active_count,
                "evidence": verified_findings,
                "remediation": "Replace all HTTP URLs with HTTPS. Implement 'upgrade-insecure-requests' CSP directive."
            }

    except Exception as e:
        return {"test_name": TEST_NAME, "status": "error", "title": f"Error: {e}", "evidence": []}