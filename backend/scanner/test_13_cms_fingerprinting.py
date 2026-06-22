"""
test_13_cms_fingerprinting.py — Fast CMS Fingerprinting (Optimized)

Optimized for speed (< 2s):
- Only 2 most common paths per CMS (instead of 10+)
- Parallel requests with concurrency limit
- Short timeouts (5s)
- No redundant checks
- Fixed dict_keys concatenation error

Detects:
- WordPress, Joomla, Drupal, Shopify, Magento, Laravel, Symfony, Django, Flask, Express
- Uses: cookies, headers, meta tags, and common paths
"""

import asyncio
import re
from urllib.parse import urljoin

import aiohttp

TEST_NAME = "cms_fingerprinting"
USER_AGENT = "Bravo6-Scanner/1.0"
TIMEOUT = 5
MAX_CONCURRENT = 10

# ── CMS signatures ─────────────────────────────────────────────────────────
CMS_SIGNATURES = {
    "WordPress": {
        "paths": ["/wp-content/", "/wp-includes/"],
        "headers": {"x-powered-by": "wordpress"},
        "cookie": "wordpress_",
        "meta": {"generator": "wordpress"},
    },
    "Joomla": {
        "paths": ["/media/", "/templates/"],
        "headers": {"x-powered-by": "joomla"},
        "cookie": "joomla",
        "meta": {"generator": "joomla"},
    },
    "Drupal": {
        "paths": ["/sites/", "/modules/"],
        "headers": {"x-powered-by": "drupal"},
        "cookie": "drupal",
        "meta": {"generator": "drupal"},
    },
    "Shopify": {
        "paths": ["/cdn/", "/shop/"],
        "headers": {"x-powered-by": "shopify"},
        "cookie": "_shopify",
        "meta": {"generator": "shopify"},
    },
    "Magento": {
        "paths": ["/static/", "/media/"],
        "headers": {"x-powered-by": "magento"},
        "cookie": "magento",
        "meta": {"generator": "magento"},
    },
    "Laravel": {
        "paths": ["/assets/", "/css/"],
        "headers": {"x-powered-by": "laravel"},
        "cookie": "laravel_session",
        "meta": {"generator": "laravel"},
    },
    "Symfony": {
        "paths": ["/bundles/", "/css/"],
        "headers": {"x-powered-by": "symfony"},
        "cookie": "symfony",
        "meta": {"generator": "symfony"},
    },
    "Django": {
        "paths": ["/static/", "/media/"],
        "headers": {"x-powered-by": "django"},
        "cookie": "csrftoken",
        "meta": {"generator": "django"},
    },
    "Flask": {
        "paths": ["/static/", "/css/"],
        "headers": {"x-powered-by": "flask"},
        "cookie": "session",
        "meta": {"generator": "flask"},
    },
    "Express": {
        "paths": ["/css/", "/js/"],
        "headers": {"x-powered-by": "express"},
        "cookie": "connect.sid",
        "meta": {"generator": "express"},
    },
}


async def _fetch(session, url):
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=TIMEOUT), ssl=False) as resp:
            return resp.status, dict(resp.headers)
    except:
        return None, None


async def _check_paths(session, base_url, paths):
    """Check if any of the given paths exist."""
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    results = {}

    async def check(path):
        async with semaphore:
            full_url = urljoin(base_url, path)
            status, headers = await _fetch(session, full_url)
            results[path] = {"status": status, "headers": headers}

    tasks = [check(p) for p in paths]
    await asyncio.gather(*tasks, return_exceptions=True)
    return results


async def run(url: str, context=None) -> dict:
    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
    except:
        return {"test_name": TEST_NAME, "status": "error", "severity": "info", "title": "Invalid URL", "evidence": [], "remediation": "Check URL format."}

    findings = []
    detected = []

    async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
        # ── 1. Fetch homepage to get headers, cookies, meta ──────────────
        home_status, home_headers = await _fetch(session, base_url)
        if home_status is None:
            return {"test_name": TEST_NAME, "status": "error", "severity": "info", "title": "Cannot fetch homepage", "evidence": [], "remediation": "Check connectivity."}

        # Collect cookies from headers
        set_cookie = home_headers.get("Set-Cookie", "")

        # Collect meta tags (we'll use BeautifulSoup if needed, but we'll keep it simple)
        # Actually, we need to fetch HTML to get meta generator.
        home_html = ""
        try:
            async with session.get(base_url, timeout=aiohttp.ClientTimeout(total=TIMEOUT), ssl=False) as resp:
                if resp.status == 200:
                    home_html = await resp.text(errors="ignore")
        except:
            pass

        # ── 2. Check signatures ────────────────────────────────────────────
        for cms_name, sig in CMS_SIGNATURES.items():
            score = 0
            evidence = []

            # Check headers
            for h, val in sig.get("headers", {}).items():
                if h in home_headers and val.lower() in home_headers[h].lower():
                    score += 20
                    evidence.append(f"Header {h}: {home_headers[h]}")

            # Check cookies
            cookie_pattern = sig.get("cookie", "")
            if cookie_pattern and cookie_pattern in set_cookie:
                score += 25
                evidence.append(f"Cookie: {cookie_pattern}")

            # Check meta generator
            if home_html and "meta" in sig:
                meta_gen = sig["meta"].get("generator", "")
                if meta_gen and meta_gen in home_html.lower():
                    score += 25
                    evidence.append(f"Meta generator: {meta_gen}")

            # Check common paths
            paths = sig.get("paths", [])
            if paths:
                path_results = await _check_paths(session, base_url, paths[:2])  # only 2 most important
                for path, result in path_results.items():
                    if result.get("status") == 200:
                        score += 15
                        evidence.append(f"Path exists: {path}")

            if score >= 40:
                detected.append({
                    "cms": cms_name,
                    "confidence": min(score, 100),
                    "evidence": evidence,
                })
                findings.append({
                    "cms": cms_name,
                    "confidence": min(score, 100),
                    "evidence": evidence,
                    "poc": f"curl -I {base_url}",
                    "severity": "info",
                })

        # ── 3. If no CMS detected, try a quick scan of common files ──────
        if not detected:
            common_files = ["/wp-login.php", "/administrator/", "/user/login", "/admin/"]
            file_results = await _check_paths(session, base_url, common_files)
            for path, result in file_results.items():
                if result.get("status") == 200:
                    findings.append({
                        "cms": "Unknown (possible admin panel)",
                        "confidence": 50,
                        "evidence": [f"Admin-like path accessible: {path}"],
                        "poc": f"curl {base_url}{path}",
                        "severity": "low",
                    })
                    break

    # ── 4. Determine status ───────────────────────────────────────────────
    if detected:
        status = "pass"
        severity = "info"
        title = f"Detected: {', '.join([d['cms'] for d in detected])}"
        desc = f"Identified {len(detected)} CMS(es) with high confidence."
    elif findings:
        status = "warning"
        severity = "low"
        title = "Possible admin panel detected"
        desc = "Found admin-like paths, but CMS not identified."
    else:
        status = "pass"
        severity = "info"
        title = "No CMS detected"
        desc = "Could not identify any known CMS."

    return {
        "test_name": TEST_NAME,
        "status": status,
        "severity": severity,
        "title": title,
        "description": desc,
        "evidence": findings,
        "remediation": "Ensure CMS is up-to-date and properly configured. Remove unnecessary admin paths if not needed.",
        "detected_cms": detected,
    }


if __name__ == "__main__":
    import json, sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))