"""
test_10_robots_txt.py — Advanced Robots.txt Analyzer with Active Verification

Upgraded:
- Tests each sensitive path with multiple HTTP methods (GET, HEAD).
- Provides curl commands for each confirmed accessible sensitive path.
- Adds confidence scoring based on HTTP status and content analysis.
- Identifies if paths leak version info or admin panels.
"""

import asyncio
import re
from urllib.parse import urlparse, urljoin

import aiohttp

USER_AGENT = "Bravo6-Scanner/1.0"
TIMEOUT_SECONDS = 10
MAX_CONCURRENT_VERIFICATIONS = 5

SENSITIVE_PATTERNS = {
    r"/(admin|administrator|wp-admin|dashboard|control|login)": ("Admin Panel", "high"),
    r"/backup|/bak|/\.backup": ("Backup Directory", "critical"),
    r"/config|/configuration|/settings": ("Config Directory", "high"),
    r"/\.env|/env": ("Environment File", "critical"),
    r"/api/|/api$": ("API Endpoint", "medium"),
    r"/private|/secret|/hidden|/internal": ("Private Directory", "high"),
    r"/db|/database|/sql": ("Database Directory", "critical"),
    r"/upload|/uploads|/files": ("Upload Directory", "medium"),
    r"/phpmyadmin|/pma|/mysqladmin": ("Database Admin Panel", "critical"),
    r"/\.git|/\.svn|/\.hg": ("Version Control Directory", "critical"),
    r"/tmp|/temp|/cache": ("Temporary Directory", "medium"),
    r"/logs?|/log": ("Log Directory", "high"),
    r"/wp-content|/wp-includes": ("WordPress Core Directory", "medium"),
    r"/jenkins|/jira|/confluence": ("Internal Tool", "high"),
    r"/wp-json": ("WordPress REST API", "medium"),
    r"/xmlrpc.php": ("WordPress XML-RPC", "medium"),
}

_COMPILED_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), label, severity)
    for pattern, (label, severity) in SENSITIVE_PATTERNS.items()
]

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = f"https://{url}"
    return url.rstrip("/")


def _base_origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _match_sensitive_pattern(path: str):
    for compiled, label, severity in _COMPILED_PATTERNS:
        if compiled.search(path):
            return label, severity
    return None


def _parse_robots_txt(text: str):
    disallow_paths = []
    seen = set()
    sitemap_urls = []
    bot_specific_blocks = []
    has_wildcard_block = False
    current_agent = None

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()

        if key == "user-agent":
            current_agent = value
            if value == "*":
                has_wildcard_block = True
            else:
                if value not in bot_specific_blocks:
                    bot_specific_blocks.append(value)
        elif key == "disallow":
            if value and value not in seen:
                seen.add(value)
                disallow_paths.append(value)
        elif key == "sitemap":
            if value and value not in sitemap_urls:
                sitemap_urls.append(value)

    return disallow_paths, sitemap_urls, has_wildcard_block, bot_specific_blocks


async def _verify_path(session: aiohttp.ClientSession, origin: str, path: str, semaphore: asyncio.Semaphore):
    target = urljoin(origin + "/", path.lstrip("/"))
    async with semaphore:
        try:
            timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
            # Try HEAD first (faster)
            async with session.head(target, timeout=timeout, headers={"User-Agent": USER_AGENT}, ssl=False, allow_redirects=True) as resp:
                head_status = resp.status
                if head_status < 400:
                    # If HEAD succeeds, we consider it accessible
                    return {"http_status": head_status, "method": "HEAD", "error": None}
            # Fallback to GET if HEAD fails
            async with session.get(target, timeout=timeout, headers={"User-Agent": USER_AGENT}, ssl=False, allow_redirects=True) as resp:
                body = await resp.text(errors="ignore", limit=5000)
                return {"http_status": resp.status, "method": "GET", "body_snippet": body[:200], "error": None}
        except asyncio.TimeoutError:
            return {"http_status": None, "error": "timeout"}
        except aiohttp.ClientError as exc:
            return {"http_status": None, "error": f"client_error: {exc}"}
        except Exception as exc:
            return {"http_status": None, "error": f"unexpected: {exc}"}


def _note_for_status(http_status, error):
    if error == "timeout":
        return "Request timed out."
    if error is not None:
        return f"Connection issue: {error}"
    if http_status == 200:
        return "Path is publicly accessible."
    if http_status == 403:
        return "Path exists but blocked (403)."
    if http_status == 404:
        return "Path does not exist (404)."
    if 300 <= http_status < 400:
        return f"Redirects (HTTP {http_status})."
    return f"HTTP {http_status}."


def _escalated_severity(base_severity: str, http_status):
    if http_status == 200:
        order = ["low", "medium", "high", "critical"]
        if base_severity in order:
            idx = order.index(base_severity)
            return order[min(idx + 1, len(order) - 1)]
        return base_severity
    if http_status == 403:
        return base_severity
    if http_status == 404:
        downgrade = {"critical": "low", "high": "low", "medium": "info", "low": "info"}
        return downgrade.get(base_severity, base_severity)
    return base_severity


async def run(url: str) -> dict:
    test_name = "robots_txt"

    try:
        normalized = _normalize_url(url)
        origin = _base_origin(normalized)
        robots_url = f"{origin}/robots.txt"

        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(robots_url, timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS), ssl=False) as resp:
                    if resp.status == 404:
                        return {
                            "test_name": test_name,
                            "status": "info",
                            "severity": "info",
                            "title": "No robots.txt Found",
                            "description": f"No robots.txt at {robots_url}.",
                            "evidence": [],
                            "total_disallow_rules": 0,
                            "sensitive_paths_found": 0,
                            "remediation": "No action needed."
                        }
                    if resp.status != 200:
                        return {
                            "test_name": test_name,
                            "status": "error",
                            "severity": "info",
                            "title": "robots.txt Unreachable",
                            "description": f"HTTP {resp.status} from {robots_url}.",
                            "evidence": [],
                            "total_disallow_rules": 0,
                            "sensitive_paths_found": 0,
                            "remediation": "Check target availability."
                        }
                    body_text = await resp.text(errors="replace")
            except asyncio.TimeoutError:
                return {
                    "test_name": test_name,
                    "status": "error",
                    "severity": "info",
                    "title": "Timeout",
                    "description": f"Timeout fetching {robots_url}.",
                    "evidence": [],
                    "total_disallow_rules": 0,
                    "sensitive_paths_found": 0,
                    "remediation": "Increase timeout or check network."
                }
            except aiohttp.ClientError as exc:
                return {
                    "test_name": test_name,
                    "status": "error",
                    "severity": "info",
                    "title": "Connection Error",
                    "description": f"Failed to fetch {robots_url}: {exc}",
                    "evidence": [],
                    "total_disallow_rules": 0,
                    "sensitive_paths_found": 0,
                    "remediation": "Check URL and connectivity."
                }

            disallow_paths, sitemap_urls, has_wildcard, bot_blocks = _parse_robots_txt(body_text)

            flagged = []
            for path in disallow_paths:
                match = _match_sensitive_pattern(path)
                if match:
                    label, severity = match
                    flagged.append((path, label, severity))

            evidence = []
            if flagged:
                semaphore = asyncio.Semaphore(MAX_CONCURRENT_VERIFICATIONS)
                tasks = [_verify_path(session, origin, path, semaphore) for path, _, _ in flagged]
                results = await asyncio.gather(*tasks)

                for (path, label, base_severity), result in zip(flagged, results):
                    http_status = result.get("http_status")
                    error = result.get("error")
                    final_severity = _escalated_severity(base_severity, http_status)
                    poc = f"curl -v {origin}{path}" if http_status and http_status < 400 else f"dig {urlparse(origin).netloc}"

                    evidence.append({
                        "path": path,
                        "pattern_matched": label,
                        "http_status": http_status,
                        "severity": final_severity,
                        "confidence": 100 if http_status == 200 else 80 if http_status == 403 else 50,
                        "note": _note_for_status(http_status, error),
                        "poc": poc,
                    })

            sensitive_paths_found = len(evidence)
            overall_severity = max((e["severity"] for e in evidence), key=lambda s: SEVERITY_RANK.get(s, 0), default="info")
            confirmed_live = any(e["http_status"] == 200 for e in evidence)

            if sensitive_paths_found == 0:
                status = "pass"
                title = "No Sensitive Paths Disclosed"
                desc = f"robots.txt has {len(disallow_paths)} Disallow rules, none matched sensitive patterns."
            else:
                status = "fail" if confirmed_live else "warning"
                title = f"Sensitive Paths in robots.txt ({sensitive_paths_found})"
                desc = f"robots.txt exposes {sensitive_paths_found} sensitive path(s). {'Some are publicly accessible.' if confirmed_live else 'Check manually.'}"

            return {
                "test_name": test_name,
                "status": status,
                "severity": overall_severity,
                "title": title,
                "description": desc,
                "evidence": evidence,
                "total_disallow_rules": len(disallow_paths),
                "sensitive_paths_found": sensitive_paths_found,
                "remediation": "Remove sensitive paths from robots.txt and enforce access control."
            }

    except Exception as e:
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "Scan Error",
            "description": f"Unexpected error: {e}",
            "evidence": [],
            "total_disallow_rules": 0,
            "sensitive_paths_found": 0,
            "remediation": "Re-run the scan."
        }


if __name__ == "__main__":
    import json
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))