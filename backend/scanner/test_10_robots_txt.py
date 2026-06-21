"""
Bravo6 Security Scanner — test_robots.py

Fetches and analyzes robots.txt for a target domain to identify
sensitive paths that are intentionally hidden from crawlers, then
verifies real-world accessibility of each flagged path.

Usage:
    result = await run("example.com")
"""

import asyncio
import re
from urllib.parse import urlparse, urljoin

import aiohttp

USER_AGENT = "Bravo6-Scanner/1.0"
TIMEOUT_SECONDS = 10
MAX_CONCURRENT_VERIFICATIONS = 5  # be polite, avoid hammering the target

SENSITIVE_PATTERNS = {
    r"/(admin|administrator|wp-admin|dashboard|control)": ("Admin Panel", "high"),
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
}

# Compile once at module load
_COMPILED_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), label, severity)
    for pattern, (label, severity) in SENSITIVE_PATTERNS.items()
]

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _normalize_url(url: str) -> str:
    """Ensure the URL has a scheme; default to https://."""
    url = url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = f"https://{url}"
    return url.rstrip("/")


def _base_origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _match_sensitive_pattern(path: str):
    """Return (label, severity) for the first pattern that matches, else None."""
    for compiled, label, severity in _COMPILED_PATTERNS:
        if compiled.search(path):
            return label, severity
    return None


def _parse_robots_txt(text: str):
    """
    Parse robots.txt content.

    Returns:
        disallow_paths: list[str] (raw paths from Disallow directives, deduped, order-preserved)
        sitemap_urls: list[str]
        has_wildcard_block: bool
        bot_specific_blocks: list[str] (User-agent values that aren't '*')
    """
    disallow_paths = []
    seen = set()
    sitemap_urls = []
    bot_specific_blocks = []
    has_wildcard_block = False
    current_agent = None

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()  # strip comments
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
    """
    Make a real request to a flagged path and classify its accessibility.
    Returns a dict with http_status (int or None), reachable (bool), error (str or None).
    """
    target = urljoin(origin + "/", path.lstrip("/"))
    async with semaphore:
        try:
            timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
            async with session.get(
                target,
                timeout=timeout,
                headers={"User-Agent": USER_AGENT},
                allow_redirects=True,
                ssl=False,
            ) as resp:
                return {"http_status": resp.status, "error": None}
        except asyncio.TimeoutError:
            return {"http_status": None, "error": "timeout"}
        except aiohttp.ClientError as exc:
            return {"http_status": None, "error": f"client_error: {exc}"}
        except Exception as exc:  # noqa: BLE001 - never crash the scanner
            return {"http_status": None, "error": f"unexpected_error: {exc}"}


def _note_for_status(http_status, error):
    if error == "timeout":
        return "Request timed out while verifying accessibility."
    if error is not None:
        return f"Could not verify path due to a connection issue ({error})."
    if http_status == 200:
        return "Path is publicly accessible."
    if http_status == 403:
        return "Path exists but is blocked (403) — still flagged as it confirms the resource is present."
    if http_status == 404:
        return "Path is referenced in robots.txt but does not appear to exist (404)."
    if http_status is not None and 300 <= http_status < 400:
        return f"Path redirects (HTTP {http_status}) — destination not followed for evidence purposes."
    if http_status is not None:
        return f"Path returned HTTP {http_status}."
    return "Accessibility could not be determined."


def _escalated_severity(base_severity: str, http_status):
    """Escalate severity if the path is confirmed live (200)."""
    if http_status == 200:
        order = ["low", "medium", "high", "critical"]
        if base_severity in order:
            idx = order.index(base_severity)
            return order[min(idx + 1, len(order) - 1)]
        return base_severity
    if http_status == 403:
        return base_severity  # confirmed to exist, but access-controlled
    if http_status == 404:
        # downgrade — path doesn't actually exist
        downgrade = {"critical": "low", "high": "low", "medium": "info", "low": "info"}
        return downgrade.get(base_severity, base_severity)
    return base_severity


async def run(url: str) -> dict:
    """
    Fetch and analyze robots.txt for sensitive disclosed paths.

    Returns a result dict per the Bravo6 standard schema, with additional
    fields: evidence (list of finding dicts), total_disallow_rules,
    sensitive_paths_found.
    """
    test_name = "robots_txt"

    try:
        normalized = _normalize_url(url)
        origin = _base_origin(normalized)
        robots_url = f"{origin}/robots.txt"

        timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
        headers = {"User-Agent": USER_AGENT}

        async with aiohttp.ClientSession(headers=headers) as session:
            # Step 1: Fetch robots.txt
            try:
                async with session.get(robots_url, timeout=timeout, ssl=False) as resp:
                    status_code = resp.status
                    if status_code == 404:
                        return {
                            "test_name": test_name,
                            "status": "info",
                            "severity": "info",
                            "title": "No robots.txt Found",
                            "description": (
                                f"No robots.txt file was found at {robots_url}. "
                                "This is not a security issue; the site simply does not "
                                "publish crawler directives."
                            ),
                            "evidence": [],
                            "total_disallow_rules": 0,
                            "sensitive_paths_found": 0,
                            "remediation": (
                                "No action required. Optionally publish a robots.txt that "
                                "avoids listing sensitive paths."
                            ),
                        }

                    if status_code != 200:
                        return {
                            "test_name": test_name,
                            "status": "error",
                            "severity": "info",
                            "title": "robots.txt Unreachable",
                            "description": (
                                f"Requesting {robots_url} returned unexpected HTTP "
                                f"status {status_code}, so it could not be analyzed."
                            ),
                            "evidence": [],
                            "total_disallow_rules": 0,
                            "sensitive_paths_found": 0,
                            "remediation": "Re-run the scan; if the issue persists, verify the target is reachable.",
                        }

                    try:
                        body_text = await resp.text(errors="replace")
                    except Exception as exc:  # noqa: BLE001
                        return {
                            "test_name": test_name,
                            "status": "error",
                            "severity": "info",
                            "title": "robots.txt Read Failure",
                            "description": f"robots.txt was fetched but its body could not be read: {exc}",
                            "evidence": [],
                            "total_disallow_rules": 0,
                            "sensitive_paths_found": 0,
                            "remediation": "Re-run the scan against this target.",
                        }

            except asyncio.TimeoutError:
                return {
                    "test_name": test_name,
                    "status": "error",
                    "severity": "info",
                    "title": "robots.txt Request Timed Out",
                    "description": f"The request to {robots_url} did not complete within {TIMEOUT_SECONDS} seconds.",
                    "evidence": [],
                    "total_disallow_rules": 0,
                    "sensitive_paths_found": 0,
                    "remediation": "Re-run the scan; the target may be slow or rate-limiting requests.",
                }
            except aiohttp.ClientError as exc:
                return {
                    "test_name": test_name,
                    "status": "error",
                    "severity": "info",
                    "title": "robots.txt Connection Error",
                    "description": f"Could not connect to {robots_url}: {exc}",
                    "evidence": [],
                    "total_disallow_rules": 0,
                    "sensitive_paths_found": 0,
                    "remediation": "Verify the target domain is correct and reachable, then re-run the scan.",
                }

            # Step 3: Parse Disallow directives (and sitemap / agent info)
            disallow_paths, sitemap_urls, has_wildcard_block, bot_specific_blocks = _parse_robots_txt(body_text)
            total_disallow_rules = len(disallow_paths)

            # Step 4: Flag sensitive paths
            flagged = []  # list of (path, label, base_severity)
            for path in disallow_paths:
                match = _match_sensitive_pattern(path)
                if match:
                    label, severity = match
                    flagged.append((path, label, severity))

            # Step 6: Verify accessibility of each flagged path (bounded concurrency)
            evidence = []
            if flagged:
                semaphore = asyncio.Semaphore(MAX_CONCURRENT_VERIFICATIONS)
                verify_tasks = [
                    _verify_path(session, origin, path, semaphore) for path, _, _ in flagged
                ]
                verify_results = await asyncio.gather(*verify_tasks, return_exceptions=False)

                for (path, label, base_severity), result in zip(flagged, verify_results):
                    http_status = result["http_status"]
                    error = result["error"]
                    final_severity = _escalated_severity(base_severity, http_status)
                    evidence.append({
                        "path": path,
                        "pattern_matched": label,
                        "http_status": http_status,
                        "severity": final_severity,
                        "note": _note_for_status(http_status, error),
                    })

            sensitive_paths_found = len(evidence)

            # Step 5: informational notes about sitemap / wildcard / bot-specific blocks
            info_notes = []
            if sitemap_urls:
                info_notes.append(
                    f"robots.txt discloses {len(sitemap_urls)} sitemap location(s): {', '.join(sitemap_urls)}."
                )
            if has_wildcard_block:
                info_notes.append("A wildcard (User-agent: *) block is present, applying rules to all crawlers.")
            if bot_specific_blocks:
                info_notes.append(
                    f"Bot-specific rules exist for: {', '.join(bot_specific_blocks)}."
                )

            # Determine overall status/severity/title/description
            if sensitive_paths_found == 0:
                status = "pass"
                overall_severity = "info"
                title = "No Sensitive Paths Disclosed in robots.txt"
                description = (
                    f"robots.txt was found at {robots_url} with {total_disallow_rules} "
                    "Disallow rule(s), none of which matched known sensitive path patterns."
                )
            else:
                # overall severity = highest severity among findings
                overall_severity = max(
                    (e["severity"] for e in evidence),
                    key=lambda s: SEVERITY_RANK.get(s, 0),
                )
                confirmed_live = any(e["http_status"] == 200 for e in evidence)
                status = "fail" if confirmed_live else "warning"
                title = (
                    "Sensitive Paths Disclosed and Publicly Accessible via robots.txt"
                    if confirmed_live
                    else "Sensitive Paths Disclosed in robots.txt"
                )
                description = (
                    f"robots.txt at {robots_url} lists {total_disallow_rules} Disallow rule(s), "
                    f"of which {sensitive_paths_found} match patterns associated with sensitive "
                    "infrastructure (admin panels, backups, config, version control, etc.). "
                    "Disallow entries are publicly readable and effectively act as a roadmap "
                    "of paths an attacker should check first."
                )

            if info_notes:
                description = description + " " + " ".join(info_notes)

            return {
                "test_name": test_name,
                "status": status,
                "severity": overall_severity,
                "title": title,
                "description": description,
                "evidence": evidence,
                "total_disallow_rules": total_disallow_rules,
                "sensitive_paths_found": sensitive_paths_found,
                "remediation": (
                    "Remove sensitive paths from robots.txt. Robots.txt is public — listing "
                    "paths here reveals your site structure to attackers. Instead, enforce "
                    "access control (authentication/authorization) directly on these "
                    "resources, and rely on robots.txt only for genuinely non-sensitive "
                    "crawl-budget management."
                ),
            }

    except Exception as exc:  # noqa: BLE001 - absolute top-level safety net
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "Scan Failed",
            "description": f"An unexpected error occurred while scanning {url}: {exc}",
            "evidence": [],
            "total_disallow_rules": 0,
            "sensitive_paths_found": 0,
            "remediation": "Re-run the scan. If the issue persists, check connectivity to the target.",
        }


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))