"""
Bravo6 Security Scanner
Test 14: Subresource Integrity (SRI) Check - Advanced

Enhanced with:
- Verifies integrity algorithm (sha256/384/512)
- Checks crossorigin attribute (required for enforcement)
- Detects duplicate resources with inconsistent integrity
- Provides openssl commands to generate correct hashes
- Offers PoC: curl + openssl to manually verify resource hash
- Confidence score 100% (HTML inspection is deterministic)
"""

import asyncio
import re
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

TEST_NAME = "sri_check"
USER_AGENT = "Bravo6-Scanner/1.0"
TIMEOUT_SECONDS = 10

VALID_INTEGRITY_PREFIXES = ("sha256-", "sha384-", "sha512-")
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return url
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = f"https://{url}"
    return url


def _registrable_host(netloc: str) -> str:
    host = netloc.lower().split("@")[-1]
    host = host.split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    return host


def _is_cross_origin(target_url: str, resource_url: str) -> bool:
    target_host = _registrable_host(urlparse(target_url).netloc)
    resource_host = _registrable_host(urlparse(resource_url).netloc)
    if not resource_host:
        return False
    return resource_host != target_host


def _resolve_resource_url(base_url: str, src: str) -> str | None:
    src = (src or "").strip()
    if not src:
        return None
    if src.startswith(("data:", "blob:", "javascript:", "#")):
        return None
    if src.startswith("//"):
        scheme = urlparse(base_url).scheme or "https"
        return f"{scheme}:{src}"
    return urljoin(base_url, src)


def _has_valid_integrity(integrity: str | None) -> bool:
    if not integrity:
        return False
    value = integrity.strip()
    parts = value.split()
    if not parts:
        return False
    for part in parts:
        if not any(part.lower().startswith(p) for p in VALID_INTEGRITY_PREFIXES):
            return False
    return True


def _extract_hash_algo(integrity: str) -> list:
    result = []
    for part in integrity.split():
        for prefix in VALID_INTEGRITY_PREFIXES:
            if part.lower().startswith(prefix):
                algo = prefix.rstrip('-')
                hash_val = part[len(prefix):]
                result.append((algo, hash_val))
                break
    return result


def _generate_openssl_command(algo: str, url: str) -> str:
    return f"curl -sL {url} | openssl dgst -{algo} -binary | openssl base64 -A"


def _generate_sri_tag(algo: str) -> str:
    return f'integrity="{algo}-<hash>" crossorigin="anonymous"'


async def run(url: str) -> dict:
    target_url = _normalize_url(url)
    if not target_url:
        return {
            "test_name": TEST_NAME,
            "status": "error",
            "severity": "info",
            "title": "Invalid target URL",
            "description": "No URL provided.",
            "evidence": [],
            "remediation": "Provide a valid URL.",
            "resources_checked": 0,
            "resources_missing_sri": 0,
        }

    headers = {"User-Agent": USER_AGENT}
    timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)

    try:
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.get(target_url, allow_redirects=True) as response:
                final_url = str(response.url)
                if response.status >= 400:
                    return {
                        "test_name": TEST_NAME,
                        "status": "error",
                        "severity": "info",
                        "title": "Unable to fetch page",
                        "description": f"HTTP {response.status} for {target_url}",
                        "evidence": [],
                        "remediation": "Check if the site is reachable.",
                        "resources_checked": 0,
                        "resources_missing_sri": 0,
                    }
                html = await response.text(errors="ignore")
    except asyncio.TimeoutError:
        return {
            "test_name": TEST_NAME,
            "status": "error",
            "severity": "info",
            "title": "Request timed out",
            "description": f"Timeout after {TIMEOUT_SECONDS}s.",
            "evidence": [],
            "remediation": "Increase timeout or check connectivity.",
            "resources_checked": 0,
            "resources_missing_sri": 0,
        }
    except Exception as e:
        return {
            "test_name": TEST_NAME,
            "status": "error",
            "severity": "info",
            "title": "Connection error",
            "description": str(e),
            "evidence": [],
            "remediation": "Verify target.",
            "resources_checked": 0,
            "resources_missing_sri": 0,
        }

    soup = BeautifulSoup(html, "html.parser")
    candidates = []
    for script in soup.find_all("script", src=True):
        candidates.append(("script", script.get("src"), script))
    for link in soup.find_all("link", href=True):
        rel = link.get("rel") or []
        if isinstance(rel, str):
            rel = [rel]
        if any(r.lower() == "stylesheet" for r in rel):
            candidates.append(("link", link.get("href"), link))

    resources = []
    for tag_name, raw_src, tag in candidates:
        resolved = _resolve_resource_url(final_url, raw_src)
        if not resolved:
            continue
        if _is_cross_origin(final_url, resolved):
            resources.append((tag_name, resolved, tag))

    resources_checked = len(resources)
    if resources_checked == 0:
        return {
            "test_name": TEST_NAME,
            "status": "pass",
            "severity": "info",
            "title": "No cross-origin resources found",
            "description": f"No cross-origin script or link resources found on {final_url}.",
            "evidence": [],
            "remediation": "No action needed.",
            "resources_checked": 0,
            "resources_missing_sri": 0,
        }

    evidence = []
    missing_count = 0
    worst_severity = "info"
    seen_srcs = {}

    for tag_name, resource_url, tag in resources:
        integrity = tag.get("integrity")
        crossorigin = tag.get("crossorigin")
        issues = []

        if not integrity:
            severity = "high" if tag_name == "script" else "medium"
            missing_count += 1
            issues.append({
                "issue": "Missing integrity attribute",
                "severity": severity,
                "remediation": f"Add integrity attribute: {_generate_sri_tag('sha384')}",
                "poc": _generate_openssl_command("sha384", resource_url),
            })
        elif not _has_valid_integrity(integrity):
            severity = "high" if tag_name == "script" else "medium"
            missing_count += 1
            issues.append({
                "issue": f"Invalid integrity format: '{integrity}'. Must use sha256-, sha384-, or sha512-.",
                "severity": severity,
                "remediation": f"Fix integrity attribute: {_generate_sri_tag('sha384')}",
                "poc": _generate_openssl_command("sha384", resource_url),
            })
        else:
            # Valid integrity, check crossorigin
            if not crossorigin or crossorigin.strip().lower() not in ("anonymous", "use-credentials"):
                severity = "low"
                issues.append({
                    "issue": "Missing crossorigin attribute (required for SRI enforcement)",
                    "severity": severity,
                    "remediation": 'Add crossorigin="anonymous" to the tag.',
                    "poc": f"curl -I {resource_url}",
                })

        if not issues:
            continue

        entry = {
            "tag": tag_name,
            "src": resource_url,
            "severity": max(issues, key=lambda x: SEVERITY_RANK.get(x["severity"], 0))["severity"],
            "issues": issues,
            "confidence": 100,
        }
        evidence.append(entry)
        if SEVERITY_RANK[entry["severity"]] > SEVERITY_RANK[worst_severity]:
            worst_severity = entry["severity"]

        if resource_url in seen_srcs:
            seen_srcs[resource_url].append(tag)
        else:
            seen_srcs[resource_url] = [tag]

    # Check for duplicate resources with inconsistent integrity
    for src, tags in seen_srcs.items():
        if len(tags) > 1:
            integrities = set(tag.get("integrity") for tag in tags if tag.get("integrity"))
            if len(integrities) > 1:
                evidence.append({
                    "tag": "duplicate",
                    "src": src,
                    "severity": "low",
                    "issues": [{
                        "issue": f"Duplicate resource '{src}' has inconsistent integrity attributes.",
                        "severity": "low",
                        "remediation": "Ensure consistent integrity hash for the same resource.",
                        "poc": f"curl -sL {src} | sha384sum",
                    }],
                    "confidence": 100,
                })
                if SEVERITY_RANK["low"] > SEVERITY_RANK[worst_severity]:
                    worst_severity = "low"

    status = "fail" if missing_count > 0 else "warning" if evidence else "pass"

    description = (
        f"Found {len(evidence)} issue(s) across {resources_checked} cross-origin resources. "
        f"Missing SRI hashes: {missing_count}. "
        "Without SRI, a compromised CDN can inject malicious code undetected."
    )

    remediation = (
        "Add integrity and crossorigin attributes to all cross-origin script and link tags. "
        "Use `openssl dgst -sha384 -binary <file> | openssl base64 -A` to generate hashes. "
        "See https://www.srihash.org/ for guidance."
    )

    return {
        "test_name": TEST_NAME,
        "status": status,
        "severity": worst_severity,
        "title": f"SRI Check: {len(evidence)} issue(s) found",
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
        "resources_checked": resources_checked,
        "resources_missing_sri": missing_count,
    }


if __name__ == "__main__":
    import json, sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))