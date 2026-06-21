"""
Bravo6 Security Scanner
Test 14: Subresource Integrity (SRI) Check

Fetches the target page and inspects every cross-origin <script src="...">
and <link rel="stylesheet" href="..."> tag for a valid `integrity` attribute
(SRI hash) and an accompanying `crossorigin` attribute, which is required
for the browser to actually enforce SRI.

Findings:
  - Cross-origin <script> with no integrity attribute      -> HIGH
  - Cross-origin <link rel="stylesheet"> with no integrity  -> MEDIUM
  - integrity present but crossorigin attribute missing     -> LOW

Dependencies: aiohttp, beautifulsoup4
"""

from __future__ import annotations

import asyncio
from typing import Optional
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

TEST_NAME = "sri_check"
USER_AGENT = "Bravo6-Scanner/1.0"
TIMEOUT_SECONDS = 10

VALID_INTEGRITY_PREFIXES = ("sha256-", "sha384-", "sha512-")

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

AI_NOTE = (
    "AI coding assistants commonly generate CDN links without SRI hashes. "
    "Use https://www.srihash.org/ to generate integrity attributes."
)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    """Ensure the URL has a scheme; default to https://."""
    url = (url or "").strip()
    if not url:
        return url
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"https://{url}"
    return url


def _registrable_host(netloc: str) -> str:
    """Lowercase a netloc, strip userinfo/port, and a leading 'www.'."""
    host = netloc.lower().split("@")[-1]  # drop userinfo if present
    host = host.split(":")[0]             # drop port
    if host.startswith("www."):
        host = host[4:]
    return host


def _is_cross_origin(target_url: str, resource_url: str) -> bool:
    target_host = _registrable_host(urlparse(target_url).netloc)
    resource_host = _registrable_host(urlparse(resource_url).netloc)
    if not resource_host:
        return False  # relative / same-page resource
    return resource_host != target_host


def _resolve_resource_url(base_url: str, src: str) -> Optional[str]:
    """Resolve a possibly-relative src/href into an absolute URL."""
    src = (src or "").strip()
    if not src:
        return None
    if src.startswith(("data:", "blob:", "javascript:", "#")):
        return None
    if src.startswith("//"):
        scheme = urlparse(base_url).scheme or "https"
        return f"{scheme}:{src}"
    return urljoin(base_url, src)


def _has_valid_integrity(integrity: Optional[str]) -> bool:
    if not integrity:
        return False
    value = integrity.strip().lower()
    return any(value.startswith(p) for p in VALID_INTEGRITY_PREFIXES)


def _build_result(
    status: str,
    severity: str,
    title: str,
    description: str,
    evidence,
    remediation: str,
    resources_checked: int = 0,
    resources_missing_sri: int = 0,
) -> dict:
    return {
        "test_name": TEST_NAME,
        "status": status,
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
        "resources_checked": resources_checked,
        "resources_missing_sri": resources_missing_sri,
    }


# --------------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------------

async def run(url: str) -> dict:
    """
    Check cross-origin <script> and <link rel="stylesheet"> tags on the
    target page for Subresource Integrity (SRI) attributes.

    Args:
        url: A domain or URL to scan (e.g. "example.com").

    Returns:
        A result dict (see module docstring / Bravo6 schema). Never raises.
    """
    target_url = _normalize_url(url)

    if not target_url:
        return _build_result(
            status="error",
            severity="info",
            title="SRI Check - Invalid Input",
            description="No URL was provided to scan.",
            evidence=[],
            remediation="Provide a valid domain or URL and re-run the scan.",
        )

    headers = {"User-Agent": USER_AGENT}
    timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)

    html = None
    final_url = target_url

    try:
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.get(target_url, allow_redirects=True) as response:
                final_url = str(response.url)
                if response.status >= 400:
                    return _build_result(
                        status="error",
                        severity="info",
                        title="SRI Check - Unable to Retrieve Page",
                        description=(
                            f"The target returned HTTP {response.status} when "
                            f"fetching {target_url}, so the page HTML could not "
                            f"be inspected for SRI attributes."
                        ),
                        evidence=[],
                        remediation=(
                            "Ensure the page is reachable and returns a successful "
                            "response, then re-run the scan."
                        ),
                    )
                try:
                    html = await response.text(errors="ignore")
                except Exception as read_exc:  # noqa: BLE001
                    return _build_result(
                        status="error",
                        severity="info",
                        title="SRI Check - Unable to Read Response Body",
                        description=(
                            f"Failed to read response content from {target_url}: {read_exc}"
                        ),
                        evidence=[],
                        remediation=(
                            "Re-run the scan; if the issue persists, verify the page "
                            "serves standard HTML content."
                        ),
                    )
    except asyncio.TimeoutError:
        return _build_result(
            status="error",
            severity="info",
            title="SRI Check - Request Timed Out",
            description=(
                f"The request to {target_url} did not complete within "
                f"{TIMEOUT_SECONDS} seconds."
            ),
            evidence=[],
            remediation="Verify the target is reachable and re-run the scan.",
        )
    except aiohttp.ClientConnectorCertificateError as exc:
        return _build_result(
            status="error",
            severity="info",
            title="SRI Check - TLS Certificate Error",
            description=(
                f"A TLS certificate error occurred while connecting to "
                f"{target_url}: {exc}"
            ),
            evidence=[],
            remediation="Fix the target's TLS certificate configuration, then re-run the scan.",
        )
    except aiohttp.ClientError as exc:
        return _build_result(
            status="error",
            severity="info",
            title="SRI Check - Connection Error",
            description=f"Could not connect to {target_url}: {exc}",
            evidence=[],
            remediation="Verify the URL is correct and the host is reachable, then re-run the scan.",
        )
    except Exception as exc:  # noqa: BLE001 - never let the scanner crash
        return _build_result(
            status="error",
            severity="info",
            title="SRI Check - Unexpected Error",
            description=f"An unexpected error occurred while scanning {target_url}: {exc}",
            evidence=[],
            remediation="Re-run the scan; contact support if the issue persists.",
        )

    # --- Parse HTML and inspect tags ---
    try:
        soup = BeautifulSoup(html or "", "html.parser")
    except Exception as exc:  # noqa: BLE001
        return _build_result(
            status="error",
            severity="info",
            title="SRI Check - HTML Parse Error",
            description=f"Failed to parse HTML from {final_url}: {exc}",
            evidence=[],
            remediation=(
                "Re-run the scan; if the issue persists, verify the page returns "
                "well-formed HTML."
            ),
        )

    try:
        candidates = []
        for script in soup.find_all("script", src=True):
            candidates.append(("script", script.get("src"), script))
        for link in soup.find_all("link", href=True):
            rel = link.get("rel") or []
            if isinstance(rel, str):
                rel = [rel]
            if any(str(r).lower() == "stylesheet" for r in rel):
                candidates.append(("link", link.get("href"), link))

        cross_origin_resources = []
        for tag_name, raw_src, tag in candidates:
            resolved = _resolve_resource_url(final_url, raw_src)
            if not resolved:
                continue
            if _is_cross_origin(final_url, resolved):
                cross_origin_resources.append((tag_name, resolved, tag))
    except Exception as exc:  # noqa: BLE001
        return _build_result(
            status="error",
            severity="info",
            title="SRI Check - Error Analyzing Page",
            description=f"An error occurred while analyzing tags on {final_url}: {exc}",
            evidence=[],
            remediation="Re-run the scan; contact support if the issue persists.",
        )

    resources_checked = len(cross_origin_resources)

    if resources_checked == 0:
        return _build_result(
            status="pass",
            severity="info",
            title="SRI Check - No Cross-Origin Resources Found",
            description=(
                f'No cross-origin <script> or <link rel="stylesheet"> resources '
                f"were found on {final_url}. Subresource Integrity is not applicable."
            ),
            evidence=[],
            remediation="No action needed.",
            resources_checked=0,
            resources_missing_sri=0,
        )

    evidence = []
    missing_count = 0
    worst_severity = "info"

    for tag_name, resource_url, tag in cross_origin_resources:
        integrity = tag.get("integrity")
        crossorigin = tag.get("crossorigin")

        if not integrity:
            severity = "high" if tag_name == "script" else "medium"
            missing_count += 1
            evidence.append({
                "tag": tag_name,
                "src": resource_url,
                "issue": "Missing SRI integrity attribute",
                "severity": severity,
            })
        elif not _has_valid_integrity(integrity):
            severity = "high" if tag_name == "script" else "medium"
            missing_count += 1
            evidence.append({
                "tag": tag_name,
                "src": resource_url,
                "issue": f"Invalid or unrecognized integrity attribute value: '{integrity}'",
                "severity": severity,
            })
        elif not crossorigin or crossorigin.strip().lower() not in ("anonymous", "use-credentials"):
            severity = "low"
            evidence.append({
                "tag": tag_name,
                "src": resource_url,
                "issue": (
                    "Has integrity attribute but missing crossorigin attribute "
                    "(SRI will not be enforced by the browser)"
                ),
                "severity": severity,
            })
        else:
            continue  # fully compliant, no finding

        if SEVERITY_RANK[severity] > SEVERITY_RANK[worst_severity]:
            worst_severity = severity

    if not evidence:
        return _build_result(
            status="pass",
            severity="info",
            title="SRI Check - All Cross-Origin Resources Protected",
            description=(
                f"All {resources_checked} cross-origin script/stylesheet "
                f"resource(s) on {final_url} have valid SRI integrity and "
                f"crossorigin attributes."
            ),
            evidence=[],
            remediation="No action needed.",
            resources_checked=resources_checked,
            resources_missing_sri=0,
        )

    status = "fail" if missing_count > 0 else "warning"

    description = (
        f"Found {len(evidence)} issue(s) across {resources_checked} cross-origin "
        f"script/stylesheet resource(s) on {final_url}. "
    )
    if missing_count > 0:
        description += (
            f"{missing_count} resource(s) are missing SRI integrity hashes entirely, "
            f"meaning a compromised or hijacked CDN could silently serve modified "
            f"content to your users without detection. "
        )
    crossorigin_only = len(evidence) - missing_count
    if crossorigin_only > 0:
        description += (
            f"{crossorigin_only} resource(s) have an integrity hash but are missing "
            f"the required 'crossorigin' attribute, so the browser will not enforce "
            f"SRI for them. "
        )
    description += AI_NOTE

    title = (
        "SRI Check - Missing Integrity Attributes Found"
        if missing_count > 0
        else "SRI Check - Missing 'crossorigin' Attribute"
    )

    remediation = (
        "Add integrity and crossorigin attributes to all cross-origin script and "
        "stylesheet tags. Generate hashes at https://www.srihash.org/"
    )

    return _build_result(
        status=status,
        severity=worst_severity,
        title=title,
        description=description,
        evidence=evidence,
        remediation=remediation,
        resources_checked=resources_checked,
        resources_missing_sri=missing_count,
    )


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))