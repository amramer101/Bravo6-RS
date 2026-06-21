"""
test_mixed_content.py

Bravo6 Security Scanner Module
--------------------------------
Checks whether an HTTPS page loads any sub-resources over insecure HTTP
("mixed content"). Active mixed content (scripts, iframes, stylesheets)
can be used by a network attacker to inject code into an otherwise secure
page. Passive mixed content (images, audio, video) leaks information and
degrades the connection's integrity guarantees but cannot execute code.

Usage:
    result = await run("https://example.com")
"""

import asyncio
import re
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

TEST_NAME = "mixed_content"
USER_AGENT = "Bravo6-Scanner/1.0"
REQUEST_TIMEOUT_SECONDS = 10

# Tags/attributes that load a sub-resource we care about.
# (tag_name, attribute_name, category_label)
RESOURCE_TAGS = [
    ("img", "src", "image"),
    ("script", "src", "script"),
    ("link", "href", "stylesheet"),
    ("iframe", "src", "iframe"),
    ("audio", "src", "audio"),
    ("video", "src", "video"),
    ("source", "src", "source"),
]

# Categories considered "active" — capable of executing/injecting content.
ACTIVE_CATEGORIES = {"script", "iframe", "stylesheet"}

# Matches url(http://...) or url('http://...') or url("http://...") inside CSS text.
CSS_URL_HTTP_RE = re.compile(
    r"""url\(\s*['"]?(http://[^'")\s]+)['"]?\s*\)""", re.IGNORECASE
)


def _normalize_url(raw: str) -> str:
    """Ensure the input URL has a scheme; default to https://."""
    raw = raw.strip()
    if not raw:
        return raw
    parsed = urlparse(raw)
    if not parsed.scheme:
        raw = f"https://{raw}"
    return raw


def _base_result(**overrides) -> dict:
    """Build a result dict with sane defaults, then apply overrides."""
    result = {
        "test_name": TEST_NAME,
        "status": "error",
        "severity": "info",
        "title": "",
        "description": "",
        "evidence": "",
        "remediation": "",
    }
    result.update(overrides)
    return result


def _is_http_url(url: str) -> bool:
    return url.strip().lower().startswith("http://")


def _extract_css_http_urls(css_text: str) -> list:
    return CSS_URL_HTTP_RE.findall(css_text or "")


def _collect_mixed_content(html: str, base_url: str) -> list:
    """
    Parse HTML and return a list of findings:
    [{"type": str, "url": str, "severity": "critical"|"medium"}, ...]
    """
    findings = []
    soup = BeautifulSoup(html, "html.parser")

    # 1) Standard resource tags with src/href attributes.
    for tag_name, attr_name, category in RESOURCE_TAGS:
        for tag in soup.find_all(tag_name):
            attr_value = tag.get(attr_name)
            if not attr_value:
                continue

            # For <link>, only care about stylesheets (and similar resource hints),
            # not e.g. rel="canonical" or rel="alternate".
            if tag_name == "link":
                rel = tag.get("rel") or []
                if isinstance(rel, str):
                    rel = [rel]
                rel_lower = {r.lower() for r in rel}
                relevant_rels = {
                    "stylesheet",
                    "preload",
                    "prefetch",
                    "icon",
                    "shortcut icon",
                    "apple-touch-icon",
                }
                if not (rel_lower & relevant_rels):
                    continue

            resolved = urljoin(base_url, attr_value.strip())
            if _is_http_url(resolved):
                severity = "critical" if category in ACTIVE_CATEGORIES else "medium"
                findings.append({"type": category, "url": resolved, "severity": severity})

    # 2) Inline <style> tags containing url(http://...)
    for style_tag in soup.find_all("style"):
        css_text = style_tag.string or style_tag.get_text() or ""
        for raw_url in _extract_css_http_urls(css_text):
            resolved = urljoin(base_url, raw_url.strip())
            findings.append({"type": "css-url", "url": resolved, "severity": "critical"})

    # 3) Inline style="" attributes containing url(http://...)
    for tag in soup.find_all(style=True):
        style_attr = tag.get("style") or ""
        for raw_url in _extract_css_http_urls(style_attr):
            resolved = urljoin(base_url, raw_url.strip())
            findings.append({"type": "css-url", "url": resolved, "severity": "critical"})

    return findings


def _check_csp_mitigation(headers) -> dict:
    """
    Inspect Content-Security-Policy header for mixed-content mitigations.
    Returns dict with booleans and the raw header value (if present).
    """
    csp_value = headers.get("Content-Security-Policy", "") if headers else ""
    csp_lower = csp_value.lower()
    return {
        "csp_present": bool(csp_value),
        "block_all_mixed_content": "block-all-mixed-content" in csp_lower,
        "upgrade_insecure_requests": "upgrade-insecure-requests" in csp_lower,
        "raw_csp": csp_value,
    }


async def run(url: str) -> dict:
    """
    Check an HTTPS page for mixed content (HTTP sub-resources loaded on an
    HTTPS page). Returns a Bravo6-format result dict.
    """
    try:
        target_url = _normalize_url(url)
        if not target_url:
            return _base_result(
                status="error",
                severity="info",
                title="Mixed Content Check",
                description="No URL was provided to scan.",
                evidence="Input URL was empty after normalization.",
                remediation="Provide a valid domain or URL, e.g. 'example.com'.",
            )

        parsed = urlparse(target_url)

        # Step 2: if the target itself isn't HTTPS, mixed content doesn't apply.
        if parsed.scheme != "https":
            return _base_result(
                status="warning",
                severity="medium",
                title="Mixed Content Check Skipped — Site Not Using HTTPS",
                description=(
                    "The target is not served over HTTPS, so the mixed-content "
                    "model does not apply. The site has a more fundamental "
                    "issue: it does not encrypt traffic at all."
                ),
                evidence=f"Target scheme is '{parsed.scheme}' for {target_url}.",
                remediation=(
                    "Deploy a valid TLS certificate and serve the site exclusively "
                    "over HTTPS before evaluating mixed content."
                ),
            )

        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
        headers = {"User-Agent": USER_AGENT}

        try:
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                async with session.get(target_url, ssl=True, allow_redirects=True) as resp:
                    final_url = str(resp.url)
                    final_parsed = urlparse(final_url)
                    response_headers = resp.headers
                    status_code = resp.status

                    # If a redirect chain dropped us to HTTP, mixed content doesn't apply
                    # to *this* page either — but it IS itself a finding worth surfacing.
                    if final_parsed.scheme != "https":
                        return _base_result(
                            status="warning",
                            severity="medium",
                            title="Mixed Content Check Skipped — Redirected to HTTP",
                            description=(
                                "The target redirected to a non-HTTPS URL, so the "
                                "mixed-content model does not apply to the final "
                                "rendered page."
                            ),
                            evidence=f"{target_url} redirected to {final_url}.",
                            remediation=(
                                "Ensure HTTPS URLs do not redirect to HTTP, and enforce "
                                "HSTS to prevent downgrade redirects."
                            ),
                        )

                    try:
                        html = await resp.text(errors="replace")
                    except Exception as read_err:
                        return _base_result(
                            status="error",
                            severity="info",
                            title="Mixed Content Check — Failed to Read Response Body",
                            description=(
                                "Connected to the target successfully but could not "
                                "read or decode the response body."
                            ),
                            evidence=f"HTTP {status_code} from {final_url}: {read_err}",
                            remediation="Re-run the scan; if the issue persists, inspect the response manually.",
                        )

        except asyncio.TimeoutError:
            return _base_result(
                status="error",
                severity="info",
                title="Mixed Content Check — Request Timed Out",
                description=f"The request to the target did not complete within {REQUEST_TIMEOUT_SECONDS} seconds.",
                evidence=f"Timeout exceeded while fetching {target_url}.",
                remediation="Verify the target is reachable and responsive, then re-run the scan.",
            )
        except aiohttp.ClientConnectorCertificateError as ssl_err:
            return _base_result(
                status="error",
                severity="info",
                title="Mixed Content Check — TLS Certificate Error",
                description=(
                    "The target's TLS certificate could not be validated, so the "
                    "page could not be safely fetched to check for mixed content."
                ),
                evidence=f"{type(ssl_err).__name__}: {ssl_err}",
                remediation="Fix the target's TLS certificate, then re-run the scan.",
            )
        except aiohttp.ClientConnectorError as conn_err:
            return _base_result(
                status="error",
                severity="info",
                title="Mixed Content Check — Connection Failed",
                description="Could not establish a connection to the target.",
                evidence=f"{type(conn_err).__name__}: {conn_err}",
                remediation="Verify the target domain/URL is correct and reachable, then re-run the scan.",
            )
        except aiohttp.ClientError as client_err:
            return _base_result(
                status="error",
                severity="info",
                title="Mixed Content Check — Request Failed",
                description="An HTTP client error occurred while fetching the target.",
                evidence=f"{type(client_err).__name__}: {client_err}",
                remediation="Re-run the scan; if the issue persists, investigate connectivity to the target.",
            )

        # Step 3 & 4: parse HTML and categorize findings.
        try:
            findings = _collect_mixed_content(html, final_url)
        except Exception as parse_err:
            return _base_result(
                status="error",
                severity="info",
                title="Mixed Content Check — HTML Parsing Failed",
                description="The response was retrieved but could not be parsed as HTML.",
                evidence=f"{type(parse_err).__name__}: {parse_err}",
                remediation="Re-run the scan; if parsing continues to fail, inspect the page source manually.",
            )

        # Step 5: CSP mitigation check.
        csp_info = _check_csp_mitigation(response_headers)

        active_findings = [f for f in findings if f["severity"] == "critical"]
        passive_findings = [f for f in findings if f["severity"] == "medium"]
        active_count = len(active_findings)
        passive_count = len(passive_findings)

        mitigation_note = ""
        if csp_info["block_all_mixed_content"] or csp_info["upgrade_insecure_requests"]:
            directives = []
            if csp_info["block_all_mixed_content"]:
                directives.append("block-all-mixed-content")
            if csp_info["upgrade_insecure_requests"]:
                directives.append("upgrade-insecure-requests")
            mitigation_note = (
                f" Note: a Content-Security-Policy mitigation is present "
                f"({', '.join(directives)}), which should cause compliant browsers "
                f"to block or auto-upgrade these requests at runtime."
            )

        if not findings:
            return _base_result(
                status="pass",
                severity="info",
                title="No Mixed Content Detected",
                description=(
                    "The HTTPS page was scanned for HTTP sub-resources "
                    "(scripts, stylesheets, iframes, images, audio, video, and "
                    "inline CSS url() references) and none were found."
                ),
                evidence=f"Scanned {final_url} (HTTP {status_code}); 0 insecure resource references found.",
                remediation="No action needed. Continue to monitor for regressions as the site evolves.",
                active_mixed_count=0,
                passive_mixed_count=0,
            )

        severity = "critical" if active_count > 0 else "medium"
        title = "Mixed Content Detected" + (
            " (Active — Code Execution Risk)" if active_count > 0 else " (Passive)"
        )

        description = (
            f"The HTTPS page at {final_url} loads {len(findings)} resource(s) over "
            f"insecure HTTP. {active_count} of these are 'active' mixed content "
            f"(scripts/stylesheets/iframes), which can be intercepted and modified "
            f"by a network attacker (e.g. on public Wi-Fi) to execute arbitrary "
            f"code in the context of the page. {passive_count} are 'passive' "
            f"mixed content (images/audio/video), which can be tampered with or "
            f"used to leak information, and will typically cause browsers to show "
            f"a 'not fully secure' warning.{mitigation_note}"
        )

        evidence_list = sorted(findings, key=lambda f: (f["severity"] != "critical", f["type"], f["url"]))

        return _base_result(
            status="fail",
            severity=severity,
            title=title,
            description=description,
            evidence=evidence_list,
            remediation=(
                "Replace all http:// resource URLs with https://. Add "
                "'upgrade-insecure-requests' (and ideally 'block-all-mixed-content' "
                "for legacy browser support) to the Content-Security-Policy header "
                "as defense-in-depth, but do not rely on CSP alone — fix the "
                "underlying URLs."
            ),
            active_mixed_count=active_count,
            passive_mixed_count=passive_count,
        )

    except Exception as unexpected_err:
        # Final safety net — this module must never crash the scanner.
        return _base_result(
            status="error",
            severity="info",
            title="Mixed Content Check — Unexpected Error",
            description="An unexpected error occurred while running this test.",
            evidence=f"{type(unexpected_err).__name__}: {unexpected_err}",
            remediation="Re-run the scan. If the issue persists, report it to the Bravo6 maintainers.",
        )


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"

    async def _main():
        result = await run(target)
        print(json.dumps(result, indent=2, default=str))

    asyncio.run(_main())