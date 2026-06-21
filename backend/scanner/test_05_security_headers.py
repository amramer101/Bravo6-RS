"""
test_security_headers.py

Bravo6 security scanning module.

Checks an HTTP target's response headers for the presence and correct
configuration of common browser-enforced security headers:

    1. Strict-Transport-Security (HSTS)
    2. X-Frame-Options
    3. Content-Security-Policy (CSP)
    4. X-Content-Type-Options
    5. Referrer-Policy
    6. Permissions-Policy

This module performs a single GET request against the normalized target
URL and evaluates the response headers. It never raises — all error paths
are captured and surfaced as a single "error" finding so the calling
platform can continue scanning other targets/modules without interruption.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import aiohttp

TEST_NAME = "security_headers"
USER_AGENT = "Bravo6-Scanner/1.0"
REQUEST_TIMEOUT_SECONDS = 10
HSTS_MIN_MAX_AGE = 31536000  # 1 year, in seconds

# Order matters: this defines headers_checked count and finding ordering.
_CHECKED_HEADERS = (
    "Strict-Transport-Security",
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


def _normalize_url(url: str) -> str:
    """Ensure the target has a scheme. Defaults to https://."""
    url = (url or "").strip()
    if not url:
        return url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = f"https://{url}"
    return url


def _make_finding(
    *,
    status: str,
    severity: str,
    title: str,
    description: str,
    evidence: str,
    remediation: str,
) -> Dict[str, Any]:
    """Build a single finding dict matching the required schema."""
    return {
        "test_name": TEST_NAME,
        "status": status,
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
    }


def _get_header(headers: "aiohttp.typedefs.LooseHeaders", name: str) -> Optional[str]:
    """Case-insensitive header lookup. aiohttp's CIMultiDict already
    handles case-insensitivity, but this keeps the call sites explicit
    and safe if headers is ever a plain dict."""
    try:
        return headers.get(name)  # type: ignore[union-attr]
    except AttributeError:
        for key, value in headers:  # type: ignore[misc]
            if key.lower() == name.lower():
                return value
    return None


def _parse_hsts_max_age(value: str) -> Optional[int]:
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


# --------------------------------------------------------------------------
# Individual header checks. Each returns a list of findings (0, 1, or more
# — HSTS can produce both a missing/misconfigured finding AND a separate
# informational finding about includeSubDomains).
# --------------------------------------------------------------------------


def _check_hsts(headers) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    value = _get_header(headers, "Strict-Transport-Security")

    if value is None:
        findings.append(
            _make_finding(
                status="fail",
                severity="high",
                title="Missing Strict-Transport-Security header",
                description=(
                    "The response does not include a Strict-Transport-Security "
                    "(HSTS) header. Without HSTS, browsers may downgrade "
                    "connections to plain HTTP, exposing users to "
                    "man-in-the-middle and SSL-stripping attacks."
                ),
                evidence="Header not present",
                remediation=(
                    'Add the header: Strict-Transport-Security: max-age=31536000; '
                    'includeSubDomains; preload'
                ),
            )
        )
        return findings

    max_age = _parse_hsts_max_age(value)
    if max_age is None:
        findings.append(
            _make_finding(
                status="fail",
                severity="high",
                title="Strict-Transport-Security missing max-age directive",
                description=(
                    "The HSTS header is present but does not contain a "
                    "parseable max-age directive, so browsers may not enforce it."
                ),
                evidence=f"Strict-Transport-Security: {value}",
                remediation=(
                    'Set a valid max-age, e.g. Strict-Transport-Security: '
                    'max-age=31536000; includeSubDomains; preload'
                ),
            )
        )
    elif max_age < HSTS_MIN_MAX_AGE:
        findings.append(
            _make_finding(
                status="warning",
                severity="medium",
                title="Strict-Transport-Security max-age too short",
                description=(
                    f"The HSTS max-age is set to {max_age} seconds, which is "
                    f"below the recommended minimum of {HSTS_MIN_MAX_AGE} "
                    "seconds (1 year). A short max-age reduces the window of "
                    "protection against downgrade attacks."
                ),
                evidence=f"Strict-Transport-Security: {value}",
                remediation=(
                    f"Increase max-age to at least {HSTS_MIN_MAX_AGE} "
                    "(1 year), e.g. max-age=31536000; includeSubDomains; preload"
                ),
            )
        )
    else:
        findings.append(
            _make_finding(
                status="pass",
                severity="info",
                title="Strict-Transport-Security correctly configured",
                description=(
                    "HSTS is present with a max-age meeting or exceeding the "
                    "recommended minimum of one year."
                ),
                evidence=f"Strict-Transport-Security: {value}",
                remediation="No action required.",
            )
        )

    # Bonus check: includeSubDomains, reported separately and informationally.
    if "includesubdomains" not in value.lower():
        findings.append(
            _make_finding(
                status="warning",
                severity="low",
                title="Strict-Transport-Security missing includeSubDomains",
                description=(
                    "The HSTS header does not include the includeSubDomains "
                    "directive, so subdomains of this host are not covered "
                    "by HSTS protection."
                ),
                evidence=f"Strict-Transport-Security: {value}",
                remediation=(
                    "Add includeSubDomains to the HSTS header if all "
                    "subdomains are served over HTTPS."
                ),
            )
        )

    return findings


def _check_x_frame_options(headers) -> List[Dict[str, Any]]:
    value = _get_header(headers, "X-Frame-Options")

    if value is None:
        return [
            _make_finding(
                status="fail",
                severity="medium",
                title="Missing X-Frame-Options header",
                description=(
                    "The response does not include an X-Frame-Options header. "
                    "Without it (or a frame-ancestors CSP directive), the "
                    "site may be vulnerable to clickjacking via iframe embedding."
                ),
                evidence="Header not present",
                remediation="Add the header: X-Frame-Options: DENY or SAMEORIGIN",
            )
        ]

    normalized = value.strip().upper()
    if normalized in ("DENY", "SAMEORIGIN"):
        return [
            _make_finding(
                status="pass",
                severity="info",
                title="X-Frame-Options correctly configured",
                description="X-Frame-Options is set to a safe value.",
                evidence=f"X-Frame-Options: {value}",
                remediation="No action required.",
            )
        ]

    if "ALLOWALL" in normalized:
        return [
            _make_finding(
                status="fail",
                severity="critical",
                title="X-Frame-Options set to ALLOWALL",
                description=(
                    "X-Frame-Options is explicitly set to ALLOWALL, which "
                    "disables clickjacking protection entirely and allows "
                    "any site to frame this page."
                ),
                evidence=f"X-Frame-Options: {value}",
                remediation="Change the value to DENY or SAMEORIGIN.",
            )
        ]

    return [
        _make_finding(
            status="fail",
            severity="medium",
            title="X-Frame-Options set to an unrecognized value",
            description=(
                "X-Frame-Options is present but set to a value other than "
                "DENY or SAMEORIGIN, so clickjacking protection cannot be "
                "guaranteed across browsers."
            ),
            evidence=f"X-Frame-Options: {value}",
            remediation="Change the value to DENY or SAMEORIGIN.",
        )
    ]


def _check_csp(headers) -> List[Dict[str, Any]]:
    value = _get_header(headers, "Content-Security-Policy")

    if value is None:
        return [
            _make_finding(
                status="fail",
                severity="high",
                title="Missing Content-Security-Policy header",
                description=(
                    "The response does not include a Content-Security-Policy "
                    "header. CSP is a key defense-in-depth control against "
                    "XSS and data injection attacks."
                ),
                evidence="Header not present",
                remediation=(
                    "Define a Content-Security-Policy appropriate to the "
                    "application, e.g. default-src 'self'; restrict script "
                    "and style sources; avoid 'unsafe-inline' and 'unsafe-eval'."
                ),
            )
        ]

    lowered = value.lower()
    unsafe_tokens = [t for t in ("unsafe-inline", "unsafe-eval") if t in lowered]
    if unsafe_tokens:
        return [
            _make_finding(
                status="warning",
                severity="medium",
                title="Content-Security-Policy allows unsafe directives",
                description=(
                    "The CSP is present but permits "
                    f"{' and '.join(unsafe_tokens)}, which significantly "
                    "weakens protection against script injection (XSS)."
                ),
                evidence=f"Content-Security-Policy: {value}",
                remediation=(
                    "Remove 'unsafe-inline' and 'unsafe-eval' from the "
                    "policy; use nonces/hashes for required inline scripts "
                    "and refactor eval()-based code."
                ),
            )
        ]

    return [
        _make_finding(
            status="pass",
            severity="info",
            title="Content-Security-Policy present without unsafe directives",
            description=(
                "A Content-Security-Policy is set and does not contain "
                "unsafe-inline or unsafe-eval."
            ),
            evidence=f"Content-Security-Policy: {value}",
            remediation="No action required.",
        )
    ]


def _check_x_content_type_options(headers) -> List[Dict[str, Any]]:
    value = _get_header(headers, "X-Content-Type-Options")

    if value is None:
        return [
            _make_finding(
                status="fail",
                severity="medium",
                title="Missing X-Content-Type-Options header",
                description=(
                    "The response does not include X-Content-Type-Options. "
                    "Without it, browsers may MIME-sniff responses, "
                    "potentially executing content as an unintended type."
                ),
                evidence="Header not present",
                remediation="Add the header: X-Content-Type-Options: nosniff",
            )
        ]

    if value.strip().lower() == "nosniff":
        return [
            _make_finding(
                status="pass",
                severity="info",
                title="X-Content-Type-Options correctly configured",
                description="X-Content-Type-Options is set to nosniff.",
                evidence=f"X-Content-Type-Options: {value}",
                remediation="No action required.",
            )
        ]

    return [
        _make_finding(
            status="fail",
            severity="medium",
            title="X-Content-Type-Options set to an invalid value",
            description=(
                "X-Content-Type-Options is present but not set to nosniff, "
                "so MIME-sniffing protection is not guaranteed."
            ),
            evidence=f"X-Content-Type-Options: {value}",
            remediation="Set the header value to exactly: nosniff",
        )
    ]


def _check_referrer_policy(headers) -> List[Dict[str, Any]]:
    value = _get_header(headers, "Referrer-Policy")
    acceptable = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin"}

    if value is None:
        return [
            _make_finding(
                status="fail",
                severity="medium",
                title="Missing Referrer-Policy header",
                description=(
                    "The response does not include a Referrer-Policy header. "
                    "Without it, full URLs (potentially including sensitive "
                    "query parameters) may leak to third parties via the "
                    "Referer header."
                ),
                evidence="Header not present",
                remediation=(
                    "Add the header: Referrer-Policy: "
                    "strict-origin-when-cross-origin (or no-referrer / "
                    "strict-origin for stricter protection)."
                ),
            )
        ]

    normalized = value.strip().lower()
    if normalized == "unsafe-url":
        return [
            _make_finding(
                status="fail",
                severity="high",
                title="Referrer-Policy set to unsafe-url",
                description=(
                    "Referrer-Policy is explicitly set to unsafe-url, which "
                    "always sends the full URL (including path and query "
                    "string) as the Referer header, even on downgrades to "
                    "insecure origins."
                ),
                evidence=f"Referrer-Policy: {value}",
                remediation=(
                    "Change to strict-origin-when-cross-origin, "
                    "strict-origin, or no-referrer."
                ),
            )
        ]

    if normalized in acceptable:
        return [
            _make_finding(
                status="pass",
                severity="info",
                title="Referrer-Policy correctly configured",
                description="Referrer-Policy is set to an acceptable, privacy-preserving value.",
                evidence=f"Referrer-Policy: {value}",
                remediation="No action required.",
            )
        ]

    return [
        _make_finding(
            status="warning",
            severity="medium",
            title="Referrer-Policy set to a non-recommended value",
            description=(
                "Referrer-Policy is present but not set to one of the "
                "recommended values (no-referrer, strict-origin, "
                "strict-origin-when-cross-origin)."
            ),
            evidence=f"Referrer-Policy: {value}",
            remediation=(
                "Use strict-origin-when-cross-origin, strict-origin, or "
                "no-referrer."
            ),
        )
    ]


def _check_permissions_policy(headers) -> List[Dict[str, Any]]:
    value = _get_header(headers, "Permissions-Policy")

    if value is None:
        return [
            _make_finding(
                status="warning",
                severity="info",
                title="Missing Permissions-Policy header",
                description=(
                    "The response does not include a Permissions-Policy "
                    "header. This is informational: Permissions-Policy "
                    "restricts access to powerful browser features (camera, "
                    "microphone, geolocation, etc.) and is recommended but "
                    "not critical for all sites."
                ),
                evidence="Header not present",
                remediation=(
                    "Consider adding a Permissions-Policy header to "
                    "explicitly disable unused browser features, e.g. "
                    "Permissions-Policy: geolocation=(), camera=(), microphone=()"
                ),
            )
        ]

    return [
        _make_finding(
            status="pass",
            severity="info",
            title="Permissions-Policy present",
            description="A Permissions-Policy header is set.",
            evidence=f"Permissions-Policy: {value}",
            remediation="No action required.",
        )
    ]


def _compute_overall_status(findings: List[Dict[str, Any]]) -> str:
    """fail if any critical/high finding with status fail/error,
    warning if only medium/low/info-level issues remain,
    pass if everything passed."""
    has_critical_or_high_failure = any(
        f["severity"] in ("critical", "high") and f["status"] in ("fail", "error")
        for f in findings
    )
    if has_critical_or_high_failure:
        return "fail"

    has_warning_or_lesser_issue = any(
        f["status"] in ("warning", "fail") for f in findings
    )
    if has_warning_or_lesser_issue:
        return "warning"

    return "pass"


def _error_result(message: str) -> Dict[str, Any]:
    finding = _make_finding(
        status="error",
        severity="info",
        title="Security headers scan could not be completed",
        description=message,
        evidence="N/A",
        remediation="Verify the target is reachable and retry the scan.",
    )
    return {
        "test_name": TEST_NAME,
        "findings": [finding],
        "overall_status": "error",
        "headers_checked": len(_CHECKED_HEADERS),
        "headers_failed": 0,
    }


async def run(url: str) -> Dict[str, Any]:
    """
    Entry point for the Bravo6 scanning platform.

    Performs a single GET request against the normalized target URL and
    evaluates the presence/configuration of common security headers.

    Never raises: all failure modes are captured and returned as a
    structured error result so the platform's scan orchestration can
    continue uninterrupted.
    """
    try:
        target = _normalize_url(url)
        if not target:
            return _error_result("No URL was provided to the scanner.")

        parsed = urlparse(target)
        if not parsed.netloc:
            return _error_result(f"Could not parse a valid host from input: {url!r}")

        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
        headers_sent = {"User-Agent": USER_AGENT}

        try:
            async with aiohttp.ClientSession(timeout=timeout, headers=headers_sent) as session:
                async with session.get(
                    target,
                    allow_redirects=True,
                    ssl=True,
                ) as response:
                    response_headers = response.headers
        except asyncio.TimeoutError:
            return _error_result(
                f"Request to {target} timed out after {REQUEST_TIMEOUT_SECONDS} seconds."
            )
        except aiohttp.ClientConnectorError as exc:
            return _error_result(f"Could not connect to {target}: {exc}")
        except aiohttp.ClientSSLError as exc:
            return _error_result(f"TLS/SSL error connecting to {target}: {exc}")
        except aiohttp.ClientResponseError as exc:
            return _error_result(f"HTTP error from {target}: {exc}")
        except aiohttp.ClientError as exc:
            return _error_result(f"Client error requesting {target}: {exc}")

        findings: List[Dict[str, Any]] = []
        findings.extend(_check_hsts(response_headers))
        findings.extend(_check_x_frame_options(response_headers))
        findings.extend(_check_csp(response_headers))
        findings.extend(_check_x_content_type_options(response_headers))
        findings.extend(_check_referrer_policy(response_headers))
        findings.extend(_check_permissions_policy(response_headers))

        overall_status = _compute_overall_status(findings)
        headers_failed = sum(1 for f in findings if f["status"] in ("fail", "warning"))

        return {
            "test_name": TEST_NAME,
            "findings": findings,
            "overall_status": overall_status,
            "headers_checked": len(_CHECKED_HEADERS),
            "headers_failed": headers_failed,
        }

    except Exception as exc:  # noqa: BLE001 - last-resort safety net, never crash
        return _error_result(f"Unexpected error scanning {url!r}: {exc!r}")


# --------------------------------------------------------------------------
# Manual / local test harness
# --------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    import sys

    async def _main() -> None:
        targets = sys.argv[1:] or ["example.com", "github.com", "http://neverssl.com"]
        for t in targets:
            print(f"\n=== Scanning: {t} ===")
            result = await run(t)
            print(json.dumps(result, indent=2))

    asyncio.run(_main())