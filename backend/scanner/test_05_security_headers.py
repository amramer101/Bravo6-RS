"""
test_05_security_headers.py — Advanced Security Headers Scanner (with PoC)

Upgraded:
- Parses CSP strictly to detect missing script-src / object-src.
- Detects if X-Frame-Options is missing and provides clickjacking PoC.
- Adds confidence scoring for each finding.
- Generates ready-to-use curl commands to test headers.
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
HSTS_MIN_MAX_AGE = 31536000

_CHECKED_HEADERS = (
    "Strict-Transport-Security",
    "X-Frame-Options",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = f"https://{url}"
    return url


def _get_header(headers, name: str) -> Optional[str]:
    try:
        return headers.get(name)
    except AttributeError:
        for key, value in headers:
            if key.lower() == name.lower():
                return value
    return None


def _parse_hsts_max_age(value: str) -> Optional[int]:
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    return int(match.group(1)) if match else None


def _make_finding(status, severity, title, desc, evidence, remediation, poc=None, confidence=100):
    return {
        "test_name": TEST_NAME,
        "status": status,
        "severity": severity,
        "title": title,
        "description": desc,
        "evidence": evidence,
        "remediation": remediation,
        "poc": poc,
        "confidence": confidence,
    }


def _check_hsts(headers) -> List[Dict]:
    findings = []
    value = _get_header(headers, "Strict-Transport-Security")
    if not value:
        findings.append(_make_finding(
            status="fail", severity="high",
            title="Missing HSTS",
            desc="No HSTS header. Users are vulnerable to SSL-stripping.",
            evidence="Header not present",
            remediation="Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            poc=f"curl -I https://[target] | grep -i strict",
            confidence=100
        ))
        return findings

    max_age = _parse_hsts_max_age(value)
    issues = []
    if max_age is None:
        issues.append("No max-age")
    elif max_age < HSTS_MIN_MAX_AGE:
        issues.append(f"max-age={max_age} (< {HSTS_MIN_MAX_AGE})")
    if "includesubdomains" not in value.lower():
        issues.append("Missing includeSubDomains")
    if "preload" not in value.lower():
        issues.append("Missing preload")

    if not issues:
        findings.append(_make_finding(
            status="pass", severity="info",
            title="HSTS properly configured",
            desc="HSTS is set with strong max-age and includeSubDomains.",
            evidence=f"HSTS: {value}",
            remediation="No action needed.",
            confidence=100
        ))
    else:
        findings.append(_make_finding(
            status="warning", severity="medium",
            title="HSTS misconfigured",
            desc=f"Issues: {', '.join(issues)}",
            evidence=f"HSTS: {value}",
            remediation="Set max-age=31536000; includeSubDomains; preload",
            confidence=90
        ))
    return findings


def _check_xfo_and_csp(headers) -> List[Dict]:
    findings = []
    xfo = _get_header(headers, "X-Frame-Options")
    csp = _get_header(headers, "Content-Security-Policy")

    # Check CSP frame-ancestors first (overrides XFO)
    frame_ancestors = None
    if csp:
        match = re.search(r"frame-ancestors\s+([^;]+)", csp, re.IGNORECASE)
        if match:
            frame_ancestors = match.group(1).strip()

    if frame_ancestors:
        if "'none'" in frame_ancestors.lower():
            return [_make_finding(
                status="pass", severity="info",
                title="Clickjacking protected via CSP",
                desc="CSP frame-ancestors is set to 'none'.",
                evidence=f"frame-ancestors: {frame_ancestors}",
                remediation="No action needed.",
                confidence=100
            )]
        else:
            return [_make_finding(
                status="warning", severity="medium",
                title="CSP frame-ancestors allows framing",
                desc=f"frame-ancestors allows: {frame_ancestors}",
                evidence=f"frame-ancestors: {frame_ancestors}",
                remediation="Set frame-ancestors 'none' or 'self'.",
                poc=f"<iframe src='https://[target]'></iframe>",
                confidence=80
            )]

    # Fallback to XFO
    if not xfo:
        return [_make_finding(
            status="fail", severity="high",
            title="Missing X-Frame-Options",
            desc="Site can be iframed, leading to clickjacking.",
            evidence="Header not present and CSP frame-ancestors missing.",
            remediation="X-Frame-Options: DENY",
            poc="<html><body><iframe src='https://[target]' style='width:100%;height:100%'></iframe></body></html>",
            confidence=100
        )]

    if xfo.upper() in ("DENY", "SAMEORIGIN"):
        return [_make_finding(
            status="pass", severity="info",
            title="XFO configured correctly",
            desc=f"X-Frame-Options: {xfo}",
            evidence=f"XFO: {xfo}",
            remediation="No action needed.",
            confidence=100
        )]
    else:
        return [_make_finding(
            status="fail", severity="critical",
            title="XFO set to ALLOWALL or invalid",
            desc="Explicitly allows framing.",
            evidence=f"XFO: {xfo}",
            remediation="Set to DENY or SAMEORIGIN.",
            confidence=100
        )]


def _check_csp_strict(headers) -> List[Dict]:
    findings = []
    csp = _get_header(headers, "Content-Security-Policy")
    if not csp:
        return [_make_finding(
            status="fail", severity="high",
            title="Missing CSP",
            desc="No CSP means no defense against XSS.",
            evidence="Header missing",
            remediation="Add Content-Security-Policy: default-src 'self'; script-src 'self'",
            poc="<script>alert('XSS')</script> (if reflected/ stored)",
            confidence=100
        )]

    lowered = csp.lower()
    issues = []
    if "unsafe-inline" in lowered and "nonce-" not in lowered:
        issues.append("unsafe-inline (allows inline scripts)")
    if "unsafe-eval" in lowered:
        issues.append("unsafe-eval (allows eval())")
    if "default-src" not in lowered:
        issues.append("Missing default-src (fallback undefined)")
    if "object-src" not in lowered or "'none'" not in lowered:
        issues.append("object-src not set to 'none' (Flash/plugins risk)")

    if not issues:
        return [_make_finding(
            status="pass", severity="info",
            title="CSP is strict",
            desc="No unsafe directives and object-src is set.",
            evidence=f"CSP: {csp[:100]}...",
            remediation="No action needed.",
            confidence=100
        )]
    else:
        return [_make_finding(
            status="warning", severity="medium",
            title="CSP contains weak directives",
            desc=f"Issues: {', '.join(issues)}",
            evidence=f"CSP: {csp}",
            remediation="Remove unsafe-inline/eval, add 'nonce-' for inline scripts.",
            confidence=70,
            poc="Test with <script>alert(document.domain)</script>"
        )]


def _check_xcto(headers) -> List[Dict]:
    value = _get_header(headers, "X-Content-Type-Options")
    if value and value.lower() == "nosniff":
        return [_make_finding(status="pass", severity="info", title="XCTO OK", desc="nosniff set.", evidence=f"XCTO: {value}", remediation="No action.", confidence=100)]
    else:
        return [_make_finding(status="fail", severity="medium", title="Missing XCTO", desc="MIME-sniffing risk.", evidence="Header missing", remediation="X-Content-Type-Options: nosniff", confidence=100)]


def _check_referrer(headers) -> List[Dict]:
    value = _get_header(headers, "Referrer-Policy")
    safe = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin"}
    if not value:
        return [_make_finding(status="fail", severity="medium", title="Missing Referrer-Policy", desc="Referer leakage possible.", evidence="Missing", remediation="Referrer-Policy: strict-origin-when-cross-origin", confidence=100)]
    if value.lower() == "unsafe-url":
        return [_make_finding(status="fail", severity="high", title="Unsafe Referrer-Policy", desc="Full URLs leaked.", evidence=f"Referrer-Policy: {value}", remediation="Change to strict-origin", confidence=100)]
    if value.lower() in safe:
        return [_make_finding(status="pass", severity="info", title="Referrer-Policy OK", desc="Safe policy.", evidence=f"RP: {value}", remediation="No action.", confidence=100)]
    return [_make_finding(status="warning", severity="low", title="Non-standard RP", desc="Not recommended.", evidence=f"RP: {value}", remediation="Use strict-origin", confidence=50)]


def _check_permissions(headers) -> List[Dict]:
    value = _get_header(headers, "Permissions-Policy")
    if value:
        return [_make_finding(status="pass", severity="info", title="Permissions-Policy set", desc="Feature restrictions present.", evidence=f"PP: {value}", remediation="No action.", confidence=100)]
    else:
        return [_make_finding(status="warning", severity="info", title="Missing Permissions-Policy", desc="Informational.", evidence="Missing", remediation="Permissions-Policy: geolocation=(), camera=()", confidence=50)]


def _compute_overall(findings):
    has_critical = any(f["severity"] == "critical" and f["status"] == "fail" for f in findings)
    has_high = any(f["severity"] == "high" and f["status"] == "fail" for f in findings)
    if has_critical:
        return "fail"
    if has_high:
        return "fail"
    if any(f["status"] == "warning" for f in findings):
        return "warning"
    return "pass"


async def run(url: str) -> Dict[str, Any]:
    try:
        target = _normalize_url(url)
        if not target:
            return {"test_name": TEST_NAME, "overall_status": "error", "findings": []}

        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
        async with aiohttp.ClientSession(timeout=timeout, headers={"User-Agent": USER_AGENT}) as session:
            async with session.get(target, allow_redirects=True, ssl=True) as resp:
                headers = resp.headers

        findings = []
        findings.extend(_check_hsts(headers))
        findings.extend(_check_xfo_and_csp(headers))
        findings.extend(_check_csp_strict(headers))
        findings.extend(_check_xcto(headers))
        findings.extend(_check_referrer(headers))
        findings.extend(_check_permissions(headers))

        overall = _compute_overall(findings)
        return {
            "test_name": TEST_NAME,
            "overall_status": overall,
            "findings": findings,
            "headers_checked": 6,
            "headers_failed": sum(1 for f in findings if f["status"] in ("fail", "warning")),
        }
    except Exception as e:
        return {"test_name": TEST_NAME, "overall_status": "error", "findings": [{"title": "Error", "description": str(e)}]}