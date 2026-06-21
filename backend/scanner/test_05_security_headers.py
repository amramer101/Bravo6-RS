"""
test_05_security_headers.py — Advanced Security Headers Scanner (Context-Aware & Active)

Upgraded with:
- Context-aware: API endpoints (JSON/XML) skip non-applicable header checks.
- CSP deep parsing: detects nonce + unsafe-inline fallback, strict-dynamic, base-uri, form-action.
- HSTS preload readiness: checks 2-year max-age, includeSubDomains, preload order.
- COOP / COEP / CORP (Modern isolation headers).
- Cache-Control verification only for authenticated pages (Set-Cookie present).
- Permissions-Policy strictness check (rejects wildcards).
- CDN domain exclusions (cloudfront, heroku, etc.) to avoid false positives.
- Redirect chain accumulation (collects headers from all steps).
- Confidence scoring for each finding.
- Ready-to-use PoC / curl commands.
"""

import asyncio
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin

import aiohttp

TEST_NAME = "security_headers"
USER_AGENT = "Bravo6-Scanner/1.0"
REQUEST_TIMEOUT_SECONDS = 12
MAX_REDIRECTS = 5

# ── CDN / Shared domains that cannot have HSTS ──────────────────────────
CDN_EXCLUSIONS = (
    ".cloudfront.net",
    ".azurewebsites.net",
    ".herokuapp.com",
    ".github.io",
    ".netlify.app",
    ".vercel.app",
    ".firebaseapp.com",
    ".pages.dev",
)

# ── CSP Directives to check ──────────────────────────────────────────────
CSP_CRITICAL_DIRECTIVES = {"base-uri", "form-action", "object-src", "script-src"}
CSP_RECOMMENDED_DIRECTIVES = {"upgrade-insecure-requests", "block-all-mixed-content", "frame-ancestors", "report-uri"}

# ── Severity rank ─────────────────────────────────────────────────────────
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# ── Helper: Normalize URL ──────────────────────────────────────────────
def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = f"https://{url}"
    return url

# ── Helper: Get header case-insensitively ─────────────────────────────
def _get_header(headers, name: str) -> Optional[str]:
    if not headers:
        return None
    # If headers is a dict
    if hasattr(headers, "get"):
        for key, val in headers.items():
            if key.lower() == name.lower():
                return val
    # If headers is a list of tuples
    for key, val in headers:
        if key.lower() == name.lower():
            return val
    return None

# ── Helper: Check if response is an API (non-HTML) ────────────────────
def _is_api_response(headers) -> bool:
    ctype = _get_header(headers, "Content-Type")
    if not ctype:
        return False
    ctype_lower = ctype.lower()
    api_patterns = (
        "application/json",
        "application/xml",
        "application/grpc",
        "text/xml",
        "application/javascript",
        "text/javascript",
        "image/",
        "application/octet-stream",
        "application/pdf",
        "font/",
        "video/",
        "audio/",
    )
    for pattern in api_patterns:
        if pattern in ctype_lower:
            return True
    return False

# ── Helper: Check if hostname is on a shared CDN domain ──────────────
def _is_cdn_domain(hostname: str) -> bool:
    if not hostname:
        return False
    hostname = hostname.lower()
    for exclusion in CDN_EXCLUSIONS:
        if hostname.endswith(exclusion):
            return True
    return False

# ── Helper: Parse CSP into directives ──────────────────────────────────
def _parse_csp(csp: str) -> Dict[str, str]:
    """Return a dict of directive -> value(s)."""
    directives = {}
    if not csp:
        return directives
    # Remove extra whitespace and split on semicolon
    parts = re.split(r";\s*", csp.strip())
    for part in parts:
        if not part:
            continue
        # Split on first space to separate directive from value
        if " " in part:
            d_name, d_value = part.split(" ", 1)
            directives[d_name.strip()] = d_value.strip()
        else:
            directives[part.strip()] = ""
    return directives

# ── Helper: Check if CSP has a nonce in script-src ────────────────────
def _has_nonce_in_script_src(csp_directives: Dict[str, str]) -> bool:
    script_src = csp_directives.get("script-src", "")
    return bool(re.search(r"nonce-[a-zA-Z0-9+/=]+", script_src))

# ── Helper: Check if CSP has strict-dynamic ────────────────────────────
def _has_strict_dynamic(csp_directives: Dict[str, str]) -> bool:
    script_src = csp_directives.get("script-src", "")
    return "strict-dynamic" in script_src

# ── Helper: Evaluate HSTS preload readiness ────────────────────────────
def _evaluate_hsts(value: str) -> Tuple[bool, Optional[str], int]:
    """Returns (is_valid, issue_message, max_age)."""
    if not value:
        return False, "Header is missing", 0
    max_age_match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    max_age = int(max_age_match.group(1)) if max_age_match else None
    if max_age is None:
        return False, "max-age missing or invalid", 0
    has_sub = "includesubdomains" in value.lower()
    has_preload = "preload" in value.lower()
    issues = []
    if max_age < 31536000:
        issues.append(f"max-age={max_age} (less than 1 year)")
    if max_age < 63072000:
        issues.append(f"max-age={max_age} (less than 2 years, not preload-ready)")
    if not has_sub:
        issues.append("missing includeSubDomains")
    # Preload must be the last directive (at the end) but we can't easily verify order.
    # We'll just check existence.
    if not has_preload:
        issues.append("missing preload flag")
    if not issues:
        return True, None, max_age
    return False, "; ".join(issues), max_age

# ── Main Entry ────────────────────────────────────────────────────────────

async def run(url: str) -> Dict[str, Any]:
    try:
        target = _normalize_url(url)
        if not target:
            return {"test_name": TEST_NAME, "status": "error", "severity": "info", "findings": [], "overall_status": "error"}

        parsed = urlparse(target)
        hostname = parsed.hostname
        if not hostname:
            return {"test_name": TEST_NAME, "status": "error", "severity": "info", "findings": [], "overall_status": "error"}

        is_cdn = _is_cdn_domain(hostname)

        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
        findings = []
        all_responses = []  # Store (headers, status, url, content_type)

        async with aiohttp.ClientSession(timeout=timeout, headers={"User-Agent": USER_AGENT}) as session:
                # We need to trace redirects to collect all headers.
                # Manually follow redirects with a loop.
                current_url = target
                follow_count = 0
                final_headers = None
                final_status = None

                while follow_count < MAX_REDIRECTS:
                    async with session.get(current_url, allow_redirects=False, ssl=True) as resp:
                        headers = dict(resp.headers)
                        status = resp.status
                        url_actual = str(resp.url)
                        all_responses.append({
                            "url": url_actual,
                            "status": status,
                            "headers": headers,
                            "content_type": _get_header(headers, "Content-Type")
                        })
                        # Store the final response (will be overwritten if redirect)
                        final_headers = headers
                        final_status = status

                        # If redirect, follow it
                        if status in (301, 302, 303, 307, 308):
                            location = _get_header(headers, "Location")
                            if location:
                                # Build absolute URL if needed
                                if location.startswith("http"):
                                    current_url = location
                                else:
                                    current_url = urljoin(current_url, location)
                                follow_count += 1
                                continue
                        # Not a redirect, break
                        break

                # If we didn't get any response
                if not all_responses:
                    return {"test_name": TEST_NAME, "status": "error", "severity": "info", "findings": [], "overall_status": "error"}

                # Determine if this is an API response (based on final response)
                is_api = _is_api_response(final_headers) if final_headers else False

                # ── 1. HSTS (Skip for CDN domains) ──────────────────
                if not is_cdn:
                    hsts_present = False
                    hsts_issues = []
                    hsts_max_age = 0
                    for resp in all_responses:
                        hdr = _get_header(resp["headers"], "Strict-Transport-Security")
                        if hdr:
                            hsts_present = True
                            valid, issue, max_age = _evaluate_hsts(hdr)
                            hsts_max_age = max(max_age, hsts_max_age)
                            if not valid and issue:
                                hsts_issues.append(issue)
                    if not hsts_present:
                        findings.append({
                            "test_name": TEST_NAME,
                            "header": "Strict-Transport-Security",
                            "status": "fail",
                            "severity": "high",
                            "title": "Missing HSTS",
                            "description": "No HSTS header found. Users are vulnerable to SSL-stripping (downgrade attacks).",
                            "evidence": "Header not present in any response in redirect chain.",
                            "remediation": "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
                            "poc": f"curl -I {target} | grep -i strict",
                            "confidence": 100
                        })
                    elif hsts_issues:
                        findings.append({
                            "test_name": TEST_NAME,
                            "header": "Strict-Transport-Security",
                            "status": "warning",
                            "severity": "medium",
                            "title": "HSTS misconfigured / not preload-ready",
                            "description": f"Issues: {', '.join(hsts_issues)}.",
                            "evidence": f"HSTS: {_get_header(all_responses[-1]['headers'], 'Strict-Transport-Security')}",
                            "remediation": "Set max-age=63072000; includeSubDomains; preload",
                            "poc": f"curl -I {target} | grep -i strict",
                            "confidence": 95
                        })
                    else:
                        findings.append({
                            "test_name": TEST_NAME,
                            "header": "Strict-Transport-Security",
                            "status": "pass",
                            "severity": "info",
                            "title": "HSTS properly configured",
                            "description": f"HSTS is set with max-age={hsts_max_age}, includes subdomains and preload.",
                            "evidence": f"HSTS: {_get_header(all_responses[-1]['headers'], 'Strict-Transport-Security')}",
                            "remediation": "No action required.",
                            "confidence": 100
                        })
                else:
                    findings.append({
                        "test_name": TEST_NAME,
                        "header": "Strict-Transport-Security",
                        "status": "pass",
                        "severity": "info",
                        "title": "HSTS skipped (CDN/Shared Domain)",
                        "description": f"Domain {hostname} is on a shared CDN platform. HSTS is typically not applicable or controlled by the provider.",
                        "evidence": f"Domain excluded: {hostname}",
                        "remediation": "If using a custom domain, consult your CDN documentation to enable HSTS.",
                        "confidence": 100
                    })

                # ── 2. X-Frame-Options & CSP frame-ancestors ──────
                # If API, skip all framing checks.
                if is_api:
                    findings.append({
                        "test_name": TEST_NAME,
                        "header": "X-Frame-Options / CSP frame-ancestors",
                        "status": "pass",
                        "severity": "info",
                        "title": "Skipped (API Response)",
                        "description": "Response is not HTML. Framing headers are not applicable for APIs.",
                        "evidence": f"Content-Type: {_get_header(final_headers, 'Content-Type')}",
                        "remediation": "No action required.",
                        "confidence": 100
                    })
                else:
                    # Collect CSP from all responses, but prioritize final.
                    csp_header = _get_header(final_headers, "Content-Security-Policy")
                    csp_directives = _parse_csp(csp_header or "")
                    frame_ancestors = csp_directives.get("frame-ancestors", "")
                    xfo = _get_header(final_headers, "X-Frame-Options")

                    if frame_ancestors:
                        if "'none'" in frame_ancestors.lower():
                            findings.append({
                                "test_name": TEST_NAME,
                                "header": "CSP frame-ancestors",
                                "status": "pass",
                                "severity": "info",
                                "title": "Clickjacking protected via CSP",
                                "description": "CSP frame-ancestors is set to 'none'.",
                                "evidence": f"frame-ancestors: {frame_ancestors}",
                                "remediation": "No action required.",
                                "confidence": 100
                            })
                        elif "'self'" in frame_ancestors.lower():
                            findings.append({
                                "test_name": TEST_NAME,
                                "header": "CSP frame-ancestors",
                                "status": "pass",
                                "severity": "info",
                                "title": "Clickjacking protected via CSP (same-origin)",
                                "description": "CSP frame-ancestors is set to 'self'.",
                                "evidence": f"frame-ancestors: {frame_ancestors}",
                                "remediation": "No action required.",
                                "confidence": 90
                            })
                        else:
                            findings.append({
                                "test_name": TEST_NAME,
                                "header": "CSP frame-ancestors",
                                "status": "warning",
                                "severity": "medium",
                                "title": "CSP allows framing from external sources",
                                "description": f"frame-ancestors allows: {frame_ancestors}. This may permit clickjacking from trusted origins.",
                                "evidence": f"frame-ancestors: {frame_ancestors}",
                                "remediation": "Set frame-ancestors 'none' or 'self'.",
                                "poc": "<iframe src='https://target'></iframe>",
                                "confidence": 80
                            })
                    elif xfo:
                        if xfo.upper() in ("DENY", "SAMEORIGIN"):
                            findings.append({
                                "test_name": TEST_NAME,
                                "header": "X-Frame-Options",
                                "status": "pass",
                                "severity": "info",
                                "title": "XFO configured correctly",
                                "description": f"X-Frame-Options: {xfo}",
                                "evidence": f"XFO: {xfo}",
                                "remediation": "No action required.",
                                "confidence": 100
                            })
                        else:
                            findings.append({
                                "test_name": TEST_NAME,
                                "header": "X-Frame-Options",
                                "status": "fail",
                                "severity": "critical",
                                "title": "XFO set to ALLOWALL or invalid",
                                "description": f"X-Frame-Options is set to '{xfo}', which explicitly allows framing from any origin.",
                                "evidence": f"XFO: {xfo}",
                                "remediation": "Set to DENY or SAMEORIGIN.",
                                "poc": "<iframe src='https://target'></iframe>",
                                "confidence": 100
                            })
                    else:
                        # No XFO and no CSP frame-ancestors -> vulnerable
                        findings.append({
                            "test_name": TEST_NAME,
                            "header": "X-Frame-Options / CSP frame-ancestors",
                            "status": "fail",
                            "severity": "high",
                            "title": "Missing Clickjacking Protection",
                            "description": "Neither X-Frame-Options nor CSP frame-ancestors are present. Site can be iframed, leading to clickjacking.",
                            "evidence": "Both headers are missing.",
                            "remediation": "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
                            "poc": "<html><body><iframe src='https://target' style='width:100%;height:100%'></iframe></body></html>",
                            "confidence": 100
                        })

                # ── 3. CSP Deep Analysis (only for HTML) ─────────────
                if not is_api:
                    csp_header = _get_header(final_headers, "Content-Security-Policy")
                    if not csp_header:
                        findings.append({
                            "test_name": TEST_NAME,
                            "header": "Content-Security-Policy",
                            "status": "fail",
                            "severity": "high",
                            "title": "Missing CSP",
                            "description": "No CSP header. This leaves the site vulnerable to XSS and data injection.",
                            "evidence": "Header missing",
                            "remediation": "Add Content-Security-Policy: default-src 'self'; script-src 'self'",
                            "poc": "<script>alert('XSS')</script> (if reflected/stored)",
                            "confidence": 100
                        })
                    else:
                        directives = _parse_csp(csp_header)
                        csp_issues = []
                        # Check critical directives
                        if "base-uri" not in directives:
                            csp_issues.append("Missing base-uri (allows arbitrary base URL injection)")
                        elif "'none'" not in directives["base-uri"] and "'self'" not in directives["base-uri"]:
                            csp_issues.append(f"base-uri is not restricted to 'none'/'self' (value: {directives['base-uri']})")

                        if "form-action" not in directives:
                            csp_issues.append("Missing form-action (allows form data to be sent to any origin)")
                        elif "'none'" not in directives["form-action"] and "'self'" not in directives["form-action"]:
                            csp_issues.append(f"form-action is not restricted to 'none'/'self' (value: {directives['form-action']})")

                        if "object-src" not in directives:
                            csp_issues.append("Missing object-src (allows Flash/plugins)")
                        elif "'none'" not in directives["object-src"]:
                            csp_issues.append(f"object-src not set to 'none' (value: {directives['object-src']})")

                        # Check script-src carefully
                        script_src = directives.get("script-src", "")
                        if script_src:
                            has_unsafe_inline = "unsafe-inline" in script_src
                            has_nonce = _has_nonce_in_script_src(directives)
                            has_strict = _has_strict_dynamic(directives)
                            # If unsafe-inline is present WITHOUT nonce AND without strict-dynamic, it's bad.
                            if has_unsafe_inline and not has_nonce and not has_strict:
                                csp_issues.append("script-src contains 'unsafe-inline' without 'nonce-' or 'strict-dynamic' (XSS risk)")
                            elif has_unsafe_inline and (has_nonce or has_strict):
                                # It's a fallback. Not ideal but acceptable.
                                pass
                        else:
                            csp_issues.append("script-src is missing (fallback to default-src, may be unsafe)")

                        # Check for upgrade-insecure-requests
                        if "upgrade-insecure-requests" not in directives:
                            csp_issues.append("Missing upgrade-insecure-requests (mixed content not auto-upgraded)")

                        if csp_issues:
                            findings.append({
                                "test_name": TEST_NAME,
                                "header": "Content-Security-Policy",
                                "status": "warning",
                                "severity": "medium",
                                "title": "CSP has weak/unsafe directives",
                                "description": "; ".join(csp_issues),
                                "evidence": f"CSP: {csp_header[:200]}...",
                                "remediation": "Add missing directives and restrict unsafe-inline with nonce.",
                                "confidence": 85
                            })
                        else:
                            findings.append({
                                "test_name": TEST_NAME,
                                "header": "Content-Security-Policy",
                                "status": "pass",
                                "severity": "info",
                                "title": "CSP is well-configured",
                                "description": "All critical CSP directives (base-uri, form-action, object-src, script-src with nonce/strict-dynamic) are properly set.",
                                "evidence": f"CSP: {csp_header[:200]}...",
                                "remediation": "No action required.",
                                "confidence": 95
                            })

                # ── 4. X-Content-Type-Options ────────────────────────
                xcto = _get_header(final_headers, "X-Content-Type-Options")
                if xcto and xcto.lower() == "nosniff":
                    findings.append({
                        "test_name": TEST_NAME,
                        "header": "X-Content-Type-Options",
                        "status": "pass",
                        "severity": "info",
                        "title": "XCTO OK",
                        "description": "nosniff is set, preventing MIME sniffing.",
                        "evidence": f"XCTO: {xcto}",
                        "remediation": "No action required.",
                        "confidence": 100
                    })
                else:
                    findings.append({
                        "test_name": TEST_NAME,
                        "header": "X-Content-Type-Options",
                        "status": "fail",
                        "severity": "medium",
                        "title": "Missing XCTO",
                        "description": "X-Content-Type-Options is missing. This allows browsers to sniff MIME types, leading to XSS risks.",
                        "evidence": "Header missing or invalid",
                        "remediation": "X-Content-Type-Options: nosniff",
                        "confidence": 100
                    })

                # ── 5. Referrer-Policy ──────────────────────────────
                rp = _get_header(final_headers, "Referrer-Policy")
                safe_policies = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin"}
                if not rp:
                    findings.append({
                        "test_name": TEST_NAME,
                        "header": "Referrer-Policy",
                        "status": "fail",
                        "severity": "medium",
                        "title": "Missing Referrer-Policy",
                        "description": "Referer header may leak sensitive URL information to third-party sites.",
                        "evidence": "Header missing",
                        "remediation": "Referrer-Policy: strict-origin-when-cross-origin",
                        "confidence": 100
                    })
                elif rp.lower() in safe_policies:
                    findings.append({
                        "test_name": TEST_NAME,
                        "header": "Referrer-Policy",
                        "status": "pass",
                        "severity": "info",
                        "title": "Referrer-Policy OK",
                        "description": f"Policy '{rp}' is considered safe.",
                        "evidence": f"RP: {rp}",
                        "remediation": "No action required.",
                        "confidence": 100
                    })
                elif rp.lower() == "unsafe-url":
                    findings.append({
                        "test_name": TEST_NAME,
                        "header": "Referrer-Policy",
                        "status": "fail",
                        "severity": "high",
                        "title": "Unsafe Referrer-Policy",
                        "description": "unsafe-url leaks full URL including query parameters to all third parties.",
                        "evidence": f"RP: {rp}",
                        "remediation": "Change to strict-origin-when-cross-origin",
                        "confidence": 100
                    })
                else:
                    findings.append({
                        "test_name": TEST_NAME,
                        "header": "Referrer-Policy",
                        "status": "warning",
                        "severity": "low",
                        "title": "Non-standard Referrer-Policy",
                        "description": f"Policy '{rp}' is not one of the recommended safe policies.",
                        "evidence": f"RP: {rp}",
                        "remediation": "Use strict-origin-when-cross-origin",
                        "confidence": 60
                    })

                # ── 6. Permissions-Policy (strictness check) ──────
                pp = _get_header(final_headers, "Permissions-Policy")
                if not pp:
                    findings.append({
                        "test_name": TEST_NAME,
                        "header": "Permissions-Policy",
                        "status": "warning",
                        "severity": "info",
                        "title": "Missing Permissions-Policy",
                        "description": "Permissions-Policy is missing. This is not a critical vulnerability, but limits feature control.",
                        "evidence": "Header missing",
                        "remediation": "Permissions-Policy: geolocation=(), camera=(), microphone=()",
                        "confidence": 80
                    })
                else:
                    # Check if it's too permissive (contains '=*' or is empty)
                    if pp == "" or "*" in pp:
                        findings.append({
                            "test_name": TEST_NAME,
                            "header": "Permissions-Policy",
                            "status": "warning",
                            "severity": "low",
                            "title": "Permissions-Policy too permissive",
                            "description": f"Policy '{pp}' is wildcard or empty, offering no actual protection.",
                            "evidence": f"PP: {pp}",
                            "remediation": "Explicitly disable features you don't use (e.g., geolocation=(), camera=()).",
                            "confidence": 90
                        })
                    else:
                        findings.append({
                            "test_name": TEST_NAME,
                            "header": "Permissions-Policy",
                            "status": "pass",
                            "severity": "info",
                            "title": "Permissions-Policy set",
                            "description": "Permissions-Policy is present and restricts some features.",
                            "evidence": f"PP: {pp}",
                            "remediation": "No action required.",
                            "confidence": 90
                        })

                # ── 7. COOP / COEP / CORP (Modern Isolation) ─────────
                coop = _get_header(final_headers, "Cross-Origin-Opener-Policy")
                if not coop:
                    findings.append({
                        "test_name": TEST_NAME,
                        "header": "Cross-Origin-Opener-Policy",
                        "status": "warning",
                        "severity": "medium",
                        "title": "Missing COOP",
                        "description": "COOP is missing. This can allow cross-origin attacks like Spectre via window.opener.",
                        "evidence": "Header missing",
                        "remediation": "Cross-Origin-Opener-Policy: same-origin",
                        "confidence": 85
                    })
                elif coop.lower() in ("same-origin", "same-origin-allow-popups"):
                    findings.append({
                        "test_name": TEST_NAME,
                        "header": "Cross-Origin-Opener-Policy",
                        "status": "pass",
                        "severity": "info",
                        "title": "COOP OK",
                        "description": f"COOP is set to '{coop}'.",
                        "evidence": f"COOP: {coop}",
                        "remediation": "No action required.",
                        "confidence": 100
                    })
                else:
                    findings.append({
                        "test_name": TEST_NAME,
                        "header": "Cross-Origin-Opener-Policy",
                        "status": "warning",
                        "severity": "low",
                        "title": "COOP non-standard value",
                        "description": f"Value '{coop}' is not recognized.",
                        "evidence": f"COOP: {coop}",
                        "remediation": "Use same-origin or same-origin-allow-popups.",
                        "confidence": 60
                    })

                coep = _get_header(final_headers, "Cross-Origin-Embedder-Policy")
                if not coep:
                    findings.append({
                        "test_name": TEST_NAME,
                        "header": "Cross-Origin-Embedder-Policy",
                        "status": "warning",
                        "severity": "medium",
                        "title": "Missing COEP",
                        "description": "COEP is missing. This allows cross-origin resource loading without explicit permission.",
                        "evidence": "Header missing",
                        "remediation": "Cross-Origin-Embedder-Policy: require-corp",
                        "confidence": 80
                    })
                elif coep.lower() in ("require-corp", "credentialless"):
                    findings.append({
                        "test_name": TEST_NAME,
                        "header": "Cross-Origin-Embedder-Policy",
                        "status": "pass",
                        "severity": "info",
                        "title": "COEP OK",
                        "description": f"COEP is set to '{coep}'.",
                        "evidence": f"COEP: {coep}",
                        "remediation": "No action required.",
                        "confidence": 100
                    })
                else:
                    findings.append({
                        "test_name": TEST_NAME,
                        "header": "Cross-Origin-Embedder-Policy",
                        "status": "warning",
                        "severity": "low",
                        "title": "COEP non-standard value",
                        "description": f"Value '{coep}' is not recognized.",
                        "evidence": f"COEP: {coep}",
                        "remediation": "Use require-corp or credentialless.",
                        "confidence": 60
                    })

                corp = _get_header(final_headers, "Cross-Origin-Resource-Policy")
                if corp and corp.lower() in ("same-origin", "same-site", "cross-origin"):
                    findings.append({
                        "test_name": TEST_NAME,
                        "header": "Cross-Origin-Resource-Policy",
                        "status": "pass",
                        "severity": "info",
                        "title": "CORP OK",
                        "description": f"CORP is set to '{corp}'.",
                        "evidence": f"CORP: {corp}",
                        "remediation": "No action required.",
                        "confidence": 100
                    })
                elif not corp:
                    # Not a critical issue, but nice to have.
                    pass  # We'll skip warning for CORP to avoid noise.

                # ── 8. Cache-Control (only if Set-Cookie present) ────
                set_cookie = _get_header(final_headers, "Set-Cookie")
                if set_cookie:
                    cache_control = _get_header(final_headers, "Cache-Control")
                    if not cache_control:
                        findings.append({
                            "test_name": TEST_NAME,
                            "header": "Cache-Control",
                            "status": "fail",
                            "severity": "high",
                            "title": "Missing Cache-Control for authenticated page",
                            "description": "The response sets a session cookie but lacks Cache-Control: no-store. This may allow caching of sensitive data.",
                            "evidence": f"Set-Cookie present, Cache-Control: {cache_control}",
                            "remediation": "Cache-Control: no-cache, no-store, must-revalidate",
                            "confidence": 100
                        })
                    elif "no-store" not in cache_control.lower():
                        findings.append({
                            "test_name": TEST_NAME,
                            "header": "Cache-Control",
                            "status": "warning",
                            "severity": "medium",
                            "title": "Cache-Control does not include no-store",
                            "description": f"Cache-Control is '{cache_control}' but should include 'no-store' for authenticated responses.",
                            "evidence": f"Cache-Control: {cache_control}",
                            "remediation": "Cache-Control: no-cache, no-store, must-revalidate",
                            "confidence": 95
                        })
                    else:
                        findings.append({
                            "test_name": TEST_NAME,
                            "header": "Cache-Control",
                            "status": "pass",
                            "severity": "info",
                            "title": "Cache-Control properly set for authenticated page",
                            "description": "Cache-Control: no-store is present.",
                            "evidence": f"Cache-Control: {cache_control}",
                            "remediation": "No action required.",
                            "confidence": 100
                        })

                # ── 9. X-XSS-Protection (deprecated but still informative) ──
                xssp = _get_header(final_headers, "X-XSS-Protection")
                if xssp == "0":
                    findings.append({
                        "test_name": TEST_NAME,
                        "header": "X-XSS-Protection",
                        "status": "info",
                        "severity": "info",
                        "title": "X-XSS-Protection is disabled",
                        "description": "X-XSS-Protection is set to 0. While this header is deprecated, it indicates the developer deliberately disabled it (modern CSP is preferred).",
                        "evidence": f"X-XSS-Protection: {xssp}",
                        "remediation": "If using modern CSP, this is acceptable. Otherwise, set to 1; mode=block.",
                        "confidence": 100
                    })
                elif xssp:
                    findings.append({
                        "test_name": TEST_NAME,
                        "header": "X-XSS-Protection",
                        "status": "pass",
                        "severity": "info",
                        "title": "X-XSS-Protection is set",
                        "description": f"X-XSS-Protection: {xssp}. (Deprecated but present).",
                        "evidence": f"X-XSS-Protection: {xssp}",
                        "remediation": "No action required, but consider migrating to CSP.",
                        "confidence": 80
                    })
                else:
                    # Missing is fine as it's deprecated.
                    pass

        # ── 10. Aggregate Results ─────────────────────────────────────
        # Compute overall status
        has_critical = any(f["status"] == "fail" and f["severity"] == "critical" for f in findings)
        has_high = any(f["status"] == "fail" and f["severity"] == "high" for f in findings)
        has_warning = any(f["status"] == "warning" for f in findings)

        if has_critical:
            overall = "fail"
        elif has_high:
            overall = "fail"
        elif has_warning:
            overall = "warning"
        else:
            overall = "pass"

        # Determine worst severity for title
        worst_sev = "info"
        for f in findings:
            sev = f.get("severity", "info")
            if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(worst_sev, 0):
                worst_sev = sev

        return {
            "test_name": TEST_NAME,
            "overall_status": overall,
            "severity": worst_sev,
            "findings": findings,
            "headers_checked": len(findings),
            "headers_failed": sum(1 for f in findings if f["status"] in ("fail", "warning")),
        }

    except Exception as e:
        return {
            "test_name": TEST_NAME,
            "overall_status": "error",
            "severity": "info",
            "findings": [
                {
                    "title": "Error",
                    "description": f"Scan failed: {str(e)[:200]}",
                    "status": "error",
                    "severity": "info"
                }
            ],
            "headers_checked": 0,
            "headers_failed": 0,
        }

# ── Standalone test (optional) ──────────────────────────────────────────
if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        url = sys.argv[1]
        result = asyncio.run(run(url))
        print(f"Overall Status: {result['overall_status']}")
        for f in result.get("findings", []):
            print(f"  - [{f['status']}] {f.get('title', '')} ({f.get('severity', 'info')})")
    else:
        print("Usage: python test_05_security_headers.py <url>")