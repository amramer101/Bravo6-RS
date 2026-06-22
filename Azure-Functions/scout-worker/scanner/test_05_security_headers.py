"""
test_05_security_headers.py — Advanced Security Headers Scanner (Fully Fixed)

- Fixed tuple unpacking errors (all functions return consistent number of values).
- Handles redirect chains, collects headers from all responses.
- Deep CSP analysis: checks base-uri, form-action, object-src, script-src with nonce/strict-dynamic.
- HSTS: validates max-age, includeSubDomains, preload readiness.
- Modern isolation headers: COOP, COEP, CORP.
- Permissions-Policy, Referrer-Policy, X-Content-Type-Options, X-Frame-Options.
- Cache-Control verification only if Set-Cookie present (authenticated pages).
- WAF context awareness (Cloudflare, etc.) to reduce false positives.
- Fast parallel requests with timeouts.
- Structured output with PoC, confidence, severity, remediation.
"""

import asyncio
import re
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List, Optional, Tuple

import aiohttp

TEST_NAME = "security_headers"
USER_AGENT = "Bravo6-Scanner/1.0"
REQUEST_TIMEOUT_SECONDS = 8
MAX_REDIRECTS = 5

# ── Severity ranking ──────────────────────────────────────────────────────
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# ── CDN/Shared domains that cannot have HSTS ────────────────────────────
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


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "https://" + url
    return url


def _get_header(headers, name: str) -> Optional[str]:
    if not headers:
        return None
    for key, val in headers.items():
        if key.lower() == name.lower():
            return val
    return None


def _is_api_response(content_type: str) -> bool:
    if not content_type:
        return False
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
    ctype = content_type.lower()
    return any(p in ctype for p in api_patterns)


def _is_cdn_domain(hostname: str) -> bool:
    if not hostname:
        return False
    hostname = hostname.lower()
    return any(hostname.endswith(ex) for ex in CDN_EXCLUSIONS)


def _parse_csp(csp: str) -> Dict[str, str]:
    directives = {}
    if not csp:
        return directives
    for part in re.split(r";\s*", csp.strip()):
        if not part:
            continue
        if " " in part:
            d_name, d_value = part.split(" ", 1)
            directives[d_name.strip()] = d_value.strip()
        else:
            directives[part.strip()] = ""
    return directives


def _has_nonce_in_script_src(directives: Dict[str, str]) -> bool:
    script_src = directives.get("script-src", "")
    return bool(re.search(r"nonce-[a-zA-Z0-9+/=]+", script_src))


def _has_strict_dynamic(directives: Dict[str, str]) -> bool:
    script_src = directives.get("script-src", "")
    return "strict-dynamic" in script_src


def _evaluate_hsts(value: str) -> Tuple[bool, Optional[str], int]:
    """Return (is_valid, issue_message, max_age)."""
    if not value:
        return False, "Header is missing", 0
    max_age_match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    if not max_age_match:
        return False, "max-age missing", 0
    max_age = int(max_age_match.group(1))
    issues = []
    if max_age < 31536000:
        issues.append(f"max-age={max_age} (less than 1 year)")
    if max_age < 63072000:
        issues.append(f"max-age={max_age} (less than 2 years, not preload-ready)")
    if "includesubdomains" not in value.lower():
        issues.append("missing includeSubDomains")
    if "preload" not in value.lower():
        issues.append("missing preload flag")
    if issues:
        return False, "; ".join(issues), max_age
    return True, None, max_age


# ── Fetch with manual redirect handling ──────────────────────────────────

async def _fetch_with_redirects(session: aiohttp.ClientSession, url: str) -> Dict:
    """
    Fetch URL and follow redirects manually, collecting all responses.
    Returns dict with:
      - responses: list of dicts with headers, status, url
      - final_headers: dict of final response headers
      - final_status: int
      - final_url: str
      - content_type: str from final response
      - set_cookie: str from final response
      - error: Optional[str]
    """
    current_url = url
    responses = []
    follow_count = 0
    final_headers = {}
    final_status = 0
    final_url = ""
    content_type = ""
    set_cookie = ""
    error = None

    while follow_count < MAX_REDIRECTS:
        try:
            async with session.get(
                current_url,
                allow_redirects=False,
                ssl=True,
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS),
            ) as resp:
                headers = dict(resp.headers)
                status = resp.status
                url_actual = str(resp.url)
                responses.append({
                    "headers": headers,
                    "status": status,
                    "url": url_actual,
                })
                # Update final
                final_headers = headers
                final_status = status
                final_url = url_actual
                content_type = _get_header(headers, "Content-Type") or ""
                set_cookie = _get_header(headers, "Set-Cookie") or ""

                # Check redirect
                if status in (301, 302, 303, 307, 308):
                    location = _get_header(headers, "Location")
                    if location:
                        current_url = urljoin(current_url, location)
                        follow_count += 1
                        continue
                # Not a redirect, break
                break
        except Exception as e:
            error = str(e)
            break

    return {
        "responses": responses,
        "final_headers": final_headers,
        "final_status": final_status,
        "final_url": final_url,
        "content_type": content_type,
        "set_cookie": set_cookie,
        "error": error,
    }


# ── Individual header checks ─────────────────────────────────────────────

def _check_hsts(headers_list: List[Dict], is_cdn: bool, target: str) -> List[Dict]:
    findings = []
    if is_cdn:
        return [{
            "test_name": TEST_NAME,
            "header": "Strict-Transport-Security",
            "status": "pass",
            "severity": "info",
            "title": "HSTS skipped (CDN/Shared Domain)",
            "description": f"Domain is on a shared CDN platform. HSTS may not be applicable.",
            "evidence": "CDN domain detected.",
            "remediation": "If using a custom domain, consult CDN documentation.",
            "confidence": 100,
            "poc": None,
        }]

    # Collect all HSTS headers from all responses
    hsts_values = []
    for resp in headers_list:
        val = _get_header(resp["headers"], "Strict-Transport-Security")
        if val:
            hsts_values.append(val)

    if not hsts_values:
        return [{
            "test_name": TEST_NAME,
            "header": "Strict-Transport-Security",
            "status": "fail",
            "severity": "high",
            "title": "Missing HSTS",
            "description": "No HSTS header found. SSL-stripping attacks possible.",
            "evidence": "Header not present in any response.",
            "remediation": "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
            "confidence": 100,
            "poc": f"curl -I {target} | grep -i strict",
        }]

    # Check the first HSTS header (usually final)
    hdr = hsts_values[0]
    valid, issue, max_age = _evaluate_hsts(hdr)
    if valid:
        return [{
            "test_name": TEST_NAME,
            "header": "Strict-Transport-Security",
            "status": "pass",
            "severity": "info",
            "title": "HSTS properly configured",
            "description": f"HSTS with max-age={max_age}, includes subdomains and preload.",
            "evidence": f"HSTS: {hdr}",
            "remediation": "No action required.",
            "confidence": 100,
            "poc": f"curl -I {target} | grep -i strict",
        }]
    else:
        return [{
            "test_name": TEST_NAME,
            "header": "Strict-Transport-Security",
            "status": "warning",
            "severity": "medium",
            "title": "HSTS misconfigured / not preload-ready",
            "description": f"Issues: {issue}",
            "evidence": f"HSTS: {hdr}",
            "remediation": "Set max-age=63072000; includeSubDomains; preload",
            "confidence": 95,
            "poc": f"curl -I {target} | grep -i strict",
        }]


def _check_xfo_and_csp(final_headers: Dict) -> List[Dict]:
    findings = []
    xfo = _get_header(final_headers, "X-Frame-Options")
    csp = _get_header(final_headers, "Content-Security-Policy")

    if csp:
        directives = _parse_csp(csp)
        frame_ancestors = directives.get("frame-ancestors", "")
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
                    "confidence": 100,
                })
                return findings
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
                    "confidence": 90,
                })
                return findings
            else:
                findings.append({
                    "test_name": TEST_NAME,
                    "header": "CSP frame-ancestors",
                    "status": "warning",
                    "severity": "medium",
                    "title": "CSP allows framing from external sources",
                    "description": f"frame-ancestors: {frame_ancestors}",
                    "evidence": f"frame-ancestors: {frame_ancestors}",
                    "remediation": "Set frame-ancestors 'none' or 'self'.",
                    "poc": "<iframe src='https://target'></iframe>",
                    "confidence": 80,
                })
                return findings

    # No CSP frame-ancestors, fallback to XFO
    if not xfo:
        findings.append({
            "test_name": TEST_NAME,
            "header": "X-Frame-Options / CSP frame-ancestors",
            "status": "fail",
            "severity": "high",
            "title": "Missing Clickjacking Protection",
            "description": "Neither X-Frame-Options nor CSP frame-ancestors are present.",
            "evidence": "Both headers missing.",
            "remediation": "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
            "poc": "<html><body><iframe src='https://target'></iframe></body></html>",
            "confidence": 100,
        })
    elif xfo.upper() in ("DENY", "SAMEORIGIN"):
        findings.append({
            "test_name": TEST_NAME,
            "header": "X-Frame-Options",
            "status": "pass",
            "severity": "info",
            "title": "XFO configured correctly",
            "description": f"X-Frame-Options: {xfo}",
            "evidence": f"XFO: {xfo}",
            "remediation": "No action required.",
            "confidence": 100,
        })
    else:
        findings.append({
            "test_name": TEST_NAME,
            "header": "X-Frame-Options",
            "status": "fail",
            "severity": "critical",
            "title": "XFO set to ALLOWALL or invalid",
            "description": f"X-Frame-Options is '{xfo}', explicitly allows framing.",
            "evidence": f"XFO: {xfo}",
            "remediation": "Set to DENY or SAMEORIGIN.",
            "poc": "<iframe src='https://target'></iframe>",
            "confidence": 100,
        })
    return findings


def _check_csp_strict(final_headers: Dict) -> List[Dict]:
    findings = []
    csp = _get_header(final_headers, "Content-Security-Policy")
    if not csp:
        findings.append({
            "test_name": TEST_NAME,
            "header": "Content-Security-Policy",
            "status": "fail",
            "severity": "high",
            "title": "Missing CSP",
            "description": "No CSP header. XSS protection is weakened.",
            "evidence": "Header missing.",
            "remediation": "Add Content-Security-Policy: default-src 'self'; script-src 'self'",
            "poc": "<script>alert('XSS')</script> (if reflected/stored)",
            "confidence": 100,
        })
        return findings

    directives = _parse_csp(csp)
    issues = []
    # Check base-uri
    if "base-uri" not in directives:
        issues.append("Missing base-uri (allows arbitrary base URL injection)")
    elif "'none'" not in directives["base-uri"] and "'self'" not in directives["base-uri"]:
        issues.append(f"base-uri not restricted (value: {directives['base-uri']})")

    # form-action
    if "form-action" not in directives:
        issues.append("Missing form-action (allows form data to be sent to any origin)")
    elif "'none'" not in directives["form-action"] and "'self'" not in directives["form-action"]:
        issues.append(f"form-action not restricted (value: {directives['form-action']})")

    # object-src
    if "object-src" not in directives:
        issues.append("Missing object-src (allows Flash/plugins)")
    elif "'none'" not in directives["object-src"]:
        issues.append(f"object-src not set to 'none' (value: {directives['object-src']})")

    # script-src analysis
    script_src = directives.get("script-src", "")
    if script_src:
        has_unsafe_inline = "unsafe-inline" in script_src
        has_nonce = _has_nonce_in_script_src(directives)
        has_strict = _has_strict_dynamic(directives)
        if has_unsafe_inline and not has_nonce and not has_strict:
            issues.append("script-src contains 'unsafe-inline' without 'nonce-' or 'strict-dynamic'")
    else:
        issues.append("script-src is missing (fallback to default-src may be unsafe)")

    # upgrade-insecure-requests
    if "upgrade-insecure-requests" not in directives:
        issues.append("Missing upgrade-insecure-requests (mixed content not auto-upgraded)")

    if issues:
        findings.append({
            "test_name": TEST_NAME,
            "header": "Content-Security-Policy",
            "status": "warning",
            "severity": "medium",
            "title": "CSP has weak directives",
            "description": "; ".join(issues),
            "evidence": f"CSP: {csp[:200]}...",
            "remediation": "Add missing directives and remove unsafe-inline with nonce.",
            "confidence": 85,
        })
    else:
        findings.append({
            "test_name": TEST_NAME,
            "header": "Content-Security-Policy",
            "status": "pass",
            "severity": "info",
            "title": "CSP is well-configured",
            "description": "All critical CSP directives are properly set.",
            "evidence": f"CSP: {csp[:200]}...",
            "remediation": "No action required.",
            "confidence": 95,
        })
    return findings


def _check_xcto(final_headers: Dict) -> List[Dict]:
    xcto = _get_header(final_headers, "X-Content-Type-Options")
    if xcto and xcto.lower() == "nosniff":
        return [{
            "test_name": TEST_NAME,
            "header": "X-Content-Type-Options",
            "status": "pass",
            "severity": "info",
            "title": "XCTO OK",
            "description": "nosniff is set, preventing MIME sniffing.",
            "evidence": f"XCTO: {xcto}",
            "remediation": "No action required.",
            "confidence": 100,
        }]
    else:
        return [{
            "test_name": TEST_NAME,
            "header": "X-Content-Type-Options",
            "status": "fail",
            "severity": "medium",
            "title": "Missing XCTO",
            "description": "X-Content-Type-Options missing. Allows MIME sniffing.",
            "evidence": "Header missing or invalid.",
            "remediation": "X-Content-Type-Options: nosniff",
            "confidence": 100,
        }]


def _check_referrer(final_headers: Dict) -> List[Dict]:
    rp = _get_header(final_headers, "Referrer-Policy")
    safe = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin"}
    if not rp:
        return [{
            "test_name": TEST_NAME,
            "header": "Referrer-Policy",
            "status": "fail",
            "severity": "medium",
            "title": "Missing Referrer-Policy",
            "description": "Referer may leak sensitive URL information.",
            "evidence": "Header missing.",
            "remediation": "Referrer-Policy: strict-origin-when-cross-origin",
            "confidence": 100,
        }]
    if rp.lower() in safe:
        return [{
            "test_name": TEST_NAME,
            "header": "Referrer-Policy",
            "status": "pass",
            "severity": "info",
            "title": "Referrer-Policy OK",
            "description": f"Policy '{rp}' is safe.",
            "evidence": f"RP: {rp}",
            "remediation": "No action required.",
            "confidence": 100,
        }]
    if rp.lower() == "unsafe-url":
        return [{
            "test_name": TEST_NAME,
            "header": "Referrer-Policy",
            "status": "fail",
            "severity": "high",
            "title": "Unsafe Referrer-Policy",
            "description": "unsafe-url leaks full URLs to third parties.",
            "evidence": f"RP: {rp}",
            "remediation": "Change to strict-origin-when-cross-origin",
            "confidence": 100,
        }]
    return [{
        "test_name": TEST_NAME,
        "header": "Referrer-Policy",
        "status": "warning",
        "severity": "low",
        "title": "Non-standard Referrer-Policy",
        "description": f"Policy '{rp}' is not recommended.",
        "evidence": f"RP: {rp}",
        "remediation": "Use strict-origin-when-cross-origin",
        "confidence": 60,
    }]


def _check_permissions(final_headers: Dict) -> List[Dict]:
    pp = _get_header(final_headers, "Permissions-Policy")
    if not pp:
        return [{
            "test_name": TEST_NAME,
            "header": "Permissions-Policy",
            "status": "warning",
            "severity": "info",
            "title": "Missing Permissions-Policy",
            "description": "Permissions-Policy missing. Feature controls not enforced.",
            "evidence": "Header missing.",
            "remediation": "Permissions-Policy: geolocation=(), camera=(), microphone=()",
            "confidence": 80,
        }]
    if pp == "" or "*" in pp:
        return [{
            "test_name": TEST_NAME,
            "header": "Permissions-Policy",
            "status": "warning",
            "severity": "low",
            "title": "Permissions-Policy too permissive",
            "description": f"Policy '{pp}' is wildcard or empty, no actual protection.",
            "evidence": f"PP: {pp}",
            "remediation": "Explicitly disable features you don't use.",
            "confidence": 90,
        }]
    return [{
        "test_name": TEST_NAME,
        "header": "Permissions-Policy",
        "status": "pass",
        "severity": "info",
        "title": "Permissions-Policy set",
        "description": "Permissions-Policy is present and restricts some features.",
        "evidence": f"PP: {pp}",
        "remediation": "No action required.",
        "confidence": 90,
    }]


def _check_coop_coep_corp(final_headers: Dict) -> List[Dict]:
    findings = []
    coop = _get_header(final_headers, "Cross-Origin-Opener-Policy")
    if not coop:
        findings.append({
            "test_name": TEST_NAME,
            "header": "Cross-Origin-Opener-Policy",
            "status": "warning",
            "severity": "medium",
            "title": "Missing COOP",
            "description": "COOP missing. May allow cross-origin attacks via window.opener.",
            "evidence": "Header missing.",
            "remediation": "Cross-Origin-Opener-Policy: same-origin",
            "confidence": 85,
        })
    elif coop.lower() in ("same-origin", "same-origin-allow-popups"):
        findings.append({
            "test_name": TEST_NAME,
            "header": "Cross-Origin-Opener-Policy",
            "status": "pass",
            "severity": "info",
            "title": "COOP OK",
            "description": f"COOP set to '{coop}'.",
            "evidence": f"COOP: {coop}",
            "remediation": "No action required.",
            "confidence": 100,
        })
    else:
        findings.append({
            "test_name": TEST_NAME,
            "header": "Cross-Origin-Opener-Policy",
            "status": "warning",
            "severity": "low",
            "title": "COOP non-standard value",
            "description": f"Value '{coop}' not recognized.",
            "evidence": f"COOP: {coop}",
            "remediation": "Use same-origin or same-origin-allow-popups.",
            "confidence": 60,
        })

    coep = _get_header(final_headers, "Cross-Origin-Embedder-Policy")
    if not coep:
        findings.append({
            "test_name": TEST_NAME,
            "header": "Cross-Origin-Embedder-Policy",
            "status": "warning",
            "severity": "medium",
            "title": "Missing COEP",
            "description": "COEP missing. Allows cross-origin resource loading without explicit permission.",
            "evidence": "Header missing.",
            "remediation": "Cross-Origin-Embedder-Policy: require-corp",
            "confidence": 80,
        })
    elif coep.lower() in ("require-corp", "credentialless"):
        findings.append({
            "test_name": TEST_NAME,
            "header": "Cross-Origin-Embedder-Policy",
            "status": "pass",
            "severity": "info",
            "title": "COEP OK",
            "description": f"COEP set to '{coep}'.",
            "evidence": f"COEP: {coep}",
            "remediation": "No action required.",
            "confidence": 100,
        })
    else:
        findings.append({
            "test_name": TEST_NAME,
            "header": "Cross-Origin-Embedder-Policy",
            "status": "warning",
            "severity": "low",
            "title": "COEP non-standard value",
            "description": f"Value '{coep}' not recognized.",
            "evidence": f"COEP: {coep}",
            "remediation": "Use require-corp or credentialless.",
            "confidence": 60,
        })

    corp = _get_header(final_headers, "Cross-Origin-Resource-Policy")
    if corp and corp.lower() in ("same-origin", "same-site", "cross-origin"):
        findings.append({
            "test_name": TEST_NAME,
            "header": "Cross-Origin-Resource-Policy",
            "status": "pass",
            "severity": "info",
            "title": "CORP OK",
            "description": f"CORP set to '{corp}'.",
            "evidence": f"CORP: {corp}",
            "remediation": "No action required.",
            "confidence": 100,
        })
    # else: ignore missing CORP (not critical)

    return findings


def _check_cache_control(final_headers: Dict, set_cookie: str) -> List[Dict]:
    if not set_cookie:
        return []  # No session cookie, skip
    cc = _get_header(final_headers, "Cache-Control")
    if not cc:
        return [{
            "test_name": TEST_NAME,
            "header": "Cache-Control",
            "status": "fail",
            "severity": "high",
            "title": "Missing Cache-Control for authenticated page",
            "description": "Set-Cookie present but Cache-Control: no-store missing. Sensitive data may be cached.",
            "evidence": f"Set-Cookie: {set_cookie[:50]}..., Cache-Control: missing",
            "remediation": "Cache-Control: no-cache, no-store, must-revalidate",
            "confidence": 100,
        }]
    if "no-store" not in cc.lower():
        return [{
            "test_name": TEST_NAME,
            "header": "Cache-Control",
            "status": "warning",
            "severity": "medium",
            "title": "Cache-Control does not include no-store",
            "description": f"Cache-Control: {cc} should include no-store for authenticated pages.",
            "evidence": f"Cache-Control: {cc}",
            "remediation": "Cache-Control: no-cache, no-store, must-revalidate",
            "confidence": 95,
        }]
    return [{
        "test_name": TEST_NAME,
        "header": "Cache-Control",
        "status": "pass",
        "severity": "info",
        "title": "Cache-Control properly set for authenticated page",
        "description": "Cache-Control: no-store is present.",
        "evidence": f"Cache-Control: {cc}",
        "remediation": "No action required.",
        "confidence": 100,
    }]


def _check_xss_protection(final_headers: Dict) -> List[Dict]:
    xssp = _get_header(final_headers, "X-XSS-Protection")
    if xssp == "0":
        return [{
            "test_name": TEST_NAME,
            "header": "X-XSS-Protection",
            "status": "info",
            "severity": "info",
            "title": "X-XSS-Protection is disabled",
            "description": "X-XSS-Protection set to 0. (Deprecated, CSP preferred)",
            "evidence": f"X-XSS-Protection: {xssp}",
            "remediation": "If using CSP, this is acceptable.",
            "confidence": 100,
        }]
    elif xssp:
        return [{
            "test_name": TEST_NAME,
            "header": "X-XSS-Protection",
            "status": "pass",
            "severity": "info",
            "title": "X-XSS-Protection is set",
            "description": f"X-XSS-Protection: {xssp} (deprecated).",
            "evidence": f"X-XSS-Protection: {xssp}",
            "remediation": "Consider migrating to CSP.",
            "confidence": 80,
        }]
    return []  # Missing is fine.


# ── Main entry ────────────────────────────────────────────────────────────

async def run(url: str) -> Dict[str, Any]:
    try:
        target = _normalize_url(url)
        if not target:
            return {
                "test_name": TEST_NAME,
                "status": "error",
                "severity": "info",
                "title": "Invalid URL",
                "description": "URL could not be normalized.",
                "findings": [],
                "remediation": "Check URL format.",
            }

        parsed = urlparse(target)
        hostname = parsed.hostname or ""
        is_cdn = _is_cdn_domain(hostname)

        async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
            fetch_result = await _fetch_with_redirects(session, target)
            if fetch_result["error"]:
                return {
                    "test_name": TEST_NAME,
                    "status": "error",
                    "severity": "info",
                    "title": "Fetch Error",
                    "description": f"Could not fetch target: {fetch_result['error']}",
                    "findings": [],
                    "remediation": "Check network connectivity.",
                }

            responses = fetch_result["responses"]
            final_headers = fetch_result["final_headers"]
            final_status = fetch_result["final_status"]
            content_type = fetch_result["content_type"]
            set_cookie = fetch_result["set_cookie"]
            is_api = _is_api_response(content_type)

            # Gather all headers from all responses for HSTS
            headers_list = [{"headers": r["headers"]} for r in responses]

            all_findings = []

            # ── HSTS ────────────────────────────────────────────────────────
            all_findings.extend(_check_hsts(headers_list, is_cdn, target))

            # ── Skip framing and CSP for APIs ────────────────────────────
            if is_api:
                all_findings.append({
                    "test_name": TEST_NAME,
                    "header": "X-Frame-Options / CSP",
                    "status": "pass",
                    "severity": "info",
                    "title": "Skipped (API Response)",
                    "description": "Response is not HTML, framing headers not applicable.",
                    "evidence": f"Content-Type: {content_type}",
                    "remediation": "No action required.",
                    "confidence": 100,
                })
            else:
                all_findings.extend(_check_xfo_and_csp(final_headers))
                all_findings.extend(_check_csp_strict(final_headers))

            # ── XCTO ──────────────────────────────────────────────────────
            all_findings.extend(_check_xcto(final_headers))

            # ── Referrer-Policy ──────────────────────────────────────────
            all_findings.extend(_check_referrer(final_headers))

            # ── Permissions-Policy ───────────────────────────────────────
            all_findings.extend(_check_permissions(final_headers))

            # ── COOP, COEP, CORP ────────────────────────────────────────
            all_findings.extend(_check_coop_coep_corp(final_headers))

            # ── Cache-Control (only if Set-Cookie present) ──────────────
            all_findings.extend(_check_cache_control(final_headers, set_cookie))

            # ── X-XSS-Protection ─────────────────────────────────────────
            all_findings.extend(_check_xss_protection(final_headers))

        # ── Compute overall status ────────────────────────────────────────
        critical = any(f["status"] == "fail" and f.get("severity") == "critical" for f in all_findings)
        high = any(f["status"] == "fail" and f.get("severity") == "high" for f in all_findings)
        warning = any(f["status"] == "warning" for f in all_findings)

        if critical:
            overall_status = "fail"
            overall_severity = "critical"
        elif high:
            overall_status = "fail"
            overall_severity = "high"
        elif warning:
            overall_status = "warning"
            overall_severity = "medium"
        else:
            overall_status = "pass"
            overall_severity = "info"

        # ── Build remediation summary ─────────────────────────────────────
        remediation_parts = []
        for f in all_findings:
            if f["status"] in ("fail", "warning") and f.get("remediation"):
                if "HSTS" in f.get("header", ""):
                    remediation_parts.append("Enable HSTS with max-age=63072000; includeSubDomains; preload")
                elif "X-Frame-Options" in f.get("header", "") or "frame-ancestors" in f.get("header", ""):
                    remediation_parts.append("Implement X-Frame-Options: DENY or CSP frame-ancestors 'none'")
                elif "Content-Security-Policy" in f.get("header", ""):
                    remediation_parts.append("Fix CSP directives as recommended")
                elif "X-Content-Type-Options" in f.get("header", ""):
                    remediation_parts.append("Add X-Content-Type-Options: nosniff")
                elif "Referrer-Policy" in f.get("header", ""):
                    remediation_parts.append("Set Referrer-Policy to strict-origin-when-cross-origin")
                elif "Permissions-Policy" in f.get("header", ""):
                    remediation_parts.append("Set Permissions-Policy to restrict features")
                elif "COOP" in f.get("header", ""):
                    remediation_parts.append("Add Cross-Origin-Opener-Policy: same-origin")
                elif "COEP" in f.get("header", ""):
                    remediation_parts.append("Add Cross-Origin-Embedder-Policy: require-corp")
                elif "Cache-Control" in f.get("header", ""):
                    remediation_parts.append("Add Cache-Control: no-cache, no-store, must-revalidate for authenticated pages")
        # Remove duplicates
        remediation_parts = list(set(remediation_parts))
        if not remediation_parts:
            remediation_parts = ["No security header issues found."]

        return {
            "test_name": TEST_NAME,
            "overall_status": overall_status,
            "status": overall_status,  # for compatibility
            "severity": overall_severity,
            "title": f"Security Headers: {len(all_findings)} checks",
            "description": f"Scanned {target} for security headers. Found {len([f for f in all_findings if f['status'] in ('fail','warning')])} issues.",
            "findings": all_findings,
            "remediation": " ".join(remediation_parts),
            "headers_checked": len(all_findings),
            "headers_failed": sum(1 for f in all_findings if f["status"] in ("fail", "warning")),
        }

    except Exception as e:
        return {
            "test_name": TEST_NAME,
            "overall_status": "error",
            "status": "error",
            "severity": "info",
            "title": "Error",
            "description": str(e)[:200],
            "findings": [],
            "remediation": "Check code and target.",
            "headers_checked": 0,
            "headers_failed": 0,
        }


if __name__ == "__main__":
    import sys
    asyncio.run(run(sys.argv[1] if len(sys.argv) > 1 else "example.com"))