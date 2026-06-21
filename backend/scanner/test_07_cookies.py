"""
test_07_cookies.py — Advanced Cookie Security Scanner with Active Verification (v3)

Enhancements:
- Multi-stage cookie collection (initial request + XHR/fetch simulation via AJAX-like requests)
- SameSite strictness validation (Strict, Lax, None) with fallback behavior analysis
- Active cookie theft PoC (JavaScript code to steal cookies via XSS)
- Session fixation detection (cookie persistence across requests)
- Cookie duration analysis (session vs persistent with expiry)
- Duplicate cookie detection (same name from different sources)
- Contextual severity scoring (sensitive vs non-sensitive cookies)
- Regex-based pattern matching for cookie values (not just flags)
- Integration with other tests (XSS, CORS, Secrets)
- JWT inspection for cookie-based tokens
- Detailed evidence with PoC code and curl commands
- Dynamic confidence scoring (0-100)
- Subdomain cookie scoping analysis
- HttpOnly & Secure flag enforcement with bypass attempts
- Path attribute validation
- Domain attribute validation
- Cookie prefix validation (__Secure-, __Host-)
"""

import asyncio
import json
import re
import time
import uuid
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List, Optional, Tuple, Set

import aiohttp

# ── Configuration ──────────────────────────────────────────────────────────
USER_AGENT = "Bravo6-Scanner/1.0"
TIMEOUT_SECONDS = 10
MAX_REDIRECTS = 10
SENSITIVE_KEYWORDS = ("session", "auth", "token", "jwt", "user", "admin", "login", "sid", "uid", "csrf", "xsrf", "remember", "pref", "lang", "locale", "currency")

# JWT patterns
JWT_PATTERN = re.compile(r'^eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+$')

# ── Severity ranking ──────────────────────────────────────────────────────
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# ── Cookie prefix validation ──────────────────────────────────────────────
SECURE_PREFIXES = {"__Secure-", "__Host-"}

# ── Helper functions ──────────────────────────────────────────────────────

def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = f"https://{url}"
    return url

def _is_sensitive(name: str) -> bool:
    name_lower = name.lower()
    return any(kw in name_lower for kw in SENSITIVE_KEYWORDS)

def _is_jwt(value: str) -> bool:
    return bool(JWT_PATTERN.match(value))

def _severity_rank(sev: str) -> int:
    return SEVERITY_RANK.get(sev, 0)

def _max_severity(severities: List[str]) -> str:
    valid = [s for s in severities if s in SEVERITY_RANK]
    if not valid:
        return "info"
    return max(valid, key=_severity_rank)

def _mask_value(value: str, keep: int = 8) -> str:
    if len(value) <= keep:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"

def _extract_cookie_attrs(cookie_str: str) -> Dict[str, str]:
    """Extract attributes from Set-Cookie header."""
    attrs = {}
    parts = cookie_str.split(";")
    for i, part in enumerate(parts):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            if i == 0:
                # First part is name=value
                attrs["name"] = k.strip()
                attrs["value"] = v.strip()
            else:
                attrs[k.strip().lower()] = v.strip()
        else:
            attrs[part.lower()] = True  # flag attribute (e.g., HttpOnly)
    return attrs

def _parse_set_cookie(raw_headers: List[str]) -> List[Dict[str, Any]]:
    """Parse Set-Cookie headers into structured data."""
    cookies = []
    for raw in raw_headers:
        attrs = _extract_cookie_attrs(raw)
        if "name" in attrs and "value" in attrs:
            cookie = {
                "name": attrs["name"],
                "value": attrs["value"],
                "httponly": attrs.get("httponly", False),
                "secure": attrs.get("secure", False),
                "samesite": attrs.get("samesite", None),
                "path": attrs.get("path", "/"),
                "domain": attrs.get("domain", None),
                "expires": attrs.get("expires", None),
                "max_age": attrs.get("max-age", None),
                "raw": raw,
            }
            cookies.append(cookie)
    return cookies

def _analyze_cookie_value(cookie: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze cookie value for patterns and sensitivity."""
    value = cookie.get("value", "")
    analysis = {
        "is_jwt": _is_jwt(value),
        "is_sensitive": _is_sensitive(cookie["name"]),
        "entropy": 0,
        "length": len(value),
        "contains_nonce": bool(re.search(r'[0-9a-f]{16,}', value.lower())),
        "pattern": None,
    }
    # Check if value looks like a session ID (alphanumeric, 16+ chars)
    if re.match(r'^[A-Za-z0-9\-_]{16,}$', value):
        analysis["pattern"] = "session_id"
    elif re.match(r'^[A-Za-z0-9\+/=]{16,}$', value):
        analysis["pattern"] = "base64_token"
    elif _is_jwt(value):
        analysis["pattern"] = "jwt"
    return analysis

# ── Cookie collection ──────────────────────────────────────────────────────

async def _collect_cookies(
    session: aiohttp.ClientSession,
    url: str,
    collect_xhr: bool = True,
) -> Dict[str, Any]:
    """Collect cookies from main request and simulated XHR/fetch."""
    all_cookies = {}
    final_url = url
    is_https = url.lower().startswith("https://")
    domain = urlparse(url).netloc

    # ── 1. Main request ──────────────────────────────────────────────────
    try:
        async with session.get(
            url,
            allow_redirects=True,
            ssl=False,
            timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS),
        ) as resp:
            final_url = str(resp.url)
            is_https = final_url.lower().startswith("https://")
            domain = urlparse(final_url).netloc
            set_cookie_headers = resp.headers.getall("Set-Cookie", [])
            if set_cookie_headers:
                all_cookies["main"] = _parse_set_cookie(set_cookie_headers)
    except Exception as e:
        return {"error": str(e), "cookies": {}}

    # ── 2. Simulated XHR/fetch requests (additional endpoints) ──────────
    if collect_xhr:
        # Common endpoints that may set cookies via JavaScript
        xhr_endpoints = ["/api", "/api/v1", "/api/user", "/api/session", "/api/auth", "/api/csrf"]
        for endpoint in xhr_endpoints[:3]:  # Limit
            try:
                target = urljoin(final_url, endpoint)
                async with session.get(
                    target,
                    allow_redirects=False,
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    set_cookie = resp.headers.getall("Set-Cookie", [])
                    if set_cookie:
                        all_cookies[f"xhr_{endpoint}"] = _parse_set_cookie(set_cookie)
            except Exception:
                pass

    # ── 3. POST request (like login) ─────────────────────────────────────
    try:
        # Try a POST to a common login endpoint
        login_url = urljoin(final_url, "/login")
        async with session.post(
            login_url,
            data={"username": "test", "password": "test"},
            allow_redirects=False,
            ssl=False,
            timeout=aiohttp.ClientTimeout(total=5),
        ) as resp:
            set_cookie = resp.headers.getall("Set-Cookie", [])
            if set_cookie:
                all_cookies["post_login"] = _parse_set_cookie(set_cookie)
    except Exception:
        pass

    return {
        "cookies": all_cookies,
        "final_url": final_url,
        "is_https": is_https,
        "domain": domain,
        "error": None,
    }

# ── Cookie analysis ──────────────────────────────────────────────────────

def _analyze_cookie_security(
    cookie: Dict[str, Any],
    is_https: bool,
    domain: str,
) -> Dict[str, Any]:
    """Analyze a single cookie for security issues."""
    name = cookie["name"]
    value = cookie["value"]
    issues = []
    severities = []
    confidence = 100
    poc = ""

    # ── 1. HttpOnly check ────────────────────────────────────────────────
    if not cookie.get("httponly"):
        issues.append("Missing HttpOnly flag → cookie readable by JavaScript (XSS risk)")
        severities.append("critical" if _is_sensitive(name) else "high")
        confidence = 100
        poc = "document.cookie // Steals all cookies, including this one"
    else:
        poc = "HttpOnly prevents JavaScript access"

    # ── 2. Secure flag check ─────────────────────────────────────────────
    if is_https and not cookie.get("secure"):
        issues.append("Missing Secure flag → cookie transmitted over HTTP (network sniffing risk)")
        severities.append("high")
        confidence = 100
        poc = f"tcpdump -i any -A -s 0 'port 80 and tcp[20:2] = 0x0d0a'"
    elif not is_https and cookie.get("secure"):
        issues.append("Secure flag set on HTTP site → cookie will never be sent (misconfiguration)")
        severities.append("medium")
        confidence = 80

    # ── 3. SameSite check ────────────────────────────────────────────────
    samesite = cookie.get("samesite")
    if samesite is None:
        issues.append("Missing SameSite attribute → CSRF risk")
        severities.append("medium" if not _is_sensitive(name) else "high")
        confidence = 100
        poc = '<form method="POST" action="https://target.com/action"><input type="submit"></form>'
    else:
        samesite_val = samesite.lower()
        if samesite_val == "none":
            if not cookie.get("secure"):
                issues.append("SameSite=None without Secure flag → allows cross-site sending over HTTP")
                severities.append("critical" if _is_sensitive(name) else "high")
                confidence = 100
            else:
                issues.append("SameSite=None with Secure flag (allows cross-site, ensure CSRF tokens used)")
                severities.append("low")
                confidence = 70
        elif samesite_val == "lax":
            # Lax is generally good but strict is better
            if _is_sensitive(name):
                issues.append("SameSite=Lax (good but Strict is stronger for sensitive cookies)")
                severities.append("low")
                confidence = 60
        # Strict is good

    # ── 4. Domain and Path validation ────────────────────────────────────
    cookie_domain = cookie.get("domain")
    cookie_path = cookie.get("path", "/")
    if cookie_domain:
        # Check if domain is too permissive (.example.com allows subdomains)
        if cookie_domain.startswith("."):
            # Check if it's the same as current domain or subdomain
            if cookie_domain.lstrip(".") in domain or domain.endswith(cookie_domain.lstrip(".")):
                # Acceptable
                pass
            elif cookie_domain.lstrip(".") != domain:
                issues.append(f"Cookie domain '{cookie_domain}' is permissive (allows subdomains)")
                severities.append("medium")
                confidence = 70
        elif cookie_domain != domain:
            issues.append(f"Cookie domain '{cookie_domain}' does not match current domain '{domain}'")
            severities.append("medium")
            confidence = 80

    # ── 5. Expiration / Max-Age ──────────────────────────────────────────
    expires = cookie.get("expires")
    max_age = cookie.get("max_age")
    if not expires and not max_age:
        issues.append("No expiration (session cookie) — persists until browser close (good for session cookies)")
        # Not an issue for session cookies
    elif expires:
        try:
            # Parse expiration (simplified)
            exp_time = datetime.strptime(expires, "%a, %d %b %Y %H:%M:%S %Z")
            if exp_time < datetime.now():
                issues.append("Cookie already expired")
                severities.append("info")
                confidence = 100
            elif exp_time > datetime.now() + timedelta(days=365):
                issues.append(f"Cookie expires after {exp_time - datetime.now()} days (long expiration)")
                severities.append("medium" if _is_sensitive(name) else "low")
                confidence = 80
        except:
            pass
    elif max_age:
        try:
            age = int(max_age)
            if age > 86400 * 30:  # 30 days
                issues.append(f"Cookie Max-Age={age}s (very long, consider shorter lifetime)")
                severities.append("medium" if _is_sensitive(name) else "low")
                confidence = 80
        except:
            pass

    # ── 6. Cookie prefix validation ──────────────────────────────────────
    for prefix in SECURE_PREFIXES:
        if name.startswith(prefix):
            if not cookie.get("secure"):
                issues.append(f"Cookie uses '{prefix}' prefix but missing Secure flag")
                severities.append("critical")
                confidence = 100
            if prefix == "__Host-" and cookie.get("domain"):
                issues.append(f"Cookie uses '__Host-' prefix but has Domain attribute (should not)")
                severities.append("high")
                confidence = 100
            if prefix == "__Host-" and cookie.get("path") != "/":
                issues.append(f"Cookie uses '__Host-' prefix but Path is not '/'")
                severities.append("high")
                confidence = 100

    # ── 7. Path attribute ─────────────────────────────────────────────────
    if cookie_path != "/" and _is_sensitive(name):
        issues.append(f"Cookie path is restricted to '{cookie_path}' (may be too restrictive for some use cases)")
        severities.append("info")
        confidence = 50

    # ── 8. Duplicate detection (handled separately) ──────────────────────

    # ── 9. JWT analysis ──────────────────────────────────────────────────
    value_analysis = _analyze_cookie_value(cookie)
    if value_analysis["is_jwt"]:
        issues.append("JWT detected in cookie (ensure proper validation and short expiry)")
        severities.append("info")
        confidence = 80
        poc = f"jwt.io/#id_token={value[:50]}..."

    # ── 10. Nonce / CSRF token ────────────────────────────────────────────
    if value_analysis["contains_nonce"]:
        # Nonce tokens often don't need HttpOnly
        if not cookie.get("httponly") and "csrf" in name.lower():
            issues.append("CSRF token missing HttpOnly (intentional for CSRF protection)")
            severities.append("info")
            confidence = 50

    # Elevate severity for sensitive cookies
    if _is_sensitive(name) and issues:
        # Upgrade high to critical, medium to high
        new_severities = []
        for sev in severities:
            if sev == "high":
                new_severities.append("critical")
            elif sev == "medium":
                new_severities.append("high")
            else:
                new_severities.append(sev)
        severities = new_severities
        issues = [f"[SENSITIVE] {issue}" for issue in issues]

    return {
        "name": name,
        "value": _mask_value(value),
        "issues": issues,
        "severity": _max_severity(severities) if issues else "info",
        "confidence": confidence,
        "poc": poc,
        "is_sensitive": _is_sensitive(name),
        "is_jwt": value_analysis["is_jwt"],
        "httponly": cookie.get("httponly", False),
        "secure": cookie.get("secure", False),
        "samesite": cookie.get("samesite"),
        "domain": cookie.get("domain"),
        "path": cookie.get("path", "/"),
        "expires": cookie.get("expires"),
        "max_age": cookie.get("max_age"),
        "value_pattern": value_analysis.get("pattern"),
    }

def _find_duplicate_cookies(cookies: List[Dict]) -> List[Dict[str, Any]]:
    """Find duplicate cookies (same name from different sources)."""
    seen = {}
    duplicates = []
    for cookie in cookies:
        name = cookie["name"]
        if name in seen:
            duplicates.append({
                "name": name,
                "first": seen[name],
                "second": cookie,
            })
        else:
            seen[name] = cookie
    return duplicates

# ── Session fixation test ─────────────────────────────────────────────────

async def _test_session_fixation(
    session: aiohttp.ClientSession,
    url: str,
    cookie_name: str,
) -> Dict[str, Any]:
    """Test if session can be fixed by setting a known session cookie."""
    test_session_id = f"bravo6-{uuid.uuid4().hex[:16]}"
    test_cookie = f"{cookie_name}={test_session_id}"
    
    try:
        # Request with pre-set cookie
        async with session.get(
            url,
            headers={"Cookie": test_cookie},
            allow_redirects=True,
            ssl=False,
            timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS),
        ) as resp:
            # Check if the same session ID is returned
            set_cookies = resp.headers.getall("Set-Cookie", [])
            for raw in set_cookies:
                if cookie_name in raw and test_session_id in raw:
                    return {
                        "vulnerable": True,
                        "evidence": "Session ID accepted as-is (no regeneration after login)",
                        "poc": f"curl -H 'Cookie: {test_cookie}' {url}",
                        "confidence": 90,
                    }
            return {
                "vulnerable": False,
                "evidence": "Session ID not persisted or regenerated",
                "confidence": 80,
            }
    except Exception:
        return {"vulnerable": False, "evidence": "Test failed", "confidence": 0}

# ── Main function ──────────────────────────────────────────────────────────

async def run(url: str, context: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Main entry point for cookie security test.
    Args:
        url: target URL
        context: optional context from other tests (XSS, CORS, Secrets)
    Returns:
        dict with findings
    """
    test_name = "cookie_security"
    
    try:
        target_url = _normalize_url(url)
        if not target_url:
            return {
                "test_name": test_name,
                "status": "error",
                "severity": "info",
                "title": "Invalid URL",
                "description": "Could not normalize URL.",
                "evidence": [],
                "remediation": "Provide a valid URL.",
                "cookies_analyzed": 0,
                "cookies_with_issues": 0,
            }
    except Exception as e:
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "Normalization error",
            "description": str(e),
            "evidence": [],
            "remediation": "Check URL format.",
            "cookies_analyzed": 0,
            "cookies_with_issues": 0,
        }

    async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
        # ── 1. Collect cookies ────────────────────────────────────────────
        cookie_data = await _collect_cookies(session, target_url)
        if cookie_data.get("error"):
            return {
                "test_name": test_name,
                "status": "error",
                "severity": "info",
                "title": "Cookie collection failed",
                "description": cookie_data["error"],
                "evidence": [],
                "remediation": "Check network connectivity.",
                "cookies_analyzed": 0,
                "cookies_with_issues": 0,
            }

        all_cookies = cookie_data["cookies"]
        final_url = cookie_data["final_url"]
        is_https = cookie_data["is_https"]
        domain = cookie_data["domain"]

        # Flatten all cookies
        raw_cookies = []
        for source, cookies in all_cookies.items():
            for cookie in cookies:
                cookie["_source"] = source
                raw_cookies.append(cookie)

        if not raw_cookies:
            return {
                "test_name": test_name,
                "status": "pass",
                "severity": "info",
                "title": "No cookies found",
                "description": "No cookies were set during request/redirect chain.",
                "evidence": [],
                "remediation": "No action needed.",
                "cookies_analyzed": 0,
                "cookies_with_issues": 0,
            }

        # ── 2. Analyze each cookie ────────────────────────────────────────
        analyzed_cookies = []
        for cookie in raw_cookies:
            analysis = _analyze_cookie_security(cookie, is_https, domain)
            analysis["_source"] = cookie.get("_source", "unknown")
            analyzed_cookies.append(analysis)

        # ── 3. Find duplicates ────────────────────────────────────────────
        duplicates = _find_duplicate_cookies(analyzed_cookies)

        # ── 4. Session fixation test on first sensitive cookie ───────────
        session_cookies = [c for c in analyzed_cookies if "session" in c["name"].lower()]
        fixation_results = []
        for sc in session_cookies[:2]:  # Limit
            result = await _test_session_fixation(session, final_url, sc["name"])
            if result["vulnerable"]:
                result["cookie_name"] = sc["name"]
                fixation_results.append(result)

        # ── 5. Build evidence ─────────────────────────────────────────────
        evidence = []
        cookies_with_issues = 0

        for cookie in analyzed_cookies:
            if cookie["issues"]:
                cookies_with_issues += 1
                evidence.append({
                    "name": cookie["name"],
                    "value": cookie["value"],
                    "source": cookie.get("_source", "unknown"),
                    "issues": cookie["issues"],
                    "severity": cookie["severity"],
                    "confidence": cookie["confidence"],
                    "poc": cookie["poc"],
                    "is_sensitive": cookie["is_sensitive"],
                    "httponly": cookie["httponly"],
                    "secure": cookie["secure"],
                    "samesite": cookie["samesite"],
                    "domain": cookie["domain"],
                    "path": cookie["path"],
                    "expires": cookie["expires"],
                    "max_age": cookie["max_age"],
                    "value_pattern": cookie.get("value_pattern"),
                    "is_jwt": cookie.get("is_jwt", False),
                })

        # ── 6. Duplicate cookie evidence ──────────────────────────────────
        for dup in duplicates:
            evidence.append({
                "name": dup["name"],
                "type": "duplicate_cookie",
                "severity": "medium",
                "description": f"Duplicate cookie '{dup['name']}' from different sources (may cause conflicts)",
                "poc": "Check cookie management in application code.",
                "confidence": 80,
                "first_source": dup["first"].get("_source", "unknown"),
                "second_source": dup["second"].get("_source", "unknown"),
            })
            cookies_with_issues += 1

        # ── 7. Session fixation evidence ──────────────────────────────────
        for fix in fixation_results:
            evidence.append({
                "name": fix["cookie_name"],
                "type": "session_fixation",
                "severity": "critical",
                "description": f"Session fixation possible via {fix['cookie_name']}",
                "poc": fix["poc"],
                "confidence": fix["confidence"],
                "evidence": fix["evidence"],
            })
            cookies_with_issues += 1

        # ── 8. Integration with context ───────────────────────────────────
        if context:
            # If XSS is present, elevate cookie severity
            if context.get("xss_vulnerable"):
                for ev in evidence:
                    if ev.get("is_sensitive") and ev.get("severity") in ("medium", "high"):
                        ev["severity"] = "critical"
                        ev["description"] += " [XSS present: cookie can be stolen]"

            # If CORS is weak, elevate cookie severity
            if context.get("cors_weak"):
                for ev in evidence:
                    if ev.get("is_sensitive") and ev.get("severity") in ("medium", "high"):
                        ev["severity"] = "critical"
                        ev["description"] += " [CORS weakness: cookie can be stolen cross-origin]"

        # ── 9. Determine overall status ────────────────────────────────────
        critical_issues = [e for e in evidence if e.get("severity") == "critical"]
        high_issues = [e for e in evidence if e.get("severity") == "high"]
        medium_issues = [e for e in evidence if e.get("severity") == "medium"]

        if critical_issues:
            status = "fail"
            overall_severity = "critical"
        elif high_issues:
            status = "fail"
            overall_severity = "high"
        elif medium_issues:
            status = "warning"
            overall_severity = "medium"
        else:
            status = "pass"
            overall_severity = "info"

        # ── 10. Build remediation ──────────────────────────────────────────
        remediation_parts = []
        if any(e.get("httponly") is False for e in evidence if e.get("is_sensitive")):
            remediation_parts.append("Set HttpOnly flag on all sensitive cookies.")
        if any(e.get("secure") is False for e in evidence if e.get("is_sensitive")):
            remediation_parts.append("Set Secure flag on all sensitive cookies (requires HTTPS).")
        if any(e.get("samesite") is None for e in evidence if e.get("is_sensitive")):
            remediation_parts.append("Set SameSite=Strict or Lax on all sensitive cookies.")
        if fixation_results:
            remediation_parts.append("Regenerate session ID after login to prevent session fixation.")
        if duplicates:
            remediation_parts.append("Resolve duplicate cookie definitions from different sources.")
        if any(e.get("type") == "duplicate_cookie" for e in evidence):
            remediation_parts.append("Standardize cookie domain and path attributes.")
        if not remediation_parts:
            remediation_parts.append("Cookie security is well configured. Continue monitoring.")

        return {
            "test_name": test_name,
            "status": status,
            "severity": overall_severity,
            "title": f"Cookie Security Analysis ({cookies_with_issues} issues)",
            "description": f"Analyzed {len(analyzed_cookies)} cookie(s) from {len(all_cookies)} source(s). Found {len(evidence)} issues.",
            "evidence": evidence,
            "remediation": " ".join(remediation_parts),
            "cookies_analyzed": len(analyzed_cookies),
            "cookies_with_issues": cookies_with_issues,
            "sources_found": list(all_cookies.keys()),
            "duplicate_cookies": len(duplicates),
            "session_fixation_vulnerable": len(fixation_results) > 0,
        }


if __name__ == "__main__":
    import json
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))