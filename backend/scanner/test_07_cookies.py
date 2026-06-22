"""
test_07_cookies.py — Fast Cookie Security Scanner (Optimized)

Optimized for speed:
- Single request only (no XHR simulation)
- No POST requests (avoid login attempts)
- Removed session fixation test (heavy)
- Simplified cookie analysis
- Short timeouts (5s)
- Fast and reliable
"""

import asyncio
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional

import aiohttp

# ── Configuration ──────────────────────────────────────────────────────────
USER_AGENT = "Bravo6-Scanner/1.0"
TIMEOUT_SECONDS = 5
MAX_REDIRECTS = 5

# ── Sensitive keywords ────────────────────────────────────────────────────
SENSITIVE_KEYWORDS = ("session", "auth", "token", "jwt", "user", "admin", "login", "sid", "uid", "csrf")

# ── Severity ranking ──────────────────────────────────────────────────────
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# ── Helper functions ──────────────────────────────────────────────────────

def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = f"https://{url}"
    return url

def _is_sensitive(name: str) -> bool:
    name_lower = name.lower()
    return any(kw in name_lower for kw in SENSITIVE_KEYWORDS)

def _mask_value(value: str, keep: int = 6) -> str:
    if len(value) <= keep:
        return "*" * len(value)
    return f"{value[:3]}...{value[-3:]}"

def _parse_set_cookie(raw: str) -> Dict[str, Any]:
    """Parse a single Set-Cookie header."""
    cookie = {"raw": raw}
    parts = raw.split(";")
    for i, part in enumerate(parts):
        part = part.strip()
        if i == 0 and "=" in part:
            name, value = part.split("=", 1)
            cookie["name"] = name.strip()
            cookie["value"] = value.strip()
        elif "=" in part:
            k, v = part.split("=", 1)
            cookie[k.strip().lower()] = v.strip()
        else:
            cookie[part.lower()] = True
    return cookie

def _is_jwt(value: str) -> bool:
    return bool(re.match(r'^eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+$', value))

# ── Main function ──────────────────────────────────────────────────────────

async def run(url: str, context: Optional[Dict] = None) -> Dict[str, Any]:
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
        }

    # ── Fetch page and collect cookies ──────────────────────────────────
    cookies = []
    is_https = target_url.lower().startswith("https://")
    domain = urlparse(target_url).netloc

    async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
        try:
            async with session.get(
                target_url,
                allow_redirects=True,
                ssl=False,
                timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
            ) as resp:
                # Get all Set-Cookie headers
                set_cookie_headers = resp.headers.getall("Set-Cookie", [])
                for raw in set_cookie_headers:
                    cookie = _parse_set_cookie(raw)
                    cookies.append(cookie)
        except Exception as e:
            return {
                "test_name": test_name,
                "status": "error",
                "severity": "info",
                "title": "Fetch failed",
                "description": f"Failed to fetch: {str(e)[:100]}",
                "evidence": [],
                "remediation": "Check network connectivity.",
                "cookies_analyzed": 0,
            }

    # ── No cookies found ──────────────────────────────────────────────────
    if not cookies:
        return {
            "test_name": test_name,
            "status": "pass",
            "severity": "info",
            "title": "No cookies found",
            "description": "No cookies were set during the request.",
            "evidence": [],
            "remediation": "No action needed.",
            "cookies_analyzed": 0,
        }

    # ── Analyze each cookie ──────────────────────────────────────────────
    evidence = []
    cookies_with_issues = 0

    for cookie in cookies:
        name = cookie.get("name", "unknown")
        value = cookie.get("value", "")
        issues = []
        severities = []
        confidence = 100
        poc = ""

        # Check HttpOnly
        if not cookie.get("httponly"):
            issues.append("Missing HttpOnly flag (XSS risk)")
            severities.append("critical" if _is_sensitive(name) else "high")
            poc = "document.cookie // Steals cookies"
        else:
            poc = "HttpOnly prevents JavaScript access"

        # Check Secure flag
        if is_https and not cookie.get("secure"):
            issues.append("Missing Secure flag (interception risk)")
            severities.append("high")
            poc = "tcpdump -i any -A -s 0 'port 80'"
        elif not is_https and cookie.get("secure"):
            issues.append("Secure flag on HTTP site (never sent)")
            severities.append("medium")

        # Check SameSite
        samesite = cookie.get("samesite")
        if samesite is None:
            issues.append("Missing SameSite (CSRF risk)")
            severities.append("medium" if not _is_sensitive(name) else "high")
            poc = '<form method="POST" action="https://target.com/action">'
        elif samesite.lower() == "none":
            if not cookie.get("secure"):
                issues.append("SameSite=None without Secure")
                severities.append("critical")
            else:
                issues.append("SameSite=None (allows cross-site)")
                severities.append("low")

        # Check expiration
        expires = cookie.get("expires")
        max_age = cookie.get("max-age")
        if expires:
            try:
                exp_time = datetime.strptime(expires, "%a, %d %b %Y %H:%M:%S %Z")
                if exp_time > datetime.now() + timedelta(days=365):
                    issues.append(f"Long expiration (1+ year)")
                    severities.append("medium" if _is_sensitive(name) else "low")
            except:
                pass
        elif max_age:
            try:
                age = int(max_age)
                if age > 86400 * 30:  # 30 days
                    issues.append(f"Max-Age={age}s (very long)")
                    severities.append("medium" if _is_sensitive(name) else "low")
            except:
                pass

        # Check Domain attribute
        cookie_domain = cookie.get("domain")
        if cookie_domain and cookie_domain.startswith("."):
            if cookie_domain.lstrip(".") != domain and not domain.endswith(cookie_domain.lstrip(".")):
                issues.append(f"Permissive domain: {cookie_domain}")
                severities.append("medium")

        # JWT detection
        if _is_jwt(value):
            issues.append("JWT detected (ensure short expiry)")
            severities.append("info")
            poc = f"jwt.io/#id_token={value[:30]}..."

        # If no issues, add info
        if not issues:
            evidence.append({
                "name": name,
                "value": _mask_value(value),
                "severity": "info",
                "status": "pass",
                "description": "Cookie is properly configured.",
                "httponly": cookie.get("httponly", False),
                "secure": cookie.get("secure", False),
                "samesite": cookie.get("samesite"),
            })
            continue

        # Determine worst severity
        worst_sev = "info"
        for sev in severities:
            if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(worst_sev, 0):
                worst_sev = sev

        cookies_with_issues += 1
        evidence.append({
            "name": name,
            "value": _mask_value(value),
            "issues": issues,
            "severity": worst_sev,
            "status": "fail" if worst_sev in ("critical", "high") else "warning",
            "confidence": confidence,
            "poc": poc,
            "is_sensitive": _is_sensitive(name),
            "is_jwt": _is_jwt(value),
            "httponly": cookie.get("httponly", False),
            "secure": cookie.get("secure", False),
            "samesite": cookie.get("samesite"),
            "domain": cookie.get("domain"),
            "path": cookie.get("path", "/"),
        })

    # ── Determine overall status ──────────────────────────────────────────
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

    # ── Build remediation ──────────────────────────────────────────────────
    remediation_parts = []
    if any(e.get("httponly") is False for e in evidence if e.get("is_sensitive")):
        remediation_parts.append("Set HttpOnly flag on sensitive cookies.")
    if any(e.get("secure") is False for e in evidence if e.get("is_sensitive")):
        remediation_parts.append("Set Secure flag on sensitive cookies (requires HTTPS).")
    if any(e.get("samesite") is None for e in evidence if e.get("is_sensitive")):
        remediation_parts.append("Set SameSite=Strict or Lax on sensitive cookies.")
    if not remediation_parts:
        remediation_parts.append("Cookie security is well configured. Continue monitoring.")

    return {
        "test_name": test_name,
        "status": status,
        "severity": overall_severity,
        "title": f"Cookie Security Analysis ({cookies_with_issues} issue{'s' if cookies_with_issues != 1 else ''})",
        "description": f"Analyzed {len(cookies)} cookie(s). Found {cookies_with_issues} issue(s).",
        "evidence": evidence,
        "remediation": " ".join(remediation_parts),
        "cookies_analyzed": len(cookies),
        "cookies_with_issues": cookies_with_issues,
    }


if __name__ == "__main__":
    import json
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))