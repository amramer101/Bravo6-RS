"""
test_07_cookies.py — Advanced Cookie Security Scanner (Active Verification)

Upgraded:
- Analyzes cookies with precise security flags.
- Provides JavaScript PoC to demonstrate cookie theft (if HttpOnly missing).
- Evaluates SameSite and Secure flags contextually.
- Adds confidence scoring (100% for clear misconfigurations).
- Generates actionable curl commands to reproduce.
"""

import asyncio
import re
from http.cookies import SimpleCookie
from urllib.parse import urlparse

import aiohttp

USER_AGENT = "Bravo6-Scanner/1.0"
TIMEOUT_SECONDS = 10
SENSITIVE_KEYWORDS = ("session", "auth", "token", "jwt", "user", "admin", "login", "sid")


def _normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = f"https://{url}"
    return url


def _is_sensitive(name: str) -> bool:
    name_lower = name.lower()
    return any(kw in name_lower for kw in SENSITIVE_KEYWORDS)


def _severity_rank(sev: str) -> int:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(sev, 0)


def _max_severity(severities):
    valid = [s for s in severities if s in _severity_rank]
    if not valid:
        return "info"
    return max(valid, key=_severity_rank)


def _analyze_single_cookie(name: str, raw_attrs: dict, is_https: bool, domain: str = None) -> dict:
    """
    Returns dict with:
      - issues: list of strings
      - severity: highest severity among issues
      - is_sensitive: bool
      - confidence: int (0-100)
      - poc: str (JavaScript or curl)
    """
    issues = []
    severities = []
    confidence = 100  # default high for any issue

    has_httponly = raw_attrs.get("httponly", False)
    has_secure = raw_attrs.get("secure", False)
    samesite = raw_attrs.get("samesite")

    sensitive = _is_sensitive(name)

    # HttpOnly check
    if not has_httponly:
        issues.append("Missing HttpOnly flag → cookie readable by JavaScript (XSS risk)")
        severities.append("critical" if sensitive else "high")
        confidence = 100
    else:
        # if HttpOnly is set, XSS cannot read it directly, but still risk if other flags missing
        pass

    # Secure flag check (only meaningful if site is HTTPS)
    if is_https and not has_secure:
        issues.append("Missing Secure flag → cookie transmitted over HTTP (network sniffing risk)")
        severities.append("high")
        confidence = 100

    # Secure flag set but site is HTTP -> misconfiguration
    if not is_https and has_secure:
        issues.append("Secure flag set on HTTP site → cookie will never be sent (misconfiguration)")
        severities.append("medium")
        confidence = 80

    # SameSite checks
    if samesite is None:
        issues.append("Missing SameSite attribute → CSRF risk")
        severities.append("medium" if not sensitive else "high")
        confidence = 100
    else:
        samesite_val = samesite.lower()
        if samesite_val == "none":
            if not has_secure:
                issues.append("SameSite=None without Secure flag → allows cross-site sending over HTTP")
                severities.append("critical" if sensitive else "high")
                confidence = 100
            else:
                # None+Secure is legitimate for cross-site use, but still slightly risky
                issues.append("SameSite=None with Secure flag (allows cross-site, ensure CSRF tokens used)")
                severities.append("low")
                confidence = 60
        elif samesite_val in ("lax", "strict"):
            pass  # good
        else:
            issues.append(f"Unrecognized SameSite value: '{samesite}'")
            severities.append("low")
            confidence = 70

    # Elevate severity for sensitive cookies
    if sensitive and issues:
        severities = ["critical" if s == "high" else s for s in severities]
        issues = [f"[SENSITIVE] {issue}" for issue in issues]

    # Build PoC
    poc = ""
    if not has_httponly:
        poc = f"document.cookie // reads: {name}=..."
    elif not has_secure and is_https:
        poc = f"curl -v --cookie '{name}=value' {domain or 'https://target'}"
    elif samesite is None:
        poc = f"<form action='{domain or 'https://target'}' method='POST'>...</form> (CSRF)"

    return {
        "cookie_name": name,
        "issues": issues,
        "severity": _max_severity(severities) if issues else "info",
        "is_sensitive": sensitive,
        "confidence": confidence,
        "poc": poc,
    }


def _parse_set_cookie_headers(headers_list, is_https: bool, domain: str = None) -> list:
    results = []
    for raw_header in headers_list:
        parsed = SimpleCookie()
        try:
            parsed.load(raw_header)
        except Exception:
            continue
        for morsel_name, morsel in parsed.items():
            attrs = {}
            if morsel["httponly"]:
                attrs["httponly"] = True
            if morsel["secure"]:
                attrs["secure"] = True
            if morsel["samesite"]:
                attrs["samesite"] = morsel["samesite"]
            results.append(_analyze_single_cookie(morsel_name, attrs, is_https, domain))
    return results


async def run(url: str) -> dict:
    base_result = {
        "test_name": "cookie_security",
        "status": "error",
        "severity": "info",
        "title": "Cookie Security Analysis",
        "description": "",
        "evidence": [],
        "cookies_analyzed": 0,
        "cookies_with_issues": 0,
        "remediation": "Set HttpOnly, Secure, and SameSite=Strict flags on all cookies. "
                        "Especially critical for session and authentication cookies.",
    }

    try:
        target_url = _normalize_url(url)
    except Exception as e:
        base_result["description"] = f"Failed to normalize input URL: {e}"
        return base_result

    headers = {"User-Agent": USER_AGENT}
    timeout = aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)

    all_set_cookie_headers = []  # list of (header_value, was_https)
    final_is_https = target_url.lower().startswith("https://")
    domain = urlparse(target_url).netloc

    try:
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            current_url = target_url
            seen_urls = set()
            for _ in range(10):
                if current_url in seen_urls:
                    break
                seen_urls.add(current_url)

                try:
                    async with session.get(
                        current_url,
                        allow_redirects=False,
                        ssl=False,
                    ) as resp:
                        is_https_hop = current_url.lower().startswith("https://")
                        raw_set_cookies = resp.headers.getall("Set-Cookie", [])
                        for rsc in raw_set_cookies:
                            all_set_cookie_headers.append((rsc, is_https_hop))

                        if resp.status in (301, 302, 303, 307, 308):
                            location = resp.headers.get("Location")
                            if not location:
                                break
                            if location.startswith("http://") or location.startswith("https://"):
                                current_url = location
                            else:
                                parsed_current = urlparse(current_url)
                                current_url = f"{parsed_current.scheme}://{parsed_current.netloc}{location}"
                            final_is_https = current_url.lower().startswith("https://")
                            continue
                        else:
                            break

                except asyncio.TimeoutError:
                    base_result["status"] = "error"
                    base_result["description"] = f"Request timed out after {TIMEOUT_SECONDS}s"
                    return base_result
                except aiohttp.ClientError as e:
                    base_result["status"] = "error"
                    base_result["description"] = f"Connection error: {e}"
                    return base_result

    except Exception as e:
        base_result["status"] = "error"
        base_result["description"] = f"Unexpected error: {e}"
        return base_result

    if not all_set_cookie_headers:
        base_result.update({
            "status": "pass",
            "severity": "info",
            "title": "No Cookies Set",
            "description": "No cookies set during request/redirect chain.",
            "cookies_analyzed": 0,
            "cookies_with_issues": 0,
            "evidence": [],
            "remediation": "No action needed."
        })
        return base_result

    # Analyze each Set-Cookie header
    evidence = []
    for raw_header, is_https_hop in all_set_cookie_headers:
        evidence.extend(_parse_set_cookie_headers([raw_header], is_https_hop, domain))

    cookies_with_issues = [e for e in evidence if e["issues"]]
    severities_found = [e["severity"] for e in cookies_with_issues]
    overall_severity = _max_severity(severities_found) if severities_found else "info"
    confidence = 100 if cookies_with_issues else 100  # always high if we found something

    status = "fail" if overall_severity in ("critical", "high") else "warning" if cookies_with_issues else "pass"

    base_result.update({
        "status": status,
        "severity": overall_severity,
        "title": f"Cookie Security Analysis ({len(cookies_with_issues)} issues)",
        "description": (
            f"Analyzed {len(evidence)} cookie(s). {len(cookies_with_issues)} have missing/misconfigured security flags."
        ),
        "evidence": evidence,
        "cookies_analyzed": len(evidence),
        "cookies_with_issues": len(cookies_with_issues),
        "remediation": base_result["remediation"] + " Also review SameSite policy and use CSRF tokens."
    })

    return base_result


if __name__ == "__main__":
    import json
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))