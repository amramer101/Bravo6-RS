"""
test_cookies.py - Bravo6 Security Scanner Module
Analyzes cookies set by a target website for missing security flags
(HttpOnly, Secure, SameSite) and flags sensitive-cookie misconfigurations.
"""

import re
import asyncio
from http.cookies import SimpleCookie
from urllib.parse import urlparse

import aiohttp

USER_AGENT = "Bravo6-Scanner/1.0"
TIMEOUT_SECONDS = 10
SENSITIVE_KEYWORDS = ("session", "auth", "token", "jwt", "user")


def _normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r'^https?://', url, re.IGNORECASE):
        url = f"https://{url}"
    return url


def _is_sensitive(cookie_name: str) -> bool:
    name_lower = cookie_name.lower()
    return any(keyword in name_lower for keyword in SENSITIVE_KEYWORDS)


def _severity_rank(sev: str) -> int:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(sev, 0)


def _max_severity(severities):
    if not severities:
        return "info"
    return max(severities, key=_severity_rank)


def _analyze_single_cookie(name: str, raw_attrs: dict, is_https: bool) -> dict:
    """
    raw_attrs is a dict of lowercased attribute keys -> values (or True for flags)
    as parsed from a single Set-Cookie header.
    """
    issues = []
    severities = []

    has_httponly = "httponly" in raw_attrs
    has_secure = "secure" in raw_attrs
    samesite = raw_attrs.get("samesite")

    sensitive = _is_sensitive(name)

    # A. HttpOnly check
    if not has_httponly:
        issues.append("Missing HttpOnly flag (readable by JavaScript, vulnerable to XSS-based theft)")
        severities.append("high")

    # B. Secure check (only meaningful to flag as missing if site is HTTPS)
    if is_https and not has_secure:
        issues.append("Missing Secure flag (cookie can be transmitted over unencrypted HTTP)")
        severities.append("high")

    # E. Secure flag set but site is plain HTTP -> misconfiguration
    if not is_https and has_secure:
        issues.append("Secure flag set on a cookie served over HTTP (cookie will never actually be sent — likely misconfiguration or broken intent)")
        severities.append("medium")

    # C. SameSite checks
    if samesite is None:
        issues.append("Missing SameSite attribute (CSRF risk)")
        severities.append("medium")
    else:
        samesite_val = samesite.lower()
        if samesite_val == "none":
            issues.append("SameSite=None used" + ("" if has_secure else " without Secure flag (high risk — cross-site sending allowed over insecure channel)"))
            if not has_secure:
                severities.append("high")
            else:
                severities.append("low")  # None+Secure is valid for legitimate cross-site use cases
        elif samesite_val == "lax":
            pass  # acceptable, no issue
        elif samesite_val == "strict":
            pass  # best practice, no issue
        else:
            issues.append(f"Unrecognized SameSite value: '{samesite}'")
            severities.append("low")

    # D. Elevate severity for sensitive cookies
    if sensitive and issues:
        severities = ["critical" if s == "high" else s for s in severities]
        issues = [f"[SENSITIVE COOKIE] {issue}" for issue in issues]

    return {
        "cookie_name": name,
        "issues": issues,
        "severity": _max_severity(severities) if issues else "info",
        "is_sensitive": sensitive,
    }


def _parse_set_cookie_headers(headers_list, is_https: bool) -> list:
    """
    headers_list: list of raw Set-Cookie header string values (one per header instance)
    Returns list of per-cookie analysis dicts.
    """
    results = []
    for raw_header in headers_list:
        # SimpleCookie handles a single Set-Cookie value reliably (name=value; attr=val; flag)
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

            results.append(_analyze_single_cookie(morsel_name, attrs, is_https))

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

    try:
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            current_url = target_url
            seen_urls = set()

            # Manually walk redirects so we can capture Set-Cookie at each hop
            for _ in range(10):
                if current_url in seen_urls:
                    break
                seen_urls.add(current_url)

                try:
                    async with session.get(
                        current_url,
                        allow_redirects=False,
                        ssl=False,  # scanner context: don't fail scan on cert issues, just record findings
                    ) as resp:
                        is_https_hop = current_url.lower().startswith("https://")

                        # aiohttp exposes raw headers; Set-Cookie can appear multiple times
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
                    base_result["description"] = f"Request timed out after {TIMEOUT_SECONDS}s while contacting {current_url}"
                    return base_result
                except aiohttp.ClientError as e:
                    base_result["status"] = "error"
                    base_result["description"] = f"Connection error while contacting {current_url}: {e}"
                    return base_result

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
        base_result["description"] = f"Unexpected error during scan: {e}"
        return base_result

    if not all_set_cookie_headers:
        base_result["status"] = "pass"
        base_result["severity"] = "info"
        base_result["title"] = "No Cookies Set"
        base_result["description"] = "The target did not set any cookies during the request/redirect chain. No cookie-based session risks to evaluate."
        base_result["cookies_analyzed"] = 0
        base_result["cookies_with_issues"] = 0
        return base_result

    # Analyze each Set-Cookie header in the context of the scheme it was served over
    evidence = []
    for raw_header, is_https_hop in all_set_cookie_headers:
        evidence.extend(_parse_set_cookie_headers([raw_header], is_https_hop))

    cookies_with_issues = [e for e in evidence if e["issues"]]
    severities_found = [e["severity"] for e in cookies_with_issues]
    overall_severity = _max_severity(severities_found)

    if cookies_with_issues:
        status = "fail" if overall_severity in ("critical", "high") else "warning"
    else:
        status = "pass"

    base_result.update({
        "status": status,
        "severity": overall_severity,
        "title": "Cookie Security Analysis",
        "description": (
            f"Analyzed {len(evidence)} cookie(s) across {len(all_set_cookie_headers)} Set-Cookie header(s). "
            f"{len(cookies_with_issues)} cookie(s) have one or more missing/misconfigured security flags."
            if cookies_with_issues else
            f"Analyzed {len(evidence)} cookie(s). All cookies have appropriate security flags configured."
        ),
        "evidence": evidence,
        "cookies_analyzed": len(evidence),
        "cookies_with_issues": len(cookies_with_issues),
    })

    return base_result


if __name__ == "__main__":
    import json
    import sys

    test_target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(test_target))
    print(json.dumps(result, indent=2))