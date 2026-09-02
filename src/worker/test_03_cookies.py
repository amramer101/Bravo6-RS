#!/usr/bin/env python3
"""
test_03_cookies.py - Bravo6 Cookie Security Scanner (v1.0)
=====================================================================
- Zero new HTTP requests: analyzes Set-Cookie headers already captured by
  the orchestrator's single main-page fetch (ctx.main_page_cache).
- Per-cookie, name-based sensitivity classification (session/auth vs.
  tracking/analytics vs. generic) drives severity -- never a page-wide
  signal. See COOKIE_SENSITIVE_NAME_RE / COOKIE_TRACKING_NAME_RE below.
- Checks: missing HttpOnly, missing Secure, missing SameSite, the
  SameSite=None-without-Secure combination (browsers reject it outright),
  __Host-/__Secure- prefix violations, and unusually long-lived
  session/auth cookies.
- Strict 12-field finding schema with explicit raw_data["tier"]
  ("baseline" for required checks, "hardening" for nice-to-have /
  low-value-target checks) on every finding.
"""

import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Optional

# ------------------------------------------------------------------------------
# Cookie name classification (documented, inspectable constants -- mirrors
# test_01's BENIGN_DOMAINS_RE and test_06's EXCLUDE_DOMAINS: the pattern
# lives in one place, not buried in inline logic).
# ------------------------------------------------------------------------------

# Cookie names that strongly suggest session/authentication relevance.
# Matched as a substring against the cookie's own name only -- classification
# is scoped to that single cookie's evidence, never a page-wide signal.
COOKIE_SENSITIVE_NAME_RE = re.compile(
    r'(?i)(session|sessid|sess[_-]?id|\bsid\b|\bauth\b|token|jwt|csrf|xsrf|'
    r'\blogin\b|credential|remember[_-]?me|refresh[_-]?token|access[_-]?token|'
    r'\.aspxauth\b|connect\.sid|laravel_session|phpsessid|wordpress_logged_in)'
)

# Well-known analytics/tracking/third-party cookie name prefixes that are
# routinely non-sensitive by design. Checked BEFORE the sensitive pattern so
# a name like "_ga_session_test" (an actual real-world Google Analytics 4
# cookie name shape) is classified as tracking, not sensitive, even though it
# contains the substring "session".
COOKIE_TRACKING_NAME_RE = re.compile(
    r'(?i)^(_ga|_gid|_gat|_fbp|_fbc|_gcl_au|_hjid|_hjsession|_hjfirstseen|'
    r'_uetsid|_uetvid|_pin_unauth|nid|ide|1p_jar|anonchk|muid|mc_id|'
    r'_clck|_clsk|amp_|intercom-|hubspotutk|_mkto_trk)'
)

# A session/auth-looking cookie persisting longer than this is flagged as a
# low-severity hardening note (long-lived credentials widen the exposure
# window if stolen). Chosen as a concrete, documented threshold rather than
# left fuzzy, per the spec for this scout.
LONG_LIVED_COOKIE_THRESHOLD_DAYS = 30


def _classify_cookie_sensitivity(name: str) -> str:
    """Classify a cookie by its own name only. Returns 'tracking',
    'sensitive', or 'generic'. Never consults page content or any other
    cookie -- the whole point is per-finding, per-cookie scoping."""
    if COOKIE_TRACKING_NAME_RE.match(name):
        return "tracking"
    if COOKIE_SENSITIVE_NAME_RE.search(name):
        return "sensitive"
    return "generic"


# ------------------------------------------------------------------------------
# Set-Cookie parsing
# ------------------------------------------------------------------------------
def _parse_set_cookie(raw: str) -> Dict[str, Any]:
    """Parse a single raw Set-Cookie header string into a structured dict.
    Returns {} if the header doesn't even have a name=value pair."""
    parts = [p.strip() for p in raw.split(";") if p.strip()]
    if not parts or "=" not in parts[0]:
        return {}

    name, value = parts[0].split("=", 1)
    cookie: Dict[str, Any] = {
        "name": name.strip(),
        "value": value.strip(),
        "httponly": False,
        "secure": False,
        "samesite": None,
        "domain": None,
        "path": None,
        "max_age": None,
        "expires": None,
        "raw": raw,
    }

    for part in parts[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            k_lower = k.strip().lower()
            v = v.strip()
            if k_lower == "samesite":
                cookie["samesite"] = v
            elif k_lower == "domain":
                cookie["domain"] = v
            elif k_lower == "path":
                cookie["path"] = v
            elif k_lower == "max-age":
                cookie["max_age"] = v
            elif k_lower == "expires":
                cookie["expires"] = v
        else:
            k_lower = part.strip().lower()
            if k_lower == "httponly":
                cookie["httponly"] = True
            elif k_lower == "secure":
                cookie["secure"] = True

    return cookie


def _cookie_lifetime_days(cookie: Dict[str, Any]) -> Optional[float]:
    """Best-effort cookie lifetime in days from Max-Age (seconds) or Expires
    (HTTP-date). Returns None if neither is present/parseable -- a session
    cookie with no expiry attribute at all is NOT "long-lived" (it dies with
    the browser session), so None correctly means "don't flag"."""
    max_age = cookie.get("max_age")
    if max_age:
        try:
            return int(max_age) / 86400.0
        except (ValueError, TypeError):
            pass

    expires = cookie.get("expires")
    if expires:
        try:
            exp_dt = parsedate_to_datetime(expires)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            delta = exp_dt - datetime.now(timezone.utc)
            return delta.total_seconds() / 86400.0
        except Exception:
            pass

    return None


# ------------------------------------------------------------------------------
# Finding factory (mirrors test_05's _make_finding: explicit tier param,
# nested under raw_data so main_scanner.py's normalize_finding/
# compute_bravo6_score pick it up correctly -- "hardening" is the literal
# string the orchestrator's scoring checks for tier-2 capping).
# ------------------------------------------------------------------------------
def _make_finding(title: str, severity: str, confidence: str, cwe: str, owasp: str,
                   location: str, evidence: str, poc: str, remediation: str,
                   detection_method: str, tier: str) -> Dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "cwe": cwe,
        "owasp": owasp,
        "location": location,
        "evidence": evidence,
        "poc": poc,
        "remediation": remediation,
        "detection_method": detection_method,
        "raw_data": {"tier": tier},
    }


# ------------------------------------------------------------------------------
# Per-cookie checks
# ------------------------------------------------------------------------------
def _check_cookie(cookie: Dict[str, Any], url: str, is_https: bool) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    name = cookie.get("name", "")
    if not name:
        return findings

    classification = _classify_cookie_sensitivity(name)
    is_sensitive = classification == "sensitive"
    is_tracking = classification == "tracking"

    def sev_for(sensitive_sev: str, generic_sev: str, tracking_sev: str = "low") -> str:
        if is_sensitive:
            return sensitive_sev
        if is_tracking:
            return tracking_sev
        return generic_sev

    # Findings on a tracking-classified cookie are capped to the hardening
    # (tier2) bucket regardless of which specific check fired -- this is the
    # scoped-per-cookie equivalent of "the same gap on a clearly non-sensitive
    # tracking cookie should be tier2/low, not escalated."
    base_tier = "hardening" if is_tracking else "baseline"

    poc = f"curl -Is {url} | grep -i 'set-cookie' | grep -i '{name}'"
    location = f"Set-Cookie: {name}"
    evidence_prefix = f"Cookie '{name}' (classified as {classification})"

    if not cookie.get("httponly"):
        findings.append(_make_finding(
            title=f"Cookie '{name}' missing HttpOnly attribute",
            severity=sev_for("high", "medium"),
            confidence="verified-live",
            cwe="CWE-1004", owasp="A05:2021-Security Misconfiguration",
            location=location,
            evidence=f"{evidence_prefix} does not set HttpOnly, making it readable by JavaScript. Raw: {cookie.get('raw', '')[:200]}",
            poc=poc,
            remediation="Add the HttpOnly attribute to prevent client-side script access to this cookie.",
            detection_method="Set-Cookie Header Analysis",
            tier=base_tier,
        ))

    if is_https and not cookie.get("secure"):
        findings.append(_make_finding(
            title=f"Cookie '{name}' missing Secure attribute",
            severity=sev_for("high", "medium"),
            confidence="verified-live",
            cwe="CWE-614", owasp="A05:2021-Security Misconfiguration",
            location=location,
            evidence=f"{evidence_prefix} is set on an HTTPS response without the Secure attribute, so it could be sent over a downgraded HTTP connection. Raw: {cookie.get('raw', '')[:200]}",
            poc=poc,
            remediation="Add the Secure attribute so this cookie is never sent over an unencrypted HTTP connection.",
            detection_method="Set-Cookie Header Analysis",
            tier=base_tier,
        ))

    samesite = (cookie.get("samesite") or "").strip().lower()
    if not samesite:
        findings.append(_make_finding(
            title=f"Cookie '{name}' missing SameSite attribute",
            severity=sev_for("medium", "low"),
            confidence="verified-live",
            cwe="CWE-1275", owasp="A01:2021-Broken Access Control",
            location=location,
            evidence=f"{evidence_prefix} does not set SameSite. Raw: {cookie.get('raw', '')[:200]}",
            poc=poc,
            remediation="Set SameSite=Lax or SameSite=Strict to reduce CSRF exposure, unless cross-site delivery is explicitly required.",
            detection_method="Set-Cookie Header Analysis",
            tier=base_tier,
        ))
    elif samesite == "none" and not cookie.get("secure"):
        # Distinct from the two checks above: this is a specific, real spec
        # violation (RFC 6265bis requires Secure whenever SameSite=None is
        # set) that modern browsers reject outright, not just a "missing
        # attribute" gap -- worth its own title per the task spec.
        findings.append(_make_finding(
            title=f"Cookie '{name}' sets SameSite=None without Secure",
            severity=sev_for("high", "medium"),
            confidence="verified-live",
            cwe="CWE-1275", owasp="A05:2021-Security Misconfiguration",
            location=location,
            evidence=f"{evidence_prefix} sets SameSite=None but not Secure -- modern browsers reject this exact combination per spec, so the cookie may silently fail to be set at all. Raw: {cookie.get('raw', '')[:200]}",
            poc=poc,
            remediation="Add the Secure attribute -- SameSite=None requires Secure per RFC 6265bis, or the cookie will be rejected by browsers.",
            detection_method="Set-Cookie Header Analysis",
            tier=base_tier,
        ))

    # __Host-/__Secure- prefix validation. These prefixes are the cookie
    # asserting a security guarantee in its own name; if the attributes
    # don't back that guarantee up, that mismatch is itself worth flagging
    # (some browsers silently reject the cookie, which is useful signal).
    # Always hardening tier: these are best-practice hardening checks, not
    # baseline requirements.
    if name.startswith("__Host-"):
        violations = []
        if not cookie.get("secure"):
            violations.append("missing Secure")
        if cookie.get("domain"):
            violations.append("sets Domain (must be host-only)")
        if (cookie.get("path") or "/") != "/":
            violations.append("Path is not '/'")
        if violations:
            findings.append(_make_finding(
                title=f"Cookie '{name}' violates __Host- prefix requirements",
                severity=sev_for("high", "medium"),
                confidence="verified-live",
                cwe="CWE-1275", owasp="A05:2021-Security Misconfiguration",
                location=location,
                evidence=f"Cookie name asserts the __Host- prefix but {', '.join(violations)}. Some browsers silently reject a cookie whose attributes don't satisfy its own prefix. Raw: {cookie.get('raw', '')[:200]}",
                poc=poc,
                remediation="A __Host- cookie must set Secure, must not set Domain, and must set Path=/.",
                detection_method="Cookie Prefix Validation",
                tier="hardening",
            ))
    elif name.startswith("__Secure-"):
        if not cookie.get("secure"):
            findings.append(_make_finding(
                title=f"Cookie '{name}' violates __Secure- prefix requirement",
                severity=sev_for("high", "medium"),
                confidence="verified-live",
                cwe="CWE-1275", owasp="A05:2021-Security Misconfiguration",
                location=location,
                evidence=f"Cookie name asserts the __Secure- prefix but does not set Secure. Some browsers silently reject a cookie whose attributes don't satisfy its own prefix. Raw: {cookie.get('raw', '')[:200]}",
                poc=poc,
                remediation="A __Secure- cookie must set the Secure attribute.",
                detection_method="Cookie Prefix Validation",
                tier="hardening",
            ))

    # Long-lived session/auth cookie -- only meaningful for cookies that
    # actually look session/auth-relevant in the first place.
    if is_sensitive:
        lifetime_days = _cookie_lifetime_days(cookie)
        if lifetime_days is not None and lifetime_days > LONG_LIVED_COOKIE_THRESHOLD_DAYS:
            findings.append(_make_finding(
                title=f"Session-like cookie '{name}' has an unusually long lifetime ({lifetime_days:.0f} days)",
                severity="low",
                confidence="verified-live",
                cwe="CWE-613", owasp="A07:2021-Identification and Authentication Failures",
                location=location,
                evidence=f"{evidence_prefix} persists for {lifetime_days:.0f} days, above the {LONG_LIVED_COOKIE_THRESHOLD_DAYS}-day threshold used for this check. Raw: {cookie.get('raw', '')[:200]}",
                poc=poc,
                remediation="Shorten the lifetime of session/authentication cookies; prefer short-lived access tokens with refresh rotation over long-lived persistent credentials.",
                detection_method="Cookie Lifetime Analysis",
                tier="hardening",
            ))

    return findings


# ------------------------------------------------------------------------------
# Main entry point
# ------------------------------------------------------------------------------
async def run(ctx: Any) -> dict:
    """Entry point for the Cookie Security scout. Analyzes Set-Cookie headers
    already captured by the orchestrator's single main-page fetch -- issues
    zero new HTTP requests of its own."""
    if not getattr(ctx, "page_is_representative", True):
        return {"fatal_error": "Page is not representative (e.g., WAF block or hard error); skipping cookie analysis."}

    url = getattr(ctx, "url", "https://example.com")
    main_cache = getattr(ctx, "main_page_cache", {}) or {}
    _m = getattr(ctx, "metrics", None)
    if isinstance(_m, dict):
        _m["cache_reads"] = _m.get("cache_reads", 0) + 1
    is_https = url.lower().startswith("https://")

    # Prefer the full multi-value list (main_scanner.py's
    # main_page_cache["set_cookie_headers"]); dict(resp.headers) flattens
    # multiple Set-Cookie headers down to one, so fall back to that single
    # value only if the richer list isn't available (e.g. an older cache
    # shape, or a hand-built context in a test/standalone run).
    raw_set_cookie_headers = list(main_cache.get("set_cookie_headers") or [])
    if not raw_set_cookie_headers:
        single = (main_cache.get("headers") or {}).get("Set-Cookie")
        if single:
            raw_set_cookie_headers = [single]

    if not raw_set_cookie_headers:
        return {
            "findings": [_make_finding(
                title="No cookies observed on the response",
                severity="info",
                confidence="informational",
                cwe="", owasp="",
                location=url,
                evidence="The response did not set any Set-Cookie headers.",
                poc=f"curl -Is {url} | grep -i 'set-cookie'",
                remediation="No action required.",
                detection_method="Set-Cookie Header Analysis",
                tier="baseline",
            )],
            "details": {"requests_made": 0, "cookies_analyzed": 0},
        }

    all_findings: List[Dict[str, Any]] = []
    cookies_seen: List[str] = []
    for raw in raw_set_cookie_headers:
        cookie = _parse_set_cookie(raw)
        name = cookie.get("name")
        if not name:
            continue
        cookies_seen.append(name)
        all_findings.extend(_check_cookie(cookie, url, is_https))

    return {
        "findings": all_findings,
        "details": {
            "requests_made": 0,
            "cookies_analyzed": len(cookies_seen),
            "cookie_names": cookies_seen,
        },
    }


# ────────────────────────────────────────────── Standalone Testing ──────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(description="Bravo6 Cookie Security Scout")
    parser.add_argument("url", nargs="?", default="https://example.com", help="Target URL")
    parser.add_argument("--test", action="store_true", help="Run Scout Regression Tests")
    args = parser.parse_args()

    if args.test:
        import unittest

        class TestCookieClassification(unittest.TestCase):
            def test_session_cookie_classified_sensitive(self):
                self.assertEqual(_classify_cookie_sensitivity("session_id"), "sensitive")
                self.assertEqual(_classify_cookie_sensitivity("auth_token"), "sensitive")
                self.assertEqual(_classify_cookie_sensitivity("PHPSESSID"), "sensitive")

            def test_tracking_cookie_classified_tracking(self):
                self.assertEqual(_classify_cookie_sensitivity("_ga"), "tracking")
                self.assertEqual(_classify_cookie_sensitivity("_fbp"), "tracking")

            def test_tracking_prefix_wins_over_session_substring(self):
                # A real GA4 cookie name shape that happens to contain "session".
                self.assertEqual(_classify_cookie_sensitivity("_ga_session_test"), "tracking")

            def test_unrelated_cookie_classified_generic(self):
                self.assertEqual(_classify_cookie_sensitivity("theme_preference"), "generic")

        class TestCookieSecurityChecks(unittest.TestCase):
            URL = "https://example.com"

            def _titles(self, findings):
                return [f["title"] for f in findings]

            def test_session_cookie_missing_httponly_and_secure_is_elevated(self):
                cookie = _parse_set_cookie("session_id=abc123; Path=/")
                findings = _check_cookie(cookie, self.URL, is_https=True)
                httponly_f = next(f for f in findings if "HttpOnly" in f["title"])
                secure_f = next(f for f in findings if "Secure attribute" in f["title"] and "SameSite" not in f["title"])
                self.assertEqual(httponly_f["severity"], "high")
                self.assertEqual(secure_f["severity"], "high")
                self.assertEqual(httponly_f["raw_data"]["tier"], "baseline")

            def test_tracking_cookie_same_gaps_is_low_and_hardening(self):
                cookie = _parse_set_cookie("_ga=GA1.2.123456789.987654321; Path=/")
                findings = _check_cookie(cookie, self.URL, is_https=True)
                httponly_f = next(f for f in findings if "HttpOnly" in f["title"])
                self.assertEqual(httponly_f["severity"], "low")
                self.assertEqual(httponly_f["raw_data"]["tier"], "hardening")

            def test_samesite_none_without_secure_is_distinct_finding(self):
                cookie = _parse_set_cookie("session_id=abc123; Path=/; SameSite=None")
                findings = _check_cookie(cookie, self.URL, is_https=True)
                titles = self._titles(findings)
                self.assertIn("Cookie 'session_id' sets SameSite=None without Secure", titles)
                # Must not ALSO fire the generic "missing SameSite" finding --
                # SameSite IS set, just invalidly combined with a missing Secure.
                self.assertNotIn("Cookie 'session_id' missing SameSite attribute", titles)

            def test_fully_correct_cookie_produces_no_findings(self):
                cookie = _parse_set_cookie(
                    "session_id=abc123; Path=/; HttpOnly; Secure; SameSite=Strict"
                )
                findings = _check_cookie(cookie, self.URL, is_https=True)
                self.assertEqual(findings, [])

            def test_host_prefix_violation_missing_secure(self):
                cookie = _parse_set_cookie("__Host-session=abc123; Path=/; HttpOnly")
                findings = _check_cookie(cookie, self.URL, is_https=True)
                titles = self._titles(findings)
                self.assertIn("Cookie '__Host-session' violates __Host- prefix requirements", titles)
                prefix_finding = next(f for f in findings if "__Host-" in f["title"] and "violates" in f["title"])
                self.assertEqual(prefix_finding["raw_data"]["tier"], "hardening")

            def test_host_prefix_violation_sets_domain(self):
                cookie = _parse_set_cookie("__Host-session=abc123; Path=/; Secure; Domain=example.com")
                findings = _check_cookie(cookie, self.URL, is_https=True)
                prefix_finding = next(f for f in findings if "violates __Host-" in f["title"])
                self.assertIn("sets Domain", prefix_finding["evidence"])

            def test_secure_prefix_violation(self):
                cookie = _parse_set_cookie("__Secure-id=abc123; Path=/")
                findings = _check_cookie(cookie, self.URL, is_https=True)
                titles = self._titles(findings)
                self.assertIn("Cookie '__Secure-id' violates __Secure- prefix requirement", titles)

            def test_long_lived_session_cookie_flagged(self):
                cookie = _parse_set_cookie("auth_token=abc123; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=63072000")  # 2 years
                findings = _check_cookie(cookie, self.URL, is_https=True)
                titles = self._titles(findings)
                self.assertTrue(any("unusually long lifetime" in t for t in titles))
                long_lived = next(f for f in findings if "unusually long lifetime" in f["title"])
                self.assertEqual(long_lived["severity"], "low")
                self.assertEqual(long_lived["raw_data"]["tier"], "hardening")

            def test_short_lived_session_cookie_not_flagged_for_lifetime(self):
                cookie = _parse_set_cookie("auth_token=abc123; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600")  # 1 hour
                findings = _check_cookie(cookie, self.URL, is_https=True)
                titles = self._titles(findings)
                self.assertFalse(any("unusually long lifetime" in t for t in titles))

            def test_long_lived_tracking_cookie_not_flagged(self):
                # The long-lived check only applies to sensitive-classified
                # cookies -- a 2-year _ga cookie is normal, not a finding.
                cookie = _parse_set_cookie("_ga=GA1.2.123.456; Path=/; Max-Age=63072000")
                findings = _check_cookie(cookie, self.URL, is_https=True)
                titles = self._titles(findings)
                self.assertFalse(any("unusually long lifetime" in t for t in titles))

            def test_no_secure_check_on_plain_http_site(self):
                cookie = _parse_set_cookie("session_id=abc123; Path=/; HttpOnly")
                findings = _check_cookie(cookie, "http://example.com", is_https=False)
                titles = self._titles(findings)
                self.assertFalse(any("Secure attribute" in t for t in titles))

        class TestRunEndToEnd(unittest.IsolatedAsyncioTestCase):
            """Confirms run(ctx) correctly reads ctx.main_page_cache without
            issuing any new HTTP requests, and prefers the multi-value
            set_cookie_headers list over the flattened single-value header."""

            async def test_multiple_cookies_all_analyzed(self):
                class Ctx:
                    url = "https://example.com"
                    page_is_representative = True
                    main_page_cache = {
                        "set_cookie_headers": [
                            "session_id=abc123; Path=/",
                            "_ga=GA1.2.123.456; Path=/",
                        ],
                        "headers": {"Set-Cookie": "_ga=GA1.2.123.456; Path=/"},  # would lose session_id if used alone
                    }

                result = await run(Ctx())
                self.assertEqual(result["details"]["cookies_analyzed"], 2)
                self.assertIn("session_id", result["details"]["cookie_names"])
                self.assertIn("_ga", result["details"]["cookie_names"])

            async def test_no_cookies_produces_informational_finding(self):
                class Ctx:
                    url = "https://example.com"
                    page_is_representative = True
                    main_page_cache = {"set_cookie_headers": [], "headers": {}}

                result = await run(Ctx())
                self.assertEqual(len(result["findings"]), 1)
                self.assertEqual(result["findings"][0]["severity"], "info")

            async def test_non_representative_page_skips_analysis(self):
                class Ctx:
                    url = "https://example.com"
                    page_is_representative = False
                    main_page_cache = {}

                result = await run(Ctx())
                self.assertIn("fatal_error", result)

        sys.argv = [sys.argv[0]]
        unittest.main()
    else:
        import asyncio
        import aiohttp
        from dataclasses import dataclass, field

        @dataclass
        class DummyContext:
            url: str
            page_is_representative: bool = True
            main_page_cache: dict = field(default_factory=dict)

        async def _live_scan():
            connector = aiohttp.TCPConnector(ssl=True)
            async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": "Bravo6-Scanner/8.5"}) as session:
                try:
                    async with session.get(args.url) as resp:
                        html = await resp.text()
                        main_page_cache = {
                            "status": resp.status,
                            "html": html,
                            "headers": dict(resp.headers),
                            "set_cookie_headers": resp.headers.getall("Set-Cookie", []),
                        }
                except Exception as e:
                    main_page_cache = {"error": str(e), "html": "", "headers": {}, "set_cookie_headers": []}

                ctx = DummyContext(url=args.url, main_page_cache=main_page_cache)
                result = await run(ctx)
                print(json.dumps(result, indent=2, ensure_ascii=False, default=str))

        asyncio.run(_live_scan())
