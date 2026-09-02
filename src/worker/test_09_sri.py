#!/usr/bin/env python3
"""
test_09_sri.py - Bravo6 Subresource Integrity (SRI) Scanner (v1.0)
=====================================================================
- ZERO new network requests. This scout is a second, read-only pass over
  the main-page HTML the orchestrator already fetched and cached in
  ctx.main_page_cache ("html"/"soup") -- the exact same cache
  test_02_frontend_libs.py reads. If it ever needs its own fetch, that is
  a sign the caching/reuse step was missed.
- Tag extraction mirrors test_02_frontend_libs.py's approach exactly
  (soup.find_all(...) + tag.get(...) + urljoin(ctx.url, ...)). That logic
  lives inline inside test_02's run() rather than as an importable helper,
  so it is reproduced here in the same shape rather than re-inventing an
  HTML/tag parser.
- Scope: cross-origin <script src="..."> and
  <link rel="stylesheet" href="..."> only. Same-origin resources are
  skipped entirely -- SRI exists to contain a compromised *third party*,
  and a same-origin file is already inside the site's own trust boundary,
  so flagging it would be a false signal. Inline <script> content is out
  of scope (SRI does not apply to it).
- Every finding is tagged raw_data["tier"] = "hardening". Missing SRI is
  a defense-in-depth absence, not a standalone exploit -- it only matters
  if the third-party host is separately compromised -- so it belongs in
  the same pooled, capped bucket as test_05's missing-header findings,
  NOT the "baseline" tier that test_08_cors uses for the directly-
  exploitable CORS misconfiguration class.

Checks, per cross-origin resource:
  - <script src>            with no integrity attribute   -> medium
  - <link rel=stylesheet>   with no integrity attribute   -> low
    (real -- CSS attribute-selector data exfiltration is documented --
    but a smaller blast radius than arbitrary JS execution)
  - cross-origin resource whose host is a SUBDOMAIN of the same
    registrable domain (eTLD+1) as the page (e.g. c.mql5.com vs
    mql5.com), with no integrity attribute -> low (script OR stylesheet),
    a distinct finding ("Cross-Origin Subresource (Same-Domain Subdomain)
    Missing SRI"). Still flagged, still tier=hardening -- but a lower
    severity/priority call than a genuine third-party CDN reference,
    because the asset sub-host is almost certainly operated by the same
    party as the site.
  - integrity present but crossorigin missing/invalid     -> medium,
    a distinct finding ("SRI Present But Not Enforced"). Browsers
    silently DO NOT perform the integrity check without a valid
    crossorigin attribute, so the team believes it is protected when it
    is not -- arguably more worth surfacing clearly than plain absence.
  - integrity present + valid crossorigin                 -> no finding
  - no cross-origin <script>/<link rel=stylesheet> at all -> one
    info/informational finding ("SRI not applicable to this page"),
    mirroring how test_08_cors reports "no CORS headers observed" rather
    than silently returning zero findings.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import tldextract
from bs4 import BeautifulSoup

# Per the HTML spec the crossorigin (CORS-settings) attribute is valid as
# a bare attribute (empty value, == "anonymous"), "anonymous", or
# "use-credentials". Anything else is an invalid value and browsers treat
# it as "anonymous" BUT authors often mean something by it -- flag it.
VALID_CROSSORIGIN = {"", "anonymous", "use-credentials"}

DETECTION_METHOD = "Cached-HTML Subresource Integrity Analysis"

# Registrable-domain (eTLD+1) extraction via the real Public Suffix List,
# same pattern/rationale as test_07_email_security.py: constructed once at
# module scope with suffix_list_urls=() so it relies purely on the PSL
# snapshot bundled with the tldextract package and never makes a live
# network call at scan time (this scout is strictly zero-request).
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


# ------------------------------------------------------------------------------
# Finding factory -- identical shape/convention to test_05 and test_08
# (explicit `tier` param, nested under raw_data).
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
# Origin comparison
# ------------------------------------------------------------------------------
def _host(parsed) -> str:
    h = (parsed.hostname or "").lower()
    return h[4:] if h.startswith("www.") else h


def _port(parsed) -> Optional[int]:
    if parsed.port:
        return parsed.port
    return {"https": 443, "http": 80}.get((parsed.scheme or "").lower())


def _registrable_domain(host: str) -> str:
    """eTLD+1 for a hostname (e.g. 'c.mql5.com' -> 'mql5.com'), lowercased.
    Falls back to the bare host if the PSL yields no registrable domain
    (e.g. a bare IP or an unknown suffix)."""
    # .top_domain_under_public_suffix is tldextract's current name for what
    # used to be .registered_domain (matches test_07_email_security.py).
    return (_TLD_EXTRACTOR(host or "").top_domain_under_public_suffix or host or "").lower()


def _same_registrable_domain(base_url: str, resource_url: str) -> bool:
    """True when the resource host and the page host share the same
    registrable domain (eTLD+1) -- i.e. the resource is a sibling/child
    subdomain (c.mql5.com vs www.mql5.com), not a genuine third party.
    Only meaningful for hosts already known to be cross-origin."""
    b = _registrable_domain(urlparse(base_url).hostname or "")
    r = _registrable_domain(urlparse(resource_url).hostname or "")
    return bool(b) and b == r


def _is_same_origin(base_url: str, resource_url: str) -> bool:
    """Same-origin == same host (leading 'www.' normalised away) and same
    effective port.

    Deliberate scoping decisions (flagged for review in the report-back):
      * A scheme-only difference (an https page pulling http://same-host/x.js)
        is treated as same-origin here -- that is a mixed-content problem,
        which is test_04's job, not an SRI gap.
      * A different sub-domain (cdn.example.com vs example.com) IS treated
        as cross-origin: the browser treats it as a separate origin, and
        it is typically a separately-operated host, so it is exactly what
        SRI is meant to guard.
    """
    r = urlparse(resource_url)
    if not r.netloc:
        return True  # relative reference -> same origin
    b = urlparse(base_url)
    return _host(b) == _host(r) and _port(b) == _port(r)


def _resolve(base_url: str, ref: str) -> Optional[str]:
    ref = (ref or "").strip()
    if not ref:
        return None
    if ref.lower().startswith(("data:", "blob:", "javascript:", "about:", "#")):
        return None
    resolved = urljoin(base_url, ref)
    if urlparse(resolved).scheme.lower() not in ("http", "https"):
        return None
    return resolved


def _rel_tokens(tag) -> List[str]:
    rel = tag.get("rel") or []
    if isinstance(rel, str):
        rel = rel.split()
    return [r.lower() for r in rel]


def _snippet(tag) -> str:
    s = " ".join(str(tag).split())
    return s if len(s) <= 300 else s[:297] + "..."


# ------------------------------------------------------------------------------
# Tag extraction -- same pattern as test_02_frontend_libs.py's run()
# ------------------------------------------------------------------------------
def _extract_targets(soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
    """Return a dict per <script src> and <link rel=stylesheet href> in the
    cached HTML. No network calls -- pure parse of already-fetched markup."""
    targets: List[Dict[str, Any]] = []

    for tag in soup.find_all("script"):
        src = tag.get("src")
        if not src:
            continue
        resolved = _resolve(base_url, src)
        if not resolved:
            continue
        targets.append(_describe(tag, "script", resolved, src))

    for tag in soup.find_all("link"):
        if "stylesheet" not in _rel_tokens(tag):
            continue
        href = tag.get("href")
        if not href:
            continue
        resolved = _resolve(base_url, href)
        if not resolved:
            continue
        targets.append(_describe(tag, "stylesheet", resolved, href))

    return targets


def _describe(tag, kind: str, resolved_url: str, raw_ref: str) -> Dict[str, Any]:
    return {
        "kind": kind,
        "url": resolved_url,
        "raw_ref": (raw_ref or "").strip(),
        "integrity": (tag.get("integrity") or "").strip(),
        "has_crossorigin": tag.has_attr("crossorigin"),
        "crossorigin": (tag.get("crossorigin") or "").strip().lower(),
        "tag": _snippet(tag),
    }


# ------------------------------------------------------------------------------
# Per-resource evaluation -- severity scoped strictly to what is observed
# for THIS resource; nothing here influences any other finding.
# ------------------------------------------------------------------------------
def _evaluate(t: Dict[str, Any], base_url: str) -> Optional[Dict[str, Any]]:
    kind = t["kind"]
    loc = t["url"]
    tag = t["tag"]
    integrity = t["integrity"]
    has_co = t["has_crossorigin"]
    co = t["crossorigin"]
    co_valid = has_co and co in VALID_CROSSORIGIN
    host = urlparse(loc).hostname or "the third-party host"

    if not integrity:
        if _same_registrable_domain(base_url, loc):
            reg = _registrable_domain(urlparse(loc).hostname or "")
            return _make_finding(
                title="Cross-Origin Subresource (Same-Domain Subdomain) Missing SRI",
                severity="low",
                confidence="verified-static",
                cwe="CWE-353",
                owasp="A08:2021-Software and Data Integrity Failures",
                location=loc,
                evidence=(
                    f"The page loads a {kind} from {host} -- a different origin than the page, "
                    f"but the same registrable domain ({reg}), i.e. a sibling/child subdomain "
                    "rather than a genuine third party. It has no integrity attribute. Because "
                    "the asset sub-host is almost certainly operated by the same party as the "
                    "site, this is a lower-priority defense-in-depth gap than an un-pinned "
                    "third-party CDN reference: SRI would only matter here if this specific "
                    "sub-host had a separate deployment/trust boundary (e.g. a shared object "
                    f"store) and were independently compromised. Tag: {tag}"
                ),
                poc=(
                    "# Compute the hash to pin, then add it to the tag:\n"
                    f"curl -sL {loc} | openssl dgst -sha384 -binary | openssl base64 -A"
                ),
                remediation=(
                    'Add integrity="sha384-<hash>" and crossorigin="anonymous" to the tag, or '
                    "serve the asset from the page's own host. Lower priority than pinning "
                    "genuine third-party / external-CDN resources."
                ),
                detection_method=DETECTION_METHOD,
                tier="hardening",
            )
        if kind == "script":
            return _make_finding(
                title="Cross-origin <script> loaded without Subresource Integrity",
                severity="medium",
                confidence="verified-static",
                cwe="CWE-494",
                owasp="A08:2021-Software and Data Integrity Failures",
                location=loc,
                evidence=(
                    f"The page loads a script from a different origin ({host}) with no "
                    "integrity attribute, so the browser executes whatever bytes that host "
                    f"returns. If {host} -- or anything on the path between it and the "
                    "visitor -- is compromised, attacker-controlled JavaScript runs with the "
                    f"full privileges of this page (DOM access, cookies, tokens). Tag: {tag}"
                ),
                poc=(
                    "# Compute the hash to pin, then add it to the tag:\n"
                    f"curl -sL {loc} | openssl dgst -sha384 -binary | openssl base64 -A"
                ),
                remediation=(
                    'Add integrity="sha384-<hash>" and crossorigin="anonymous" to the '
                    "<script> tag; regenerate the hash whenever the pinned version changes, "
                    "or self-host the script so it is same-origin."
                ),
                detection_method=DETECTION_METHOD,
                tier="hardening",
            )
        return _make_finding(
            title="Cross-origin stylesheet loaded without Subresource Integrity",
            severity="low",
            confidence="verified-static",
            cwe="CWE-353",
            owasp="A08:2021-Software and Data Integrity Failures",
            location=loc,
            evidence=(
                f"The page loads a stylesheet from a different origin ({host}) with no "
                "integrity attribute. A compromised replacement cannot execute arbitrary "
                "JavaScript, but CSS-based attacks are real: attribute-selector rules plus "
                "background-image requests can exfiltrate the values of form fields and "
                "hidden tokens, and injected @import / content rules can deface or overlay "
                f"the page. Tag: {tag}"
            ),
            poc=(
                "# Compute the hash to pin, then add it to the tag:\n"
                f"curl -sL {loc} | openssl dgst -sha384 -binary | openssl base64 -A"
            ),
            remediation=(
                'Add integrity="sha384-<hash>" and crossorigin="anonymous" to the '
                '<link rel="stylesheet"> tag, or self-host the stylesheet.'
            ),
            detection_method=DETECTION_METHOD,
            tier="hardening",
        )

    # integrity IS present past this point
    if not co_valid:
        reason = ("it has no crossorigin attribute" if not has_co
                  else f'its crossorigin value ("{co}") is not "anonymous" or "use-credentials"')
        return _make_finding(
            title="SRI present but not enforced - missing/invalid crossorigin attribute",
            severity="medium",
            confidence="verified-static",
            cwe="CWE-353",
            owasp="A08:2021-Software and Data Integrity Failures",
            location=loc,
            evidence=(
                f"This cross-origin {kind} tag carries an integrity attribute, but {reason}. "
                "Without a valid crossorigin attribute the browser requests the resource in "
                "no-cors mode, cannot read the opaque response to hash it, and therefore "
                "SILENTLY SKIPS the integrity check entirely -- the resource loads "
                "completely unverified while the integrity attribute creates a false "
                f"impression that it is pinned. Tag: {tag}"
            ),
            poc=(
                "Add the crossorigin attribute to the existing tag, e.g.: "
                '<script src="..." integrity="sha384-..." crossorigin="anonymous"></script>'
            ),
            remediation=(
                'Add crossorigin="anonymous" (or "use-credentials" if the resource genuinely '
                "needs credentials) alongside the existing integrity attribute so the browser "
                "actually performs the check. Also confirm the pinned CDN sends "
                "Access-Control-Allow-Origin."
            ),
            detection_method=DETECTION_METHOD,
            tier="hardening",
        )

    return None  # integrity + valid crossorigin -> correctly configured, no finding


# ------------------------------------------------------------------------------
# Main entry point
# ------------------------------------------------------------------------------
async def run(ctx: Any) -> dict:
    """Entry point for the Subresource Integrity scout. Reads only the
    already-cached main-page HTML (ctx.main_page_cache); issues zero new
    HTTP requests of its own."""
    if not getattr(ctx, "page_is_representative", True):
        return {"fatal_error": "Page is not representative (e.g., WAF block or hard error); skipping SRI analysis."}

    url = getattr(ctx, "url", "https://example.com")
    main_cache = getattr(ctx, "main_page_cache", {}) or {}
    html = main_cache.get("html", "")
    soup = main_cache.get("soup")
    if not soup and html:
        soup = BeautifulSoup(html, "html.parser")
    if not soup:
        return {"fatal_error": "Failed to parse main page HTML."}

    _m = getattr(ctx, "metrics", None)
    if isinstance(_m, dict):
        _m["cache_reads"] = _m.get("cache_reads", 0) + 1

    targets = _extract_targets(soup, url)
    cross_origin = [t for t in targets if not _is_same_origin(url, t["url"])]
    same_origin_skipped = len(targets) - len(cross_origin)

    details = {
        "requests_made": 0,
        "script_link_tags_seen": len(targets),
        "cross_origin_resources": len(cross_origin),
        "same_origin_skipped": same_origin_skipped,
    }

    if not cross_origin:
        if not targets:
            detail = 'No <script src> or <link rel="stylesheet"> tags were found in the page HTML.'
        else:
            detail = (
                f"All {same_origin_skipped} <script>/<stylesheet> resource(s) on the page are "
                "same-origin, which sit inside the site's own trust boundary and do not need SRI."
            )
        return {
            "findings": [_make_finding(
                title="Subresource Integrity not applicable to this page",
                severity="info",
                confidence="informational",
                cwe="", owasp="",
                location=url,
                evidence=(
                    f"{detail} SRI protects against a compromised third-party host serving a "
                    "malicious replacement for a cross-origin script or stylesheet; with no "
                    "such resource present there is nothing for it to protect. This confirms "
                    "the check ran rather than silently no-op'ing."
                ),
                poc="Manual verification: view-source and confirm no cross-origin <script src> / <link rel=stylesheet>.",
                remediation=(
                    "No action required. If cross-origin CDN resources are added later, pin "
                    'each one with integrity="sha384-<hash>" plus crossorigin="anonymous".'
                ),
                detection_method=DETECTION_METHOD,
                tier="hardening",
            )],
            "details": details,
        }

    findings: List[Dict[str, Any]] = []
    for t in cross_origin:
        f = _evaluate(t, url)
        if f:
            findings.append(f)

    if not findings:
        # Cross-origin resources exist and every one is correctly pinned.
        # Emit a confirmation rather than silence, same rationale as the
        # "not applicable" case above.
        findings.append(_make_finding(
            title="All cross-origin subresources correctly pinned with SRI",
            severity="info",
            confidence="informational",
            cwe="", owasp="",
            location=url,
            evidence=(
                f"{len(cross_origin)} cross-origin script/stylesheet resource(s) were checked; "
                "every one carries an integrity attribute together with a valid crossorigin "
                "attribute. This confirms the check ran."
            ),
            poc="N/A",
            remediation="No action required. Re-verify the pinned hashes whenever a CDN resource version is bumped.",
            detection_method=DETECTION_METHOD,
            tier="hardening",
        ))

    return {"findings": findings, "details": details}


# ────────────────────────────────────────────── Standalone Testing ──────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(description="Bravo6 Subresource Integrity (SRI) Scout")
    parser.add_argument("url", nargs="?", default="https://example.com", help="Target URL")
    parser.add_argument("--test", action="store_true", help="Run Scout Regression Tests")
    args = parser.parse_args()

    if args.test:
        import asyncio
        import unittest

        BASE = "https://example.com"

        class _Ctx:
            def __init__(self, html, url=BASE, page_is_representative=True):
                self.url = url
                self.page_is_representative = page_is_representative
                self.main_page_cache = {
                    "html": html,
                    "soup": BeautifulSoup(html, "html.parser") if html is not None else None,
                    "status": 200,
                }

        def _run(html, **kw):
            return asyncio.run(run(_Ctx(html, **kw)))

        def _titles(result):
            return [f["title"] for f in result["findings"]]

        class TestSriScout(unittest.TestCase):
            def test_cross_origin_script_missing_integrity_is_medium(self):
                html = '<html><head><script src="https://cdn.jsdelivr.net/npm/foo/foo.js"></script></head></html>'
                result = _run(html)
                self.assertEqual(len(result["findings"]), 1)
                f = result["findings"][0]
                self.assertEqual(f["title"], "Cross-origin <script> loaded without Subresource Integrity")
                self.assertEqual(f["severity"], "medium")
                self.assertEqual(f["confidence"], "verified-static")
                self.assertEqual(f["raw_data"]["tier"], "hardening")
                self.assertEqual(result["details"]["requests_made"], 0)

            def test_cross_origin_stylesheet_missing_integrity_is_low(self):
                html = '<html><head><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bar/bar.css"></head></html>'
                result = _run(html)
                self.assertEqual(len(result["findings"]), 1)
                f = result["findings"][0]
                self.assertEqual(f["title"], "Cross-origin stylesheet loaded without Subresource Integrity")
                self.assertEqual(f["severity"], "low")
                self.assertEqual(f["raw_data"]["tier"], "hardening")

            def test_script_severity_does_not_leak_into_stylesheet_finding(self):
                # One bad cross-origin script must not inflate the co-located
                # stylesheet finding's severity.
                html = (
                    '<html><head>'
                    '<script src="https://cdn.example.net/a.js"></script>'
                    '<link rel="stylesheet" href="https://cdn.example.net/a.css">'
                    '</head></html>'
                )
                result = _run(html)
                by_title = {f["title"]: f for f in result["findings"]}
                self.assertEqual(by_title["Cross-origin <script> loaded without Subresource Integrity"]["severity"], "medium")
                self.assertEqual(by_title["Cross-origin stylesheet loaded without Subresource Integrity"]["severity"], "low")

            def test_integrity_present_but_crossorigin_missing_is_medium_distinct(self):
                html = (
                    '<html><head><script src="https://cdn.jsdelivr.net/npm/foo/foo.js" '
                    'integrity="sha384-abc123"></script></head></html>'
                )
                result = _run(html)
                self.assertEqual(len(result["findings"]), 1)
                f = result["findings"][0]
                self.assertEqual(f["title"], "SRI present but not enforced - missing/invalid crossorigin attribute")
                self.assertEqual(f["severity"], "medium")
                self.assertEqual(f["raw_data"]["tier"], "hardening")
                self.assertNotIn("without Subresource Integrity", f["title"])
                self.assertIn("no crossorigin attribute", f["evidence"])

            def test_integrity_present_but_crossorigin_invalid_value_is_flagged(self):
                html = (
                    '<html><head><script src="https://cdn.jsdelivr.net/npm/foo/foo.js" '
                    'integrity="sha384-abc123" crossorigin="bogus"></script></head></html>'
                )
                result = _run(html)
                self.assertEqual(len(result["findings"]), 1)
                f = result["findings"][0]
                self.assertEqual(f["title"], "SRI present but not enforced - missing/invalid crossorigin attribute")
                self.assertEqual(f["severity"], "medium")
                self.assertIn('"bogus"', f["evidence"])

            def test_correctly_configured_cross_origin_script_produces_no_resource_finding(self):
                html = (
                    '<html><head><script src="https://cdn.jsdelivr.net/npm/foo/foo.js" '
                    'integrity="sha384-abc123" crossorigin="anonymous"></script></head></html>'
                )
                result = _run(html)
                titles = _titles(result)
                self.assertNotIn("Cross-origin <script> loaded without Subresource Integrity", titles)
                self.assertNotIn("SRI present but not enforced - missing/invalid crossorigin attribute", titles)
                # Confirmation finding only.
                self.assertEqual(len(result["findings"]), 1)
                self.assertEqual(result["findings"][0]["severity"], "info")
                self.assertEqual(result["findings"][0]["title"], "All cross-origin subresources correctly pinned with SRI")

            def test_bare_crossorigin_attribute_counts_as_valid(self):
                html = (
                    '<html><head><script src="https://cdn.jsdelivr.net/npm/foo/foo.js" '
                    'integrity="sha384-abc123" crossorigin></script></head></html>'
                )
                result = _run(html)
                self.assertEqual(result["findings"][0]["title"], "All cross-origin subresources correctly pinned with SRI")

            def test_same_origin_script_without_integrity_is_not_flagged(self):
                html = '<html><head><script src="/js/app.js"></script></head></html>'
                result = _run(html)
                titles = _titles(result)
                self.assertNotIn("Cross-origin <script> loaded without Subresource Integrity", titles)
                self.assertEqual(len(result["findings"]), 1)
                self.assertEqual(result["findings"][0]["title"], "Subresource Integrity not applicable to this page")
                self.assertEqual(result["findings"][0]["severity"], "info")
                self.assertEqual(result["details"]["same_origin_skipped"], 1)

            def test_same_origin_absolute_url_and_www_normalisation(self):
                html = (
                    '<html><head>'
                    '<script src="https://www.example.com/a.js"></script>'
                    '<script src="https://example.com/b.js"></script>'
                    '</head></html>'
                )
                result = _run(html, url="https://example.com")
                self.assertEqual(result["details"]["cross_origin_resources"], 0)
                self.assertEqual(result["findings"][0]["title"], "Subresource Integrity not applicable to this page")

            def test_subdomain_is_treated_as_cross_origin(self):
                # Still detected as cross-origin (still flagged, still
                # tier=hardening) -- but a subdomain of the same registrable
                # domain gets the distinct, lower-severity finding, not the
                # genuine-third-party one.
                html = '<html><head><script src="https://cdn.example.com/a.js"></script></head></html>'
                result = _run(html, url="https://example.com")
                self.assertEqual(result["details"]["cross_origin_resources"], 1)
                f = result["findings"][0]
                self.assertEqual(f["title"], "Cross-Origin Subresource (Same-Domain Subdomain) Missing SRI")
                self.assertEqual(f["severity"], "low")
                self.assertEqual(f["raw_data"]["tier"], "hardening")

            def test_same_registrable_domain_subdomain_script_is_low_with_distinct_title(self):
                # The exact real-world case from the n=20 batch: c.mql5.com
                # serving all of www.mql5.com's scripts. Same eTLD+1, different
                # sub-host -> flagged, but low + distinct title, NOT the
                # medium "Cross-origin <script> ... without Subresource Integrity".
                html = '<html><head><script src="https://c.mql5.com/js/all.5ee082fb.js"></script></head></html>'
                result = _run(html, url="https://www.mql5.com")
                self.assertEqual(len(result["findings"]), 1)
                f = result["findings"][0]
                self.assertEqual(f["title"], "Cross-Origin Subresource (Same-Domain Subdomain) Missing SRI")
                self.assertEqual(f["severity"], "low")
                self.assertEqual(f["confidence"], "verified-static")
                self.assertEqual(f["raw_data"]["tier"], "hardening")
                self.assertEqual(result["details"]["cross_origin_resources"], 1)
                self.assertNotIn("without Subresource Integrity", f["title"])
                self.assertIn("mql5.com", f["evidence"])

            def test_same_registrable_domain_subdomain_stylesheet_is_also_low_same_title(self):
                # Stylesheet path takes the SAME distinct low finding
                # (severity is low regardless of script/stylesheet here).
                html = '<html><head><link rel="stylesheet" href="https://assets.example.com/a.css"></head></html>'
                result = _run(html, url="https://example.com")
                self.assertEqual(len(result["findings"]), 1)
                f = result["findings"][0]
                self.assertEqual(f["title"], "Cross-Origin Subresource (Same-Domain Subdomain) Missing SRI")
                self.assertEqual(f["severity"], "low")
                self.assertEqual(f["raw_data"]["tier"], "hardening")

            def test_genuine_third_party_still_uses_third_party_titles(self):
                # Guard: a real third party (different eTLD+1) is unaffected by
                # the same-domain refinement -- script still medium, stylesheet
                # still low, with the original titles.
                html = (
                    '<html><head>'
                    '<script src="https://cdn.jsdelivr.net/npm/foo/foo.js"></script>'
                    '<link rel="stylesheet" href="https://fonts.googleapis.com/css?family=X">'
                    '</head></html>'
                )
                result = _run(html, url="https://example.com")
                by_title = {f["title"]: f for f in result["findings"]}
                self.assertEqual(
                    by_title["Cross-origin <script> loaded without Subresource Integrity"]["severity"], "medium")
                self.assertEqual(
                    by_title["Cross-origin stylesheet loaded without Subresource Integrity"]["severity"], "low")

            def test_protocol_relative_cross_origin_url_handled(self):
                html = '<html><head><script src="//cdn.jsdelivr.net/npm/foo/foo.js"></script></head></html>'
                result = _run(html, url="https://example.com")
                self.assertEqual(result["details"]["cross_origin_resources"], 1)
                self.assertEqual(result["findings"][0]["severity"], "medium")

            def test_page_with_no_script_or_link_tags_emits_info_not_applicable(self):
                html = "<html><head><title>hi</title></head><body><p>nothing here</p></body></html>"
                result = _run(html)
                self.assertEqual(len(result["findings"]), 1)
                f = result["findings"][0]
                self.assertEqual(f["title"], "Subresource Integrity not applicable to this page")
                self.assertEqual(f["severity"], "info")
                self.assertEqual(f["confidence"], "informational")
                self.assertEqual(f["raw_data"]["tier"], "hardening")
                self.assertIn("No <script src>", f["evidence"])

            def test_data_uri_script_is_ignored(self):
                html = '<html><head><script src="data:text/javascript,alert(1)"></script></head></html>'
                result = _run(html)
                self.assertEqual(result["details"]["script_link_tags_seen"], 0)
                self.assertEqual(result["findings"][0]["title"], "Subresource Integrity not applicable to this page")

            def test_non_stylesheet_link_is_ignored(self):
                html = '<html><head><link rel="preload" as="script" href="https://cdn.example.net/x.js"></head></html>'
                result = _run(html)
                self.assertEqual(result["details"]["script_link_tags_seen"], 0)

            def test_non_representative_page_skips_analysis(self):
                result = _run("<html></html>", page_is_representative=False)
                self.assertIn("fatal_error", result)

            def test_unparseable_page_returns_fatal_error(self):
                result = _run(None)
                self.assertIn("fatal_error", result)

            def test_every_finding_is_tagged_hardening_tier(self):
                html = (
                    '<html><head>'
                    '<script src="https://cdn.example.net/a.js"></script>'
                    '<link rel="stylesheet" href="https://cdn.example.net/a.css">'
                    '<script src="https://cdn.example.net/b.js" integrity="sha384-x"></script>'
                    '</head></html>'
                )
                result = _run(html)
                self.assertTrue(result["findings"])
                for f in result["findings"]:
                    self.assertEqual(f["raw_data"]["tier"], "hardening", f["title"])

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
                        page_html = await resp.text()
                        main_page_cache = {
                            "status": resp.status,
                            "html": page_html,
                            "headers": dict(resp.headers),
                            "soup": BeautifulSoup(page_html, "html.parser"),
                        }
                except Exception as e:
                    main_page_cache = {"error": str(e), "html": "", "headers": {}, "soup": None}

                ctx = DummyContext(url=args.url, main_page_cache=main_page_cache)
                result = await run(ctx)
                print(json.dumps(result, indent=2, ensure_ascii=False, default=str))

        asyncio.run(_live_scan())