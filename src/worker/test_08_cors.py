#!/usr/bin/env python3
"""
test_08_cors.py - Bravo6 CORS Misconfiguration Scanner (v1.0)
=====================================================================
- Exactly one additional passive request beyond what the orchestrator
  already cached: a cross-origin OPTIONS probe (falling back to GET only
  if OPTIONS isn't handled) to the SAME URL already being scanned, with a
  synthetic Origin header -- mirrors what a real browser CORS preflight
  sends, not an exploit attempt. No other paths/endpoints are probed.
- Checks the response's Access-Control-* headers for: wildcard origin +
  credentials (invalid per the Fetch spec, critical), origin reflection
  (critical with credentials, high without), a bare wildcard origin (low,
  often intentional for public APIs), and reports "no CORS headers" or
  "probe failed, inconclusive" explicitly rather than staying silent.
- Every finding is tagged raw_data["tier"] = "baseline": CORS
  misconfiguration is a real, exploitable vulnerability class, not a
  defense-in-depth nicety, so none of it belongs in the capped
  "hardening" pool alongside bleeding-edge headers like COOP/COEP.
"""

from typing import Any, Dict, List, Optional, Tuple

import aiohttp

SYNTHETIC_ORIGIN = "https://bravo6-cors-probe.invalid"
PROBE_TIMEOUT = aiohttp.ClientTimeout(total=8)

STATE_CHANGING_METHODS = {"PUT", "DELETE", "PATCH"}


# ------------------------------------------------------------------------------
# Finding factory (same convention as test_05/test_03/test_07: explicit tier
# param nested under raw_data).
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


def _state_changing_methods_note(acam: str) -> str:
    """Folds Access-Control-Allow-Methods' state-changing methods into an
    evidence-string detail rather than a separate finding -- one
    misconfiguration, one finding, per the task's explicit instruction."""
    found = [m.strip().upper() for m in acam.split(",") if m.strip().upper() in STATE_CHANGING_METHODS]
    if not found:
        return ""
    return f" Access-Control-Allow-Methods also allows state-changing method(s): {', '.join(found)}."


# ------------------------------------------------------------------------------
# The probe
# ------------------------------------------------------------------------------
async def _probe_cors(ctx: Any) -> Tuple[str, Dict[str, str]]:
    """Send a synthetic cross-origin OPTIONS request (preferred -- mirrors a
    real browser CORS preflight) to the exact URL already being scanned.
    Falls back to GET only if OPTIONS itself fails to complete, or
    responds with a status implying the method isn't handled at all
    (405/501) and gave no CORS-related headers either -- some servers only
    apply CORS headers to the actual request, not the preflight. Returns
    ("ok", lowercased-headers-dict) once ANY response was obtained (even
    one with zero CORS headers -- that's a real, reportable outcome), or
    ("failed", {}) only if neither request could be completed at all.
    """
    probe_headers = {"Origin": SYNTHETIC_ORIGIN, "Access-Control-Request-Method": "GET"}

    options_headers: Optional[Dict[str, str]] = None
    try:
        async with ctx.session.options(ctx.url, headers=probe_headers, timeout=PROBE_TIMEOUT) as resp:
            options_headers = {k.lower(): v for k, v in resp.headers.items()}
            has_cors_signal = any(
                h in options_headers
                for h in ("access-control-allow-origin", "access-control-allow-credentials", "access-control-allow-methods")
            )
            if has_cors_signal or resp.status not in (405, 501):
                return "ok", options_headers
    except Exception:
        pass

    try:
        async with ctx.session.get(ctx.url, headers={"Origin": SYNTHETIC_ORIGIN}, timeout=PROBE_TIMEOUT) as resp:
            return "ok", {k.lower(): v for k, v in resp.headers.items()}
    except Exception:
        if options_headers is not None:
            # OPTIONS itself completed (just without a strong CORS signal
            # and an ambiguous status) but the GET fallback failed --
            # trust what OPTIONS actually gave us instead of declaring the
            # whole probe inconclusive over a second request's failure.
            return "ok", options_headers
        return "failed", {}


# ------------------------------------------------------------------------------
# Main entry point
# ------------------------------------------------------------------------------
async def run(ctx: Any) -> dict:
    """Entry point for the CORS Misconfiguration scout."""
    if not getattr(ctx, "page_is_representative", True):
        return {"fatal_error": "Page is not representative (e.g., WAF block or hard error); skipping CORS analysis."}

    url = getattr(ctx, "url", "https://example.com")
    status, headers = await _probe_cors(ctx)

    if status == "failed":
        return {
            "findings": [_make_finding(
                title="CORS check inconclusive (probe request failed)",
                severity="info",
                confidence="plausible-unconfirmed",
                cwe="", owasp="",
                location=url,
                evidence=(
                    "The cross-origin CORS probe request did not complete (timeout or connection "
                    "error). This is NOT confirmation that CORS is safely configured -- only that "
                    "it could not be checked from here."
                ),
                poc=f"curl -i -X OPTIONS {url} -H 'Origin: {SYNTHETIC_ORIGIN}' -H 'Access-Control-Request-Method: GET'",
                remediation="Re-run this check; if it consistently fails, verify the endpoint is reachable.",
                detection_method="CORS Probe (inconclusive)",
                tier="baseline",
            )],
            "details": {"requests_made": 1},
        }

    acao = headers.get("access-control-allow-origin")
    acac = (headers.get("access-control-allow-credentials") or "").strip().lower() == "true"
    acam = headers.get("access-control-allow-methods") or ""
    methods_note = _state_changing_methods_note(acam)

    poc = f"curl -i -X OPTIONS {url} -H 'Origin: {SYNTHETIC_ORIGIN}' -H 'Access-Control-Request-Method: GET'"
    findings: List[Dict[str, Any]] = []

    if acao is None:
        findings.append(_make_finding(
            title="No CORS response headers observed",
            severity="info",
            confidence="informational",
            cwe="", owasp="",
            location=url,
            evidence=(
                f"No Access-Control-Allow-Origin header was returned for a cross-origin probe "
                f"request (Origin: {SYNTHETIC_ORIGIN}). Cross-origin access is blocked by the "
                "browser's default same-origin policy."
            ),
            poc=poc,
            remediation="No action required unless cross-origin access is intentionally needed, in which case configure CORS explicitly with an origin allowlist.",
            detection_method="CORS Probe",
            tier="baseline",
        ))
    elif acao.strip() == "*" and acac:
        findings.append(_make_finding(
            title="CORS wildcard origin combined with credentials allowed",
            severity="critical",
            confidence="verified-live",
            cwe="CWE-942", owasp="A05:2021-Security Misconfiguration",
            location=url,
            evidence=(
                f"Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: "
                "true. This exact combination is invalid per the Fetch spec -- compliant browsers "
                "refuse to honor it -- and a server emitting it anyway signals a fundamentally "
                f"broken CORS implementation.{methods_note}"
            ),
            poc=poc,
            remediation="Never combine a wildcard origin with credentials. Replace '*' with a specific, validated allowlist of trusted origins, or disable credentialed CORS entirely.",
            detection_method="CORS Probe",
            tier="baseline",
        ))
    elif acao.strip() == SYNTHETIC_ORIGIN and acac:
        findings.append(_make_finding(
            title="CORS reflects arbitrary Origin with credentials allowed",
            severity="critical",
            confidence="verified-live",
            cwe="CWE-942", owasp="A01:2021-Broken Access Control",
            location=url,
            evidence=(
                f"The server echoed our synthetic, unrelated probe origin ({SYNTHETIC_ORIGIN}) "
                "back verbatim in Access-Control-Allow-Origin, with Access-Control-Allow-"
                "Credentials: true. This is a confirmed, exploitable pattern: any origin can make "
                f"authenticated cross-origin requests and read the response.{methods_note}"
            ),
            poc=poc,
            remediation="Validate the Origin header against an explicit allowlist server-side before reflecting it; never reflect an arbitrary Origin when credentials are allowed.",
            detection_method="CORS Probe",
            tier="baseline",
        ))
    elif acao.strip() == SYNTHETIC_ORIGIN:
        findings.append(_make_finding(
            title="CORS reflects arbitrary Origin without validation",
            severity="high",
            confidence="verified-live",
            cwe="CWE-942", owasp="A05:2021-Security Misconfiguration",
            location=url,
            evidence=(
                f"The server echoed our synthetic, unrelated probe origin ({SYNTHETIC_ORIGIN}) "
                "back verbatim in Access-Control-Allow-Origin instead of validating it against an "
                "allowlist. Credentials are not allowed, so this doesn't expose authenticated "
                "data, but it does let any site read this endpoint's non-credentialed responses "
                f"cross-origin.{methods_note}"
            ),
            poc=poc,
            remediation="Validate the Origin header against an explicit allowlist server-side instead of reflecting whatever origin is sent.",
            detection_method="CORS Probe",
            tier="baseline",
        ))
    elif acao.strip() == "*":
        findings.append(_make_finding(
            title="CORS wildcard origin allowed (no credentials)",
            severity="low",
            confidence="verified-live",
            cwe="CWE-942", owasp="A05:2021-Security Misconfiguration",
            location=url,
            evidence=(
                "Access-Control-Allow-Origin: * allows any origin to read this endpoint's "
                "response. Credentials are not allowed, so this may be an intentional choice for "
                "a genuinely public API rather than a vulnerability -- confirm this endpoint is "
                f"meant to be publicly cross-origin-readable.{methods_note}"
            ),
            poc=poc,
            remediation="If this endpoint is not intended to be public, replace '*' with a specific allowlist of trusted origins.",
            detection_method="CORS Probe",
            tier="baseline",
        ))
    # else: Access-Control-Allow-Origin was set to some other fixed value
    # that does NOT match our synthetic probe origin and isn't a wildcard
    # -- the server has its own allowlist and didn't grant our fake
    # origin access. A real browser would reject this response against
    # the actual requesting origin too. This is the secure, correctly-
    # configured case: no finding.

    return {"findings": findings, "details": {"requests_made": 1}}


# ────────────────────────────────────────────── Standalone Testing ──────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(description="Bravo6 CORS Misconfiguration Scout")
    parser.add_argument("url", nargs="?", default="https://example.com", help="Target URL")
    parser.add_argument("--test", action="store_true", help="Run Scout Regression Tests")
    args = parser.parse_args()

    if args.test:
        import asyncio
        import unittest
        class _FakeCtx:
            def __init__(self, url, session, page_is_representative=True):
                self.url = url
                self.session = session
                self.page_is_representative = page_is_representative

        class _FakeResponse:
            def __init__(self, headers=None, status=200):
                self.headers = headers or {}
                self.status = status

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

        class _FakeSession:
            """Minimal aiohttp.ClientSession stand-in: .options()/.get()
            both return a pre-baked _FakeResponse, or raise if configured to
            simulate a probe failure."""
            def __init__(self, options_response=None, get_response=None, options_raises=False, get_raises=False):
                self._options_response = options_response
                self._get_response = get_response
                self._options_raises = options_raises
                self._get_raises = get_raises

            def options(self, url, headers=None, timeout=None):
                if self._options_raises:
                    raise ConnectionError("simulated OPTIONS failure")
                return self._options_response

            def get(self, url, headers=None, timeout=None):
                if self._get_raises:
                    raise ConnectionError("simulated GET failure")
                return self._get_response

        def _run(ctx):
            return asyncio.run(run(ctx))

        class TestCorsChecks(unittest.TestCase):
            URL = "https://example.com"

            def _titles(self, result):
                return [f["title"] for f in result["findings"]]

            def test_wildcard_with_credentials_is_critical(self):
                resp = _FakeResponse({"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
                ctx = _FakeCtx(self.URL, _FakeSession(options_response=resp))
                result = _run(ctx)
                self.assertEqual(len(result["findings"]), 1)
                f = result["findings"][0]
                self.assertEqual(f["title"], "CORS wildcard origin combined with credentials allowed")
                self.assertEqual(f["severity"], "critical")
                self.assertEqual(f["raw_data"]["tier"], "baseline")

            def test_reflected_origin_with_credentials_is_critical(self):
                resp = _FakeResponse({"Access-Control-Allow-Origin": SYNTHETIC_ORIGIN, "Access-Control-Allow-Credentials": "true"})
                ctx = _FakeCtx(self.URL, _FakeSession(options_response=resp))
                result = _run(ctx)
                titles = self._titles(result)
                self.assertIn("CORS reflects arbitrary Origin with credentials allowed", titles)
                f = result["findings"][0]
                self.assertEqual(f["severity"], "critical")

            def test_reflected_origin_without_credentials_is_high(self):
                resp = _FakeResponse({"Access-Control-Allow-Origin": SYNTHETIC_ORIGIN})
                ctx = _FakeCtx(self.URL, _FakeSession(options_response=resp))
                result = _run(ctx)
                f = result["findings"][0]
                self.assertEqual(f["title"], "CORS reflects arbitrary Origin without validation")
                self.assertEqual(f["severity"], "high")

            def test_wildcard_without_credentials_is_low(self):
                resp = _FakeResponse({"Access-Control-Allow-Origin": "*"})
                ctx = _FakeCtx(self.URL, _FakeSession(options_response=resp))
                result = _run(ctx)
                f = result["findings"][0]
                self.assertEqual(f["title"], "CORS wildcard origin allowed (no credentials)")
                self.assertEqual(f["severity"], "low")
                self.assertIn("may be an intentional choice", f["evidence"])

            def test_no_cors_headers_present_is_info(self):
                resp = _FakeResponse({})
                ctx = _FakeCtx(self.URL, _FakeSession(options_response=resp))
                result = _run(ctx)
                f = result["findings"][0]
                self.assertEqual(f["title"], "No CORS response headers observed")
                self.assertEqual(f["severity"], "info")
                self.assertEqual(f["confidence"], "informational")

            def test_allowlisted_server_rejecting_probe_origin_produces_no_finding(self):
                # Properly configured: the server has its own allowlist and
                # returns ITS designated origin, not ours -- a real browser
                # would reject this against the actual request origin too.
                resp = _FakeResponse({"Access-Control-Allow-Origin": "https://app.example.com", "Access-Control-Allow-Credentials": "true"})
                ctx = _FakeCtx(self.URL, _FakeSession(options_response=resp))
                result = _run(ctx)
                self.assertEqual(result["findings"], [])

            def test_state_changing_methods_folded_into_evidence_not_separate_finding(self):
                resp = _FakeResponse({
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Credentials": "true",
                    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE",
                })
                ctx = _FakeCtx(self.URL, _FakeSession(options_response=resp))
                result = _run(ctx)
                self.assertEqual(len(result["findings"]), 1, "State-changing methods must not create a second finding.")
                self.assertIn("PUT", result["findings"][0]["evidence"])
                self.assertIn("DELETE", result["findings"][0]["evidence"])

            def test_probe_failure_produces_inconclusive_not_false_negative(self):
                ctx = _FakeCtx(self.URL, _FakeSession(options_raises=True, get_raises=True))
                result = _run(ctx)
                self.assertEqual(len(result["findings"]), 1)
                f = result["findings"][0]
                self.assertIn("inconclusive", f["title"].lower())
                self.assertEqual(f["confidence"], "plausible-unconfirmed")
                self.assertNotIn("No CORS", f["title"])

            def test_options_405_falls_back_to_get(self):
                options_resp = _FakeResponse({}, status=405)
                get_resp = _FakeResponse({"Access-Control-Allow-Origin": "*"})
                ctx = _FakeCtx(self.URL, _FakeSession(options_response=options_resp, get_response=get_resp))
                result = _run(ctx)
                self.assertEqual(result["findings"][0]["title"], "CORS wildcard origin allowed (no credentials)")

            def test_options_failure_falls_back_to_get(self):
                get_resp = _FakeResponse({"Access-Control-Allow-Origin": SYNTHETIC_ORIGIN})
                ctx = _FakeCtx(self.URL, _FakeSession(options_raises=True, get_response=get_resp))
                result = _run(ctx)
                self.assertEqual(result["findings"][0]["title"], "CORS reflects arbitrary Origin without validation")

            def test_non_representative_page_skips_analysis(self):
                ctx = _FakeCtx(self.URL, _FakeSession(), page_is_representative=False)
                result = _run(ctx)
                self.assertIn("fatal_error", result)

        sys.argv = [sys.argv[0]]
        unittest.main()
    else:
        import asyncio
        import aiohttp as _aiohttp
        from dataclasses import dataclass

        @dataclass
        class DummyContext:
            url: str
            session: Any = None
            page_is_representative: bool = True

        async def _live_scan():
            connector = _aiohttp.TCPConnector(ssl=True)
            async with _aiohttp.ClientSession(connector=connector, headers={"User-Agent": "Bravo6-Scanner/8.5"}) as session:
                ctx = DummyContext(url=args.url, session=session)
                result = await run(ctx)
                print(json.dumps(result, indent=2, ensure_ascii=False, default=str))

        asyncio.run(_live_scan())
