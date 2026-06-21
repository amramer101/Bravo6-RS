"""
Bravo6 Security Scanner — CORS Misconfiguration Test
======================================================

Detects Cross-Origin Resource Sharing (CORS) misconfigurations that could
allow unauthorized cross-origin reads or authenticated cross-origin requests.

Checks performed:
  1. Reflected/wildcard Origin handling combined with Access-Control-Allow-Credentials
  2. "null" origin handling (sandboxed iframe exploitation vector)
  3. Subdomain-suffix bypass attempts (e.g. example.com.evil.com)
  4. Unrelated-domain reflection
  5. Preflight (OPTIONS) handling and dangerous allowed methods

Author: Bravo6 Scanner
"""

import asyncio
from typing import Optional
import aiohttp

TEST_NAME = "cors"
USER_AGENT = "Bravo6-Scanner/1.0"
TIMEOUT_SECONDS = 10

ATTACKER_ORIGIN = "https://evil-attacker.com"
DANGEROUS_METHODS = {"PUT", "DELETE", "PATCH", "CONNECT", "TRACE"}

# Additional origins tested per the spec: null-origin sandbox exploit,
# subdomain-suffix bypass, and an unrelated domain control case.
ADDITIONAL_ORIGINS = [
    "null",
    "https://example.com.evil.com",
    "https://notexample.com",
]


def _normalize_url(url: str) -> str:
    """Ensure the target URL has a scheme; default to https://."""
    url = url.strip()
    if not url:
        return url
    if not url.lower().startswith(("http://", "https://")):
        url = f"https://{url}"
    return url.rstrip("/")


def _base_result(
    status: str,
    severity: str,
    title: str,
    description: str,
    evidence,
    remediation: str,
) -> dict:
    return {
        "test_name": TEST_NAME,
        "status": status,
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
    }


def _error_result(message: str) -> dict:
    return _base_result(
        status="error",
        severity="info",
        title="CORS Test Could Not Complete",
        description=f"The CORS scan could not be completed due to an error: {message}",
        evidence={"error": message},
        remediation="Verify the target is reachable and retry the scan.",
    )


async def _send_request(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    headers: dict,
) -> Optional[aiohttp.ClientResponse]:
    """Issue a single request, swallowing all exceptions and returning None on failure."""
    try:
        async with session.request(
            method,
            url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS),
            ssl=False,
            allow_redirects=True,
        ) as response:
            # Drain body so the connection can be reused/closed cleanly.
            await response.read()
            return _ResponseSnapshot(response)
    except Exception:
        return None


class _ResponseSnapshot:
    """Lightweight, exception-safe snapshot of the parts of a response we need."""

    def __init__(self, response: aiohttp.ClientResponse):
        self.status = response.status
        self.headers = {k: v for k, v in response.headers.items()}

    def header(self, name: str) -> Optional[str]:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None


def _analyze_primary_origin(snapshot: "_ResponseSnapshot") -> dict:
    """
    Analyze the response to the malicious-origin GET request and classify
    the CORS posture per the CASE 1–4 logic.
    """
    acao = snapshot.header("Access-Control-Allow-Origin")
    acac = snapshot.header("Access-Control-Allow-Credentials")
    acac_true = bool(acac and acac.strip().lower() == "true")

    evidence = {
        "tested_origin": ATTACKER_ORIGIN,
        "acao_header": acao if acao is not None else "(not present)",
        "acac_header": acac if acac is not None else "(not present)",
    }

    # CASE 4 — no ACAO header at all → pass
    if acao is None:
        evidence["verdict"] = "No Access-Control-Allow-Origin header present — origin not granted access."
        return _base_result(
            status="pass",
            severity="info",
            title="No CORS Access Granted to Untrusted Origins",
            description=(
                "The server did not return an Access-Control-Allow-Origin header in "
                "response to a request from an untrusted origin, meaning browsers will "
                "block cross-origin reads of the response by default."
            ),
            evidence=evidence,
            remediation=(
                "No action required for this check. Continue to avoid reflecting "
                "arbitrary Origin headers if CORS support is added in the future."
            ),
        )

    # CASE 3 — ACAO: null
    if acao.strip() == "null":
        if acac_true:
            evidence["verdict"] = (
                "ACAO is 'null' with credentials allowed — exploitable via sandboxed "
                "iframes that send a 'null' Origin header."
            )
            return _base_result(
                status="fail",
                severity="high",
                title="CORS Misconfiguration: 'null' Origin Allowed With Credentials",
                description=(
                    "The server responds with Access-Control-Allow-Origin: null and "
                    "Access-Control-Allow-Credentials: true. An attacker can generate a "
                    "request with a 'null' Origin (e.g. via a sandboxed iframe or a "
                    "data: URI) to make authenticated cross-origin requests and read "
                    "the response."
                ),
                evidence=evidence,
                remediation=(
                    "Never explicitly allow the 'null' origin. Maintain an explicit "
                    "allowlist of trusted origins instead of reflecting or special-"
                    "casing 'null'."
                ),
            )
        evidence["verdict"] = "ACAO is 'null' without credentials — limited risk."
        return _base_result(
            status="warning",
            severity="low",
            title="CORS: 'null' Origin Permitted",
            description=(
                "The server returns Access-Control-Allow-Origin: null. While "
                "credentials are not allowed here, this configuration is unusual and "
                "can be risky if credential support is added later."
            ),
            evidence=evidence,
            remediation="Avoid using 'null' as an allowed origin value; use an explicit allowlist instead.",
        )

    # CASE 1 — ACAO: * (wildcard)
    if acao.strip() == "*":
        if acac_true:
            # Per spec, browsers reject ACAO:* combined with ACAC:true, but a server
            # sending this combination is still a misconfiguration worth flagging.
            evidence["verdict"] = (
                "Server sent ACAO: * together with Access-Control-Allow-Credentials: true. "
                "Browsers will reject this combination, but it indicates broken/inconsistent "
                "CORS logic on the server."
            )
            return _base_result(
                status="fail",
                severity="medium",
                title="CORS Misconfiguration: Wildcard Origin Combined With Credentials Flag",
                description=(
                    "The server returned Access-Control-Allow-Origin: * alongside "
                    "Access-Control-Allow-Credentials: true. Modern browsers will not "
                    "honor credentialed requests in this case, but it signals flawed "
                    "CORS handling that should be corrected."
                ),
                evidence=evidence,
                remediation=(
                    "Never combine a wildcard Access-Control-Allow-Origin with "
                    "Access-Control-Allow-Credentials: true. Use an explicit origin "
                    "allowlist for any endpoint that requires credentials."
                ),
            )
        evidence["verdict"] = "ACAO is '*' without credentials — any site can read non-credentialed responses."
        return _base_result(
            status="warning",
            severity="medium",
            title="CORS: Wildcard Origin Allowed",
            description=(
                "The server returns Access-Control-Allow-Origin: * for all origins, "
                "meaning any website can read responses from this endpoint via "
                "cross-origin requests (without credentials)."
            ),
            evidence=evidence,
            remediation=(
                "If this endpoint serves non-sensitive public data, the wildcard may be "
                "acceptable. Otherwise, restrict Access-Control-Allow-Origin to an "
                "explicit allowlist of trusted origins."
            ),
        )

    # CASE 2 — ACAO reflects the exact attacker origin
    if acao.strip() == ATTACKER_ORIGIN:
        if acac_true:
            evidence["verdict"] = "Origin reflected with credentials — critical CORS misconfiguration"
            return _base_result(
                status="fail",
                severity="critical",
                title="Critical CORS Misconfiguration: Origin Reflected With Credentials",
                description=(
                    "The server reflects an arbitrary, attacker-controlled Origin header "
                    "back in Access-Control-Allow-Origin and also sets "
                    "Access-Control-Allow-Credentials: true. This allows any malicious "
                    "website to make authenticated, credentialed cross-origin requests "
                    "to this server on behalf of a logged-in victim and read the "
                    "responses — a critical vulnerability typically leading to full "
                    "account compromise or data theft."
                ),
                evidence=evidence,
                remediation=(
                    "Maintain an explicit allowlist of trusted origins. Never reflect "
                    "the Origin header directly. Never combine wildcard or reflected "
                    "origins with Access-Control-Allow-Credentials: true."
                ),
            )
        evidence["verdict"] = "Origin reflected without credentials — moderate risk of unauthorized reads."
        return _base_result(
            status="warning",
            severity="medium",
            title="CORS: Arbitrary Origin Reflected",
            description=(
                "The server reflects an arbitrary Origin header value back in "
                "Access-Control-Allow-Origin without requiring it to match an "
                "allowlist. Although credentials are not enabled here, this is "
                "indicative of improper validation and could become critical if "
                "credentials support is added."
            ),
            evidence=evidence,
            remediation=(
                "Validate the Origin header against an explicit allowlist rather than "
                "reflecting any value received."
            ),
        )

    # Anything else: ACAO present but set to some other specific, non-attacker value.
    evidence["verdict"] = f"ACAO restricted to a specific origin ('{acao}') unrelated to the tested attacker origin."
    return _base_result(
        status="pass",
        severity="info",
        title="CORS Restricted to Specific Origin",
        description=(
            "The server returned an Access-Control-Allow-Origin value that does not "
            "match the tested attacker-controlled origin, suggesting origin validation "
            "is in place."
        ),
        evidence=evidence,
        remediation=(
            "No action required for this check. Periodically verify the origin "
            "allowlist remains accurate and does not include overly broad patterns."
        ),
    )


async def _test_additional_origins(session: aiohttp.ClientSession, url: str) -> list:
    """
    Probe the target with additional origins (null, subdomain-suffix bypass,
    unrelated domain) and report which ones were granted access.
    """
    findings = []
    for origin in ADDITIONAL_ORIGINS:
        headers = {"User-Agent": USER_AGENT, "Origin": origin}
        snapshot = await _send_request(session, "GET", url, headers)
        if snapshot is None:
            continue
        acao = snapshot.header("Access-Control-Allow-Origin")
        acac = snapshot.header("Access-Control-Allow-Credentials")
        granted = acao is not None and (acao.strip() == origin or acao.strip() == "*")
        findings.append(
            {
                "origin_tested": origin,
                "acao_header": acao if acao is not None else "(not present)",
                "acac_header": acac if acac is not None else "(not present)",
                "origin_accepted": granted,
            }
        )
    return findings


async def _test_preflight(session: aiohttp.ClientSession, url: str) -> dict:
    """
    Send a CORS preflight (OPTIONS) request and inspect the allowed methods
    and headers for overly permissive configuration.
    """
    headers = {
        "User-Agent": USER_AGENT,
        "Origin": ATTACKER_ORIGIN,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Authorization",
    }
    snapshot = await _send_request(session, "OPTIONS", url, headers)
    if snapshot is None:
        return {
            "preflight_supported": False,
            "note": "OPTIONS request failed or was not handled; preflight could not be evaluated.",
        }

    allow_methods_raw = snapshot.header("Access-Control-Allow-Methods") or ""
    allow_headers_raw = snapshot.header("Access-Control-Allow-Headers") or ""
    acao = snapshot.header("Access-Control-Allow-Origin")

    allowed_methods = {m.strip().upper() for m in allow_methods_raw.split(",") if m.strip()}
    dangerous_allowed = sorted(allowed_methods & DANGEROUS_METHODS)

    return {
        "preflight_supported": True,
        "status_code": snapshot.status,
        "acao_header": acao if acao is not None else "(not present)",
        "access_control_allow_methods": allow_methods_raw or "(not present)",
        "access_control_allow_headers": allow_headers_raw or "(not present)",
        "dangerous_methods_allowed": dangerous_allowed,
        "attacker_origin_allowed_in_preflight": acao == ATTACKER_ORIGIN or acao == "*",
    }


async def run(url: str) -> dict:
    """
    Run the CORS misconfiguration test against the target URL.

    Args:
        url: A domain or URL, e.g. "example.com" or "https://example.com".

    Returns:
        A result dict following the Bravo6 standard test result format.
    """
    try:
        target = _normalize_url(url)
        if not target:
            return _error_result("Empty or invalid URL provided.")
    except Exception as exc:
        return _error_result(f"Failed to normalize URL: {exc}")

    try:
        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Step 1 & 2: primary malicious-origin request
            primary_headers = {"User-Agent": USER_AGENT, "Origin": ATTACKER_ORIGIN}
            primary_snapshot = await _send_request(session, "GET", target, primary_headers)

            if primary_snapshot is None:
                return _error_result(
                    f"Could not connect to '{target}' to perform the CORS test "
                    "(connection failed, timed out, or was refused)."
                )

            # Step 3: analyze primary result
            result = _analyze_primary_origin(primary_snapshot)

            # Step 4: test additional origins concurrently
            additional_findings = await _test_additional_origins(session, target)

            # Step 5: preflight check
            preflight_findings = await _test_preflight(session, target)

            # Enrich evidence with the supplementary findings without overwriting
            # the primary verdict fields already set by _analyze_primary_origin.
            if isinstance(result.get("evidence"), dict):
                result["evidence"]["additional_origin_tests"] = additional_findings
                result["evidence"]["preflight_test"] = preflight_findings

            # Escalate status/severity if preflight reveals dangerous methods
            # explicitly allowed for the attacker origin, even if the simple GET
            # check looked benign.
            if (
                preflight_findings.get("attacker_origin_allowed_in_preflight")
                and preflight_findings.get("dangerous_methods_allowed")
                and result["status"] == "pass"
            ):
                result["status"] = "warning"
                result["severity"] = "medium"
                result["title"] = "CORS Preflight Allows Dangerous Methods for Untrusted Origin"
                result["description"] = (
                    "While simple GET requests are not granted cross-origin access, the "
                    "preflight (OPTIONS) response allows the attacker-controlled origin "
                    "to use potentially dangerous HTTP methods: "
                    f"{', '.join(preflight_findings['dangerous_methods_allowed'])}."
                )
                result["remediation"] = (
                    "Restrict Access-Control-Allow-Methods in preflight responses to only "
                    "the methods required by legitimate trusted origins, and ensure the "
                    "preflight Access-Control-Allow-Origin matches the same allowlist used "
                    "for actual requests."
                )

            return result

    except asyncio.TimeoutError:
        return _error_result(f"Request to '{url}' timed out after {TIMEOUT_SECONDS} seconds.")
    except Exception as exc:
        return _error_result(f"Unexpected error during CORS test: {exc}")


# Allow standalone execution for manual testing: python test_cors.py example.com
if __name__ == "__main__":
    import sys
    import json

    target_arg = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    output = asyncio.run(run(target_arg))
    print(json.dumps(output, indent=2))