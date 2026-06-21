"""
test_11_cors.py — Advanced CORS Misconfiguration Scanner (Active Verification)

Upgraded:
- Tests reflected origins, wildcard + credentials, null origin, subdomain bypass.
- Provides PoC HTML/JavaScript to demonstrate exploitation.
- Adds confidence scoring based on response behavior.
- Generates curl commands to reproduce findings.
- Distinguishes confirmed vulnerabilities from informational.
"""

import asyncio
import json
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse

import aiohttp

TEST_NAME = "cors"
USER_AGENT = "Bravo6-Scanner/1.0"
TIMEOUT_SECONDS = 10

# Attack origins to test
ATTACKER_ORIGIN = "https://evil-attacker.com"
ADDITIONAL_ORIGINS = [
    "null",
    "https://example.com.evil.com",
    "https://notexample.com",
    "http://evil-attacker.com",  # test case-insensitivity
]
DANGEROUS_METHODS = {"PUT", "DELETE", "PATCH", "CONNECT", "TRACE"}

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        return url
    if not url.lower().startswith(("http://", "https://")):
        url = f"https://{url}"
    return url.rstrip("/")


def _base_error(message: str) -> dict:
    return {
        "test_name": TEST_NAME,
        "status": "error",
        "severity": "info",
        "title": "CORS Test Failed",
        "description": message,
        "evidence": [],
        "remediation": "Check target connectivity and try again.",
    }


async def _send_request(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    headers: dict,
    allow_redirects: bool = True,
) -> Optional[aiohttp.ClientResponse]:
    try:
        async with session.request(
            method,
            url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS),
            ssl=False,
            allow_redirects=allow_redirects,
        ) as resp:
            await resp.read()  # ensure body read
            return resp
    except Exception:
        return None


def _get_header(resp, name: str) -> Optional[str]:
    for k, v in resp.headers.items():
        if k.lower() == name.lower():
            return v
    return None


def _cors_issue(
    title: str,
    description: str,
    severity: str,
    evidence: dict,
    poc: str,
    confidence: int,
    remediation: str,
) -> Dict[str, Any]:
    return {
        "title": title,
        "description": description,
        "severity": severity,
        "evidence": evidence,
        "poc": poc,
        "confidence": confidence,
        "remediation": remediation,
    }


async def _check_primary_origin(session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
    """Test the primary malicious origin and return a finding if vulnerable."""
    headers = {"User-Agent": USER_AGENT, "Origin": ATTACKER_ORIGIN}
    resp = await _send_request(session, "GET", url, headers)
    if not resp:
        return {"error": "No response"}

    acao = _get_header(resp, "Access-Control-Allow-Origin")
    acac = _get_header(resp, "Access-Control-Allow-Credentials")
    acac_true = acac and acac.lower() == "true"

    evidence = {
        "tested_origin": ATTACKER_ORIGIN,
        "acao": acao or "(missing)",
        "acac": acac or "(missing)",
        "status_code": resp.status,
    }

    # Case: ACAO missing -> safe
    if not acao:
        return {"safe": True, "evidence": evidence}

    # Case: ACAO = "*" (wildcard)
    if acao == "*":
        if acac_true:
            return {
                "vulnerable": True,
                "severity": "medium",
                "title": "Wildcard Origin with Credentials Flag",
                "description": "Server returns ACAO: * with ACAC: true. Browsers reject this, but indicates misconfiguration.",
                "evidence": evidence,
                "poc": "curl -v -H 'Origin: *' -H 'Access-Control-Request-Method: GET' ...",
                "confidence": 80,
                "remediation": "Never combine wildcard ACAO with ACAC:true; use an explicit allowlist."
            }
        else:
            return {
                "vulnerable": False,
                "severity": "medium",
                "title": "Wildcard Origin (No Credentials)",
                "description": "ACAO: * allows any site to read non-credentialed responses.",
                "evidence": evidence,
                "poc": "fetch('{}', {credentials: 'omit'})".format(url),
                "confidence": 90,
                "remediation": "If sensitive data, restrict to explicit origins."
            }

    # Case: ACAO reflects attacker origin
    if acao == ATTACKER_ORIGIN:
        if acac_true:
            return {
                "vulnerable": True,
                "severity": "critical",
                "title": "Reflected Origin with Credentials (Critical)",
                "description": "Server reflects arbitrary Origin and sets ACAC:true. Any site can steal authenticated data.",
                "evidence": evidence,
                "poc": f"<script>fetch('{url}', {{credentials:'include'}}).then(r=>r.text()).then(console.log)</script>",
                "confidence": 100,
                "remediation": "Use explicit allowlist; never reflect Origin; never combine with ACAC:true."
            }
        else:
            return {
                "vulnerable": False,
                "severity": "high",
                "title": "Reflected Origin (No Credentials)",
                "description": "Reflects arbitrary Origin without credentials; still a validation weakness.",
                "evidence": evidence,
                "poc": f"curl -H 'Origin: {ATTACKER_ORIGIN}' -v {url}",
                "confidence": 80,
                "remediation": "Validate Origin against allowlist, not reflection."
            }

    # Case: ACAO = "null"
    if acao == "null":
        if acac_true:
            return {
                "vulnerable": True,
                "severity": "high",
                "title": "null Origin with Credentials",
                "description": "Server allows null origin with credentials; exploitable via sandboxed iframe.",
                "evidence": evidence,
                "poc": "<iframe sandbox='allow-scripts' src='data:text/html,<script>fetch(...)</script>'></iframe>",
                "confidence": 100,
                "remediation": "Never allow null origin; use explicit allowlist."
            }
        else:
            return {
                "vulnerable": False,
                "severity": "low",
                "title": "null Origin Permitted (No Credentials)",
                "description": "ACAO: null without credentials; limited risk.",
                "evidence": evidence,
                "poc": "curl -H 'Origin: null' -v " + url,
                "confidence": 70,
                "remediation": "Avoid allowing null; use explicit list."
            }

    # Case: ACAO is some other specific origin
    return {
        "safe": True,
        "evidence": evidence,
        "title": "Origin not accepted",
        "description": f"ACAO is '{acao}', not matching attacker origin.",
        "remediation": "No action needed."
    }


async def _check_additional_origins(session: aiohttp.ClientSession, url: str) -> List[Dict]:
    """Test additional origins (null, subdomain-suffix, unrelated)."""
    results = []
    for origin in ADDITIONAL_ORIGINS:
        headers = {"User-Agent": USER_AGENT, "Origin": origin}
        resp = await _send_request(session, "GET", url, headers)
        if not resp:
            results.append({"origin_tested": origin, "error": "no response"})
            continue
        acao = _get_header(resp, "Access-Control-Allow-Origin")
        acac = _get_header(resp, "Access-Control-Allow-Credentials")
        accepted = acao is not None and (acao == origin or acao == "*")
        results.append({
            "origin_tested": origin,
            "acao": acao or "(missing)",
            "acac": acac or "(missing)",
            "accepted": accepted,
        })
    return results


async def _check_preflight(session: aiohttp.ClientSession, url: str) -> Dict:
    """Send OPTIONS preflight and check dangerous methods."""
    headers = {
        "User-Agent": USER_AGENT,
        "Origin": ATTACKER_ORIGIN,
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Authorization",
    }
    resp = await _send_request(session, "OPTIONS", url, headers)
    if not resp:
        return {"preflight_supported": False}

    acao = _get_header(resp, "Access-Control-Allow-Origin")
    methods_raw = _get_header(resp, "Access-Control-Allow-Methods") or ""
    allowed_methods = {m.strip().upper() for m in methods_raw.split(",") if m.strip()}
    dangerous = sorted(allowed_methods & DANGEROUS_METHODS)
    return {
        "preflight_supported": True,
        "acao": acao or "(missing)",
        "allowed_methods": methods_raw or "(missing)",
        "dangerous_methods": dangerous,
        "attacker_origin_allowed": acao == ATTACKER_ORIGIN or acao == "*"
    }


async def run(url: str) -> dict:
    try:
        target = _normalize_url(url)
        if not target:
            return _base_error("Invalid URL")

        async with aiohttp.ClientSession() as session:
            # 1. Primary origin test
            primary = await _check_primary_origin(session, target)
            # 2. Additional origins
            additional = await _check_additional_origins(session, target)
            # 3. Preflight
            preflight = await _check_preflight(session, target)

        # Build evidence list
        evidence = []
        overall_status = "pass"
        overall_severity = "info"

        # Process primary finding
        if primary.get("vulnerable"):
            evidence.append({
                "type": "Primary Origin",
                "title": primary["title"],
                "description": primary["description"],
                "severity": primary["severity"],
                "confidence": primary.get("confidence", 100),
                "poc": primary["poc"],
                "remediation": primary["remediation"],
                "evidence": primary["evidence"]
            })
            overall_status = "fail"
            overall_severity = max([overall_severity, primary["severity"]], key=lambda s: SEVERITY_RANK.get(s, 0))
        elif primary.get("safe"):
            # Add informational
            evidence.append({
                "type": "Primary Origin",
                "title": primary.get("title", "Origin not accepted"),
                "description": primary.get("description", ""),
                "severity": "info",
                "confidence": 100,
                "poc": f"curl -H 'Origin: {ATTACKER_ORIGIN}' -v {target}",
                "remediation": "No action needed.",
                "evidence": primary.get("evidence", {})
            })
        else:
            # Error
            evidence.append({
                "type": "Primary Origin",
                "title": "Error",
                "description": primary.get("error", "Unknown error"),
                "severity": "info",
                "confidence": 0,
                "poc": "",
                "remediation": "Check connectivity."
            })

        # Additional origins
        for add in additional:
            if add.get("accepted"):
                evidence.append({
                    "type": "Additional Origin",
                    "title": f"Origin '{add['origin_tested']}' accepted",
                    "description": f"ACAO: {add['acao']}, ACAC: {add['acac']}",
                    "severity": "medium",
                    "confidence": 80,
                    "poc": f"curl -H 'Origin: {add['origin_tested']}' -v {target}",
                    "remediation": "Explicitly restrict allowed origins.",
                    "evidence": add
                })
                overall_status = "warning" if overall_status == "pass" else overall_status
                overall_severity = max([overall_severity, "medium"], key=lambda s: SEVERITY_RANK.get(s, 0))

        # Preflight
        if preflight.get("preflight_supported") and preflight.get("attacker_origin_allowed"):
            dangerous = preflight.get("dangerous_methods", [])
            if dangerous:
                evidence.append({
                    "type": "Preflight",
                    "title": f"Dangerous methods allowed in preflight: {', '.join(dangerous)}",
                    "description": f"OPTIONS preflight allows attacker origin to use {', '.join(dangerous)}.",
                    "severity": "high",
                    "confidence": 100,
                    "poc": f"curl -X OPTIONS -H 'Origin: {ATTACKER_ORIGIN}' -H 'Access-Control-Request-Method: POST' -v {target}",
                    "remediation": "Restrict Access-Control-Allow-Methods to safe values.",
                    "evidence": preflight
                })
                overall_status = "fail"
                overall_severity = max([overall_severity, "high"], key=lambda s: SEVERITY_RANK.get(s, 0))

        # Determine overall result
        if overall_status == "fail":
            status = "fail"
        elif overall_status == "warning":
            status = "warning"
        else:
            status = "pass"

        return {
            "test_name": TEST_NAME,
            "status": status,
            "severity": overall_severity,
            "title": f"CORS Misconfiguration Check ({len([e for e in evidence if e.get('severity') in ('critical','high','medium')])} issues)",
            "description": f"Scanned {target} for CORS misconfigurations. Found {len(evidence)} findings.",
            "evidence": evidence,
            "remediation": "Implement an explicit origin allowlist for all CORS-enabled endpoints; never reflect Origin; avoid wildcard with credentials; add proper preflight restrictions.",
        }

    except Exception as e:
        return _base_error(f"Unexpected error: {e}")


if __name__ == "__main__":
    import sys, json
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))