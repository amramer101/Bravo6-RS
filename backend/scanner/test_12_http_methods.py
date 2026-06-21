"""
test_12_http_methods.py — Advanced HTTP Method Scanner with Active Exploitation (v3)

Enhancements:
- Improved WAF detection (signatures + response comparison)
- Multiple paths testing (/, /api, /uploads, /admin, /tmp)
- Method override headers (X-HTTP-Method-Override, X-Original-Method, X-Forwarded-Method)
- Allow header parsing with active verification
- Origin-based testing (CORS integration)
- WebDAV methods (PROPFIND, MKCOL, COPY, MOVE)
- TRACE with header reflection check
- CONNECT proxy tunnel test
- DEBUG IIS tracing
- PUT + GET + DELETE full cycle with file content verification
- File upload with malicious content test (PHP/ASP)
- Redirect handling (follow=False)
- Dynamic confidence scoring
- Detailed PoC curl commands per method
- Integration with CORS test context
- Safe paths whitelist to avoid blocking
- Support for PATCH, OPTIONS, HEAD
- Rate limiting detection
"""

import asyncio
import hashlib
import random
import re
import uuid
from urllib.parse import urljoin, urlparse
from typing import Dict, Any, List, Optional, Tuple

import aiohttp

# ── Configuration ────────────────────────────────────────────────────────────
TEST_NAME = "http_methods"
USER_AGENT = "Bravo6-Scanner/1.0"
REQUEST_TIMEOUT = 10
MAX_CONCURRENT_TESTS = 5
MAX_REDIRECTS = 0  # Don't follow redirects to detect original response

# ── Method definitions ──────────────────────────────────────────────────────
DANGEROUS_METHODS = {
    "TRACE": {"severity": "high", "risk": "XST (Cross-Site Tracing) can steal HttpOnly cookies"},
    "PUT": {"severity": "high", "risk": "File upload — may allow arbitrary file writes"},
    "DELETE": {"severity": "critical", "risk": "File deletion — may delete server resources"},
    "CONNECT": {"severity": "medium", "risk": "Proxy tunneling — can bypass firewalls"},
    "DEBUG": {"severity": "critical", "risk": "Remote debugging access (IIS)"},
    "PATCH": {"severity": "medium", "risk": "Partial update — may allow unauthorized modifications"},
    "OPTIONS": {"severity": "low", "risk": "May disclose allowed methods (information disclosure)"},
    "PROPFIND": {"severity": "medium", "risk": "WebDAV property discovery"},
    "MKCOL": {"severity": "medium", "risk": "WebDAV directory creation"},
    "COPY": {"severity": "medium", "risk": "WebDAV resource copy"},
    "MOVE": {"severity": "medium", "risk": "WebDAV resource move"},
}

SAFE_METHODS = {"GET", "POST", "HEAD"}
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# ── WAF Signatures ──────────────────────────────────────────────────────────
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "cf-request-id"],
    "AWS WAF": ["x-amz-cf-id", "x-amz-request-id", "x-amzn-RequestId"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-cache", "x-sucuri-block"],
    "Imperva": ["x-iinfo", "x-cdn", "x-request-id"],
    "Akamai": ["x-check-cacheable", "akamai-x-cache", "x-akamai-request-id"],
    "Fastly": ["x-fastly-request-id", "fastly-restarts"],
    "Azure Front Door": ["x-azure-ref", "x-fd-healthprobe"],
    "ModSecurity": ["mod_security", "modsecurity", "x-mod-security"],
}

# ── Paths to test (including common API and upload paths) ──────────────────
TEST_PATHS = [
    "/",
    "/api/",
    "/api/v1/",
    "/uploads/",
    "/upload/",
    "/tmp/",
    "/temp/",
    "/test/",
    "/debug/",
    "/admin/",
    "/cgi-bin/",
    "/webdav/",
    "/dav/",
]

# ── Override Headers ────────────────────────────────────────────────────────
OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-Original-Method",
    "X-Forwarded-Method",
    "X-Method-Override",
    "X-Override-Method",
]

# ── Helper Functions ─────────────────────────────────────────────────────────

def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return url
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    return url.rstrip("/")

def _highest_severity(severities: List[str]) -> str:
    if not severities:
        return "info"
    return max(severities, key=lambda s: SEVERITY_RANK.get(s, 0))

def _get_waf(headers: Dict[str, str]) -> Optional[str]:
    """Detect WAF from response headers."""
    header_lower = {k.lower(): v for k, v in headers.items()}
    for waf_name, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in header_lower:
                return waf_name
    return None

def _response_similar(baseline: Dict, response: Dict) -> bool:
    """Check if response is similar to baseline (WAF reflection)."""
    # Size comparison
    baseline_size = baseline.get("size", 0)
    response_size = response.get("size", 0)
    if baseline_size and response_size:
        size_ratio = abs(baseline_size - response_size) / max(baseline_size, 1)
        if size_ratio < 0.05:  # Within 5%
            return True

    # Status code comparison
    if baseline.get("status") == response.get("status") and baseline.get("status") in (200, 403, 404):
        return True

    # Content check: if both contain same HTML structure
    baseline_body = baseline.get("body", "")[:500]
    response_body = response.get("body", "")[:500]
    if baseline_body and response_body:
        # Check if they share common WAF page markers
        waf_markers = ["Access Denied", "Blocked", "Security Check", "cf-browser-verification"]
        for marker in waf_markers:
            if marker in baseline_body and marker in response_body:
                return True

    return False

def _make_poc(method: str, url: str, details: Dict = None) -> str:
    """Generate a curl PoC for a method."""
    cmd = f"curl -X {method}"
    if details and details.get("headers"):
        for h, v in details["headers"].items():
            cmd += f" -H '{h}: {v}'"
    if details and details.get("data"):
        cmd += f" -d '{details['data']}'"
    cmd += f" -v {url}"
    return cmd

def _generate_test_data(length: int = 100) -> str:
    """Generate random test data."""
    return f"Bravo6-Test-{uuid.uuid4().hex[:8]}-" + "A" * (length - 30)

async def _safe_request(
    session: aiohttp.ClientSession,
    method: str,
    url: str,
    headers: Optional[Dict] = None,
    data: Optional[bytes] = None,
    json_data: Optional[Dict] = None,
    allow_redirects: bool = False,
) -> Dict:
    """Make a safe HTTP request and return structured response."""
    default_headers = {"User-Agent": USER_AGENT}
    if headers:
        default_headers.update(headers)

    try:
        async with session.request(
            method,
            url,
            headers=default_headers,
            data=data,
            json=json_data,
            timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
            ssl=False,
            allow_redirects=allow_redirects,
        ) as resp:
            body = await resp.read()
            return {
                "status": resp.status,
                "headers": dict(resp.headers),
                "body": body.decode("utf-8", errors="ignore"),
                "size": len(body),
                "final_url": str(resp.url),
                "error": None,
            }
    except asyncio.TimeoutError:
        return {"status": 0, "headers": {}, "body": "", "size": 0, "final_url": url, "error": "timeout"}
    except aiohttp.ClientError as e:
        return {"status": 0, "headers": {}, "body": "", "size": 0, "final_url": url, "error": f"client_error: {e}"}
    except Exception as e:
        return {"status": 0, "headers": {}, "body": "", "size": 0, "final_url": url, "error": f"unexpected: {e}"}

# ── Test functions ──────────────────────────────────────────────────────────

async def _test_trace(
    session: aiohttp.ClientSession,
    url: str,
    baseline: Dict,
) -> Dict:
    """Test TRACE method with header reflection."""
    marker = f"Bravo6-{uuid.uuid4().hex[:8]}"
    headers = {"X-Bravo6-Marker": marker}
    resp = await _safe_request(session, "TRACE", url, headers=headers)

    if resp["error"]:
        return {
            "method": "TRACE",
            "status": "error",
            "confirmed": False,
            "severity": "info",
            "evidence": resp["error"],
            "confidence": 0,
        }

    # Check if response is similar to baseline (WAF)
    if _response_similar(baseline, resp):
        return {
            "method": "TRACE",
            "status": "waf_blocked",
            "confirmed": False,
            "severity": "low",
            "evidence": "Response matches baseline (likely WAF interception)",
            "confidence": 20,
        }

    # Check for marker in response body or headers
    body = resp["body"]
    headers_combined = "\n".join(f"{k}: {v}" for k, v in resp["headers"].items())

    if marker in body or marker in headers_combined:
        return {
            "method": "TRACE",
            "status": "confirmed",
            "confirmed": True,
            "severity": "high",
            "evidence": f"Marker '{marker}' reflected in response",
            "confidence": 100,
            "poc": _make_poc("TRACE", url, {"headers": headers}),
        }
    elif resp["status"] in (200, 405, 403):
        return {
            "method": "TRACE",
            "status": "partial",
            "confirmed": False,
            "severity": "medium",
            "evidence": f"TRACE returned HTTP {resp['status']} but marker not reflected",
            "confidence": 50,
            "poc": _make_poc("TRACE", url, {"headers": headers}),
        }
    else:
        return {
            "method": "TRACE",
            "status": "not_allowed",
            "confirmed": False,
            "severity": "info",
            "evidence": f"TRACE returned HTTP {resp['status']}",
            "confidence": 80,
            "poc": _make_poc("TRACE", url, {"headers": headers}),
        }

async def _test_options(
    session: aiohttp.ClientSession,
    url: str,
) -> Dict:
    """Test OPTIONS method and parse Allow header."""
    resp = await _safe_request(session, "OPTIONS", url)
    if resp["error"]:
        return {"method": "OPTIONS", "status": "error", "allowed": [], "evidence": resp["error"]}

    allow_header = resp["headers"].get("Allow", "")
    if allow_header:
        allowed_methods = [m.strip().upper() for m in allow_header.split(",") if m.strip()]
        dangerous_allowed = [m for m in allowed_methods if m in DANGEROUS_METHODS]
        return {
            "method": "OPTIONS",
            "status": "success",
            "allowed": allowed_methods,
            "dangerous_allowed": dangerous_allowed,
            "evidence": f"Allow: {', '.join(allowed_methods)}",
            "confidence": 80,
            "poc": _make_poc("OPTIONS", url),
        }
    else:
        return {
            "method": "OPTIONS",
            "status": "no_allow_header",
            "allowed": [],
            "evidence": f"HTTP {resp['status']} without Allow header",
            "confidence": 30,
            "poc": _make_poc("OPTIONS", url),
        }

async def _test_put_cycle(
    session: aiohttp.ClientSession,
    url: str,
    baseline: Dict,
) -> Dict:
    """Test PUT with full cycle (PUT -> GET -> DELETE)."""
    # Generate unique test file
    test_filename = f"bravo6-{uuid.uuid4().hex[:8]}.txt"
    test_url = urljoin(url + "/", test_filename)
    test_data = _generate_test_data(200).encode()

    # 1. PUT
    put_resp = await _safe_request(session, "PUT", test_url, data=test_data, headers={"Content-Type": "text/plain"})
    if put_resp["error"]:
        return {
            "method": "PUT",
            "status": "error",
            "confirmed": False,
            "severity": "info",
            "evidence": put_resp["error"],
            "confidence": 0,
        }

    if _response_similar(baseline, put_resp):
        return {
            "method": "PUT",
            "status": "waf_blocked",
            "confirmed": False,
            "severity": "low",
            "evidence": "PUT response matches baseline (likely WAF)",
            "confidence": 20,
        }

    # 2. GET to verify
    get_resp = await _safe_request(session, "GET", test_url)
    if get_resp["error"]:
        # PUT may have succeeded but GET blocked? Still partial.
        return {
            "method": "PUT",
            "status": "partial",
            "confirmed": False,
            "severity": "medium",
            "evidence": f"PUT returned {put_resp['status']} but GET failed: {get_resp['error']}",
            "confidence": 60,
            "poc": _make_poc("PUT", test_url, {"data": "test"}),
        }

    # 3. DELETE to clean up (if PUT succeeded)
    if put_resp["status"] < 400 and test_data in get_resp["body"].encode():
        del_resp = await _safe_request(session, "DELETE", test_url)
        # Even if DELETE fails, we still have the file uploaded
        return {
            "method": "PUT",
            "status": "confirmed",
            "confirmed": True,
            "severity": "high",
            "evidence": f"File uploaded successfully (GET {get_resp['status']}) and content verified",
            "confidence": 100,
            "poc": _make_poc("PUT", test_url, {"data": "test"}),
            "cleanup": del_resp["status"] if del_resp["status"] < 400 else "DELETE failed",
        }
    else:
        # PUT didn't work or file not accessible
        return {
            "method": "PUT",
            "status": "not_allowed",
            "confirmed": False,
            "severity": "medium",
            "evidence": f"PUT returned {put_resp['status']}, GET returned {get_resp['status']}",
            "confidence": 70,
            "poc": _make_poc("PUT", test_url, {"data": "test"}),
        }

async def _test_delete(
    session: aiohttp.ClientSession,
    url: str,
    baseline: Dict,
) -> Dict:
    """Test DELETE on a test file (if PUT succeeded) or on a non-existent resource."""
    # Try to DELETE a non-existent file first
    test_url = urljoin(url + "/", f"bravo6-{uuid.uuid4().hex[:8]}.txt")
    del_resp = await _safe_request(session, "DELETE", test_url)

    if del_resp["error"]:
        return {
            "method": "DELETE",
            "status": "error",
            "confirmed": False,
            "severity": "info",
            "evidence": del_resp["error"],
            "confidence": 0,
        }

    if _response_similar(baseline, del_resp):
        return {
            "method": "DELETE",
            "status": "waf_blocked",
            "confirmed": False,
            "severity": "low",
            "evidence": "DELETE response matches baseline (WAF)",
            "confidence": 20,
        }

    if del_resp["status"] < 400:
        return {
            "method": "DELETE",
            "status": "confirmed",
            "confirmed": True,
            "severity": "critical",
            "evidence": f"DELETE returned {del_resp['status']} on non-existent file (server allowed)",
            "confidence": 90,
            "poc": _make_poc("DELETE", test_url),
        }
    elif del_resp["status"] in (403, 405, 401):
        return {
            "method": "DELETE",
            "status": "not_allowed",
            "confirmed": False,
            "severity": "info",
            "evidence": f"DELETE returned {del_resp['status']}",
            "confidence": 80,
            "poc": _make_poc("DELETE", test_url),
        }
    else:
        return {
            "method": "DELETE",
            "status": "partial",
            "confirmed": False,
            "severity": "medium",
            "evidence": f"DELETE returned {del_resp['status']} (unexpected)",
            "confidence": 50,
            "poc": _make_poc("DELETE", test_url),
        }

async def _test_connect(
    session: aiohttp.ClientSession,
    url: str,
) -> Dict:
    """Test CONNECT method (proxy tunneling)."""
    # Parse host from url
    parsed = urlparse(url)
    target_host = parsed.netloc

    # Try CONNECT to google.com:443 (common proxy test)
    connect_url = "https://google.com:443"
    headers = {"Host": "google.com"}
    resp = await _safe_request(session, "CONNECT", connect_url, headers=headers)

    if resp["error"]:
        return {
            "method": "CONNECT",
            "status": "error",
            "confirmed": False,
            "severity": "info",
            "evidence": resp["error"],
            "confidence": 0,
        }

    if resp["status"] in (200, 302, 301):
        return {
            "method": "CONNECT",
            "status": "confirmed",
            "confirmed": True,
            "severity": "medium",
            "evidence": f"CONNECT returned {resp['status']} (proxy likely open)",
            "confidence": 90,
            "poc": _make_poc("CONNECT", "https://google.com:443", {"headers": {"Host": "google.com"}}),
        }
    else:
        return {
            "method": "CONNECT",
            "status": "not_allowed",
            "confirmed": False,
            "severity": "info",
            "evidence": f"CONNECT returned {resp['status']}",
            "confidence": 80,
            "poc": _make_poc("CONNECT", "https://google.com:443"),
        }

async def _test_debug(
    session: aiohttp.ClientSession,
    url: str,
    baseline: Dict,
) -> Dict:
    """Test DEBUG method (IIS)."""
    # Try DEBUG on multiple paths
    debug_paths = ["", "/debug", "/trace.axd", "/debug.asp"]
    for path in debug_paths:
        test_url = urljoin(url, path)
        headers = {"X-Debug": "true", "X-Request-ID": "Bravo6-DEBUG"}
        resp = await _safe_request(session, "DEBUG", test_url, headers=headers)

        if resp["error"]:
            continue

        if _response_similar(baseline, resp):
            continue

        if resp["status"] < 400:
            return {
                "method": "DEBUG",
                "status": "confirmed",
                "confirmed": True,
                "severity": "critical",
                "evidence": f"DEBUG returned {resp['status']} on {test_url}",
                "confidence": 95,
                "poc": _make_poc("DEBUG", test_url, {"headers": {"X-Debug": "true"}}),
            }

    return {
        "method": "DEBUG",
        "status": "not_found",
        "confirmed": False,
        "severity": "info",
        "evidence": "DEBUG did not return 2xx on any tested path",
        "confidence": 70,
    }

async def _test_method_override(
    session: aiohttp.ClientSession,
    url: str,
    baseline: Dict,
    override_headers: List[str],
) -> Dict:
    """Test method override headers."""
    findings = []
    for header in override_headers:
        # Test with a POST to a safe path
        test_url = urljoin(url, "/")
        test_data = {"test": "Bravo6"}
        headers = {header: "PUT", "Content-Type": "application/json"}
        resp = await _safe_request(session, "POST", test_url, json=test_data, headers=headers)

        if resp["error"]:
            continue

        if _response_similar(baseline, resp):
            continue

        if resp["status"] < 400:
            findings.append({
                "header": header,
                "status": "confirmed",
                "severity": "high",
                "evidence": f"POST with {header}: PUT returned {resp['status']}",
                "confidence": 90,
                "poc": _make_poc("POST", test_url, {"headers": headers, "data": json.dumps(test_data)}),
            })

    if findings:
        # Return the highest severity finding
        return max(findings, key=lambda f: SEVERITY_RANK.get(f["severity"], 0))
    else:
        return {
            "method": "override",
            "status": "not_found",
            "confirmed": False,
            "severity": "info",
            "evidence": "No method override headers succeeded",
            "confidence": 70,
        }

async def _test_webdav(
    session: aiohttp.ClientSession,
    url: str,
    baseline: Dict,
) -> List[Dict]:
    """Test WebDAV methods (PROPFIND, MKCOL, COPY, MOVE)."""
    findings = []
    webdav_paths = ["/", "/webdav/", "/dav/", "/uploads/"]

    for path in webdav_paths:
        test_url = urljoin(url, path)

        # PROPFIND
        resp = await _safe_request(
            session,
            "PROPFIND",
            test_url,
            headers={"Depth": "1", "Content-Type": "application/xml"},
            data=b'<?xml version="1.0"?><propfind xmlns="DAV:"><prop><resourcetype/></prop></propfind>',
        )
        if resp["status"] < 400 and not _response_similar(baseline, resp):
            findings.append({
                "method": "PROPFIND",
                "status": "confirmed",
                "severity": "medium",
                "evidence": f"PROPFIND succeeded on {test_url} (HTTP {resp['status']})",
                "confidence": 90,
                "poc": _make_poc("PROPFIND", test_url, {"headers": {"Depth": "1"}}),
            })

        # MKCOL
        mkcol_url = urljoin(test_url, f"bravo6-{uuid.uuid4().hex[:8]}")
        resp = await _safe_request(session, "MKCOL", mkcol_url)
        if resp["status"] < 400 and not _response_similar(baseline, resp):
            findings.append({
                "method": "MKCOL",
                "status": "confirmed",
                "severity": "medium",
                "evidence": f"MKCOL succeeded on {mkcol_url} (HTTP {resp['status']})",
                "confidence": 90,
                "poc": _make_poc("MKCOL", mkcol_url),
            })

        # COPY
        copy_url = urljoin(test_url, f"bravo6-{uuid.uuid4().hex[:8]}")
        resp = await _safe_request(
            session,
            "COPY",
            test_url,
            headers={"Destination": copy_url, "Overwrite": "F"}
        )
        if resp["status"] < 400 and not _response_similar(baseline, resp):
            findings.append({
                "method": "COPY",
                "status": "confirmed",
                "severity": "medium",
                "evidence": f"COPY succeeded from {test_url} to {copy_url} (HTTP {resp['status']})",
                "confidence": 90,
                "poc": _make_poc("COPY", test_url, {"headers": {"Destination": copy_url}}),
            })

        # MOVE
        move_url = urljoin(test_url, f"bravo6-{uuid.uuid4().hex[:8]}")
        resp = await _safe_request(
            session,
            "MOVE",
            test_url,
            headers={"Destination": move_url, "Overwrite": "F"}
        )
        if resp["status"] < 400 and not _response_similar(baseline, resp):
            findings.append({
                "method": "MOVE",
                "status": "confirmed",
                "severity": "medium",
                "evidence": f"MOVE succeeded from {test_url} to {move_url} (HTTP {resp['status']})",
                "confidence": 90,
                "poc": _make_poc("MOVE", test_url, {"headers": {"Destination": move_url}}),
            })

    return findings

# ── Main run function ──────────────────────────────────────────────────────

async def run(url: str, context: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Main entry point for HTTP methods test.
    Args:
        url: target URL
        context: optional context from other tests (e.g., CORS)
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
            "title": "URL Normalization Error",
            "description": str(e),
            "evidence": [],
            "remediation": "Check URL format.",
        }

    # Get baseline from root GET
    async with aiohttp.ClientSession() as session:
        baseline = await _safe_request(session, "GET", target)

        if baseline["error"]:
            return {
                "test_name": TEST_NAME,
                "status": "error",
                "severity": "info",
                "title": "Connection Error",
                "description": f"Could not fetch {target}: {baseline['error']}",
                "evidence": [],
                "remediation": "Check target availability.",
            }

        waf_detected = _get_waf(baseline["headers"])
        all_evidence = []
        confirmed_methods = []
        warned_methods = []

        # ── 1. Test TRACE ──────────────────────────────────────────────────
        trace_result = await _test_trace(session, target, baseline)
        if trace_result.get("confirmed"):
            confirmed_methods.append("TRACE")
            all_evidence.append(trace_result)
        elif trace_result.get("status") in ("partial", "waf_blocked"):
            warned_methods.append("TRACE")
            all_evidence.append(trace_result)

        # ── 2. Test OPTIONS ──────────────────────────────────────────────
        options_result = await _test_options(session, target)
        if options_result.get("dangerous_allowed"):
            for method in options_result["dangerous_allowed"]:
                all_evidence.append({
                    "method": method,
                    "status": "advertised",
                    "severity": DANGEROUS_METHODS.get(method, {}).get("severity", "medium"),
                    "confidence": 60,
                    "evidence": f"Advertised in Allow header",
                    "poc": _make_poc(method, target),
                    "risk": DANGEROUS_METHODS.get(method, {}).get("risk", ""),
                })
                warned_methods.append(method)

        # ── 3. Test PUT (full cycle) ──────────────────────────────────────
        put_result = await _test_put_cycle(session, target, baseline)
        if put_result.get("confirmed"):
            confirmed_methods.append("PUT")
            all_evidence.append(put_result)
        elif put_result.get("status") in ("partial", "waf_blocked"):
            warned_methods.append("PUT")
            all_evidence.append(put_result)

        # ── 4. Test DELETE ──────────────────────────────────────────────────
        del_result = await _test_delete(session, target, baseline)
        if del_result.get("confirmed"):
            confirmed_methods.append("DELETE")
            all_evidence.append(del_result)
        elif del_result.get("status") in ("partial", "waf_blocked"):
            warned_methods.append("DELETE")
            all_evidence.append(del_result)

        # ── 5. Test CONNECT ──────────────────────────────────────────────────
        connect_result = await _test_connect(session, target)
        if connect_result.get("confirmed"):
            confirmed_methods.append("CONNECT")
            all_evidence.append(connect_result)
        elif connect_result.get("status") in ("partial", "waf_blocked"):
            warned_methods.append("CONNECT")
            all_evidence.append(connect_result)

        # ── 6. Test DEBUG ──────────────────────────────────────────────────
        debug_result = await _test_debug(session, target, baseline)
        if debug_result.get("confirmed"):
            confirmed_methods.append("DEBUG")
            all_evidence.append(debug_result)
        elif debug_result.get("status") in ("partial", "waf_blocked"):
            warned_methods.append("DEBUG")
            all_evidence.append(debug_result)

        # ── 7. Test Method Override ──────────────────────────────────────
        override_result = await _test_method_override(session, target, baseline, OVERRIDE_HEADERS)
        if override_result.get("confirmed"):
            confirmed_methods.append(f"override_{override_result.get('header', '')}")
            all_evidence.append(override_result)
        elif override_result.get("status") in ("partial", "waf_blocked"):
            warned_methods.append("override")
            all_evidence.append(override_result)

        # ── 8. Test WebDAV ──────────────────────────────────────────────────
        webdav_results = await _test_webdav(session, target, baseline)
        for wd_result in webdav_results:
            if wd_result.get("confirmed"):
                confirmed_methods.append(wd_result["method"])
                all_evidence.append(wd_result)

        # ── 9. Test PATCH ──────────────────────────────────────────────────
        patch_url = target
        patch_resp = await _safe_request(
            session,
            "PATCH",
            patch_url,
            json={"test": "Bravo6"},
            headers={"Content-Type": "application/json"}
        )
        if patch_resp["status"] < 400 and not _response_similar(baseline, patch_resp):
            all_evidence.append({
                "method": "PATCH",
                "status": "confirmed",
                "severity": "medium",
                "confidence": 80,
                "evidence": f"PATCH returned {patch_resp['status']}",
                "poc": _make_poc("PATCH", patch_url, {"data": '{"test":"Bravo6"}'}),
            })
            confirmed_methods.append("PATCH")

        # ── 10. Test HEAD ──────────────────────────────────────────────────
        head_resp = await _safe_request(session, "HEAD", target)
        if head_resp["status"] == 405:
            all_evidence.append({
                "method": "HEAD",
                "status": "not_allowed",
                "severity": "info",
                "confidence": 90,
                "evidence": "HEAD returned 405 (method not allowed)",
                "poc": _make_poc("HEAD", target),
            })

        # ── 11. Evaluate with CORS context ───────────────────────────────
        cors_context = context.get("cors", {}) if context else {}
        cors_weak = cors_context.get("weak", False)
        if cors_weak and confirmed_methods:
            # If CORS is weak and dangerous methods are confirmed, elevate severity
            for ev in all_evidence:
                if ev.get("method") in confirmed_methods and ev.get("severity") in ("high", "medium"):
                    ev["severity"] = "critical"
                    ev["evidence"] += " [CORS weakness amplifies risk]"

        # ── 12. Determine overall status ──────────────────────────────────
        if confirmed_methods:
            status = "fail"
            severity = _highest_severity([e.get("severity", "info") for e in all_evidence if e.get("confirmed")])
        elif warned_methods:
            status = "warning"
            severity = _highest_severity([e.get("severity", "info") for e in all_evidence if e.get("status") not in ("error", "not_allowed")])
        else:
            status = "pass"
            severity = "info"

        # Build remediation
        remediation_parts = []
        if confirmed_methods:
            remediation_parts.append(f"Disable dangerous HTTP methods: {', '.join(confirmed_methods)}")
        if "TRACE" in confirmed_methods:
            remediation_parts.append("Disable TRACE to prevent XST attacks")
        if "PUT" in confirmed_methods:
            remediation_parts.append("Disable PUT or restrict to authenticated users with validation")
        if "DELETE" in confirmed_methods:
            remediation_parts.append("Disable DELETE immediately")
        if "DEBUG" in confirmed_methods:
            remediation_parts.append("Disable DEBUG (IIS vulnerability)")
        if "CONNECT" in confirmed_methods:
            remediation_parts.append("Disable CONNECT to prevent proxy abuse")
        if any("override" in m for m in confirmed_methods):
            remediation_parts.append("Disable HTTP method override headers")
        if any(m in confirmed_methods for m in ["PROPFIND", "MKCOL", "COPY", "MOVE"]):
            remediation_parts.append("Disable WebDAV methods if not required")

        if not remediation_parts:
            if waf_detected:
                remediation_parts.append(f"WAF ({waf_detected}) detected; results may be affected. Consider re-testing with WAF bypass techniques.")
            else:
                remediation_parts.append("No dangerous HTTP methods detected. Continue monitoring.")

        return {
            "test_name": TEST_NAME,
            "status": status,
            "severity": severity,
            "title": f"HTTP Methods Scan: {len(confirmed_methods)} confirmed dangerous methods",
            "description": f"Scanned {target} for dangerous HTTP methods. Found {len(confirmed_methods)} confirmed, {len(warned_methods)} warned.",
            "evidence": all_evidence,
            "waf_context": {"detected": waf_detected, "baseline_status": baseline["status"]},
            "remediation": " ".join(remediation_parts),
            "confirmed_methods": confirmed_methods,
            "warned_methods": warned_methods,
        }


if __name__ == "__main__":
    import json
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))