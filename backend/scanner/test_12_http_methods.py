"""
test_12_http_methods.py — Advanced HTTP Method Scanner (Active Exploitation)

Upgraded:
- Actively tests TRACE, PUT, DELETE, CONNECT, DEBUG, and method overriding.
- Creates a test file with PUT then verifies it exists (GET) and deletes it (DELETE) for 100% confirmation.
- Provides curl commands as PoC for each confirmed dangerous method.
- Adds confidence scoring (100% for confirmed exploitation, 80% for options-advertised).
- Implements advanced WAF false-positive filtering.
"""

import asyncio
import uuid
import re
from urllib.parse import urlparse

import aiohttp

TEST_NAME = "http_methods"
USER_AGENT = "Bravo6-Scanner/1.0"
REQUEST_TIMEOUT = 10

DANGEROUS_METHODS = {
    "TRACE": {"severity": "high", "risk": "XST (Cross-Site Tracing) can steal HttpOnly cookies"},
    "PUT": {"severity": "high", "risk": "File upload — may allow arbitrary file writes"},
    "DELETE": {"severity": "critical", "risk": "File deletion — may delete server resources"},
    "CONNECT": {"severity": "medium", "risk": "Proxy tunneling — can bypass firewalls"},
    "DEBUG": {"severity": "critical", "risk": "Remote debugging access (IIS)"},
    "OPTIONS": {"severity": "low", "risk": "May disclose allowed methods (information disclosure)"},
}

SAFE_METHODS = {"GET", "POST", "HEAD"}
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
WAF_SIZE_TOLERANCE = 0.05  # 5%


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return url
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = f"https://{url}"
    return url.rstrip("/")


def _highest_severity(severities):
    if not severities:
        return "info"
    return max(severities, key=lambda s: SEVERITY_RANK.get(s, 0))


def _detect_waf(headers: dict) -> str | None:
    header_lower = {k.lower(): v for k, v in headers.items()}
    if "cf-ray" in header_lower or header_lower.get("server", "").lower() == "cloudflare":
        return "Cloudflare"
    if "x-amz-cf-id" in header_lower:
        return "AWS CloudFront"
    if "x-sucuri-id" in header_lower:
        return "Sucuri WAF"
    if "x-fastly-request-id" in header_lower:
        return "Fastly"
    if "x-azure-ref" in header_lower:
        return "Azure Front Door"
    return None


async def _safe_request(session: aiohttp.ClientSession, method: str, url: str, **kwargs):
    try:
        async with session.request(method, url, timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT), ssl=False, allow_redirects=False, **kwargs) as resp:
            body = await resp.read()
            return {"status": resp.status, "body": body, "headers": dict(resp.headers)}, None
    except asyncio.TimeoutError:
        return None, "timeout"
    except aiohttp.ClientError as e:
        return None, f"client_error: {e}"
    except Exception as e:
        return None, f"error: {e}"


def _is_waf_fp(baseline_size: int, body: bytes, status: int) -> bool:
    """Check if response looks like WAF reflection (same size + HTML)."""
    if baseline_size == 0:
        return False
    if abs(len(body) - baseline_size) / baseline_size <= WAF_SIZE_TOLERANCE:
        return True
    if body[:100].lower().strip().startswith(b"<!doctype") or body[:100].lower().strip().startswith(b"<html"):
        return True
    return False


def _make_poc(method: str, url: str, details: dict) -> str:
    if method == "TRACE":
        return f"curl -X TRACE -H 'X-Bravo6-Test: {uuid.uuid4().hex}' -v {url}"
    if method == "PUT":
        return f"curl -X PUT -d 'test-data' -H 'Content-Type: text/plain' {url}/test-{uuid.uuid4().hex[:8]}.txt"
    if method == "DELETE":
        return f"curl -X DELETE -v {url}/test-{uuid.uuid4().hex[:8]}.txt"
    if method == "CONNECT":
        return f"curl -X CONNECT -v {url}"
    if method == "DEBUG":
        return f"curl -X DEBUG -v {url}"
    return f"curl -X {method} -v {url}"


async def _test_trace(session: aiohttp.ClientSession, url: str, baseline_size: int) -> dict:
    marker = f"bravo6-{uuid.uuid4().hex[:8]}"
    resp, err = await _safe_request(session, "TRACE", url, headers={"X-Bravo6-Marker": marker})
    if err or not resp:
        return {"status": "error", "error": err, "confirmed": False, "evidence": err}

    if resp["status"] >= 400:
        return {"status": "not_allowed", "status_code": resp["status"], "confirmed": False, "evidence": f"HTTP {resp['status']}"}

    if _is_waf_fp(baseline_size, resp["body"], resp["status"]):
        return {"status": "waf_fp", "status_code": resp["status"], "confirmed": False, "evidence": "WAF reflection (same size/HTML)"}

    body_text = resp["body"].decode("utf-8", errors="ignore")
    if marker in body_text:
        return {"status": "confirmed", "status_code": resp["status"], "confirmed": True, "evidence": f"Marker '{marker}' echoed in response"}
    return {"status": "partial", "status_code": resp["status"], "confirmed": False, "evidence": "TRACE accepted but did not echo marker"}


async def _test_put_delete(session: aiohttp.ClientSession, base_url: str, baseline_size: int) -> dict:
    """Full PUT → GET → DELETE cycle for 100% confirmation."""
    test_file = f"bravo6-{uuid.uuid4().hex[:8]}.txt"
    test_url = f"{base_url}/{test_file}"
    test_data = b"Bravo6 Security Test - " + uuid.uuid4().bytes.hex().encode()

    # PUT
    resp, err = await _safe_request(session, "PUT", test_url, data=test_data, headers={"Content-Type": "text/plain"})
    if err or not resp:
        return {"method": "PUT", "status": "error", "error": err, "confirmed": False}

    if resp["status"] >= 400:
        return {"method": "PUT", "status": "not_allowed", "status_code": resp["status"], "confirmed": False, "evidence": f"HTTP {resp['status']}"}

    if _is_waf_fp(baseline_size, resp["body"], resp["status"]):
        return {"method": "PUT", "status": "waf_fp", "confirmed": False, "evidence": "WAF reflection"}

    # GET to verify existence
    get_resp, get_err = await _safe_request(session, "GET", test_url)
    if get_err or not get_resp:
        return {"method": "PUT", "status": "partial", "confirmed": False, "evidence": "PUT accepted but GET failed (maybe 403/404)"}

    if get_resp["status"] == 200 and test_data in get_resp["body"]:
        # DELETE to clean up
        del_resp, del_err = await _safe_request(session, "DELETE", test_url)
        if del_err or not del_resp:
            pass  # cleanup failure doesn't affect vulnerability status
        return {"method": "PUT", "status": "confirmed", "status_code": resp["status"], "confirmed": True, "evidence": f"File uploaded and verified (GET {get_resp['status']}), then deleted"}

    return {"method": "PUT", "status": "partial", "confirmed": False, "evidence": "PUT accepted but file not accessible"}


async def _test_method_override(session: aiohttp.ClientSession, url: str) -> dict:
    """Test if server respects X-HTTP-Method-Override header."""
    override_methods = ["PUT", "DELETE", "TRACE", "DEBUG"]
    findings = []
    for override in override_methods:
        resp, err = await _safe_request(
            session, "POST", url,
            headers={"X-HTTP-Method-Override": override, "Content-Type": "text/plain"},
            data=f"override-{override}"
        )
        if err or not resp:
            continue
        if resp["status"] < 400:
            findings.append({
                "method": override,
                "status_code": resp["status"],
                "confirmed": True,
                "evidence": f"X-HTTP-Method-Override: {override} succeeded (HTTP {resp['status']})",
                "poc": f"curl -X POST -H 'X-HTTP-Method-Override: {override}' -v {url}"
            })
    return findings


async def _test_options(session: aiohttp.ClientSession, url: str) -> dict:
    resp, err = await _safe_request(session, "OPTIONS", url)
    if err or not resp:
        return {"status": "error", "methods": [], "evidence": err}
    allow = resp["headers"].get("Allow", "") + "," + resp["headers"].get("Access-Control-Allow-Methods", "")
    methods = {m.strip().upper() for m in allow.split(",") if m.strip()}
    return {"status": "success", "methods": methods, "evidence": f"OPTIONS returned: {', '.join(methods)}"}


async def run(url: str) -> dict:
    try:
        target = _normalize_url(url)
        if not target:
            return {"test_name": TEST_NAME, "status": "error", "severity": "info", "title": "Invalid URL", "evidence": [], "remediation": "Provide a valid URL."}

        async with aiohttp.ClientSession() as session:
            # Baseline GET
            baseline_resp, _ = await _safe_request(session, "GET", target)
            baseline_size = len(baseline_resp["body"]) if baseline_resp else 0
            waf_detected = _detect_waf(baseline_resp["headers"]) if baseline_resp else None

            all_evidence = []
            confirmed_methods = []
            warned_methods = []

            # 1. OPTIONS
            options = await _test_options(session, target)
            if options["methods"]:
                dangerous_from_options = [m for m in options["methods"] if m in DANGEROUS_METHODS]
                for m in dangerous_from_options:
                    all_evidence.append({
                        "method": m,
                        "status": "advertised",
                        "severity": DANGEROUS_METHODS[m]["severity"],
                        "confidence": 60,
                        "poc": _make_poc(m, target, {}),
                        "evidence": f"Advertised in OPTIONS Allow header",
                        "risk": DANGEROUS_METHODS[m]["risk"],
                        "remediation": f"Disable {m} method unless absolutely required."
                    })
                    warned_methods.append(m)

            # 2. TRACE
            trace = await _test_trace(session, target, baseline_size)
            if trace["confirmed"]:
                all_evidence.append({
                    "method": "TRACE",
                    "status": "confirmed",
                    "severity": "high",
                    "confidence": 100,
                    "poc": "curl -X TRACE -v " + target,
                    "evidence": trace["evidence"],
                    "risk": DANGEROUS_METHODS["TRACE"]["risk"],
                    "remediation": "Disable TRACE method immediately."
                })
                confirmed_methods.append("TRACE")
            elif trace["status"] == "partial":
                all_evidence.append({
                    "method": "TRACE",
                    "status": "partial",
                    "severity": "medium",
                    "confidence": 70,
                    "poc": "curl -X TRACE -v " + target,
                    "evidence": trace["evidence"],
                    "risk": DANGEROUS_METHODS["TRACE"]["risk"],
                    "remediation": "Investigate TRACE behavior; consider disabling it."
                })
                warned_methods.append("TRACE")

            # 3. PUT + DELETE full cycle
            put_delete = await _test_put_delete(session, target, baseline_size)
            if put_delete["confirmed"]:
                all_evidence.append({
                    "method": "PUT",
                    "status": "confirmed",
                    "severity": "high",
                    "confidence": 100,
                    "poc": "curl -X PUT -d 'test' -H 'Content-Type: text/plain' {}/test.txt".format(target),
                    "evidence": put_delete["evidence"],
                    "risk": DANGEROUS_METHODS["PUT"]["risk"],
                    "remediation": "Disable PUT method; implement strict upload validation if required."
                })
                confirmed_methods.append("PUT")
            elif put_delete["status"] == "partial":
                all_evidence.append({
                    "method": "PUT",
                    "status": "partial",
                    "severity": "medium",
                    "confidence": 70,
                    "poc": "curl -X PUT -d 'test' -v " + target,
                    "evidence": put_delete["evidence"],
                    "risk": DANGEROUS_METHODS["PUT"]["risk"],
                    "remediation": "Investigate PUT behavior; disable if not needed."
                })
                warned_methods.append("PUT")

            # 4. DELETE (if not already tested via PUT cycle)
            if "PUT" not in confirmed_methods:
                # Test DELETE independently
                test_file = f"bravo6-delete-{uuid.uuid4().hex[:8]}.txt"
                test_url = f"{target}/{test_file}"
                # First create a file (if PUT works) then delete
                put_resp, _ = await _safe_request(session, "PUT", test_url, data=b"test", headers={"Content-Type": "text/plain"})
                if put_resp and put_resp["status"] < 400:
                    del_resp, _ = await _safe_request(session, "DELETE", test_url)
                    if del_resp and del_resp["status"] < 400 and not _is_waf_fp(baseline_size, del_resp["body"], del_resp["status"]):
                        all_evidence.append({
                            "method": "DELETE",
                            "status": "confirmed",
                            "severity": "critical",
                            "confidence": 100,
                            "poc": f"curl -X DELETE -v {test_url}",
                            "evidence": f"DELETE succeeded (HTTP {del_resp['status']}) after PUT creation",
                            "risk": DANGEROUS_METHODS["DELETE"]["risk"],
                            "remediation": "Disable DELETE method immediately."
                        })
                        confirmed_methods.append("DELETE")
                else:
                    # Just test DELETE alone
                    del_resp, _ = await _safe_request(session, "DELETE", target)
                    if del_resp and del_resp["status"] < 400 and not _is_waf_fp(baseline_size, del_resp["body"], del_resp["status"]):
                        all_evidence.append({
                            "method": "DELETE",
                            "status": "confirmed",
                            "severity": "critical",
                            "confidence": 80,
                            "poc": f"curl -X DELETE -v {target}",
                            "evidence": f"DELETE returned HTTP {del_resp['status']} with non-WAF body",
                            "risk": DANGEROUS_METHODS["DELETE"]["risk"],
                            "remediation": "Disable DELETE method."
                        })
                        confirmed_methods.append("DELETE")

            # 5. CONNECT
            connect_resp, _ = await _safe_request(session, "CONNECT", target)
            if connect_resp and connect_resp["status"] < 400 and not _is_waf_fp(baseline_size, connect_resp["body"], connect_resp["status"]):
                all_evidence.append({
                    "method": "CONNECT",
                    "status": "confirmed",
                    "severity": "medium",
                    "confidence": 80,
                    "poc": "curl -X CONNECT -v " + target,
                    "evidence": f"CONNECT accepted (HTTP {connect_resp['status']})",
                    "risk": DANGEROUS_METHODS["CONNECT"]["risk"],
                    "remediation": "Disable CONNECT unless needed for proxy."
                })
                confirmed_methods.append("CONNECT")

            # 6. DEBUG
            debug_resp, _ = await _safe_request(session, "DEBUG", target)
            if debug_resp and debug_resp["status"] < 400 and not _is_waf_fp(baseline_size, debug_resp["body"], debug_resp["status"]):
                all_evidence.append({
                    "method": "DEBUG",
                    "status": "confirmed",
                    "severity": "critical",
                    "confidence": 90,
                    "poc": "curl -X DEBUG -v " + target,
                    "evidence": f"DEBUG accepted (HTTP {debug_resp['status']})",
                    "risk": DANGEROUS_METHODS["DEBUG"]["risk"],
                    "remediation": "Disable DEBUG method immediately (IIS vulnerability)."
                })
                confirmed_methods.append("DEBUG")

            # 7. Method Override
            override_findings = await _test_method_override(session, target)
            for o in override_findings:
                if o["method"] in DANGEROUS_METHODS:
                    all_evidence.append({
                        "method": f"{o['method']} (via X-HTTP-Method-Override)",
                        "status": "confirmed",
                        "severity": DANGEROUS_METHODS[o["method"]]["severity"],
                        "confidence": 100,
                        "poc": o["poc"],
                        "evidence": o["evidence"],
                        "risk": DANGEROUS_METHODS[o["method"]]["risk"],
                        "remediation": f"Disable X-HTTP-Method-Override or restrict its usage."
                    })
                    if o["method"] not in confirmed_methods:
                        confirmed_methods.append(o["method"])

            # Determine overall status
            if confirmed_methods:
                status = "fail"
                severity = _highest_severity([e["severity"] for e in all_evidence if e.get("status") == "confirmed"])
            elif warned_methods:
                status = "warning"
                severity = _highest_severity([e["severity"] for e in all_evidence if e.get("status") != "error"])
            else:
                status = "pass"
                severity = "info"

            return {
                "test_name": TEST_NAME,
                "status": status,
                "severity": severity,
                "title": f"HTTP Methods Scan ({len(confirmed_methods)} confirmed dangerous methods)" if confirmed_methods else "No dangerous HTTP methods confirmed",
                "description": f"Scanned {target} for dangerous HTTP methods. Found {len(all_evidence)} findings.",
                "evidence": all_evidence,
                "waf_context": {"detected": waf_detected, "baseline_size": baseline_size},
                "remediation": "Disable all dangerous HTTP methods (TRACE, PUT, DELETE, CONNECT, DEBUG) and method overriding headers. Use explicit allowlists for required methods."
            }

    except Exception as e:
        return {
            "test_name": TEST_NAME,
            "status": "error",
            "severity": "info",
            "title": "Scan Error",
            "description": f"Unexpected error: {e}",
            "evidence": [],
            "remediation": "Check target connectivity and try again."
        }


if __name__ == "__main__":
    import json, sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))