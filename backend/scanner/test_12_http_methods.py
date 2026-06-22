"""
test_12_http_methods.py — HTTP Methods Scanner (Full with WAF Intelligence)

- All methods: TRACE, OPTIONS, PUT, DELETE, CONNECT, DEBUG, PATCH, HEAD
- WebDAV: PROPFIND, MKCOL, COPY, MOVE
- Override Headers (X-HTTP-Method-Override, etc.)
- Multiple path testing (/api, /uploads, /admin, etc.)
- WAF detection reduces false positives
- CORS context integration
"""

import asyncio
import json
import re
import uuid
from urllib.parse import urljoin, urlparse

import aiohttp

TEST_NAME = "http_methods"
USER_AGENT = "Bravo6-Scanner/1.0"
REQUEST_TIMEOUT = 10
MAX_REDIRECTS = 0

DANGEROUS_METHODS = {
    "TRACE": {"severity": "high", "risk": "XST (Cross-Site Tracing)"},
    "PUT": {"severity": "high", "risk": "File upload — may allow arbitrary file writes"},
    "DELETE": {"severity": "critical", "risk": "File deletion — may delete server resources"},
    "CONNECT": {"severity": "medium", "risk": "Proxy tunneling — can bypass firewalls"},
    "DEBUG": {"severity": "critical", "risk": "Remote debugging access (IIS)"},
    "PATCH": {"severity": "medium", "risk": "Partial update — may allow unauthorized modifications"},
    "PROPFIND": {"severity": "medium", "risk": "WebDAV property discovery"},
    "MKCOL": {"severity": "medium", "risk": "WebDAV directory creation"},
    "COPY": {"severity": "medium", "risk": "WebDAV resource copy"},
    "MOVE": {"severity": "medium", "risk": "WebDAV resource move"},
}

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "cf-request-id"],
    "AWS WAF": ["x-amz-cf-id", "x-amzn-RequestId"],
    "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    "Imperva": ["x-iinfo", "x-cdn"],
    "Akamai": ["x-check-cacheable", "akamai-x-cache"],
    "Fastly": ["x-fastly-request-id"],
    "Azure Front Door": ["x-azure-ref", "x-fd-healthprobe"],
}

OVERRIDE_HEADERS = [
    "X-HTTP-Method-Override",
    "X-Original-Method",
    "X-Forwarded-Method",
    "X-Method-Override",
    "X-Override-Method",
]

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

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    return url.rstrip("/")


def _get_waf(headers: dict) -> str:
    header_lower = {k.lower(): v for k, v in headers.items()}
    for waf_name, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in header_lower:
                return waf_name
    return None


def _response_similar(baseline: dict, response: dict) -> bool:
    """تحقق مما إذا كانت الاستجابة مشابهة للـ baseline (WAF)."""
    if baseline.get("status") == response.get("status"):
        return True
    baseline_body = baseline.get("body", "")[:200]
    response_body = response.get("body", "")[:200]
    if baseline_body and response_body:
        markers = ["Access Denied", "Blocked", "Security Check", "cf-browser-verification"]
        for marker in markers:
            if marker in baseline_body and marker in response_body:
                return True
    return False


def _make_poc(method: str, url: str, details: dict = None) -> str:
    cmd = f"curl -X {method}"
    if details and details.get("headers"):
        for h, v in details["headers"].items():
            cmd += f" -H '{h}: {v}'"
    if details and details.get("data"):
        cmd += f" -d '{details['data']}'"
    cmd += f" -v {url}"
    return cmd


def _highest_severity(severities: list) -> str:
    if not severities:
        return "info"
    return max(severities, key=lambda s: SEVERITY_RANK.get(s, 0))


async def _safe_request(session, method, url, headers=None, data=None, json_data=None):
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
            allow_redirects=False,
        ) as resp:
            body = await resp.read()
            return {
                "status": resp.status,
                "headers": dict(resp.headers),
                "body": body.decode("utf-8", errors="ignore"),
                "size": len(body),
                "error": None,
            }
    except Exception as e:
        return {"status": 0, "headers": {}, "body": "", "size": 0, "error": str(e)}


async def run(url: str, context: dict = None) -> dict:
    try:
        target = _normalize_url(url)
        if not target:
            return {"test_name": TEST_NAME, "status": "error", "severity": "info", "title": "Invalid URL", "evidence": [], "remediation": "Check URL."}
    except Exception as e:
        return {"test_name": TEST_NAME, "status": "error", "severity": "info", "title": "Error", "description": str(e), "evidence": [], "remediation": "Check URL."}

    findings = []
    confirmed = []
    warned = []

    async with aiohttp.ClientSession() as session:
        # Baseline
        baseline = await _safe_request(session, "GET", target)
        waf = _get_waf(baseline["headers"])
        waf_confidence = 1.0 if waf else 0.0

        # ── 1. TRACE ──────────────────────────────────────────────────────
        marker = f"Bravo6-{uuid.uuid4().hex[:8]}"
        headers = {"X-Bravo6-Marker": marker}
        trace_resp = await _safe_request(session, "TRACE", target, headers=headers)
        if trace_resp["status"] < 400 and marker in trace_resp["body"]:
            conf = 100 - int(waf_confidence * 20)
            findings.append({
                "method": "TRACE",
                "status": "confirmed",
                "severity": "high",
                "evidence": f"Marker reflected: {marker}",
                "poc": _make_poc("TRACE", target, {"headers": headers}),
                "confidence": conf,
            })
            confirmed.append("TRACE")
        elif trace_resp["status"] == 405:
            findings.append({
                "method": "TRACE",
                "status": "not_allowed",
                "severity": "info",
                "evidence": "TRACE returned 405",
                "confidence": 90,
            })
        elif waf and trace_resp["status"] < 400:
            findings.append({
                "method": "TRACE",
                "status": "waf_intercepted",
                "severity": "low",
                "evidence": f"WAF ({waf}) may be intercepting. Manual verification recommended.",
                "confidence": 30,
            })

        # ── 2. OPTIONS ──────────────────────────────────────────────────
        opt_resp = await _safe_request(session, "OPTIONS", target)
        if opt_resp["status"] < 400:
            allow_header = opt_resp["headers"].get("Allow", "")
            if allow_header:
                allowed = [m.strip().upper() for m in allow_header.split(",") if m.strip()]
                dangerous = [m for m in allowed if m in DANGEROUS_METHODS]
                for m in dangerous:
                    if m in confirmed:
                        continue
                    conf = 50 if not waf else 30
                    sev = DANGEROUS_METHODS.get(m, {}).get("severity", "medium")
                    findings.append({
                        "method": m,
                        "status": "advertised",
                        "severity": sev if not waf else "medium",
                        "evidence": f"Advertised in Allow header",
                        "poc": _make_poc(m, target),
                        "confidence": conf,
                    })
                    warned.append(m)

        # ── 3. PUT (دورة كاملة) ──────────────────────────────────────
        test_url = urljoin(target, f"bravo6-{uuid.uuid4().hex[:8]}.txt")
        test_data = b"Bravo6 Security Test Content"
        put_resp = await _safe_request(session, "PUT", test_url, data=test_data)
        if put_resp["status"] < 400 and not _response_similar(baseline, put_resp):
            get_resp = await _safe_request(session, "GET", test_url)
            if get_resp["status"] < 400 and test_data in get_resp["body"].encode():
                conf = 100 if not waf else 60
                sev = "high" if conf >= 80 else "medium"
                findings.append({
                    "method": "PUT",
                    "status": "confirmed",
                    "severity": sev,
                    "evidence": f"File uploaded and verified (GET {get_resp['status']})",
                    "poc": _make_poc("PUT", test_url, {"data": "test"}),
                    "confidence": conf,
                })
                confirmed.append("PUT")
                await _safe_request(session, "DELETE", test_url)
            else:
                findings.append({
                    "method": "PUT",
                    "status": "partial",
                    "severity": "medium",
                    "evidence": f"PUT returned {put_resp['status']} but file not accessible",
                    "confidence": 50 if not waf else 20,
                })
                warned.append("PUT")
        elif put_resp["status"] == 405:
            findings.append({
                "method": "PUT",
                "status": "not_allowed",
                "severity": "info",
                "evidence": "PUT returned 405",
                "confidence": 90,
            })

        # ── 4. DELETE ──────────────────────────────────────────────────
        test_url = urljoin(target, f"bravo6-{uuid.uuid4().hex[:8]}.txt")
        del_resp = await _safe_request(session, "DELETE", test_url)
        if del_resp["status"] < 400 and not _response_similar(baseline, del_resp):
            conf = 80 if not waf else 40
            sev = "critical" if conf >= 80 else "high"
            findings.append({
                "method": "DELETE",
                "status": "confirmed" if conf >= 80 else "partial",
                "severity": sev,
                "evidence": f"DELETE returned {del_resp['status']} on non-existent resource",
                "poc": _make_poc("DELETE", test_url),
                "confidence": conf,
            })
            if conf >= 80:
                confirmed.append("DELETE")
            else:
                warned.append("DELETE")
        elif del_resp["status"] == 405:
            findings.append({
                "method": "DELETE",
                "status": "not_allowed",
                "severity": "info",
                "evidence": "DELETE returned 405",
                "confidence": 90,
            })

        # ── 5. CONNECT ──────────────────────────────────────────────────
        connect_url = "https://google.com:443"
        headers = {"Host": "google.com"}
        conn_resp = await _safe_request(session, "CONNECT", connect_url, headers=headers)
        if conn_resp["status"] < 400:
            conf = 70 if not waf else 30
            findings.append({
                "method": "CONNECT",
                "status": "confirmed" if conf >= 70 else "partial",
                "severity": "medium",
                "evidence": f"CONNECT returned {conn_resp['status']}",
                "poc": _make_poc("CONNECT", connect_url, {"headers": headers}),
                "confidence": conf,
            })
            if conf >= 70:
                confirmed.append("CONNECT")
            else:
                warned.append("CONNECT")

        # ── 6. DEBUG ──────────────────────────────────────────────────
        debug_paths = ["", "/debug", "/trace.axd", "/debug.asp"]
        debug_found = False
        for path in debug_paths:
            test_url = urljoin(target, path)
            headers = {"X-Debug": "true", "X-Request-ID": "Bravo6-DEBUG"}
            debug_resp = await _safe_request(session, "DEBUG", test_url, headers=headers)
            if debug_resp["status"] < 400 and not _response_similar(baseline, debug_resp):
                conf = 95 if not waf else 60
                findings.append({
                    "method": "DEBUG",
                    "status": "confirmed" if conf >= 80 else "partial",
                    "severity": "critical",
                    "evidence": f"DEBUG returned {debug_resp['status']} on {test_url}",
                    "poc": _make_poc("DEBUG", test_url, {"headers": headers}),
                    "confidence": conf,
                })
                if conf >= 80:
                    confirmed.append("DEBUG")
                else:
                    warned.append("DEBUG")
                debug_found = True
                break
        if not debug_found:
            findings.append({
                "method": "DEBUG",
                "status": "not_found",
                "severity": "info",
                "evidence": "DEBUG did not return 2xx on any tested path",
                "confidence": 70,
            })

        # ── 7. PATCH ──────────────────────────────────────────────────
        patch_url = target
        patch_resp = await _safe_request(
            session,
            "PATCH",
            patch_url,
            json_data={"test": "Bravo6"},
            headers={"Content-Type": "application/json"}
        )
        if patch_resp["status"] < 400 and not _response_similar(baseline, patch_resp):
            conf = 80 if not waf else 40
            findings.append({
                "method": "PATCH",
                "status": "confirmed" if conf >= 80 else "partial",
                "severity": "medium",
                "evidence": f"PATCH returned {patch_resp['status']}",
                "poc": _make_poc("PATCH", patch_url, {"data": '{"test":"Bravo6"}'}),
                "confidence": conf,
            })
            if conf >= 80:
                confirmed.append("PATCH")
            else:
                warned.append("PATCH")
        elif patch_resp["status"] == 405:
            findings.append({
                "method": "PATCH",
                "status": "not_allowed",
                "severity": "info",
                "evidence": "PATCH returned 405",
                "confidence": 90,
            })

        # ── 8. HEAD ──────────────────────────────────────────────────
        head_resp = await _safe_request(session, "HEAD", target)
        if head_resp["status"] == 405:
            findings.append({
                "method": "HEAD",
                "status": "not_allowed",
                "severity": "info",
                "evidence": "HEAD returned 405 (method not allowed)",
                "confidence": 90,
            })

        # ── 9. Override Headers ──────────────────────────────────────
        for header in OVERRIDE_HEADERS:
            test_data = {"test": "Bravo6"}
            headers = {header: "PUT", "Content-Type": "application/json"}
            override_resp = await _safe_request(
                session,
                "POST",
                target,
                headers=headers,
                json_data=test_data
            )
            if override_resp["status"] < 400 and not _response_similar(baseline, override_resp):
                conf = 90 if not waf else 50
                findings.append({
                    "method": f"override_{header}",
                    "status": "confirmed" if conf >= 80 else "partial",
                    "severity": "high",
                    "evidence": f"POST with {header}: PUT returned {override_resp['status']}",
                    "poc": _make_poc("POST", target, {"headers": headers, "data": json.dumps(test_data)}),
                    "confidence": conf,
                })
                if conf >= 80:
                    confirmed.append(f"override_{header}")
                else:
                    warned.append(f"override_{header}")
                break  # اكتفاء بواحد

        # ── 10. WebDAV (PROPFIND, MKCOL, COPY, MOVE) ──────────────────
        webdav_paths = ["/", "/webdav/", "/dav/", "/uploads/"]
        for path in webdav_paths:
            test_url = urljoin(target, path)

            # PROPFIND
            prop_resp = await _safe_request(
                session,
                "PROPFIND",
                test_url,
                headers={"Depth": "1", "Content-Type": "application/xml"},
                data=b'<?xml version="1.0"?><propfind xmlns="DAV:"><prop><resourcetype/></prop></propfind>',
            )
            if prop_resp["status"] < 400 and not _response_similar(baseline, prop_resp):
                conf = 90 if not waf else 50
                findings.append({
                    "method": "PROPFIND",
                    "status": "confirmed" if conf >= 80 else "partial",
                    "severity": "medium",
                    "evidence": f"PROPFIND succeeded on {test_url}",
                    "poc": _make_poc("PROPFIND", test_url, {"headers": {"Depth": "1"}}),
                    "confidence": conf,
                })
                if conf >= 80:
                    confirmed.append("PROPFIND")
                else:
                    warned.append("PROPFIND")

            # MKCOL
            mkcol_url = urljoin(test_url, f"bravo6-{uuid.uuid4().hex[:8]}")
            mkcol_resp = await _safe_request(session, "MKCOL", mkcol_url)
            if mkcol_resp["status"] < 400 and not _response_similar(baseline, mkcol_resp):
                conf = 90 if not waf else 50
                findings.append({
                    "method": "MKCOL",
                    "status": "confirmed" if conf >= 80 else "partial",
                    "severity": "medium",
                    "evidence": f"MKCOL succeeded on {mkcol_url}",
                    "poc": _make_poc("MKCOL", mkcol_url),
                    "confidence": conf,
                })
                if conf >= 80:
                    confirmed.append("MKCOL")
                else:
                    warned.append("MKCOL")
                await _safe_request(session, "DELETE", mkcol_url)

            # COPY
            copy_url = urljoin(test_url, f"bravo6-{uuid.uuid4().hex[:8]}")
            copy_resp = await _safe_request(
                session,
                "COPY",
                test_url,
                headers={"Destination": copy_url, "Overwrite": "F"}
            )
            if copy_resp["status"] < 400 and not _response_similar(baseline, copy_resp):
                conf = 90 if not waf else 50
                findings.append({
                    "method": "COPY",
                    "status": "confirmed" if conf >= 80 else "partial",
                    "severity": "medium",
                    "evidence": f"COPY succeeded from {test_url} to {copy_url}",
                    "poc": _make_poc("COPY", test_url, {"headers": {"Destination": copy_url}}),
                    "confidence": conf,
                })
                if conf >= 80:
                    confirmed.append("COPY")
                else:
                    warned.append("COPY")
                await _safe_request(session, "DELETE", copy_url)

            # MOVE
            move_url = urljoin(test_url, f"bravo6-{uuid.uuid4().hex[:8]}")
            move_resp = await _safe_request(
                session,
                "MOVE",
                test_url,
                headers={"Destination": move_url, "Overwrite": "F"}
            )
            if move_resp["status"] < 400 and not _response_similar(baseline, move_resp):
                conf = 90 if not waf else 50
                findings.append({
                    "method": "MOVE",
                    "status": "confirmed" if conf >= 80 else "partial",
                    "severity": "medium",
                    "evidence": f"MOVE succeeded from {test_url} to {move_url}",
                    "poc": _make_poc("MOVE", test_url, {"headers": {"Destination": move_url}}),
                    "confidence": conf,
                })
                if conf >= 80:
                    confirmed.append("MOVE")
                else:
                    warned.append("MOVE")
                await _safe_request(session, "DELETE", move_url)

            # نخرج بعد أول مسار نجح لتجنب التكرار
            if any(m in confirmed for m in ["PROPFIND", "MKCOL", "COPY", "MOVE"]):
                break

    # ── 11. تكامل مع CORS ──────────────────────────────────────────────
    cors_context = context.get("cors", {}) if context else {}
    cors_weak = cors_context.get("weak", False)
    if cors_weak and confirmed:
        for f in findings:
            if f.get("method") in confirmed and f.get("severity") in ("high", "medium"):
                f["severity"] = "critical"
                f["evidence"] += " [CORS weakness amplifies risk]"

    # ── 12. تحديد الحالة النهائية ────────────────────────────────────
    critical = [f for f in findings if f.get("severity") == "critical" and f.get("status") == "confirmed"]
    high = [f for f in findings if f.get("severity") == "high" and f.get("status") == "confirmed"]

    if critical:
        status = "fail"
        severity = "critical"
    elif high:
        status = "fail"
        severity = "high"
    elif confirmed:
        status = "warning"
        severity = "medium"
    elif warned:
        status = "warning"
        severity = "low"
    else:
        status = "pass"
        severity = "info"

    # ── 13. بناء التوصيات ──────────────────────────────────────────────
    remediation = []
    if "TRACE" in confirmed:
        remediation.append("Disable TRACE to prevent XST.")
    if "PUT" in confirmed:
        remediation.append("Disable PUT or restrict to authenticated users with validation.")
    if "DELETE" in confirmed:
        remediation.append("Disable DELETE immediately.")
    if "DEBUG" in confirmed:
        remediation.append("Disable DEBUG (IIS vulnerability).")
    if "CONNECT" in confirmed:
        remediation.append("Disable CONNECT to prevent proxy abuse.")
    if "PATCH" in confirmed:
        remediation.append("Restrict PATCH to authenticated users.")
    if any("override" in m for m in confirmed):
        remediation.append("Disable HTTP method override headers.")
    if any(m in confirmed for m in ["PROPFIND", "MKCOL", "COPY", "MOVE"]):
        remediation.append("Disable WebDAV methods if not required.")

    if not remediation:
        if waf:
            remediation.append(f"WAF ({waf}) detected; results may be affected. Manual verification recommended.")
        else:
            remediation.append("No dangerous HTTP methods detected. Continue monitoring.")

    return {
        "test_name": TEST_NAME,
        "status": status,
        "severity": severity,
        "title": f"HTTP Methods: {len(confirmed)} confirmed, {len(warned)} warned",
        "description": f"Scanned {target} for dangerous HTTP methods.",
        "evidence": findings,
        "remediation": " ".join(remediation),
        "confirmed_methods": confirmed,
        "warned_methods": warned,
        "waf_detected": waf,
    }


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(f"Status: {result['status']} | Severity: {result['severity']}")
    print(f"Confirmed: {result['confirmed_methods']}")
    print(f"Findings: {len(result['evidence'])}")