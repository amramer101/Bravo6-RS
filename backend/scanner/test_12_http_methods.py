"""
Bravo6 Security Scanner
Module: test_12_http_methods.py

Discovers which HTTP methods a target web server supports and flags
dangerous ones (TRACE, PUT, DELETE, CONNECT, DEBUG, etc.).

v2: Added WAF/CDN false positive detection.
    A server behind Cloudflare or similar CDN often returns HTTP 200
    for ANY method (including DELETE) by serving a cached HTML page.
    We detect this by comparing the response body size of a dangerous
    method against a baseline GET — if they match within a tolerance,
    the result is flagged as a WAF false positive and NOT reported
    as a confirmed finding.
"""

import asyncio
import uuid
from urllib.parse import urlparse

import aiohttp

USER_AGENT = "Bravo6-Scanner/1.0"
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=10)

DANGEROUS_METHODS = {
    "TRACE": {
        "severity": "medium",
        "reason": "TRACE enables Cross-Site Tracing (XST) attacks. Combined with XSS, it can steal HttpOnly cookies.",
    },
    "PUT": {
        "severity": "high",
        "reason": "PUT method may allow uploading arbitrary files to the server.",
    },
    "DELETE": {
        "severity": "high",
        "reason": "DELETE method may allow deleting server resources.",
    },
    "CONNECT": {
        "severity": "medium",
        "reason": "CONNECT can be used for proxy tunneling attacks.",
    },
    "DEBUG": {
        "severity": "critical",
        "reason": "DEBUG is a Microsoft IIS method that can enable remote debugging and expose sensitive info.",
    },
}

SAFE_METHODS = ["GET", "POST", "HEAD", "OPTIONS"]
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# If a dangerous method's response body size is within this % of the GET
# baseline, we treat it as a WAF/CDN reflection (false positive).
WAF_SIZE_TOLERANCE = 0.05  # 5%


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return url
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"https://{url}"
    return url


def _highest_severity(severities):
    if not severities:
        return "info"
    return max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0))


async def _safe_request(session: aiohttp.ClientSession, method: str, url: str, **kwargs):
    """
    Perform an HTTP request, swallowing all exceptions.
    Returns (response_snapshot_or_None, error_string_or_None).
    We read the body immediately so the connection is freed.
    """
    try:
        async with session.request(method, url, **kwargs) as resp:
            try:
                body = await resp.read()
            except Exception:
                body = b""
            return {"status": resp.status, "body": body, "headers": dict(resp.headers)}, None
    except asyncio.TimeoutError:
        return None, f"{method} request timed out after 10s"
    except aiohttp.ClientConnectorError as e:
        return None, f"{method} connection failed: {e}"
    except aiohttp.ClientError as e:
        return None, f"{method} client error: {e}"
    except Exception as e:
        return None, f"{method} unexpected error: {e}"


# --------------------------------------------------------------------------
# WAF Detection
# --------------------------------------------------------------------------

def _is_waf_reflection(baseline_size: int, response_body: bytes) -> bool:
    """
    Compare a method's response body size to the GET baseline.
    If within WAF_SIZE_TOLERANCE (5%), it's almost certainly a cached
    page served by a WAF/CDN — not a real method acceptance.

    Also checks if the response looks like HTML (which a DELETE response
    should never be if it was genuinely processed).
    """
    if baseline_size == 0:
        return False

    response_size = len(response_body)
    size_diff = abs(response_size - baseline_size) / baseline_size

    if size_diff <= WAF_SIZE_TOLERANCE:
        return True

    # Secondary check: if response body starts with HTML doctype/tag,
    # it's almost certainly a cached page, not a real method response.
    body_start = response_body[:100].lower().strip()
    if body_start.startswith(b"<!doctype") or body_start.startswith(b"<html"):
        return True

    return False


def _detect_waf_from_headers(headers: dict) -> str | None:
    """
    Detect known WAF/CDN headers that indicate a proxy is in front.
    Returns the WAF name if detected, None otherwise.
    """
    header_lower = {k.lower(): v for k, v in headers.items()}

    if "cf-ray" in header_lower or header_lower.get("server", "").lower() == "cloudflare":
        return "Cloudflare"
    if "x-cache" in header_lower and "akamai" in header_lower.get("x-cache", "").lower():
        return "Akamai"
    if "x-amz-cf-id" in header_lower or "x-amz-request-id" in header_lower:
        return "AWS CloudFront"
    if "x-sucuri-id" in header_lower:
        return "Sucuri WAF"
    if "x-fastly-request-id" in header_lower:
        return "Fastly CDN"
    if "x-azure-ref" in header_lower:
        return "Azure Front Door"

    return None


# --------------------------------------------------------------------------
# Individual method checks
# --------------------------------------------------------------------------

async def _check_options(session: aiohttp.ClientSession, url: str):
    methods = set()
    resp, err = await _safe_request(session, "OPTIONS", url)
    if err or resp is None:
        return methods, err

    allow_header = resp["headers"].get("Allow", "")
    acam_header = resp["headers"].get("Access-Control-Allow-Methods", "")
    for header_value in (allow_header, acam_header):
        if header_value:
            for m in header_value.split(","):
                m = m.strip().upper()
                if m:
                    methods.add(m)

    return methods, None


async def _check_trace(session: aiohttp.ClientSession, url: str, baseline_size: int):
    result = {
        "attempted": True,
        "status_code": None,
        "confirmed": False,
        "waf_false_positive": False,
        "evidence": None,
        "error": None,
    }

    marker_header = "X-Bravo6-Trace-Check"
    marker_value = f"bravo6-{uuid.uuid4().hex[:12]}"

    resp, err = await _safe_request(
        session, "TRACE", url,
        headers={marker_header: marker_value}
    )
    if err or resp is None:
        result["error"] = err
        return result

    result["status_code"] = resp["status"]
    body = resp["body"]

    if resp["status"] >= 400:
        result["evidence"] = f"Server returned HTTP {resp['status']} for TRACE (not allowed)."
        return result

    # Check WAF reflection first
    if _is_waf_reflection(baseline_size, body):
        result["waf_false_positive"] = True
        result["evidence"] = (
            f"TRACE returned HTTP {resp['status']} but response body matches GET baseline "
            f"— WAF/CDN is reflecting cached page, not a real TRACE response."
        )
        return result

    # Real TRACE check: does response echo our marker?
    body_text = body.decode("utf-8", errors="ignore")
    body_snippet = body_text[:2000]
    if marker_value in body_snippet or marker_header.lower() in body_snippet.lower():
        result["confirmed"] = True
        result["evidence"] = (
            f"TRACE request with header '{marker_header}: {marker_value}' "
            f"was echoed back in the response body (HTTP {resp['status']}). "
            f"Response snippet: {body_snippet[:300]!r}"
        )
    else:
        result["evidence"] = (
            f"Server returned HTTP {resp['status']} for TRACE but did not "
            f"echo request headers — method may be partially supported."
        )

    return result


async def _check_put(session: aiohttp.ClientSession, url: str, baseline_size: int):
    result = {
        "attempted": True,
        "status_code": None,
        "confirmed": False,
        "waf_false_positive": False,
        "evidence": None,
        "error": None,
    }

    test_path = "bravo6-test-file.txt"
    test_url = url.rstrip("/") + "/" + test_path
    test_body = b"bravo6-security-scan-test"

    resp, err = await _safe_request(
        session, "PUT", test_url,
        data=test_body,
        headers={"Content-Type": "text/plain"},
    )
    if err or resp is None:
        result["error"] = err
        return result

    result["status_code"] = resp["status"]
    body = resp["body"]

    if resp["status"] in (405, 403, 401):
        result["evidence"] = (
            f"PUT {test_path} returned HTTP {resp['status']} — "
            f"server correctly rejects PUT."
        )
        return result

    if resp["status"] in (200, 201, 204):
        # Before confirming, check for WAF reflection
        if _is_waf_reflection(baseline_size, body):
            result["waf_false_positive"] = True
            result["evidence"] = (
                f"PUT returned HTTP {resp['status']} but response body matches GET baseline "
                f"({len(body)} vs {baseline_size} bytes) — "
                f"WAF/CDN is serving cached page, not confirming file write."
            )
            return result

        result["confirmed"] = True
        result["evidence"] = (
            f"PUT {test_path} returned HTTP {resp['status']}, indicating the "
            f"server accepted an arbitrary file write at '{test_url}'."
        )

    return result


async def _check_generic_dangerous_method(
    session: aiohttp.ClientSession,
    url: str,
    method: str,
    baseline_size: int,
):
    result = {
        "attempted": True,
        "status_code": None,
        "confirmed": False,
        "waf_false_positive": False,
        "evidence": None,
        "error": None,
    }

    resp, err = await _safe_request(session, method, url)
    if err or resp is None:
        result["error"] = err
        return result

    result["status_code"] = resp["status"]
    body = resp["body"]

    if resp["status"] >= 400:
        result["evidence"] = (
            f"{method} request returned HTTP {resp['status']} (not allowed)."
        )
        return result

    # 200-level: check WAF reflection before confirming
    if _is_waf_reflection(baseline_size, body):
        result["waf_false_positive"] = True
        result["evidence"] = (
            f"{method} returned HTTP {resp['status']} but response body matches "
            f"GET baseline ({len(body)} vs {baseline_size} bytes) — "
            f"WAF/CDN false positive detected."
        )
        return result

    result["confirmed"] = True
    result["evidence"] = (
        f"{method} request returned HTTP {resp['status']} with a response "
        f"body different from the GET baseline — method appears genuinely accepted."
    )

    return result


# --------------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------------

async def run(url: str) -> dict:
    test_name = "http_methods"
    normalized_url = _normalize_url(url)

    if not normalized_url:
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "Invalid target URL",
            "description": "No URL or domain was provided.",
            "evidence": {"methods_allowed": [], "dangerous_methods_found": []},
            "remediation": "Provide a valid domain or URL to scan.",
        }

    methods_allowed = set()
    dangerous_methods_found = []
    notes = []
    waf_detected = None

    try:
        connector = aiohttp.TCPConnector(ssl=False, limit=10)
        async with aiohttp.ClientSession(
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            connector=connector,
        ) as session:

            # ── Step 0: GET baseline ──────────────────────────────────────
            # Fetch the page normally to get a size baseline for WAF detection
            baseline_resp, baseline_err = await _safe_request(session, "GET", normalized_url)
            baseline_size = len(baseline_resp["body"]) if baseline_resp else 0

            # Detect WAF from baseline response headers
            if baseline_resp:
                waf_detected = _detect_waf_from_headers(baseline_resp["headers"])
                if waf_detected:
                    notes.append(
                        f"WAF/CDN detected: {waf_detected}. "
                        f"Applying false positive filtering (baseline response size: {baseline_size} bytes)."
                    )

            # ── Step 1: OPTIONS ───────────────────────────────────────────
            options_methods, options_err = await _check_options(session, normalized_url)
            methods_allowed |= options_methods
            if options_err:
                notes.append(f"OPTIONS check: {options_err}")

            # ── Step 2: Probe each dangerous method ───────────────────────
            for method, meta in DANGEROUS_METHODS.items():
                if method == "TRACE":
                    detail = await _check_trace(session, normalized_url, baseline_size)
                elif method == "PUT":
                    detail = await _check_put(session, normalized_url, baseline_size)
                else:
                    detail = await _check_generic_dangerous_method(
                        session, normalized_url, method, baseline_size
                    )

                if detail.get("error"):
                    notes.append(f"{method} check: {detail['error']}")

                # Skip WAF false positives entirely
                if detail.get("waf_false_positive"):
                    notes.append(
                        f"{method}: WAF false positive filtered out. "
                        f"({detail.get('evidence', '')})"
                    )
                    continue

                allowed_via_options = method in methods_allowed
                allowed_via_probe = detail.get("confirmed") or (
                    detail.get("status_code") is not None
                    and detail["status_code"] < 400
                    and not detail.get("waf_false_positive")
                )

                if allowed_via_options or allowed_via_probe:
                    methods_allowed.add(method)
                    dangerous_methods_found.append(
                        {
                            "method": method,
                            "severity": meta["severity"],
                            "confirmed": bool(detail.get("confirmed")),
                            "status_code": detail.get("status_code"),
                            "evidence": detail.get("evidence") or "Method advertised via OPTIONS Allow header.",
                            "reason": meta["reason"],
                            "waf_false_positive": False,
                        }
                    )

    except Exception as e:
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "HTTP methods test failed to execute",
            "description": f"An unexpected error occurred while scanning '{normalized_url}'.",
            "evidence": {
                "methods_allowed": [],
                "dangerous_methods_found": [],
                "error": str(e),
            },
            "remediation": "Verify the target is reachable and retry the scan.",
        }

    sorted_methods_allowed = sorted(methods_allowed)
    evidence = {
        "methods_allowed": sorted_methods_allowed,
        "dangerous_methods_found": dangerous_methods_found,
        "waf_detected": waf_detected,
    }
    if notes:
        evidence["notes"] = notes

    # All probes failed
    total_probes = 1 + len(DANGEROUS_METHODS)
    if len(notes) >= total_probes and not methods_allowed:
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "Unable to reach target host",
            "description": (
                f"All requests to '{normalized_url}' failed. The host may be "
                "unreachable, DNS may not resolve, or the server may be blocking the scanner."
            ),
            "evidence": evidence,
            "remediation": "Verify the target host is reachable and retry the scan.",
        }

    remediation = (
        "Disable TRACE, PUT, DELETE, DEBUG, and CONNECT methods unless explicitly "
        "required. Configure the web server to only allow GET, POST, HEAD, and "
        "OPTIONS for standard endpoints."
    )

    if not dangerous_methods_found:
        note_about_waf = f" ({waf_detected} WAF filtering applied)" if waf_detected else ""
        return {
            "test_name": test_name,
            "status": "pass",
            "severity": "info",
            "title": f"No dangerous HTTP methods detected{note_about_waf}",
            "description": (
                f"The server at '{normalized_url}' did not appear to support any of the "
                f"tested dangerous HTTP methods ({', '.join(DANGEROUS_METHODS.keys())})."
                + (f" Note: {waf_detected} was detected and false positives were filtered." if waf_detected else "")
            ),
            "evidence": evidence,
            "remediation": "No action required.",
        }

    confirmed_findings = [f for f in dangerous_methods_found if f["confirmed"]]
    overall_severity = _highest_severity([f["severity"] for f in dangerous_methods_found])
    status = "fail" if confirmed_findings else "warning"
    method_names = [f["method"] for f in dangerous_methods_found]

    title = (
        f"Dangerous HTTP methods confirmed: {', '.join(f['method'] for f in confirmed_findings)}"
        if confirmed_findings
        else f"Potentially dangerous HTTP methods detected: {', '.join(method_names)}"
    )

    description = (
        f"The server at '{normalized_url}' accepts the following potentially dangerous "
        f"HTTP methods: {', '.join(method_names)}."
    )
    if waf_detected:
        description += (
            f" Note: {waf_detected} was detected and WAF false positives were filtered "
            f"— remaining findings passed body-size comparison validation."
        )

    return {
        "test_name": test_name,
        "status": status,
        "severity": overall_severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
    }


# --------------------------------------------------------------------------
# Manual test harness
# --------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))