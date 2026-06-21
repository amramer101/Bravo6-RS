"""
Bravo6 Security Scanner
Module: test_http_methods.py

Discovers which HTTP methods a target web server supports and flags
dangerous ones (TRACE, PUT, DELETE, CONNECT, DEBUG, etc.).

Test methodology:
  1. Send OPTIONS request, inspect Allow / Access-Control-Allow-Methods headers.
  2. Send each dangerous method directly and observe the server's response.
  3. For TRACE, check whether the response echoes back our request headers
     (confirms Cross-Site Tracing / XST exposure).
  4. For PUT, attempt to write a harmless test resource and check whether
     the server accepts it (confirms arbitrary file upload risk).
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


def _normalize_url(url: str) -> str:
    """Ensure the URL has a scheme; default to https://."""
    url = (url or "").strip()
    if not url:
        return url
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"https://{url}"
    return url


def _highest_severity(severities):
    """Return the highest-ranked severity from a list, defaulting to 'info'."""
    if not severities:
        return "info"
    return max(severities, key=lambda s: SEVERITY_ORDER.get(s, 0))


async def _safe_request(session: aiohttp.ClientSession, method: str, url: str, **kwargs):
    """
    Perform an HTTP request, swallowing all exceptions.
    Returns (response_or_None, error_string_or_None).
    """
    try:
        resp = await session.request(method, url, **kwargs)
        return resp, None
    except asyncio.TimeoutError:
        return None, f"{method} request timed out after 10s"
    except aiohttp.ClientConnectorError as e:
        return None, f"{method} connection failed: {e}"
    except aiohttp.ClientError as e:
        return None, f"{method} client error: {e}"
    except Exception as e:  # noqa: BLE001 - never let the scanner crash
        return None, f"{method} unexpected error: {e}"


async def _check_options(session: aiohttp.ClientSession, url: str):
    """
    Send OPTIONS request and parse Allow / Access-Control-Allow-Methods headers.
    Returns (methods_set, error_string_or_None).
    """
    methods = set()
    resp, err = await _safe_request(session, "OPTIONS", url)
    if err:
        return methods, err

    try:
        async with resp:
            allow_header = resp.headers.get("Allow", "")
            acam_header = resp.headers.get("Access-Control-Allow-Methods", "")
            for header_value in (allow_header, acam_header):
                if header_value:
                    for m in header_value.split(","):
                        m = m.strip().upper()
                        if m:
                            methods.add(m)
    except Exception as e:  # noqa: BLE001
        return methods, f"Failed parsing OPTIONS response: {e}"

    return methods, None


async def _check_trace(session: aiohttp.ClientSession, url: str):
    """
    Send a TRACE request and check whether the response echoes our headers
    (confirms Cross-Site Tracing vulnerability).
    Returns dict: {attempted, status_code, confirmed, evidence, error}
    """
    result = {
        "attempted": True,
        "status_code": None,
        "confirmed": False,
        "evidence": None,
        "error": None,
    }

    marker_header = "X-Bravo6-Trace-Check"
    marker_value = f"bravo6-{uuid.uuid4().hex[:12]}"

    resp, err = await _safe_request(
        session, "TRACE", url, headers={marker_header: marker_value}
    )
    if err:
        result["error"] = err
        return result

    try:
        async with resp:
            result["status_code"] = resp.status
            if resp.status < 400:
                body = await resp.text(errors="ignore")
                # Truncate to avoid huge bodies; TRACE responses are normally small
                body_snippet = body[:2000]
                if marker_value in body_snippet or marker_header.lower() in body_snippet.lower():
                    result["confirmed"] = True
                    result["evidence"] = (
                        f"TRACE request with header '{marker_header}: {marker_value}' "
                        f"was echoed back in the response body (HTTP {resp.status}). "
                        f"Response snippet: {body_snippet[:500]!r}"
                    )
                else:
                    result["evidence"] = (
                        f"Server returned HTTP {resp.status} for TRACE but did not "
                        f"echo request headers in the response body."
                    )
            else:
                result["evidence"] = f"Server returned HTTP {resp.status} for TRACE (not allowed)."
    except Exception as e:  # noqa: BLE001
        result["error"] = f"Failed reading TRACE response: {e}"

    return result


async def _check_put(session: aiohttp.ClientSession, url: str):
    """
    Attempt to PUT a harmless test file and check whether the server accepts it.
    Returns dict: {attempted, status_code, confirmed, evidence, error}
    """
    result = {
        "attempted": True,
        "status_code": None,
        "confirmed": False,
        "evidence": None,
        "error": None,
    }

    test_path = "bravo6-test-file.txt"
    test_url = url.rstrip("/") + "/" + test_path
    test_body = b"bravo6-security-scan-test"

    resp, err = await _safe_request(
        session,
        "PUT",
        test_url,
        data=test_body,
        headers={"Content-Type": "text/plain"},
    )
    if err:
        result["error"] = err
        return result

    try:
        async with resp:
            result["status_code"] = resp.status
            if resp.status in (200, 201, 204):
                result["confirmed"] = True
                result["evidence"] = (
                    f"PUT {test_path} returned HTTP {resp.status}, indicating the "
                    f"server accepted an arbitrary file write at '{test_url}'."
                )
            elif resp.status in (405, 403, 401):
                result["evidence"] = (
                    f"PUT {test_path} returned HTTP {resp.status} (method not allowed / "
                    f"forbidden) — server correctly rejects PUT."
                )
            else:
                result["evidence"] = (
                    f"PUT {test_path} returned HTTP {resp.status} (inconclusive)."
                )
    except Exception as e:  # noqa: BLE001
        result["error"] = f"Failed reading PUT response: {e}"

    return result


async def _check_generic_dangerous_method(session: aiohttp.ClientSession, url: str, method: str):
    """
    Send a dangerous method directly (used for DELETE, CONNECT, DEBUG) and
    observe whether the server appears to accept it.
    Returns dict: {attempted, status_code, confirmed, evidence, error}
    """
    result = {
        "attempted": True,
        "status_code": None,
        "confirmed": False,
        "evidence": None,
        "error": None,
    }

    resp, err = await _safe_request(session, method, url)
    if err:
        result["error"] = err
        return result

    try:
        async with resp:
            result["status_code"] = resp.status
            if resp.status < 400:
                result["confirmed"] = True
                result["evidence"] = (
                    f"{method} request returned HTTP {resp.status}, suggesting the "
                    f"method is accepted by the server."
                )
            else:
                result["evidence"] = (
                    f"{method} request returned HTTP {resp.status} "
                    f"(likely not allowed)."
                )
    except Exception as e:  # noqa: BLE001
        result["error"] = f"Failed reading {method} response: {e}"

    return result


async def run(url: str) -> dict:
    """
    Discover supported HTTP methods on the target and flag dangerous ones.

    Returns a result dict matching the Bravo6 scanner contract.
    """
    test_name = "http_methods"
    normalized_url = _normalize_url(url)

    if not normalized_url:
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "Invalid target URL",
            "description": "No URL or domain was provided to the HTTP methods test.",
            "evidence": {"methods_allowed": [], "dangerous_methods_found": []},
            "remediation": "Provide a valid domain or URL to scan.",
        }

    methods_allowed = set()
    dangerous_methods_found = []
    notes = []

    try:
        connector = aiohttp.TCPConnector(ssl=False, limit=10)
        async with aiohttp.ClientSession(
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            connector=connector,
        ) as session:

            # Step 1 & 2: OPTIONS request, check Allow / Access-Control-Allow-Methods
            options_methods, options_err = await _check_options(session, normalized_url)
            methods_allowed |= options_methods
            if options_err:
                notes.append(f"OPTIONS check: {options_err}")

            # Step 3: Try each dangerous method directly
            for method, meta in DANGEROUS_METHODS.items():
                if method == "TRACE":
                    detail = await _check_trace(session, normalized_url)
                elif method == "PUT":
                    detail = await _check_put(session, normalized_url)
                else:
                    detail = await _check_generic_dangerous_method(
                        session, normalized_url, method
                    )

                if detail.get("error"):
                    notes.append(f"{method} check: {detail['error']}")

                # Method is considered "allowed" if OPTIONS advertised it,
                # or if the direct probe got a non-error status / confirmed result.
                allowed_via_options = method in methods_allowed
                allowed_via_probe = detail.get("confirmed") or (
                    detail.get("status_code") is not None and detail["status_code"] < 400
                )

                if allowed_via_options or allowed_via_probe:
                    methods_allowed.add(method)
                    dangerous_methods_found.append(
                        {
                            "method": method,
                            "severity": meta["severity"],
                            "confirmed": bool(detail.get("confirmed")),
                            "status_code": detail.get("status_code"),
                            "evidence": detail.get("evidence")
                            or f"Method advertised via OPTIONS Allow header.",
                            "reason": meta["reason"],
                        }
                    )

    except Exception as e:  # noqa: BLE001 - top-level safety net
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
    }
    if notes:
        evidence["notes"] = notes

    # If every single probe failed (e.g. unreachable host, DNS failure), this
    # is an execution error, not a clean "pass" — we never actually tested anything.
    total_probes = 1 + len(DANGEROUS_METHODS)  # OPTIONS + each dangerous method
    if len(notes) >= total_probes and not methods_allowed:
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "Unable to reach target host",
            "description": (
                f"All requests to '{normalized_url}' failed, so HTTP methods could "
                f"not be determined. The host may be unreachable, DNS may not resolve, "
                f"or the server may be blocking the scanner."
            ),
            "evidence": evidence,
            "remediation": "Verify the target host is reachable and retry the scan.",
        }

    remediation = (
        "Disable TRACE, PUT, DELETE, DEBUG, and CONNECT methods unless explicitly "
        "required. Configure the web server to only allow GET, POST, HEAD, and "
        "OPTIONS for standard endpoints, and restrict any required state-changing "
        "methods behind authentication and authorization."
    )

    if not dangerous_methods_found:
        return {
            "test_name": test_name,
            "status": "pass",
            "severity": "info",
            "title": "No dangerous HTTP methods detected",
            "description": (
                f"The server at '{normalized_url}' did not appear to support any of the "
                f"tested dangerous HTTP methods ({', '.join(DANGEROUS_METHODS.keys())})."
            ),
            "evidence": evidence,
            "remediation": "No action required. Continue to periodically verify allowed HTTP methods.",
        }

    confirmed_findings = [f for f in dangerous_methods_found if f["confirmed"]]
    unconfirmed_findings = [f for f in dangerous_methods_found if not f["confirmed"]]

    overall_severity = _highest_severity([f["severity"] for f in dangerous_methods_found])
    status = "fail" if confirmed_findings else "warning"

    method_names = [f["method"] for f in dangerous_methods_found]
    if confirmed_findings:
        confirmed_names = [f["method"] for f in confirmed_findings]
        title = f"Dangerous HTTP methods confirmed: {', '.join(confirmed_names)}"
    else:
        title = f"Potentially dangerous HTTP methods detected: {', '.join(method_names)}"

    description_parts = [
        f"The server at '{normalized_url}' advertises or accepts the following "
        f"potentially dangerous HTTP methods: {', '.join(method_names)}."
    ]
    if confirmed_findings:
        description_parts.append(
            "The following were actively confirmed via direct testing: "
            + ", ".join(f"{f['method']} (HTTP {f['status_code']})" for f in confirmed_findings)
            + "."
        )
    if unconfirmed_findings:
        description_parts.append(
            "The following were advertised by the server but not actively confirmed: "
            + ", ".join(f["method"] for f in unconfirmed_findings)
            + "."
        )

    return {
        "test_name": test_name,
        "status": status,
        "severity": overall_severity,
        "title": title,
        "description": " ".join(description_parts),
        "evidence": evidence,
        "remediation": remediation,
    }


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))