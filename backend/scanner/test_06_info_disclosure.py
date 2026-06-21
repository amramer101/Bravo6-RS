"""
Bravo6 Security Scanner
Module: test_info_disclosure.py

Detects unnecessarily exposed server/technology information via:
  1. Response headers (Server, X-Powered-By, X-AspNet-Version, X-Generator, Via)
  2. HTML source (comments, meta generator tags, hidden form fields)
  3. Custom error page detection (404 stack traces / framework leaks)
  4. Directory listing exposure (/images/, /assets/, /static/)

Single GET to the target root drives checks 1 & 2. Checks 3 & 4 issue
their own bounded follow-up requests. All network calls share one
aiohttp session, a 10s per-request timeout, and a fixed User-Agent.
"""

import asyncio
import re
from urllib.parse import urljoin, urlparse

import aiohttp

USER_AGENT = "Bravo6-Scanner/1.0"
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=10)
VERSION_PATTERN = re.compile(r"\d+\.\d+\.?\d*")

# Severity ranking used to roll up the single worst finding into the
# top-level "severity"/"status" fields.
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

HEADER_404_PATH = "/bravo6-test-404-xyz"
DIRECTORY_PATHS = ("/images/", "/assets/", "/static/")

# Headers that leak product/version info, mapped to base severity.
INFO_HEADERS = {
    "server": "high",
    "x-powered-by": "high",
    "x-aspnet-version": "medium",
    "x-aspnetmvc-version": "medium",
    "x-generator": "medium",
}

HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL | re.IGNORECASE)
META_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.IGNORECASE,
)
HIDDEN_INPUT_RE = re.compile(
    r'<input[^>]+type=["\']hidden["\'][^>]*>', re.IGNORECASE
)

COMMENT_FLAG_KEYWORDS = (
    "todo",
    "fixme",
    "internal",
    "password",
    "secret",
    "api_key",
    "apikey",
    "debug",
    "staging",
    "localhost",
)

# Internal/private IP prefixes to flag when seen in a Via header.
PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.0\.0\.1)\b"
)

INTERNAL_PATH_RE = re.compile(
    r"(?:[A-Za-z]:\\\\?(?:[\w.\-]+\\\\?)+|/(?:home|var|usr|srv|opt)/[\w./\-]+)"
)

STACK_TRACE_MARKERS = (
    "traceback (most recent call last)",
    "stack trace",
    "fatal error",
    "warning: include",
    "warning: require",
    "uncaught exception",
    "unhandled exception",
    "at System.",
    "at java.",
    "django.core.exceptions",
    "django.db.utils",
    "sqlstate[",
    "mysql_fetch",
    "ora-00",
    "pdoexception",
    "microsoft ole db provider",
    "you have an error in your sql syntax",
    "internal server error",
    "500 internal server error",
)

DB_ERROR_MARKERS = (
    "sqlstate[",
    "mysql_fetch",
    "ora-00",
    "pdoexception",
    "you have an error in your sql syntax",
    "microsoft ole db provider",
    "psql:",
    "pg_query",
)

FRAMEWORK_VERSION_MARKERS = (
    "django",
    "flask",
    "express",
    "laravel",
    "rails",
    "asp.net",
    "spring",
    "symfony",
)


def _normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "https://" + url
    return url


def _rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity, 0)


async def _safe_get(session: aiohttp.ClientSession, url: str, **kwargs):
    """
    Perform a GET request, swallowing all network-level exceptions.
    Returns (response_text, headers_dict, status_code) or (None, None, None)
    on any failure (timeout, connection error, decode error, etc).
    """
    try:
        async with session.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            ssl=False,
            **kwargs,
        ) as resp:
            try:
                text = await resp.text(errors="replace")
            except Exception:
                text = ""
            return text, dict(resp.headers), resp.status
    except asyncio.TimeoutError:
        return None, None, None
    except aiohttp.ClientError:
        return None, None, None
    except Exception:
        return None, None, None


def _check_headers(headers: dict) -> list:
    findings = []
    if not headers:
        return findings

    lower_headers = {k.lower(): v for k, v in headers.items()}

    for header_name, base_severity in INFO_HEADERS.items():
        value = lower_headers.get(header_name)
        if not value:
            continue
        has_version = bool(VERSION_PATTERN.search(value))
        severity = base_severity if has_version else (
            "medium" if base_severity == "high" else "low"
        )
        risk = "Version exposed" if has_version else "Technology disclosed"
        findings.append(
            {
                "location": f"{header_name.title() if header_name != 'x-aspnet-version' else 'X-AspNet-Version'} header",
                "value": value,
                "risk": risk,
                "_severity": severity,
            }
        )

    via_value = lower_headers.get("via")
    if via_value and PRIVATE_IP_RE.search(via_value):
        findings.append(
            {
                "location": "Via header",
                "value": via_value,
                "risk": "Internal IP address exposed",
                "_severity": "medium",
            }
        )

    return findings


def _check_html(html: str) -> list:
    findings = []
    if not html:
        return findings

    # HTML comments
    for match in HTML_COMMENT_RE.finditer(html):
        comment = match.group(1).strip()
        if not comment:
            continue
        lowered = comment.lower()

        has_version = bool(VERSION_PATTERN.search(comment))
        has_keyword = any(kw in lowered for kw in COMMENT_FLAG_KEYWORDS)
        has_internal_path = bool(INTERNAL_PATH_RE.search(comment))

        if not (has_version or has_keyword or has_internal_path):
            continue

        snippet = comment if len(comment) <= 200 else comment[:200] + "..."

        if has_internal_path:
            risk = "Internal file path exposed in comment"
            severity = "medium"
        elif has_keyword:
            risk = "Developer note / sensitive keyword exposed in comment"
            severity = "medium"
        else:
            risk = "Version information exposed in comment"
            severity = "low"

        findings.append(
            {
                "location": "HTML comment",
                "value": f"<!--{snippet}-->",
                "risk": risk,
                "_severity": severity,
            }
        )

    # Meta generator tag
    meta_match = META_GENERATOR_RE.search(html)
    if meta_match:
        content = meta_match.group(1).strip()
        has_version = bool(VERSION_PATTERN.search(content))
        findings.append(
            {
                "location": "Meta generator tag",
                "value": f'<meta name="generator" content="{content}">',
                "risk": "CMS/framework version exposed"
                if has_version
                else "CMS/framework disclosed",
                "_severity": "medium" if has_version else "low",
            }
        )

    # Hidden form fields — flag ones whose name/value look internal,
    # not every hidden input (CSRF tokens etc. are normal and noisy).
    for match in HIDDEN_INPUT_RE.finditer(html):
        tag = match.group(0)
        tag_lower = tag.lower()
        if any(kw in tag_lower for kw in COMMENT_FLAG_KEYWORDS) or INTERNAL_PATH_RE.search(tag):
            snippet = tag if len(tag) <= 200 else tag[:200] + "..."
            findings.append(
                {
                    "location": "Hidden form field",
                    "value": snippet,
                    "risk": "Potentially sensitive internal data in hidden field",
                    "_severity": "medium",
                }
            )

    return findings


def _check_error_page(text: str, status: int) -> list:
    findings = []
    if text is None:
        return findings

    lowered = text.lower()

    db_hit = next((m for m in DB_ERROR_MARKERS if m in lowered), None)
    if db_hit:
        findings.append(
            {
                "location": f"404 error page (HTTP {status})",
                "value": f"Database error pattern detected: '{db_hit}'",
                "risk": "Database error details exposed on error page",
                "_severity": "critical",
            }
        )

    path_match = INTERNAL_PATH_RE.search(text)
    if path_match:
        snippet = path_match.group(0)
        findings.append(
            {
                "location": f"404 error page (HTTP {status})",
                "value": snippet,
                "risk": "Internal file path exposed on error page",
                "_severity": "critical",
            }
        )

    trace_hit = next((m for m in STACK_TRACE_MARKERS if m in lowered), None)
    if trace_hit and not db_hit:
        findings.append(
            {
                "location": f"404 error page (HTTP {status})",
                "value": f"Error pattern detected: '{trace_hit}'",
                "risk": "Stack trace / verbose error exposed on error page",
                "_severity": "critical",
            }
        )

    fw_hit = next((m for m in FRAMEWORK_VERSION_MARKERS if m in lowered), None)
    if fw_hit and VERSION_PATTERN.search(text) and not (db_hit or trace_hit):
        findings.append(
            {
                "location": f"404 error page (HTTP {status})",
                "value": f"Framework reference detected: '{fw_hit}'",
                "risk": "Framework/version referenced on error page",
                "_severity": "medium",
            }
        )

    return findings


def _check_directory_listing(text: str, path: str) -> list:
    findings = []
    if not text:
        return findings

    lowered = text.lower()
    if "index of /" in lowered or (
        "<title>index of" in lowered
    ):
        snippet = text.strip()[:200]
        findings.append(
            {
                "location": f"Directory listing ({path})",
                "value": snippet,
                "risk": "Directory listing enabled, exposing file structure",
                "_severity": "high",
            }
        )

    return findings


async def run(url: str) -> dict:
    """
    Scan a target for unnecessarily exposed server/technology information.

    Checks performed:
      1. Response headers for version/technology disclosure
      2. HTML comments, meta generator tags, hidden form fields
      3. Custom vs. verbose 404 error page behavior
      4. Directory listing exposure on common static paths

    Never raises — all failures are captured and reported as a
    status="error" result instead.
    """
    test_name = "information_disclosure"

    try:
        target_url = _normalize_url(url)
        parsed = urlparse(target_url)
        if not parsed.netloc:
            return {
                "test_name": test_name,
                "status": "error",
                "severity": "info",
                "title": "Information Disclosure Scan",
                "description": f"Could not parse a valid target from input: '{url}'",
                "evidence": [],
                "remediation": "Provide a valid domain or URL (e.g. example.com).",
            }

        base_url = f"{parsed.scheme}://{parsed.netloc}"

        all_findings = []
        request_errors = []

        connector = aiohttp.TCPConnector(ssl=False, limit=10)
        async with aiohttp.ClientSession(
            headers={"User-Agent": USER_AGENT}, connector=connector
        ) as session:

            # --- 1 & 2: root page — headers + HTML ---
            root_text, root_headers, root_status = await _safe_get(session, base_url)
            if root_headers is None:
                request_errors.append("root page")
            else:
                all_findings.extend(_check_headers(root_headers))
                all_findings.extend(_check_html(root_text or ""))

            # --- 3: custom 404 / error page detection ---
            error_url = urljoin(base_url, HEADER_404_PATH)
            error_text, error_headers, error_status = await _safe_get(session, error_url)
            if error_headers is None:
                request_errors.append("404 probe")
            else:
                all_findings.extend(
                    _check_error_page(error_text or "", error_status or 0)
                )

            # --- 4: directory listing checks ---
            dir_tasks = [
                _safe_get(session, urljoin(base_url, p)) for p in DIRECTORY_PATHS
            ]
            dir_results = await asyncio.gather(*dir_tasks, return_exceptions=False)
            for path, (dtext, dheaders, dstatus) in zip(DIRECTORY_PATHS, dir_results):
                if dheaders is None:
                    continue
                if dstatus and 200 <= dstatus < 300:
                    all_findings.extend(_check_directory_listing(dtext or "", path))

        # If literally every request failed, report as error/connection issue.
        if root_headers is None and error_headers is None and all(
            r[1] is None for r in dir_results
        ):
            return {
                "test_name": test_name,
                "status": "error",
                "severity": "info",
                "title": "Information Disclosure Scan",
                "description": (
                    f"Unable to connect to {base_url}. The host may be unreachable, "
                    "blocking the scanner, or the timeout (10s) was exceeded."
                ),
                "evidence": [],
                "remediation": "Verify the target is reachable and not blocking automated requests.",
            }

        # --- Build final result ---
        if not all_findings:
            return {
                "test_name": test_name,
                "status": "pass",
                "severity": "info",
                "title": "Information Disclosure Scan",
                "description": (
                    "No unnecessary server, technology, or error-page information "
                    "disclosure was detected for the checks performed."
                ),
                "evidence": [],
                "remediation": "No action required. Continue periodic re-scanning as the stack evolves.",
            }

        worst_severity = max(
            (f["_severity"] for f in all_findings), key=_rank
        )
        status = "fail" if _rank(worst_severity) >= _rank("medium") else "warning"

        evidence = [
            {"location": f["location"], "value": f["value"], "risk": f["risk"]}
            for f in all_findings
        ]

        finding_count = len(evidence)
        description = (
            f"Detected {finding_count} information disclosure issue"
            f"{'s' if finding_count != 1 else ''} across response headers, "
            "page content, and/or error handling. Highest severity: "
            f"{worst_severity}."
        )
        if request_errors:
            description += (
                f" (Note: {', '.join(request_errors)} request(s) failed and "
                "were skipped.)"
            )

        return {
            "test_name": test_name,
            "status": status,
            "severity": worst_severity,
            "title": "Information Disclosure Scan",
            "description": description,
            "evidence": evidence,
            "remediation": (
                "Remove version information from all HTTP headers (Server, "
                "X-Powered-By, X-AspNet-Version, X-Generator). Strip developer "
                "comments, internal paths, and CMS generator tags from production "
                "HTML. Configure custom, generic error pages for 4xx/5xx responses "
                "that do not leak stack traces, file paths, or framework details. "
                "Disable directory listing on web-accessible static directories."
            ),
        }

    except Exception as exc:  # absolute last-resort safety net
        return {
            "test_name": "information_disclosure",
            "status": "error",
            "severity": "info",
            "title": "Information Disclosure Scan",
            "description": f"Scan failed due to an unexpected error: {type(exc).__name__}: {exc}",
            "evidence": [],
            "remediation": "Re-run the scan. If the issue persists, check scanner logs for details.",
        }


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))