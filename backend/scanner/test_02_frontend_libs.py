"""
test_js_libraries.py
Bravo6 Security Scanner Module

Identifies JavaScript libraries used on a target page (via <script src> filenames,
inline script version banners, and known CDN URL patterns) and checks detected
versions against a hardcoded database of known-vulnerable library versions.

Async, aiohttp-based, never raises — always returns the standard Bravo6 result dict.
"""

import asyncio
import re
from urllib.parse import urlparse, unquote

import aiohttp
from packaging.version import Version, InvalidVersion

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

USER_AGENT = "Bravo6-Scanner/1.0"
REQUEST_TIMEOUT_SECONDS = 10

VULNERABLE_LIBS = {
    "jquery": {
        "vulnerable_below": "3.5.0",
        "cve": "CVE-2020-11022, CVE-2020-11023",
        "description": "XSS via HTML passed to manipulation methods",
        "severity": "high",
    },
    "bootstrap": {
        "vulnerable_below": "4.3.1",
        "cve": "CVE-2019-8331",
        "description": "XSS in tooltip/popover data-template attribute",
        "severity": "medium",
    },
    "angular": {
        "vulnerable_below": "1.8.0",
        "cve": "CVE-2019-14863",
        "description": "XSS via ng-attr-* directives",
        "severity": "high",
    },
    "lodash": {
        "vulnerable_below": "4.17.21",
        "cve": "CVE-2021-23337",
        "description": "Command injection via template function",
        "severity": "high",
    },
    "moment": {
        "vulnerable_below": "2.29.4",
        "cve": "CVE-2022-24785",
        "description": "Path traversal vulnerability",
        "severity": "high",
    },
    "axios": {
        "vulnerable_below": "0.21.2",
        "cve": "CVE-2021-3749",
        "description": "ReDoS via crafted HTTP response",
        "severity": "medium",
    },
}

# Severity ranking used to pick the "worst" finding for the top-level severity field
_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


# --------------------------------------------------------------------------
# Library detection patterns
# --------------------------------------------------------------------------
# Each entry: canonical key -> (Display Name, [regex patterns with a 'version' group])
#
# Filename patterns match against the basename of a script src, e.g.
#   jquery-3.2.1.min.js, jquery.min.js?v=3.2.1, bootstrap.bundle.min.js
#
# Content patterns match against inline <script> text or (optionally) fetched
# external script bodies, looking for self-reported version banners, e.g.
#   "jQuery JavaScript Library v3.2.1"
#   "Bootstrap v4.3.1 (https://getbootstrap.com/)"
#   "angular.js@1.7.9"
#   "lodash.js 4.17.15"
#   "moment.js v2.24.0"
#   "axios v0.19.0"

_VERSION_RE = r"(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)"

FILENAME_PATTERNS = {
    "jquery": [
        re.compile(r"jquery[.\-]?(?:ui)?[.\-]?v?" + _VERSION_RE, re.IGNORECASE),
    ],
    "bootstrap": [
        re.compile(r"bootstrap[.\-]?v?" + _VERSION_RE, re.IGNORECASE),
    ],
    "angular": [
        re.compile(r"angular(?:\.min)?[.\-]?v?" + _VERSION_RE, re.IGNORECASE),
    ],
    "lodash": [
        re.compile(r"lodash[.\-]?v?" + _VERSION_RE, re.IGNORECASE),
    ],
    "moment": [
        re.compile(r"moment[.\-]?v?" + _VERSION_RE, re.IGNORECASE),
    ],
    "axios": [
        re.compile(r"axios[.\-]?v?" + _VERSION_RE, re.IGNORECASE),
    ],
}

CONTENT_PATTERNS = {
    "jquery": [
        re.compile(r"jQuery\s+JavaScript\s+Library\s+v?" + _VERSION_RE, re.IGNORECASE),
        re.compile(r"jquery\.fn\.jquery\s*=\s*[\"']" + _VERSION_RE + r"[\"']", re.IGNORECASE),
    ],
    "bootstrap": [
        re.compile(r"Bootstrap\s+v" + _VERSION_RE, re.IGNORECASE),
    ],
    "angular": [
        re.compile(r"angular(?:\.js)?[\s@\/]v?" + _VERSION_RE, re.IGNORECASE),
        re.compile(r"AngularJS\s+v?" + _VERSION_RE, re.IGNORECASE),
    ],
    "lodash": [
        re.compile(r"lodash(?:\.js)?\s+v?" + _VERSION_RE, re.IGNORECASE),
        re.compile(r"lodash\s*=\s*\{\s*VERSION\s*:\s*[\"']" + _VERSION_RE + r"[\"']", re.IGNORECASE),
    ],
    "moment": [
        re.compile(r"moment\.js\s+v?" + _VERSION_RE, re.IGNORECASE),
        re.compile(r"moment\.version\s*=\s*[\"']" + _VERSION_RE + r"[\"']", re.IGNORECASE),
    ],
    "axios": [
        re.compile(r"axios\s+v" + _VERSION_RE, re.IGNORECASE),
    ],
}

# Known CDN URL host/path patterns -> library key, with a version-capturing regex
# applied against the full URL.
# Known CDN URL host/path patterns -> library key, with a version-capturing regex
# applied against the full URL. Allows arbitrary path segments (e.g. an extra
# "/bootstrap/" or "/libs/jquery/" segment) between the CDN host marker and the
# version number, since CDN URL structures vary (e.g.
# stackpath.bootstrapcdn.com/bootstrap/4.1.0/js/bootstrap.min.js vs
# cdn.jsdelivr.net/npm/bootstrap@4.1.0/...).
CDN_PATTERNS = [
    ("jquery", re.compile(r"(?:ajax\.googleapis\.com/ajax/libs/jquery|cdnjs\.cloudflare\.com/ajax/libs/jquery|code\.jquery\.com/jquery)[^\s\"'>]*?" + _VERSION_RE, re.IGNORECASE)),
    ("bootstrap", re.compile(r"(?:stackpath\.bootstrapcdn\.com|maxcdn\.bootstrapcdn\.com|cdn\.jsdelivr\.net/npm/bootstrap|cdnjs\.cloudflare\.com/ajax/libs/(?:twitter-)?bootstrap)[^\s\"'>]*?" + _VERSION_RE, re.IGNORECASE)),
    ("angular", re.compile(r"(?:ajax\.googleapis\.com/ajax/libs/angularjs|cdnjs\.cloudflare\.com/ajax/libs/angular\.js)[^\s\"'>]*?" + _VERSION_RE, re.IGNORECASE)),
    ("lodash", re.compile(r"(?:cdnjs\.cloudflare\.com/ajax/libs/lodash\.js|cdn\.jsdelivr\.net/npm/lodash)[^\s\"'>]*?" + _VERSION_RE, re.IGNORECASE)),
    ("moment", re.compile(r"(?:cdnjs\.cloudflare\.com/ajax/libs/moment\.js|cdn\.jsdelivr\.net/npm/moment)[^\s\"'>]*?" + _VERSION_RE, re.IGNORECASE)),
    ("axios", re.compile(r"(?:cdnjs\.cloudflare\.com/ajax/libs/axios|cdn\.jsdelivr\.net/npm/axios)[^\s\"'>]*?" + _VERSION_RE, re.IGNORECASE)),
]

LIB_DISPLAY_NAMES = {
    "jquery": "jQuery",
    "bootstrap": "Bootstrap",
    "angular": "AngularJS",
    "lodash": "Lodash",
    "moment": "Moment.js",
    "axios": "Axios",
}

# Simple <script ...> tag extractor (avoids requiring a full HTML parser dependency)
_SCRIPT_TAG_RE = re.compile(
    r"<script\b([^>]*)>(.*?)</script\s*>",
    re.IGNORECASE | re.DOTALL,
)
_SRC_ATTR_RE = re.compile(r"""src\s*=\s*["']([^"']+)["']""", re.IGNORECASE)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url):
        url = "https://" + url
    return url


def _result(
    status: str,
    severity: str,
    title: str,
    description: str,
    evidence,
    libraries_detected: int = 0,
    vulnerable_count: int = 0,
    remediation: str = "Update all libraries to latest stable versions.",
) -> dict:
    return {
        "test_name": "js_library_audit",
        "status": status,
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "libraries_detected": libraries_detected,
        "vulnerable_count": vulnerable_count,
        "remediation": remediation,
    }


def _safe_version(raw: str):
    """Parse a version string defensively; return None if unparsable."""
    try:
        return Version(raw)
    except (InvalidVersion, TypeError):
        return None


def _extract_scripts(html: str):
    """Return list of (src_or_none, inline_content) tuples for every <script> tag."""
    scripts = []
    for match in _SCRIPT_TAG_RE.finditer(html or ""):
        attrs, content = match.group(1), match.group(2)
        src_match = _SRC_ATTR_RE.search(attrs)
        src = unquote(src_match.group(1)) if src_match else None
        scripts.append((src, content or ""))
    return scripts


def _detect_from_filename(src: str, findings: dict):
    basename = src.rsplit("/", 1)[-1]
    # strip query string from basename for filename matching, but keep full src for CDN matching
    basename_no_query = basename.split("?", 1)[0]
    query_string = basename.split("?", 1)[1] if "?" in basename else ""

    for lib_key, patterns in FILENAME_PATTERNS.items():
        matched = False
        for pattern in patterns:
            m = pattern.search(basename_no_query) or pattern.search(basename)
            if m:
                _record_finding(findings, lib_key, m.group(1), f"filename: {basename}")
                matched = True
                break

        # Fallback: library name appears in filename (e.g. jquery.min.js) but the
        # version is only present in a query-string param (e.g. ?ver=3.4.1 or ?v=3.4.1)
        if not matched and query_string and re.search(lib_key, basename_no_query, re.IGNORECASE):
            qm = re.search(r"(?:ver|v|version)=" + _VERSION_RE, query_string, re.IGNORECASE)
            if qm:
                _record_finding(findings, lib_key, qm.group(1), f"filename+query: {basename}")


def _detect_from_cdn(src: str, findings: dict):
    for lib_key, pattern in CDN_PATTERNS:
        m = pattern.search(src)
        if m:
            _record_finding(findings, lib_key, m.group(1), f"CDN URL: {src}")


def _detect_from_content(text: str, source_label: str, findings: dict):
    if not text:
        return
    # Only scan a reasonable prefix of large scripts to keep this fast/safe
    snippet = text[:20000]
    for lib_key, patterns in CONTENT_PATTERNS.items():
        for pattern in patterns:
            m = pattern.search(snippet)
            if m:
                _record_finding(findings, lib_key, m.group(1), f"script content ({source_label})")
                break


def _record_finding(findings: dict, lib_key: str, version_str: str, evidence_source: str):
    """
    Keep the most precise/parseable version per library. If we already have a
    finding for this library, only overwrite if the new version actually parses
    and the old one didn't, or this is genuinely a different version worth noting.
    """
    parsed = _safe_version(version_str)
    if lib_key not in findings:
        findings[lib_key] = {
            "version": version_str,
            "parsed": parsed,
            "source": evidence_source,
        }
        return

    existing = findings[lib_key]
    if existing["parsed"] is None and parsed is not None:
        findings[lib_key] = {
            "version": version_str,
            "parsed": parsed,
            "source": evidence_source,
        }


def _build_evidence_entry(lib_key: str, version_str: str, parsed_version):
    vuln_info = VULNERABLE_LIBS[lib_key]
    is_vulnerable = False
    if parsed_version is not None:
        threshold = _safe_version(vuln_info["vulnerable_below"])
        if threshold is not None:
            is_vulnerable = parsed_version < threshold

    return {
        "library": LIB_DISPLAY_NAMES.get(lib_key, lib_key),
        "version_detected": version_str,
        "vulnerable": is_vulnerable,
        "cve": vuln_info["cve"] if is_vulnerable else None,
        "severity": vuln_info["severity"] if is_vulnerable else "info",
    }


# --------------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------------

async def run(url: str) -> dict:
    """
    Bravo6 scanner module entry point.

    Fetches the target page, detects JavaScript libraries in use via filename,
    inline script content, and CDN URL patterns, then checks detected versions
    against the VULNERABLE_LIBS database.
    """
    try:
        target_url = _normalize_url(url)
        if not target_url:
            return _result(
                status="error",
                severity="info",
                title="JavaScript Library Audit",
                description="No URL was provided to scan.",
                evidence=[],
            )

        parsed_target = urlparse(target_url)
        if not parsed_target.scheme or not parsed_target.netloc:
            return _result(
                status="error",
                severity="info",
                title="JavaScript Library Audit",
                description=f"Could not parse a valid URL from input: {url!r}",
                evidence=[],
            )

        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
        headers = {"User-Agent": USER_AGENT}

        try:
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                try:
                    async with session.get(target_url, ssl=False, allow_redirects=True) as resp:
                        status_code = resp.status
                        try:
                            html = await resp.text(errors="ignore")
                        except Exception:
                            html = ""
                except asyncio.TimeoutError:
                    return _result(
                        status="error",
                        severity="info",
                        title="JavaScript Library Audit",
                        description=f"Request to {target_url} timed out after {REQUEST_TIMEOUT_SECONDS} seconds.",
                        evidence=[],
                    )
                except aiohttp.ClientConnectorError as e:
                    return _result(
                        status="error",
                        severity="info",
                        title="JavaScript Library Audit",
                        description=f"Could not connect to {target_url}: {e}",
                        evidence=[],
                    )
                except aiohttp.ClientError as e:
                    return _result(
                        status="error",
                        severity="info",
                        title="JavaScript Library Audit",
                        description=f"HTTP client error while fetching {target_url}: {e}",
                        evidence=[],
                    )

                if status_code >= 400:
                    return _result(
                        status="error",
                        severity="info",
                        title="JavaScript Library Audit",
                        description=f"Target returned HTTP {status_code}; could not analyze page content.",
                        evidence=[],
                    )

                if not html:
                    return _result(
                        status="error",
                        severity="info",
                        title="JavaScript Library Audit",
                        description="Target page returned no readable HTML content.",
                        evidence=[],
                    )

                # --- Parse scripts ---
                try:
                    scripts = _extract_scripts(html)
                except Exception:
                    scripts = []

                findings = {}  # lib_key -> {version, parsed, source}

                for src, inline_content in scripts:
                    try:
                        if src:
                            # Resolve relative URLs for clearer evidence / better CDN matching
                            full_src = src
                            if not re.match(r"^https?://", src, re.IGNORECASE):
                                try:
                                    from urllib.parse import urljoin
                                    full_src = urljoin(target_url, src)
                                except Exception:
                                    full_src = src
                            _detect_from_filename(full_src, findings)
                            _detect_from_cdn(full_src, findings)
                        if inline_content:
                            _detect_from_content(inline_content, "inline <script>", findings)
                    except Exception:
                        # Never let a single malformed script tag kill the whole scan
                        continue

                # Also scan the raw HTML for version banners that might appear
                # outside recognized <script> boundaries (rare, but cheap to check)
                try:
                    _detect_from_content(html, "page HTML", findings)
                except Exception:
                    pass

                libraries_detected = len(findings)

                if libraries_detected == 0:
                    return _result(
                        status="pass",
                        severity="info",
                        title="JavaScript Library Audit",
                        description="No recognizable JavaScript libraries with identifiable version strings were detected on the target page.",
                        evidence=[],
                        libraries_detected=0,
                        vulnerable_count=0,
                    )

                evidence_list = []
                vulnerable_count = 0
                worst_severity = "info"

                for lib_key, data in findings.items():
                    entry = _build_evidence_entry(lib_key, data["version"], data["parsed"])
                    evidence_list.append(entry)
                    if entry["vulnerable"]:
                        vulnerable_count += 1
                        if _SEVERITY_RANK.get(entry["severity"], 0) > _SEVERITY_RANK.get(worst_severity, 0):
                            worst_severity = entry["severity"]

                # Sort evidence: vulnerable findings first, then by severity rank desc
                evidence_list.sort(
                    key=lambda e: (not e["vulnerable"], -_SEVERITY_RANK.get(e["severity"], 0))
                )

                if vulnerable_count > 0:
                    status = "fail"
                    title = f"Vulnerable JavaScript Libraries Detected ({vulnerable_count})"
                    description = (
                        f"Detected {libraries_detected} JavaScript librar{'y' if libraries_detected == 1 else 'ies'} on the page; "
                        f"{vulnerable_count} of them are running versions with known publicly disclosed vulnerabilities (CVEs)."
                    )
                    severity = worst_severity
                else:
                    status = "pass"
                    title = "JavaScript Libraries Up to Date"
                    description = (
                        f"Detected {libraries_detected} JavaScript librar{'y' if libraries_detected == 1 else 'ies'} on the page; "
                        f"none matched known vulnerable versions in the current detection database."
                    )
                    severity = "info"

                return _result(
                    status=status,
                    severity=severity,
                    title=title,
                    description=description,
                    evidence=evidence_list,
                    libraries_detected=libraries_detected,
                    vulnerable_count=vulnerable_count,
                )

        except asyncio.TimeoutError:
            return _result(
                status="error",
                severity="info",
                title="JavaScript Library Audit",
                description=f"Scan timed out after {REQUEST_TIMEOUT_SECONDS} seconds.",
                evidence=[],
            )

    except Exception as e:
        # Absolute last-resort catch-all — the module must never crash the scanner
        return _result(
            status="error",
            severity="info",
            title="JavaScript Library Audit",
            description=f"Unexpected error during scan: {type(e).__name__}: {e}",
            evidence=[],
        )


# --------------------------------------------------------------------------
# Local manual test (not part of the module's public API)
# --------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    import sys

    test_url = sys.argv[1] if len(sys.argv) > 1 else "example.com"

    async def _main():
        result = await run(test_url)
        print(json.dumps(result, indent=2, default=str))

    asyncio.run(_main())