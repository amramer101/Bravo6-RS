"""
test_secrets.py — Bravo6 Security Scanner Module

Fetches a target page, discovers linked JavaScript files, downloads them,
and scans the combined JS content for hardcoded secrets / sensitive data
using known credential patterns plus a Shannon-entropy heuristic.

Author: Bravo6 Scanner Suite
"""

import asyncio
import math
import re
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

USER_AGENT = "Bravo6-Scanner/1.0"
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=10)
MAX_JS_FILES = 10
MAX_JS_FILE_SIZE = 500 * 1024  # 500 KB

# --------------------------------------------------------------------------
# Secret detection patterns
# --------------------------------------------------------------------------
# Each entry: (label, compiled_regex, severity, group_index_for_value)
# group_index_for_value: which regex group holds the actual secret value
# to preview (0 = whole match).

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r'AKIA[0-9A-Z]{16}'), "critical", 0),
    ("AWS Secret Key", re.compile(r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']'), "critical", 1),
    ("Google API Key", re.compile(r'AIza[0-9A-Za-z\-_]{35}'), "high", 0),
    ("Firebase Key", re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'), "high", 0),
    ("Private Key", re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'), "critical", 0),
    ("DB Connection String", re.compile(r'(?i)(mongodb|mysql|postgresql|redis):\/\/[^\s"\'<>]+'), "high", 0),
    ("Generic Secret", re.compile(r'(?i)(secret|password|passwd|api_key|apikey|token|auth)[\s]*[=:]["\'`]([^\s"\'`]{8,})'), "high", 2),
    ("GitHub Token", re.compile(r'ghp_[A-Za-z0-9]{36}'), "high", 0),
    ("Slack Token", re.compile(r'xox[baprs]-([0-9a-zA-Z]{10,48})'), "high", 0),
    ("JWT Token", re.compile(r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'), "high", 0),
    ("Stripe Live Key", re.compile(r'(?:r|s)k_live_[0-9a-zA-Z]{24}'), "critical", 0),
]

# Words that, when found near a high-entropy string, suggest it's a secret.
ENTROPY_CONTEXT_WORDS = re.compile(r'(?i)(key|token|secret|auth|credential|passwd|password)')
ENTROPY_CANDIDATE = re.compile(r'["\'`]([A-Za-z0-9+/_\-=]{20,})["\'`]')
ENTROPY_THRESHOLD = 4.5


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    """Ensure the URL has a scheme; default to https://."""
    url = (url or "").strip()
    if not url:
        return url
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
    return url


def _truncate(value: str, length: int = 20) -> str:
    value = value or ""
    if len(value) > length:
        return value[:length] + "..."
    return value


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy (bits/char) of a string."""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def _line_number_for_offset(text: str, offset: int) -> int:
    """Given a character offset into text, return the 1-indexed line number."""
    return text.count("\n", 0, offset) + 1


async def _fetch_text(session: aiohttp.ClientSession, url: str, max_bytes: int = None):
    """
    Fetch a URL and return (text, status, error). Never raises.
    If max_bytes is set, aborts the read early if the body exceeds it.
    """
    try:
        async with session.get(url, timeout=REQUEST_TIMEOUT, ssl=False) as resp:
            status = resp.status
            if max_bytes is not None:
                content_length = resp.headers.get("Content-Length")
                if content_length and content_length.isdigit():
                    if int(content_length) > max_bytes:
                        return None, status, f"Skipped: declared size exceeds {max_bytes} bytes"

                chunks = []
                total = 0
                async for chunk in resp.content.iter_chunked(8192):
                    total += len(chunk)
                    if total > max_bytes:
                        return None, status, f"Skipped: body exceeds {max_bytes} bytes"
                    chunks.append(chunk)
                raw = b"".join(chunks)
            else:
                raw = await resp.read()

            try:
                text = raw.decode("utf-8", errors="replace")
            except Exception:
                text = raw.decode("latin-1", errors="replace")

            return text, status, None
    except asyncio.TimeoutError:
        return None, None, "Request timed out"
    except aiohttp.ClientError as e:
        return None, None, f"Client error: {e}"
    except Exception as e:
        return None, None, f"Unexpected error: {e}"


def _extract_script_urls(html: str, base_url: str) -> list:
    """Parse HTML and return absolute URLs of all <script src="..."> tags."""
    urls = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("script"):
            src = tag.get("src")
            if not src:
                continue
            src = src.strip()
            if not src:
                continue
            try:
                absolute = urljoin(base_url, src)
                parsed = urlparse(absolute)
                if parsed.scheme in ("http", "https"):
                    urls.append(absolute)
            except Exception:
                continue
    except Exception:
        # Malformed HTML — bail out with whatever we found (likely nothing)
        pass

    # Dedupe, preserve order
    seen = set()
    deduped = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped


def _scan_content_for_secrets(filename: str, content: str) -> list:
    """Run all regex patterns + entropy check against JS content. Returns evidence list."""
    findings = []

    for label, pattern, severity, group_idx in SECRET_PATTERNS:
        try:
            for match in pattern.finditer(content):
                try:
                    value = match.group(group_idx) if group_idx else match.group(0)
                except (IndexError, AttributeError):
                    value = match.group(0)
                line_no = _line_number_for_offset(content, match.start())
                findings.append({
                    "type": label,
                    "file": filename,
                    "line": line_no,
                    "preview": _truncate(value, 20),
                    "severity": severity,
                })
        except Exception:
            # A single bad pattern/match should never kill the whole scan
            continue

    # Entropy heuristic: look at quoted strings near suspicious keywords
    try:
        for match in ENTROPY_CANDIDATE.finditer(content):
            candidate = match.group(1)
            if len(candidate) < 20:
                continue
            entropy = _shannon_entropy(candidate)
            if entropy <= ENTROPY_THRESHOLD:
                continue

            window_start = max(0, match.start() - 40)
            context_window = content[window_start:match.start()]
            if ENTROPY_CONTEXT_WORDS.search(context_window):
                line_no = _line_number_for_offset(content, match.start())
                findings.append({
                    "type": "Potential Secret (High Entropy)",
                    "file": filename,
                    "line": line_no,
                    "preview": _truncate(candidate, 20),
                    "severity": "high",
                })
    except Exception:
        pass

    return findings


# --------------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------------

async def run(url: str) -> dict:
    """
    Scan a target site's linked JavaScript files for hardcoded secrets.

    Returns a dict in the standard Bravo6 module result format.
    """
    test_name = "secrets_detection"

    try:
        target_url = _normalize_url(url)
        if not target_url:
            return {
                "test_name": test_name,
                "status": "error",
                "severity": "info",
                "title": "Invalid Target",
                "description": "No URL was provided to scan.",
                "evidence": [],
                "remediation": "Provide a valid domain or URL.",
                "js_files_scanned": 0,
                "secrets_found": 0,
            }

        headers = {"User-Agent": USER_AGENT}
        connector = aiohttp.TCPConnector(ssl=False)

        async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
            # Step 1: Fetch target HTML
            html, status, err = await _fetch_text(session, target_url)
            if err or html is None:
                return {
                    "test_name": test_name,
                    "status": "error",
                    "severity": "info",
                    "title": "Could Not Fetch Target",
                    "description": f"Failed to retrieve the target page: {err or 'unknown error'}",
                    "evidence": [],
                    "remediation": "Verify the URL is reachable and try again.",
                    "js_files_scanned": 0,
                    "secrets_found": 0,
                }

            # Step 2: Parse HTML, find <script src="...">
            script_urls = _extract_script_urls(html, target_url)

            if not script_urls:
                return {
                    "test_name": test_name,
                    "status": "pass",
                    "severity": "info",
                    "title": "No Secrets Found",
                    "description": "No linked JavaScript files were found on the target page.",
                    "evidence": [],
                    "remediation": "No action needed.",
                    "js_files_scanned": 0,
                    "secrets_found": 0,
                }

            script_urls = script_urls[:MAX_JS_FILES]

            # Step 3: Download each JS file concurrently (bounded)
            async def fetch_one(js_url):
                content, st, ferr = await _fetch_text(session, js_url, max_bytes=MAX_JS_FILE_SIZE)
                return js_url, content, ferr

            results = await asyncio.gather(
                *[fetch_one(u) for u in script_urls],
                return_exceptions=True
            )

            all_evidence = []
            files_scanned = 0

            for result in results:
                if isinstance(result, Exception):
                    continue
                js_url, content, ferr = result
                if content is None:
                    # Skipped (too large) or failed to fetch — not a crash, just skip
                    continue

                files_scanned += 1
                filename = urlparse(js_url).path.rsplit("/", 1)[-1] or js_url
                file_findings = _scan_content_for_secrets(filename, content)
                all_evidence.extend(file_findings)

            # Step 4: Aggregate results
            secrets_found = len(all_evidence)
            has_critical = any(f["severity"] == "critical" for f in all_evidence)
            has_high = any(f["severity"] == "high" for f in all_evidence)

            if secrets_found > 0:
                status_val = "fail"
                overall_severity = "critical" if has_critical else ("high" if has_high else "info")
                title = "Hardcoded Secrets Detected"
                description = (
                    f"Scanned {files_scanned} JavaScript file(s) and found {secrets_found} "
                    f"potential hardcoded secret(s) or sensitive credential(s) exposed in client-side code."
                )
            else:
                status_val = "pass"
                overall_severity = "info"
                title = "No Secrets Found"
                description = (
                    f"Scanned {files_scanned} JavaScript file(s) and found no hardcoded secrets "
                    f"matching known credential patterns."
                )

            # Clean evidence to match the spec's external shape (type/file/preview),
            # while keeping line number too since it's genuinely useful for triage.
            clean_evidence = [
                {
                    "type": f["type"],
                    "file": f["file"],
                    "line": f["line"],
                    "preview": f["preview"],
                }
                for f in all_evidence
            ]

            return {
                "test_name": test_name,
                "status": status_val,
                "severity": overall_severity,
                "title": title,
                "description": description,
                "evidence": clean_evidence,
                "remediation": (
                    "Move all secrets to environment variables. Use Azure Key Vault or "
                    "AWS Secrets Manager. Rotate all exposed credentials immediately."
                ),
                "js_files_scanned": files_scanned,
                "secrets_found": secrets_found,
            }

    except Exception as e:
        # Absolute last-resort catch-all — the module must never crash.
        return {
            "test_name": "secrets_detection",
            "status": "error",
            "severity": "info",
            "title": "Scan Error",
            "description": f"An unexpected error occurred during the scan: {e}",
            "evidence": [],
            "remediation": "Review scanner logs and retry the scan.",
            "js_files_scanned": 0,
            "secrets_found": 0,
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