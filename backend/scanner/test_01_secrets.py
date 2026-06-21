"""
test_secrets.py — Bravo6 Security Scanner Module: Client-Side Secrets Hunter

Fetches a target page, scans every inline <script> block AND every linked
external .js file for hardcoded secrets / sensitive credentials, using a
combination of known credential-format patterns (OpenAI, Anthropic, Stripe,
AWS, Google, Firebase, GitHub, Slack, SendGrid, JWTs, DB connection strings,
private keys, Bearer tokens, generic key=value assignments) plus a
Shannon-entropy heuristic for unrecognized high-entropy strings.

Built-in false-positive filtering skips obvious placeholders/test values
("sk_test_...", "YOUR_API_KEY", "demo", "fake", etc.) and assigns a
confidence level (high / medium / low) to every finding so triage can be
prioritized.

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
PER_REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=8)
TOTAL_BUDGET_SECONDS = 10  # hard cap for the whole test, enforced via wait_for
MAX_JS_FILES = 12
MAX_JS_FILE_SIZE = 500 * 1024  # 500 KB
MAX_INLINE_SCRIPTS = 25

# --------------------------------------------------------------------------
# False-positive / placeholder filtering
# --------------------------------------------------------------------------

_PLACEHOLDER_MARKERS = (
    "test", "demo", "fake", "example", "sample", "placeholder", "dummy",
    "changeme", "change_me", "your_", "youkey", "insert_", "redacted",
    "xxxxxxxx", "00000000", "0000000000", "1234567890", "abcdefgh",
    "<key>", "<token>", "<secret>", "{api_key}", "${", "{{", "process.env",
    "lorem", "foobar", "asdf",
)


def _looks_like_placeholder(value: str) -> bool:
    """Heuristic check for obvious example/placeholder values."""
    if not value:
        return True
    low = value.lower()
    for marker in _PLACEHOLDER_MARKERS:
        if marker in low:
            return True
    # Very low character diversity (e.g. "aaaaaaaaaaaaaaaa", "1111111111")
    if len(low) >= 8 and len(set(low)) <= 3:
        return True
    return False


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


# --------------------------------------------------------------------------
# Small helpers
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


def _mask(value: str, keep_start: int = 6, keep_end: int = 4) -> str:
    """Mask a secret value, never revealing the full string."""
    value = value or ""
    if len(value) <= keep_start + keep_end:
        if len(value) <= 4:
            return "*" * len(value)
        return value[:2] + "*" * max(len(value) - 4, 4) + value[-2:]
    stars = "*" * max(8, len(value) - keep_start - keep_end)
    return f"{value[:keep_start]}{stars}{value[-keep_end:]}"


def _line_number_for_offset(text: str, offset: int) -> int:
    """Given a character offset into text, return the 1-indexed line number."""
    return text.count("\n", 0, offset) + 1


def _risk_for(label: str) -> str:
    low = label.lower()
    if "aws" in low:
        return ("Anyone with this AWS credential can access or provision cloud "
                "resources on the account, leading to data theft or runaway billing.")
    if "openai" in low:
        return ("Anyone can use this key to make OpenAI API calls billed to your "
                "account, exfiltrate usage data, or exhaust your rate limits.")
    if "anthropic" in low:
        return ("Anyone can use this key to make Claude API calls billed to your "
                "account or exhaust your usage limits.")
    if "stripe" in low or "clerk" in low:
        if "live" in low and ("secret" in low or low.startswith("sk")):
            return ("A live secret key grants full account access to create charges, "
                     "issue refunds, or read customer/payment data.")
        return ("Exposed even as a 'test' or publishable key, this can leak account "
                 "structure or be combined with other findings to escalate access.")
    if "google" in low:
        return ("This key can be used to make billed calls against Google APIs on "
                 "your project; restrict it by referrer/API or rotate it.")
    if "firebase" in low:
        return ("This legacy server key can send push notifications and access "
                 "project resources on your behalf.")
    if "private key" in low:
        return ("A private key grants full cryptographic identity/control to "
                 "whoever holds it — treat this as a full compromise.")
    if "connection string" in low or "database" in low:
        return ("Embedded database credentials let anyone connect directly to "
                 "your database, bypassing your application's access controls.")
    if "github" in low:
        return ("This token can read/write repositories, CI secrets, or packages "
                 "depending on its scopes.")
    if "slack" in low:
        return ("This token can post messages, read channel content, or take "
                 "other actions in your Slack workspace.")
    if "sendgrid" in low:
        return "This key can be used to send email as your domain or read account data."
    if "bearer" in low or "jwt" in low or "session" in low or "supabase" in low:
        return ("A leaked session/auth token can let an attacker impersonate a "
                 "user or service until the token expires or is revoked.")
    if "password" in low:
        return "A hardcoded password allows direct, persistent unauthorized access."
    return ("Exposed credentials in client-side code can be read by anyone viewing "
            "page source or network traffic, enabling unauthorized access or abuse.")


# --------------------------------------------------------------------------
# Network helpers
# --------------------------------------------------------------------------

async def _fetch_text(session: aiohttp.ClientSession, url: str, max_bytes: int = None):
    """
    Fetch a URL and return (text, status, error). Never raises.
    If max_bytes is set, aborts the read early if the body exceeds it.
    """
    try:
        async with session.get(url, timeout=PER_REQUEST_TIMEOUT, ssl=False) as resp:
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


def _extract_scripts(html: str, base_url: str):
    """
    Parse HTML and return (external_urls, inline_scripts).
    external_urls: absolute URLs of all <script src="..."> tags (deduped).
    inline_scripts: list of raw text content of <script> tags with no src,
                     in document order.
    """
    external_urls = []
    inline_scripts = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("script"):
            src = tag.get("src")
            if src:
                src = src.strip()
                if not src:
                    continue
                try:
                    absolute = urljoin(base_url, src)
                    parsed = urlparse(absolute)
                    if parsed.scheme in ("http", "https"):
                        external_urls.append(absolute)
                except Exception:
                    continue
            else:
                content = tag.string
                if content is None:
                    content = tag.get_text() or ""
                if content.strip():
                    inline_scripts.append(content)
    except Exception:
        # Malformed HTML — bail out with whatever we found so far
        pass

    # Dedupe external URLs, preserve order
    seen = set()
    deduped = []
    for u in external_urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped, inline_scripts


# --------------------------------------------------------------------------
# Secret detection patterns
# --------------------------------------------------------------------------
# Each resolver receives (value, context_window) and returns either None
# (treat as false positive / skip) or (confidence, is_critical_type, label).

def _simple_resolver(label, confidence, critical):
    def resolver(value, context):
        if _looks_like_placeholder(value):
            return None
        return confidence, critical, label
    return resolver


def _password_resolver(value, context):
    if _looks_like_placeholder(value):
        return None
    ctx_low = context.lower()
    if "password" in ctx_low or "passwd" in ctx_low:
        return "high", True, "Hardcoded Password"
    entropy = _shannon_entropy(value)
    if entropy >= 4.0 and len(value) >= 16:
        return "high", True, "Generic Secret / API Key"
    return "medium", False, "Generic Secret / API Key"


def _stripe_clerk_resolver(value, context):
    # Note: deliberately does NOT run the generic placeholder filter here —
    # legitimate sk_test_/pk_test_ values always contain the substring
    # "test", which would otherwise be (wrongly) treated as a placeholder.
    ctx_low = context.lower()
    service = "Clerk" if "clerk" in ctx_low else "Stripe"
    is_secret = value.startswith(("sk_", "rk_"))
    is_live = "_live_" in value
    if is_secret and not is_live:
        # Test-mode secret keys carry no real production risk — ignore.
        return None
    if is_secret and is_live:
        return "high", True, f"{service} Live Secret Key"
    # Publishable keys are meant to be public-ish, but still worth a
    # low-confidence note (e.g. to confirm rate limiting/restrictions exist).
    if is_live:
        return "low", False, f"{service} Live Publishable Key"
    return "low", False, f"{service} Test Publishable Key"


def _google_resolver(value, context):
    if _looks_like_placeholder(value):
        return None
    # Google API keys are frequently restricted/intended for client-side use
    # (e.g. Maps), so default to medium rather than critical.
    return "medium", False, "Google API Key"


def _jwt_resolver(value, context):
    if _looks_like_placeholder(value):
        return None
    if len(value) < 30 or value.count(".") < 2:
        return None
    ctx_low = context.lower()
    if "supabase" in ctx_low:
        return "medium", False, "Supabase API Key (JWT)"
    return "medium", False, "JWT / Session Token"


def _bearer_resolver(value, context):
    token = re.sub(r"(?i)^bearer\s+", "", value).strip()
    if _looks_like_placeholder(token) or len(token) < 20:
        return None
    return "medium", False, "Bearer Token"


SECRET_PATTERNS = [
    # (label_for_pattern, regex, group_idx_for_value, resolver)
    ("OpenAI API Key", re.compile(r'sk-proj-[A-Za-z0-9_\-]{20,}'), 0,
     _simple_resolver("OpenAI API Key", "high", True)),
    ("OpenAI API Key (legacy)", re.compile(r'sk-(?!ant-|live_|test_|proj-)[A-Za-z0-9]{20,}'), 0,
     _simple_resolver("OpenAI API Key", "high", True)),
    ("Anthropic API Key", re.compile(r'sk-ant-(?:api03-)?[A-Za-z0-9_\-]{20,}'), 0,
     _simple_resolver("Anthropic API Key", "high", True)),
    ("Stripe/Clerk Key", re.compile(r'(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}'), 0,
     _stripe_clerk_resolver),
    ("AWS Access Key ID", re.compile(r'AKIA[0-9A-Z]{16}'), 0,
     _simple_resolver("AWS Access Key ID", "high", True)),
    ("AWS Secret Access Key", re.compile(r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']'), 1,
     _simple_resolver("AWS Secret Access Key", "high", True)),
    ("Google API Key", re.compile(r'AIza[0-9A-Za-z\-_]{35}'), 0, _google_resolver),
    ("Firebase Server Key", re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'), 0,
     _simple_resolver("Firebase Server Key", "high", True)),
    ("Private Key Block", re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), 0,
     _simple_resolver("Private Key", "high", True)),
    ("DB Connection String w/ Credentials",
     re.compile(r'(?i)(mongodb(?:\+srv)?|mysql|postgresql|postgres|redis|amqp):\/\/[^:\/\s"\'<>]+:[^@\/\s"\'<>]+@[^\s"\'<>]+'),
     0, _simple_resolver("Database Connection String (with credentials)", "high", True)),
    ("GitHub Token", re.compile(r'gh[pousr]_[A-Za-z0-9]{36,}'), 0,
     _simple_resolver("GitHub Token", "high", True)),
    ("Slack Token", re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,48}'), 0,
     _simple_resolver("Slack Token", "high", True)),
    ("SendGrid API Key", re.compile(r'SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}'), 0,
     _simple_resolver("SendGrid API Key", "high", True)),
    ("Bearer Token", re.compile(r'(?i)bearer\s+[A-Za-z0-9\-_\.=]{20,}'), 0, _bearer_resolver),
    ("JWT Token", re.compile(r'eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*'), 0, _jwt_resolver),
    ("Generic Secret/Password",
     re.compile(r'(?i)(secret|password|passwd|api_key|apikey|token|auth)[\s]*[=:][\s]*["\'`]([^\s"\'`]{8,})'),
     2, _password_resolver),
]

# Fallback heuristic for unrecognized high-entropy strings near suspicious keywords.
_ENTROPY_CONTEXT_WORDS = re.compile(r'(?i)(key|token|secret|auth|credential|passwd|password|api)')
_ENTROPY_CANDIDATE = re.compile(r'["\'`]([A-Za-z0-9+/_\-=]{40,})["\'`]')
_ENTROPY_THRESHOLD_MEDIUM = 4.3
_ENTROPY_THRESHOLD_HIGH = 5.0


def _scan_content_for_secrets(content: str, location_for_line):
    """
    Run all regex patterns + entropy heuristic against JS content.
    location_for_line: callable(line_no) -> location string for evidence.
    Returns a list of finding dicts.
    """
    findings = []
    matched_spans = []

    for _, pattern, group_idx, resolver in SECRET_PATTERNS:
        try:
            for match in pattern.finditer(content):
                try:
                    value = match.group(group_idx) if group_idx else match.group(0)
                    val_start = match.start(group_idx) if group_idx else match.start()
                    val_end = match.end(group_idx) if group_idx else match.end()
                except (IndexError, AttributeError):
                    value = match.group(0)
                    val_start, val_end = match.start(), match.end()

                # Skip if this exact secret value was already claimed by an
                # earlier, more specific pattern (patterns are ordered from
                # most-specific to most-generic in SECRET_PATTERNS).
                if any(val_start < e and val_end > s for s, e in matched_spans):
                    continue

                window_start = max(0, match.start() - 40)
                context = content[window_start:match.start()]
                result = resolver(value, context)
                if result is None:
                    continue
                confidence, critical_type, label = result
                line_no = _line_number_for_offset(content, val_start)
                findings.append({
                    "type": label,
                    "confidence": confidence,
                    "critical_type": critical_type,
                    "location": location_for_line(line_no),
                    "example": _mask(value),
                })
                matched_spans.append((val_start, val_end))
        except Exception:
            # A single bad pattern/match should never kill the whole scan
            continue

    # Entropy heuristic for strings not already caught above
    try:
        for match in _ENTROPY_CANDIDATE.finditer(content):
            start, end = match.start(), match.end()
            if any(start < e and end > s for s, e in matched_spans):
                continue  # already flagged by a specific pattern
            candidate = match.group(1)
            if _looks_like_placeholder(candidate):
                continue
            entropy = _shannon_entropy(candidate)
            if entropy < _ENTROPY_THRESHOLD_MEDIUM:
                continue

            window_start = max(0, start - 40)
            context_window = content[window_start:start]
            if not _ENTROPY_CONTEXT_WORDS.search(context_window):
                continue

            confidence = "high" if entropy >= _ENTROPY_THRESHOLD_HIGH else "medium"
            line_no = _line_number_for_offset(content, start)
            findings.append({
                "type": "Potential Secret (High Entropy)",
                "confidence": confidence,
                "critical_type": False,
                "location": location_for_line(line_no),
                "example": _mask(candidate),
            })
    except Exception:
        pass

    return findings


# --------------------------------------------------------------------------
# Result builders
# --------------------------------------------------------------------------

def _empty_result(status, severity, title, description, remediation="No action needed."):
    return {
        "test_name": "secrets_detection",
        "status": status,
        "severity": severity,
        "title": title,
        "description": description,
        "findings_count": 0,
        "evidence": [],
        "remediation": remediation,
        "recommendation": "No action needed." if status == "pass" else "Re-run the scan once the target is reachable.",
    }


# --------------------------------------------------------------------------
# Core scan logic
# --------------------------------------------------------------------------

async def _scan_target(url: str) -> dict:
    target_url = _normalize_url(url)
    if not target_url:
        return _empty_result(
            "warning", "low", "Invalid Target",
            "No URL was provided to scan.",
            "Provide a valid domain or URL.",
        )

    headers = {"User-Agent": USER_AGENT}
    connector = aiohttp.TCPConnector(ssl=False)

    async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
        # Step 1: Fetch target HTML
        html, status, err = await _fetch_text(session, target_url)
        if err or html is None:
            return _empty_result(
                "warning", "low", "Could Not Fetch Target",
                f"Failed to retrieve the target page: {err or 'unknown error'}",
                "Verify the URL is reachable and try again.",
            )

        # Step 2: Parse HTML for inline scripts + external script URLs
        script_urls, inline_scripts = _extract_scripts(html, target_url)
        script_urls = script_urls[:MAX_JS_FILES]
        inline_scripts = inline_scripts[:MAX_INLINE_SCRIPTS]

        if not script_urls and not inline_scripts:
            return _empty_result(
                "pass", "low", "No Hardcoded Secrets Detected",
                "No inline scripts or linked JavaScript files were found on the target page.",
            )

        all_findings = []
        resources_scanned = 0

        # Step 3: Scan inline scripts (no network needed)
        for idx, content in enumerate(inline_scripts, start=1):
            resources_scanned += 1
            findings = _scan_content_for_secrets(
                content,
                lambda line_no, i=idx: f"inline script #{i} line {line_no}",
            )
            all_findings.extend(findings)

        # Step 4: Download external JS files concurrently (bounded)
        async def fetch_one(js_url):
            content, st, ferr = await _fetch_text(session, js_url, max_bytes=MAX_JS_FILE_SIZE)
            return js_url, content, ferr

        if script_urls:
            results = await asyncio.gather(
                *[fetch_one(u) for u in script_urls],
                return_exceptions=True,
            )

            for result in results:
                if isinstance(result, Exception):
                    continue
                js_url, content, ferr = result
                if content is None:
                    # Skipped (too large) or failed to fetch — not a crash, just skip
                    continue

                resources_scanned += 1
                path = urlparse(js_url).path.lstrip("/") or js_url
                findings = _scan_content_for_secrets(
                    content,
                    lambda line_no, p=path: f"{p}:{line_no}",
                )
                all_findings.extend(findings)

        # Step 5: Aggregate
        findings_count = len(all_findings)

        if findings_count == 0:
            return _empty_result(
                "pass", "low", "No Hardcoded Secrets Detected",
                f"Scanned {resources_scanned} JavaScript resource(s) (external files and inline "
                f"scripts) and found no hardcoded secrets matching known credential patterns or "
                f"entropy heuristics.",
            )

        has_critical_high = any(f["critical_type"] and f["confidence"] == "high" for f in all_findings)
        has_high = any(f["confidence"] == "high" for f in all_findings)
        has_medium = any(f["confidence"] == "medium" for f in all_findings)

        if has_critical_high:
            severity = "critical"
        elif has_high:
            severity = "high"
        elif has_medium:
            severity = "medium"
        else:
            severity = "low"

        status_val = "fail" if (has_critical_high or has_high) else "warning"

        clean_evidence = [
            {
                "type": f["type"],
                "confidence": f["confidence"],
                "location": f["location"],
                "example": f["example"],
                "risk": _risk_for(f["type"]),
            }
            for f in all_findings
        ]

        recommendation = (
            "Critical - Rotate all exposed keys right away."
            if severity in ("critical", "high")
            else "Review and rotate flagged credentials; confirm low-confidence items are not real secrets."
        )

        return {
            "test_name": "secrets_detection",
            "status": status_val,
            "severity": severity,
            "title": f"Hardcoded Secrets Detected ({findings_count} found)",
            "description": (
                f"Scanned {resources_scanned} JavaScript resource(s) (external files and inline "
                f"scripts) and found {findings_count} potential hardcoded secret(s) in client-side "
                f"code. This poses a serious security risk."
            ),
            "findings_count": findings_count,
            "evidence": clean_evidence,
            "remediation": (
                "Move ALL secrets to server-side environment variables only. Never expose them in "
                "frontend JavaScript. For Next.js use `NEXT_PUBLIC_` only for genuinely public values. "
                "Rotate every exposed credential immediately and audit access logs for misuse."
            ),
            "recommendation": recommendation,
        }


# --------------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------------

async def run(url: str) -> dict:
    """
    Scan a target site's inline scripts and linked JavaScript files for
    hardcoded secrets. Always returns a single result dict; never raises.
    """
    try:
        return await asyncio.wait_for(_scan_target(url), timeout=TOTAL_BUDGET_SECONDS)
    except asyncio.TimeoutError:
        return _empty_result(
            "warning", "low", "Scan Timed Out",
            f"The scan exceeded the {TOTAL_BUDGET_SECONDS}-second time budget and was aborted.",
            "Try again, or scan a target with fewer/smaller JavaScript resources.",
        )
    except Exception as e:
        # Absolute last-resort catch-all — the module must never crash.
        return _empty_result(
            "warning", "low", "Scan Error",
            f"An unexpected error occurred during the scan: {e}",
            "Review scanner logs and retry the scan.",
        )


# --------------------------------------------------------------------------
# Manual test harness
# --------------------------------------------------------------------------

if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))