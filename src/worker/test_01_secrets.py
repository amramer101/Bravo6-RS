#!/usr/bin/env python3
"""
Bravo6 Ultimate Secrets Hunter (v6.2.1 – Clean Summary)
=========================================================
- Fixed misclassification: non‑secret evidence (e.g. Tech Stack)
  no longer inflates secret counts or severity.
- All previous optimizations retained.
- CRITICAL: Added proper logging for failed JS fetches (was swallowing all exceptions silently)
- HIGH: Added internal timeout handling to return partial results on timeout
- MEDIUM: Enhanced AWS key pair detection with safe PoC (no real values in poc field)
- LOW: Made soft-404 probe path random per scan to avoid caching/special-casing
"""

import argparse
import asyncio
import base64
import difflib
import json
import logging
import math
import re
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────── Configuration ──────────────────────────────────────────────
USER_AGENT = "Bravo6-SecretsHunter/6.2.1"
VERIFY_USER_AGENT = "Bravo6-Verification/2.0"
TIMEOUT = aiohttp.ClientTimeout(total=15)
VERIFY_TIMEOUT = aiohttp.ClientTimeout(total=8)
MAX_CONCURRENT_VERIFIES = 8
MAX_CONCURRENT_JS_FETCHES = 5
MAX_JS_FILES = 15
MAX_INLINE_SCRIPTS = 40
INLINE_SCRIPT_MAX_BYTES = 250 * 1024
FETCH_MAX_BYTES_HTML = 2 * 1024 * 1024
FETCH_MAX_BYTES_JS = 1 * 1024 * 1024
JS_SIZE_LIMIT = 500 * 1024

SENSITIVE_PATHS = [
    "/.env", "/config.js", "/credentials.json",
    "/secrets.yaml", "/app.config", "/settings.py",
    "/.git/config", "/config/secrets.yml",
    "/id_rsa", "/id_rsa.pub", "/.ssh/id_rsa",
    "/.ssh/id_ecdsa", "/.ssh/id_ed25519",
    "/server.key", "/private.key", "/cert.pem",
    "/private.pem", "/key.pem"
]

DEFAULT_MIN_CONFIDENCE = 75

# ────────────────────────────────────────────── False‑positive filters ──────────────────────────────────────
PLACEHOLDER_MARKERS = (
    "test", "demo", "fake", "example", "sample", "placeholder", "dummy",
    "changeme", "your_", "insert_", "redacted", "xxxxxxxx", "00000000",
    "1234567890", "abcdefgh", "<key>", "<token>", "{api_key}", "${",
    "process.env", "lorem", "foobar", "asdf", "yourkey", "your-api-key",
    "api_key_here", "secret_key_here", "put_your", "replace_me",
    "your-secret", "my-secret", "example-", "sample-",
    "00000000-0000-0000-0000-000000000000"
)
KNOWN_TEST_PREFIXES = (
    "sk_test_", "pk_test_", "sk_live_",
    "ghp_", "gho_", "ghu_", "ghs_",
    "xoxb-", "xoxp-",
    "SG.",
)
CONTEXT_KEYWORDS = ("key", "secret", "token", "auth", "credential",
                    "password", "api", "access", "passwd", "private",
                    "database", "dsn", "connection")
HIGH_ENTROPY_EXCLUDES = re.compile(
    r'(encrypted.slate|csrf|nonce|analytics|tracking|gtag|google_tag)',
    re.IGNORECASE
)

SOFT_404_PHRASES = [
    "404 Not Found",
    "Not Found",
    "The requested URL was not found on this server.",
    "The page you are looking for could not be found",
    "Error 404",
    "Page not found",
]

# ────────────────────────────────────────────── Helper Functions ──────────────────────────────────────────────
def _looks_like_placeholder(value: str) -> bool:
    if not value:
        return True
    low = value.lower()
    for marker in PLACEHOLDER_MARKERS:
        if marker in low:
            return True
    if len(set(low)) <= 3 and len(low) > 5:
        return True
    if value.isdigit() and len(value) < 20:
        return True
    if re.match(r'^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$', low):
        return all(c == '0' for c in low if c != '-')
    return False

def _is_known_test_key(value: str) -> bool:
    return any(value.startswith(p) for p in KNOWN_TEST_PREFIXES)

def _has_credential_context(text: str, match_start: int, match_end: int, window: int = 60) -> bool:
    start_win = max(0, match_start - window)
    end_win = min(len(text), match_end + window)
    snippet = text[start_win:end_win]
    return any(re.search(rf'\b{kw}\b', snippet, re.IGNORECASE) for kw in CONTEXT_KEYWORDS)

def _is_in_comment(text: str, match_start: int) -> bool:
    line_start = text.rfind('\n', 0, match_start) + 1
    line = text[line_start:match_start].strip()
    if line.startswith('//') or '<!--' in line:
        return True
    return bool(re.search(r'/\*.*$', text[:match_start], re.DOTALL)) and \
           not re.search(r'\*/', text[:match_start])

def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

def _is_soft_404(html: str) -> bool:
    if not html:
        return False
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ", strip=True)
    title = ""
    title_tag = soup.find("title")
    if title_tag and title_tag.string:
        title = title_tag.string.strip()
    if re.search(r'\b(404|not\s*found)\b', title, re.IGNORECASE):
        return True
    for phrase in SOFT_404_PHRASES:
        if difflib.SequenceMatcher(None, text.lower(), phrase.lower()).ratio() > 0.65:
            return True
    return False

# ────────────────────────────────────────────── Active Verification ──────────────────────────────────────────

async def _verify_with_retry(verifier, key, session, *args) -> dict:
    try:
        return await verifier(key, session, *args)
    except Exception:
        try:
            await asyncio.sleep(0.5)
            return await verifier(key, session, *args)
        except Exception as e:
            return {"verified": False, "error": f"Retry failed: {e}"}

async def _verify_openai(key: str, session: aiohttp.ClientSession) -> dict:
    url = "https://api.openai.com/v1/models"
    headers = {"Authorization": f"Bearer {key}", "User-Agent": VERIFY_USER_AGENT}
    async with session.get(url, headers=headers, timeout=VERIFY_TIMEOUT) as resp:
        body = await resp.text(errors="ignore")
        return {"verified": resp.status == 200, "status": resp.status, "preview": body[:300]}

async def _verify_anthropic(key: str, session: aiohttp.ClientSession) -> dict:
    url = "https://api.anthropic.com/v1/messages"
    payload = {"model": "claude-3-haiku-20240307", "max_tokens": 1,
               "messages": [{"role": "user", "content": "Hi"}]}
    headers = {"x-api-key": key, "anthropic-version": "2023-06-01",
               "content-type": "application/json", "User-Agent": VERIFY_USER_AGENT}
    async with session.post(url, json=payload, headers=headers, timeout=VERIFY_TIMEOUT) as resp:
        body = await resp.text(errors="ignore")
        return {"verified": resp.status in (200, 400), "status": resp.status, "preview": body[:300]}

async def _verify_stripe(key: str, session: aiohttp.ClientSession) -> dict:
    if not key.startswith("sk_live_"):
        return {"verified": False, "note": "Not a live secret key"}
    url = "https://api.stripe.com/v1/balance"
    headers = {"Authorization": f"Bearer {key}", "User-Agent": VERIFY_USER_AGENT}
    async with session.get(url, headers=headers, timeout=VERIFY_TIMEOUT) as resp:
        body = await resp.text(errors="ignore")
        return {"verified": resp.status == 200, "status": resp.status, "preview": body[:300]}

async def _verify_github(key: str, session: aiohttp.ClientSession) -> dict:
    url = "https://api.github.com/rate_limit"
    headers = {"Authorization": f"token {key}", "User-Agent": VERIFY_USER_AGENT}
    async with session.get(url, headers=headers, timeout=VERIFY_TIMEOUT) as resp:
        body = await resp.text(errors="ignore")
        return {"verified": resp.status == 200, "status": resp.status, "preview": body[:300]}

async def _verify_slack(key: str, session: aiohttp.ClientSession) -> dict:
    url = "https://slack.com/api/auth.test"
    headers = {"Authorization": f"Bearer {key}", "User-Agent": VERIFY_USER_AGENT}
    async with session.get(url, headers=headers, timeout=VERIFY_TIMEOUT) as resp:
        body = await resp.text(errors="ignore")
        if resp.status == 200:
            try:
                data = json.loads(body)
                return {"verified": data.get("ok", False), "status": resp.status, "preview": body[:300]}
            except:
                pass
        return {"verified": False, "status": resp.status, "preview": body[:300]}

async def _verify_sendgrid(key: str, session: aiohttp.ClientSession) -> dict:
    url = "https://api.sendgrid.com/v3/user/profile"
    headers = {"Authorization": f"Bearer {key}", "User-Agent": VERIFY_USER_AGENT}
    async with session.get(url, headers=headers, timeout=VERIFY_TIMEOUT) as resp:
        body = await resp.text(errors="ignore")
        return {"verified": resp.status == 200, "status": resp.status, "preview": body[:300]}

async def _verify_mailgun(key: str, session: aiohttp.ClientSession) -> dict:
    url = "https://api.mailgun.net/v3/domains"
    auth = aiohttp.BasicAuth("api", key)
    headers = {"User-Agent": VERIFY_USER_AGENT}
    async with session.get(url, auth=auth, headers=headers, timeout=VERIFY_TIMEOUT) as resp:
        body = await resp.text(errors="ignore")
        return {"verified": resp.status == 200, "status": resp.status, "preview": body[:300]}

async def _verify_mapbox(key: str, session: aiohttp.ClientSession) -> dict:
    url = f"https://api.mapbox.com/tokens/v1?access_token={key}"
    headers = {"User-Agent": VERIFY_USER_AGENT}
    async with session.get(url, headers=headers, timeout=VERIFY_TIMEOUT) as resp:
        body = await resp.text(errors="ignore")
        return {"verified": resp.status == 200, "status": resp.status, "preview": body[:300]}

async def _verify_firebase(api_key: str, project_id: str, session: aiohttp.ClientSession) -> dict:
    url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/__test_collection__"
    headers = {"User-Agent": VERIFY_USER_AGENT}
    params = {"key": api_key}
    try:
        async with session.get(url, headers=headers, params=params, timeout=VERIFY_TIMEOUT) as resp:
            body = await resp.text(errors="ignore")
            return {"verified": resp.status == 200, "status": resp.status, "preview": body[:300]}
    except Exception as e:
        return {"verified": False, "error": str(e)}

VERIFIERS = {
    "OpenAI API Key":        _verify_openai,
    "Anthropic API Key":     _verify_anthropic,
    "Stripe Live Secret Key": _verify_stripe,
    "GitHub Token":          _verify_github,
    "GitHub App Token":      _verify_github,
    "GitHub OAuth Token":    _verify_github,
    "Slack Token":           _verify_slack,
    "SendGrid API Key":      _verify_sendgrid,
    "Mailgun API Key":       _verify_mailgun,
    "MapBox API Key":        _verify_mapbox,
}

# ────────────────────────────────────────────── Secret Patterns ──────────────────────────────────────────────
SECRET_PATTERNS = [
    ("OpenAI API Key",          re.compile(r'sk-proj-[A-Za-z0-9_\-]{20,}'), 0, True),
    ("OpenAI API Key",          re.compile(r'sk-(?!ant-|live_|test_|proj-)[A-Za-z0-9]{20,}'), 0, True),
    ("Anthropic API Key",       re.compile(r'sk-ant-(?:api03-)?[A-Za-z0-9_\-]{20,}'), 0, True),
    ("Stripe Live Secret Key",  re.compile(r'sk_live_[0-9a-zA-Z]{16,}'), 0, True),
    ("GitHub Token",            re.compile(r'gh[pusr]_[A-Za-z0-9]{36,}'), 0, True),
    ("GitHub App Token",        re.compile(r'ghs_[A-Za-z0-9]{36,}'), 0, True),
    ("GitHub OAuth Token",      re.compile(r'gho_[A-Za-z0-9]{36,}'), 0, True),
    ("npm Token",               re.compile(r'npm_[A-Za-z0-9]{36,}'), 0, True),
    ("Docker Token",            re.compile(r'dckr_[A-Za-z0-9]{40,}'), 0, True),
    ("Slack Token",             re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,48}'), 0, True),
    ("SendGrid API Key",        re.compile(r'SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}'), 0, True),
    ("Heroku API Key",          re.compile(r'(HEROKU_API_KEY|heroku_[A-Za-z0-9]{20,})'), 0, True),
    ("Mailgun API Key",         re.compile(r'key-[a-zA-Z0-9]{32}'), 0, True),
    ("Supabase Key",            re.compile(r'sb-[a-z0-9]{20,}-[a-z0-9]{20,}'), 0, True),
    ("Vercel Token",            re.compile(r'[a-zA-Z0-9]{24}\.[a-zA-Z0-9_]{60,70}'), 0, True),
    ("Cloudflare API Token",    re.compile(r'[A-Za-z0-9_-]{40}'), 0, False),
    ("MapBox API Key",          re.compile(r'(pk|sk)\.eyJ1Ijoi[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+'), 0, True),
    ("Google API Key",          re.compile(r'AIza[0-9A-Za-z\-_]{35}'), 0, False),
    ("Firebase API Key",        re.compile(r'AIza[0-9A-Za-z\-_]{35}'), 0, False),
    ("Twilio Auth Token",       re.compile(r'SK[0-9a-fA-F]{32}'), 0, False),
    ("Twilio Account SID",      re.compile(r'AC[0-9a-fA-F]{32}'), 0, False),
    ("Algolia Application ID",  re.compile(r'[A-Z0-9]{10}'), 0, False),
    ("Algolia API Key",         re.compile(r'[a-fA-F0-9]{32}'), 0, False),
    ("AWS Access Key ID",       re.compile(r'AKIA[0-9A-Z]{16}'), 0, True),
    ("AWS Secret Access Key",   re.compile(r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']'), 1, True),
    ("AWS4-HMAC-SHA256",        re.compile(r'AWS4-HMAC-SHA256\s+Credential=([A-Z0-9]{16})/[0-9]+/[a-z0-9-]+/[a-z0-9]+/aws4_request'), 1, True),
    ("AWS Signed Header",       re.compile(r'x-amz-[a-z0-9-]+:\s*([A-Za-z0-9+/=]{30,})'), 1, True),
    ("Private Key",             re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), 0, True),
    ("Database Connection",     re.compile(r'(?i)(mongodb(?:\+srv)?|mysql|postgresql|redis|amqp):\/\/[^:\/\s"\'<>]+:[^@\/\s"\'<>]+@[^\s"\'<>]+'), 0, True),
    ("Bearer Token",            re.compile(r'Bearer\s+([A-Za-z0-9\-_\.]+)'), 1, True),
    ("JWT Token",               re.compile(r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'), 0, True),
]

FIREBASE_CONFIG = re.compile(
    r'apiKey\s*:\s*["\'](AIza[0-9A-Za-z\-_]{35})["\'][^}]*projectId\s*:\s*["\']([a-z0-9-]+)["\']',
    re.DOTALL
)

ENTROPY_CANDIDATE = re.compile(r'["\'`]([A-Za-z0-9+/_\-=]{40,})["\'`]')
ENTROPY_CONTEXT = re.compile(r'(?i)(key|token|secret|auth|credential|passwd)')

# ────────────────────────────────────────────── Helpers ──────────────────────────────────────────────────────
def _mask(value: str, keep_start: int = 4, keep_end: int = 4) -> str:
    if len(value) <= keep_start + keep_end:
        return "*" * len(value)
    return f"{value[:keep_start]}...{value[-keep_end:]}"

def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1

def _extract_context(text: str, start: int, end: int) -> str:
    lines = text.splitlines()
    ln = _line_number(text, start) - 1
    ctx_lines = []
    for i in range(max(0, ln - 2), min(len(lines), ln + 3)):
        line = lines[i].strip()
        if len(line) > 200:
            line = line[:200] + "..."
        ctx_lines.append(f"{i + 1}: {line}")
    return "\n".join(ctx_lines)

def _poc_command(secret_type: str, key: str, url: str = "") -> str:
    if "OpenAI" in secret_type:
        return 'curl https://api.openai.com/v1/models -H "Authorization: Bearer <API_KEY>" (see evidence field)'
    if "Stripe" in secret_type:
        return 'curl https://api.stripe.com/v1/balance -H "Authorization: Bearer <API_KEY>" (see evidence field)'
    if "GitHub" in secret_type:
        return 'curl https://api.github.com/user -H "Authorization: token <TOKEN>" (see evidence field)'
    if "Slack" in secret_type:
        return 'curl https://slack.com/api/auth.test -H "Authorization: Bearer <TOKEN>" (see evidence field)'
    if "SendGrid" in secret_type:
        return 'curl https://api.sendgrid.com/v3/user/profile -H "Authorization: Bearer <API_KEY>" (see evidence field)'
    if "Mailgun" in secret_type:
        return 'curl -u "api:<API_KEY>" https://api.mailgun.net/v3/domains (see evidence field)'
    if "MapBox" in secret_type:
        return 'curl "https://api.mapbox.com/tokens/v1?access_token=<API_KEY>" (see evidence field)'
    if "Database" in secret_type:
        return "Use connection string from evidence field"
    if "Bearer" in secret_type or "JWT" in secret_type:
        return 'curl -H "Authorization: Bearer <TOKEN>" <TARGET_URL> (see evidence field)'
    if "AWS" in secret_type:
        if "Secret" in secret_type:
            return "aws sts get-caller-identity --secret-access-key <SECRET_KEY> (needs Access Key, see evidence field)"
        return "aws sts get-caller-identity --access-key-id <ACCESS_KEY> (needs Secret Key, see evidence field)"
    if "AWS4" in secret_type:
        return "AWS4 signing key detected. Needs secret access key for full verification (see evidence field)."
    if secret_type == "AWS Key Pair":
        # FIX #3: Never include real secret values in PoC - reference evidence field instead
        return "aws sts get-caller-identity --access-key-id <ACCESS_KEY> --secret-access-key <SECRET_KEY> (see evidence field)"
    return f"Manual verification required for {secret_type} (see evidence field)."

def _risk_description(secret_type: str, verified: bool, note: str = "") -> str:
    if verified:
        return f"ACTIVE CREDENTIAL: {secret_type} grants unauthorised access."
    if note:
        return f"Unverified {secret_type}: {note}"
    return f"High‑confidence pattern for {secret_type}; manual verification needed."

# ────────────────────────────────────────────── Deobfuscation ────────────────────────────────────────────────
def _extract_decoded_strings(content: str) -> Tuple[List[str], Optional[str]]:
    decoded = []
    methods = []
    atob_pat = re.compile(r'atob\s*\(\s*(["\'])((?:(?!\1).)*)\1\s*\)', re.IGNORECASE)
    for m in atob_pat.finditer(content):
        b64 = m.group(2)
        try:
            decoded.append(base64.b64decode(b64).decode("utf-8", errors="replace"))
            if "atob" not in methods:
                methods.append("atob")
        except:
            pass
    fromcc_pat = re.compile(r'String\.fromCharCode\s*\(\s*([\d,\s]+)\s*\)', re.IGNORECASE)
    for m in fromcc_pat.finditer(content):
        nums = [int(x) for x in m.group(1).split(',') if x.strip().isdigit()]
        try:
            decoded.append(''.join(chr(n) for n in nums))
            if "fromCharCode" not in methods:
                methods.append("fromCharCode")
        except:
            pass
    seen = set()
    unique = []
    for s in decoded:
        if s not in seen:
            seen.add(s)
            unique.append(s)
    method_str = ", ".join(methods) if methods else None
    return unique, method_str

# ────────────────────────────────────────────── Header‑based fingerprinting ─────────────────────────────────
def _fingerprint_from_headers(resp_headers: Dict[str, str], raw_set_cookies: List[str]) -> List[str]:
    tech = []
    server = resp_headers.get("server", "")
    powered = resp_headers.get("x-powered-by", "")
    generator = resp_headers.get("x-generator", "")
    cookies = "; ".join(raw_set_cookies)

    if "php" in powered.lower():
        tech.append("PHP")
    if "asp.net" in powered.lower():
        tech.append("ASP.NET")
    if "express" in powered.lower():
        tech.append("Express")
    if "nginx" in server.lower():
        tech.append("nginx")
    if "apache" in server.lower():
        tech.append("Apache")
    if "cloudflare" in server.lower():
        tech.append("Cloudflare")
    if "django" in generator.lower():
        tech.append("Django")
    if "joomla" in generator.lower():
        tech.append("Joomla")
    if "wordpress" in generator.lower():
        tech.append("WordPress")

    cookie_hints = {
        "php": "PHPSESSID",
        "laravel": "laravel_session",
        "wordpress": "wp-settings-",
        "django": "csrftoken",
        "express": "connect.sid",
        "aspnet": "ASP.NET_SessionId",
        "java": "JSESSIONID",
    }
    for name, hint in cookie_hints.items():
        if hint.lower() in cookies.lower():
            if name == "aspnet":
                tech.append("ASP.NET")
            else:
                tech.append(name.capitalize())
            break
    return list(set(tech))

# ────────────────────────────────────────────── Fetch helpers ────────────────────────────────────────────────

async def _fetch_text(session, url, max_bytes=FETCH_MAX_BYTES_JS, timeout=8):
    """Fetch text content from a URL with size limit."""
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=True) as resp:
            status = resp.status
            if status != 200:
                return None, status, f"HTTP {status}"
            content = await resp.content.read(max_bytes)
            if len(content) > max_bytes:
                return None, status, "Too large"
            return content.decode("utf-8", errors="replace"), status, None
    except Exception as e:
        return None, None, str(e)

async def _fetch_full(session, url, max_bytes=FETCH_MAX_BYTES_JS, timeout=8):
    """Fetch full content from a URL."""
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=True) as resp:
            content = await resp.content.read(max_bytes)
            text = content.decode("utf-8", errors="replace") if content else ""
            return resp.status, text
    except Exception as e:
        return None, None

# FIX #4: Soft-404 probe path is now generated per-scan with random component
async def _get_generic_403_info(session, base_url):
    """
    FIX #4: Generate random probe path per scan to avoid caching/special-casing.
    OLD: Used static path /Bravo6-Nonexistent-Test-404 which could be cached or special-cased.
    NEW: Uses random component per scan: /bravo6-probe-{uuid[:10]}
    """
    probe_path = f"/bravo6-probe-{uuid.uuid4().hex[:10]}"
    test_url = urljoin(base_url, probe_path)
    status, body = await _fetch_full(session, test_url, max_bytes=8192, timeout=5)
    return (status == 403), body if status == 403 else ""

def _extract_scripts(soup_or_html, base_url, soup_obj=None):
    if soup_obj is None:
        soup = BeautifulSoup(soup_or_html, "html.parser") if isinstance(soup_or_html, str) else soup_or_html
    else:
        soup = soup_obj
    external, inline = [], []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            abs_url = urljoin(base_url, src.strip())
            if urlparse(abs_url).scheme in ("http", "https"):
                external.append(abs_url)
        else:
            content = (tag.string or "").strip()
            if content and len(content) <= INLINE_SCRIPT_MAX_BYTES:
                inline.append(content)
    return list(dict.fromkeys(external))[:MAX_JS_FILES], inline[:MAX_INLINE_SCRIPTS]

def _find_risky_files(soup_or_html, base_url, soup_obj=None):
    if soup_obj is None:
        soup = BeautifulSoup(soup_or_html, "html.parser") if isinstance(soup_or_html, str) else soup_or_html
    else:
        soup = soup_obj
    risky = set()
    for tag in soup.find_all(True):
        for attr in ("src", "href", "content"):
            val = tag.get(attr)
            if val:
                abs_url = urljoin(base_url, val.strip())
                if any(abs_url.endswith(ext) for ext in (
                        ".env", ".json", ".yaml", ".yml", ".config", ".conf", ".properties", ".xml", ".toml")) \
                   or "secret" in abs_url.lower():
                    risky.add(abs_url)
    if isinstance(soup_or_html, str):
        for m in re.finditer(r'https?://[^\s"\'<>]+', soup_or_html):
            u = m.group(0)
            if any(u.endswith(ext) for ext in (
                    ".env", ".json", ".yaml", ".yml", ".config", ".conf", ".properties", ".xml", ".toml")) \
               or "secret" in u.lower():
                risky.add(u)
    return list(risky)[:10]

# FIX #1: Proper exception handling with logging for JS fetches
async def _fetch_one_js(
    js_url: str,
    fetch_js_func: Optional[callable],
    js_cache: Optional[dict],
    session: Optional[aiohttp.ClientSession] = None
) -> Optional[str]:
    """
    FIX #1: CRITICAL - Do not let a single failed JS fetch disappear without a trace.
    OLD: except Exception: return None  (swallowed all errors silently)
    NEW: Log all failures with type and message, track in summary.

    Uses fetch_js callable if provided (from orchestrator), otherwise falls back to session.
    Respects js_cache for deduplication.

    FIX #5: VERIFY - fetch_js signature is callable(js_url) -> str as provided by main_scanner.
    Called with single positional argument (the URL) as required.
    """
    # Check cache first
    if js_cache is not None and js_url in js_cache:
        return js_cache[js_url]

    # Try using the provided fetch_js callable (from orchestrator)
    if fetch_js_func is not None:
        try:
            # FIX #5: Call fetch_js with single positional argument - the URL
            content = await fetch_js_func(js_url)
            if content is not None and js_cache is not None:
                js_cache[js_url] = content
            return content
        except Exception as exc:
            # FIX #1: Log the failure instead of swallowing it
            logger.debug(f"Failed to fetch JS {js_url} via fetch_js: {type(exc).__name__}: {exc}")
            return None

    # Fall back to direct session fetch if no fetch_js provided
    if session is not None:
        try:
            content, status, error = await _fetch_text(session, js_url)
            if content is not None and js_cache is not None:
                js_cache[js_url] = content
            return content
        except Exception as exc:
            # FIX #1: Log the failure instead of swallowing it
            logger.debug(f"Failed to fetch JS {js_url} via session: {type(exc).__name__}: {exc}")
            return None

    logger.debug(f"No fetch method available for JS {js_url}")
    return None

# ────────────────────────────────────────────── Core scanning ────────────────────────────────────────────────
async def _scan_content(
    content: str,
    location_fn_factory,
    session: aiohttp.ClientSession,
    is_script: bool,
    semaphore: asyncio.Semaphore,
    decoded_method: Optional[str] = None,
    verify_live: bool = False,
    min_confidence: int = DEFAULT_MIN_CONFIDENCE,
) -> List[dict]:
    findings = []
    matched_spans = []
    aws_access_keys: Dict[str, dict] = {}
    aws_secret_keys: Dict[str, dict] = {}

    for label, pattern, group_idx, is_high_conf in SECRET_PATTERNS:
        for match in pattern.finditer(content):
            try:
                value = match.group(group_idx) if group_idx else match.group(0)
                start = match.start(group_idx) if group_idx else match.start()
                end = match.end(group_idx) if group_idx else match.end()
            except IndexError:
                continue

            if any(start < e and end > s for s, e in matched_spans):
                continue
            if _looks_like_placeholder(value):
                continue
            if _is_known_test_key(value):
                continue
            if is_script and _is_in_comment(content, start):
                continue

            if not is_high_conf:
                if not _has_credential_context(content, start, end, window=60):
                    continue

            if label == "Cloudflare API Token":
                ctx = content[max(0, start - 60):end + 60]
                if not re.search(r'(cloudflare|cf_)', ctx, re.IGNORECASE):
                    continue
            if label == "Vercel Token":
                ctx = content[max(0, start - 60):end + 60]
                if not re.search(r'vercel', ctx, re.IGNORECASE):
                    continue
            if label in ("Twilio Auth Token", "Twilio Account SID"):
                if not _has_credential_context(content, start, end, window=60):
                    continue
            if label in ("Algolia Application ID", "Algolia API Key"):
                ctx = content[max(0, start - 60):end + 60]
                if not re.search(r'algolia', ctx, re.IGNORECASE):
                    continue
            if label == "Bearer Token":
                win = content[max(0, start - 80):end + 80]
                if not re.search(r'(?:Authorization|auth)', win, re.IGNORECASE):
                    continue

            if label not in ("AWS Access Key ID", "AWS4-HMAC-SHA256", "AWS Signed Header"):
                if _shannon_entropy(value) < 4.0:
                    continue

            if label in ("AWS Access Key ID", "AWS Secret Access Key"):
                if label == "AWS Access Key ID":
                    aws_access_keys[value] = {"start": start, "end": end, "line": _line_number(content, start)}
                else:
                    aws_secret_keys[value] = {"start": start, "end": end, "line": _line_number(content, start)}
                matched_spans.append((start, end))
                continue

            verifier = VERIFIERS.get(label)
            verify_note = ""
            if label == "Anthropic API Key" and not verify_live:
                verifier = None
                verify_note = "Live Anthropic verification disabled (use --verify-live)"

            verified = False
            verify_response = ""
            if verifier:
                async with semaphore:
                    result = await _verify_with_retry(verifier, value, session)
                    verified = result.get("verified", False)
                    if "note" in result:
                        verify_note = result["note"]
                    if "preview" in result:
                        verify_response = result["preview"]
                    elif "error" in result:
                        verify_response = f"Error: {result['error']}"
            else:
                if not verify_note:
                    verify_note = "No active verification for this secret type."

            base_conf = 90 if is_high_conf else 60
            confidence = 100 if verified else base_conf
            severity = "critical" if verified else ("high" if confidence >= 80 else "medium")
            if confidence < min_confidence:
                continue

            line_no = _line_number(content, start)
            location = location_fn_factory(line_no)
            context = _extract_context(content, start, end)
            poc = _poc_command(label, value)

            evidence = {
                "type": label,
                "location": location,
                "value_masked": _mask(value),
                "verified": verified,
                "confidence": confidence,
                "severity": severity,
                "poc": poc,
                "risk": _risk_description(label, verified, verify_note),
                "context": context,
            }
            if verify_response:
                evidence["verification_response"] = verify_response[:300]
            if decoded_method:
                evidence["decoded_from"] = decoded_method

            findings.append(evidence)
            matched_spans.append((start, end))

    # AWS Key Pair combination detection (FIX #3: Already present, PoC fixed to not include real values)
    if aws_access_keys and aws_secret_keys:
        for ak, ak_data in aws_access_keys.items():
            for sk, sk_data in aws_secret_keys.items():
                if abs(ak_data["start"] - sk_data["start"]) < 3000:
                    pair_conf = 90
                    if pair_conf < min_confidence:
                        continue
                    loc_ak = location_fn_factory(ak_data["line"])
                    loc_sk = location_fn_factory(sk_data["line"])
                    findings.append({
                        "type": "AWS Key Pair",
                        "location": f"AK {loc_ak}, SK {loc_sk}",
                        "value_masked": f"{_mask(ak)} & {_mask(sk)}",
                        "verified": False,
                        "confidence": pair_conf,
                        "severity": "critical",
                        "poc": _poc_command("AWS Key Pair", ""),  # FIX #3: Uses safe PoC without real values
                        "risk": "AWS Access + Secret Key found – possible full account compromise.",
                        "context": _extract_context(content, ak_data["start"], sk_data["end"]),
                    })
                    break

    # Firebase configuration detection
    for match in FIREBASE_CONFIG.finditer(content):
        apikey = match.group(1)
        project_id = match.group(2)
        start, end = match.start(), match.end()
        if any(start < e and end > s for s, e in matched_spans):
            continue
        verified_fb = False
        verify_resp_fb = ""
        async with semaphore:
            fb_result = await _verify_with_retry(_verify_firebase, apikey, session, project_id)
            verified_fb = fb_result.get("verified", False)
            if "preview" in fb_result:
                verify_resp_fb = fb_result["preview"][:300]
            elif "error" in fb_result:
                verify_resp_fb = f"Error: {fb_result['error']}"
        confidence_fb = 95 if verified_fb else 70
        if confidence_fb < min_confidence:
            continue
        severity_fb = "critical" if verified_fb else "medium"
        line_no = _line_number(content, start)
        location = location_fn_factory(line_no)
        evidence = {
            "type": "Firebase Configuration",
            "location": location,
            "value_masked": f"apiKey={_mask(apikey)}, projectId={project_id}",
            "verified": verified_fb,
            "confidence": confidence_fb,
            "severity": severity_fb,
            "poc": f"Firebase project {project_id} with key (see evidence field)",
            "risk": "Firebase configuration verified – API key is active." if verified_fb else "Firebase config exposed – may allow unauthorised access.",
            "context": _extract_context(content, start, end),
        }
        if verify_resp_fb:
            evidence["verification_response"] = verify_resp_fb
        findings.append(evidence)
        matched_spans.append((start, end))

    # High‑entropy generic secrets
    if min_confidence <= 50:
        for match in ENTROPY_CANDIDATE.finditer(content):
            start, end = match.start(), match.end()
            if any(start < e and end > s for s, e in matched_spans):
                continue
            candidate = match.group(1)
            if len(candidate) < 30 or _looks_like_placeholder(candidate):
                continue
            if _shannon_entropy(candidate) < 5.0:
                continue
            ctx_window = content[max(0, start - 60):end + 60]
            if not ENTROPY_CONTEXT.search(ctx_window):
                continue
            if HIGH_ENTROPY_EXCLUDES.search(ctx_window):
                continue
            line_no = _line_number(content, start)
            location = location_fn_factory(line_no)
            findings.append({
                "type": "High‑Entropy Secret",
                "location": location,
                "value_masked": _mask(candidate),
                "verified": False,
                "confidence": 50,
                "severity": "low",
                "poc": "Manual inspection required.",
                "risk": "Unrecognised format but high entropy in credential context.",
                "context": _extract_context(content, start, end),
            })
            matched_spans.append((start, end))

    return findings

# ────────────────────────────────────────────── Main entry point ──────────────────────────────────────────────
async def run(
    url: str,
    shared_page: dict = None,
    verify_live: bool = False,
    session: aiohttp.ClientSession = None,
    min_confidence: int = DEFAULT_MIN_CONFIDENCE,
    *,
    js_cache: dict = None,
    fetch_js: callable = None,
    skip_js_lib_scan: bool = False,
) -> Dict[str, Any]:
    """
    Main entry point for secrets detection.

    FIX: Updated signature to match orchestrator expectations exactly:
    - url, shared_page, verify_live, session, min_confidence as positional
    - js_cache, fetch_js, skip_js_lib_scan as keyword-only

    The orchestrator (main_scanner.py) calls this via introspection with these exact names.

    Returns dict with: test_name, status, severity, title, description, summary, evidence, remediation
    """
    target = url.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    own_session = None
    should_close = False
    if session is None:
        connector = aiohttp.TCPConnector(ssl=True, limit=10, limit_per_host=5)
        headers = {"User-Agent": USER_AGENT}
        own_session = aiohttp.ClientSession(connector=connector, headers=headers, timeout=TIMEOUT)
        should_close = True
    else:
        own_session = session

    findings = []
    resources_scanned = 0
    scanned_urls = []
    fetch_failures = 0  # FIX #1: Track failed fetches for summary
    sem_verify = asyncio.Semaphore(MAX_CONCURRENT_VERIFIES)
    sem_js_fetch = asyncio.Semaphore(MAX_CONCURRENT_JS_FETCHES)

    resp_headers = {}
    raw_set_cookies = []

    try:
        html = None
        status = None
        soup_obj = None

        # Use shared_page if provided by orchestrator
        if shared_page and not shared_page.get("error") and shared_page.get("status") == 200:
            html = shared_page.get("html", "")
            status = shared_page.get("status", 0)
            soup_obj = shared_page.get("soup")
            raw_headers = shared_page.get("headers", {})
            resp_headers = {k.lower(): v for k, v in raw_headers.items()}
            raw_set_cookies = shared_page.get("raw_set_cookies", [])
        else:
            async with own_session.get(target, timeout=aiohttp.ClientTimeout(total=20),
                                       ssl=True, allow_redirects=True) as resp:
                status = resp.status
                if status != 200:
                    return {
                        "test_name": "secrets_detection",
                        "status": "warning",
                        "title": f"HTTP {status} – could not fetch target",
                        "severity": "high",
                        "description": "Deep scanning of client‑side code with active verification, deobfuscation, and header fingerprinting.",
                        "summary": {
                            "total_secrets": 0,
                            "verified_active": 0,
                            "high_confidence_unverified": 0,
                            "forbidden_files_count": 0,
                            "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                            "resources_scanned": 0,
                            "scanned_urls": [],
                            "fetch_failures": 0,
                            "tech_stack_detected": [],
                        },
                        "evidence": [],
                        "remediation": "Check target URL accessibility."
                    }
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                raw_set_cookies = resp.headers.getall("set-cookie")
                body_bytes = await resp.content.read(FETCH_MAX_BYTES_HTML + 1)
                if len(body_bytes) > FETCH_MAX_BYTES_HTML:
                    return {
                        "test_name": "secrets_detection",
                        "status": "warning",
                        "title": f"HTML exceeds size limit ({FETCH_MAX_BYTES_HTML} bytes)",
                        "severity": "medium",
                        "description": "Deep scanning of client‑side code with active verification, deobfuscation, and header fingerprinting.",
                        "summary": {
                            "total_secrets": 0,
                            "verified_active": 0,
                            "high_confidence_unverified": 0,
                            "forbidden_files_count": 0,
                            "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                            "resources_scanned": 0,
                            "scanned_urls": [],
                            "fetch_failures": 0,
                            "tech_stack_detected": [],
                        },
                        "evidence": [],
                        "remediation": "Target page is too large to scan completely."
                    }
                html = body_bytes.decode("utf-8", errors="replace")
                soup_obj = BeautifulSoup(html, "html.parser")

        if not html:
            return {
                "test_name": "secrets_detection",
                "status": "warning",
                "title": "Empty response body",
                "severity": "medium",
                "description": "Deep scanning of client‑side code with active verification, deobfuscation, and header fingerprinting.",
                "summary": {
                    "total_secrets": 0,
                    "verified_active": 0,
                    "high_confidence_unverified": 0,
                    "forbidden_files_count": 0,
                    "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                    "resources_scanned": 0,
                    "scanned_urls": [],
                    "fetch_failures": 0,
                    "tech_stack_detected": [],
                },
                "evidence": [],
                "remediation": "Target returned empty content."
            }

        tech_stack = _fingerprint_from_headers(resp_headers, raw_set_cookies)
        if tech_stack:
            findings.append({
                "type": "Tech Stack (from headers)",
                "location": "HTTP response headers",
                "value_masked": ", ".join(tech_stack),
                "verified": False,
                "confidence": 90,
                "severity": "info",
                "poc": "N/A",
                "risk": f"Detected technologies: {', '.join(tech_stack)}",
                "context": f"Server: {resp_headers.get('server','')}, X-Powered-By: {resp_headers.get('x-powered-by','')}"
            })

        is_generic_403, generic_403_body = await _get_generic_403_info(own_session, target)

        # Extract scripts from HTML
        ext_urls, inline_scripts = _extract_scripts(html, target, soup_obj=soup_obj)

        # FIX #2: Phase 1 - Fast scanning (HTML and inline scripts) - always completes
        # This ensures we have partial results even if external JS scanning times out

        # Scan inline scripts
        for idx, script in enumerate(inline_scripts):
            resources_scanned += 1
            def make_loc_fn(idx):
                return lambda ln: f"Inline script #{idx+1} line {ln}"
            loc_fn = make_loc_fn(idx)
            f = await _scan_content(script, loc_fn, own_session, True, sem_verify,
                                    verify_live=verify_live, min_confidence=min_confidence)
            findings.extend(f)
            decoded_strings, method = _extract_decoded_strings(script)
            if decoded_strings:
                combined = "\n".join(decoded_strings)
                def make_dec_loc_fn(idx, method):
                    return lambda ln: f"Inline script #{idx+1} (decoded {method}) line {ln}"
                dec_loc_fn = make_dec_loc_fn(idx, method)
                f_dec = await _scan_content(combined, dec_loc_fn, own_session, True, sem_verify,
                                            decoded_method=method, verify_live=verify_live,
                                            min_confidence=min_confidence)
                findings.extend(f_dec)

        # Scan HTML content
        def html_loc_fn(ln):
            return f"HTML line {ln}"
        f = await _scan_content(html, html_loc_fn, own_session, False, sem_verify,
                                verify_live=verify_live, min_confidence=min_confidence)
        findings.extend(f)

        # FIX #2: Phase 2 - External JS scanning with internal timeout
        # Wrap external JS fetching in wait_for to catch timeouts and return partial results
        external_findings = []
        external_scanned = 0

        async def _scan_external_js_phase():
            """Scan all external JS files. Can be timed out."""
            nonlocal external_scanned, fetch_failures
            tasks = []
            for u in ext_urls:
                if skip_js_lib_scan:
                    # Skip library scanning if requested
                    if any(lib in u for lib in ['jquery', 'bootstrap', 'react', 'angular', 'vue', 'lodash', 'moment']):
                        continue

                async def fetch_and_scan(url):
                    nonlocal fetch_failures
                    async with sem_js_fetch:
                        # FIX #1 & #5: Use _fetch_one_js which properly logs failures and uses fetch_js callable
                        content = await _fetch_one_js(url, fetch_js, js_cache, own_session)
                        if content is None:
                            fetch_failures += 1
                            return None, url
                        return content, url

                tasks.append(fetch_and_scan(u))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    # This catches exceptions from the gather itself
                    logger.debug(f"Exception during JS fetch: {type(result).__name__}: {result}")
                    fetch_failures += 1
                    continue
                if result is None:
                    continue

                js_content, js_url = result
                if js_content is None:
                    continue

                external_scanned += 1
                scanned_urls.append(js_url)
                filename = urlparse(js_url).path.split("/")[-1] or "external.js"

                def make_js_loc_fn(filename):
                    return lambda ln: f"{filename} line {ln}"
                loc_fn = make_js_loc_fn(filename)

                f = await _scan_content(js_content, loc_fn, own_session, True, sem_verify,
                                        verify_live=verify_live, min_confidence=min_confidence)
                external_findings.extend(f)

                # Also scan decoded strings from external JS
                decoded_strings, method = _extract_decoded_strings(js_content)
                if decoded_strings:
                    combined = "\n".join(decoded_strings)
                    def make_dec_js_loc_fn(filename, method):
                        return lambda ln: f"{filename} (decoded {method}) line {ln}"
                    dec_loc_fn = make_dec_js_loc_fn(filename, method)
                    f_dec = await _scan_content(combined, dec_loc_fn, own_session, True, sem_verify,
                                                decoded_method=method, verify_live=verify_live,
                                                min_confidence=min_confidence)
                    external_findings.extend(f_dec)

            return external_findings

        try:
            # FIX #2: Use internal timeout (45s) to leave room for other operations within orchestrator's 60s
            # If this times out, we still have findings from HTML and inline scripts
            external_findings = await asyncio.wait_for(
                _scan_external_js_phase(),
                timeout=45.0
            )
            findings.extend(external_findings)
            resources_scanned += external_scanned
        except asyncio.TimeoutError:
            # FIX #2: HIGH - Return partial results on timeout
            # Log how many external files were scanned before timeout
            logger.warning(
                f"External JS scan timed out after 45s. "
                f"Scanned {external_scanned} of {len(ext_urls)} external files. "
                f"Returning partial results with {len(findings)} findings so far."
            )
            # Still add whatever external findings we got before timeout
            findings.extend(external_findings)
            resources_scanned += external_scanned
        except asyncio.CancelledError:
            # FIX #2: Handle cancellation gracefully
            logger.warning(
                f"External JS scan cancelled. "
                f"Scanned {external_scanned} of {len(ext_urls)} external files."
            )
            findings.extend(external_findings)
            resources_scanned += external_scanned
        except Exception as e:
            logger.error(f"Unexpected error in external JS scan: {type(e).__name__}: {e}")
            # Still keep partial results
            findings.extend(external_findings)
            resources_scanned += external_scanned

        # Scan risky files (config files, etc.)
        risky_urls = _find_risky_files(html, target, soup_obj=soup_obj)
        for path in SENSITIVE_PATHS:
            risky_urls.append(urljoin(target, path))
        risky_urls = list(set(risky_urls))

        risky_tasks = []
        for furl in risky_urls:
            async def fetch_risky(url):
                return await _fetch_full(own_session, url, max_bytes=8192)
            risky_tasks.append(fetch_risky(furl))

        risky_results = await asyncio.gather(*risky_tasks, return_exceptions=True)
        for i, result in enumerate(risky_results):
            if isinstance(result, Exception) or result is None:
                continue
            status_code, body = result
            file_url = risky_urls[i]
            if status_code in (403, 401):
                if status_code == 403 and is_generic_403:
                    if generic_403_body and body:
                        similarity = difflib.SequenceMatcher(None, body, generic_403_body).ratio()
                        if similarity > 0.9:
                            continue
                parsed_path = urlparse(file_url).path
                is_builtin = any(parsed_path == p for p in SENSITIVE_PATHS)
                confidence = 80 if is_builtin else (70 if status_code == 403 else 60)
                findings.append({
                    "type": "Forbidden Sensitive File",
                    "location": f"{parsed_path} (HTTP {status_code})",
                    "value_masked": file_url,
                    "verified": False,
                    "confidence": confidence,
                    "severity": "low",
                    "poc": f"Check if file is accessible: {file_url}",
                    "risk": f"Sensitive configuration file appears to exist but is forbidden (HTTP {status_code}).",
                    "context": "",
                })
                resources_scanned += 1
                scanned_urls.append(file_url)
            elif body and status_code == 200:
                if _is_soft_404(body):
                    continue
                resources_scanned += 1
                scanned_urls.append(file_url)
                filename = urlparse(file_url).path.split("/")[-1] or "config"
                def risky_loc_fn(ln):
                    return f"{filename} line {ln}"
                f = await _scan_content(body, risky_loc_fn, own_session, False, sem_verify,
                                        verify_live=verify_live, min_confidence=min_confidence)
                findings.extend(f)

    except Exception as e:
        logger.error(f"Critical error in run(): {type(e).__name__}: {e}")
        return {
            "test_name": "secrets_detection",
            "status": "error",
            "title": f"Error: {e}",
            "severity": "critical",
            "description": "Deep scanning of client‑side code with active verification, deobfuscation, and header fingerprinting.",
            "summary": {
                "total_secrets": 0,
                "verified_active": 0,
                "high_confidence_unverified": 0,
                "forbidden_files_count": 0,
                "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                "resources_scanned": resources_scanned,
                "scanned_urls": scanned_urls,
                "fetch_failures": fetch_failures,
                "tech_stack_detected": tech_stack if 'tech_stack' in locals() else [],
            },
            "evidence": findings,
            "remediation": "An unexpected error occurred during scanning."
        }
    finally:
        if should_close and own_session is not None:
            await own_session.close()

    # ── Summary logic ──
    NON_SECRET_TYPES = {"Tech Stack (from headers)"}

    all_secrets = [
        f for f in findings
        if f.get("type") != "Forbidden Sensitive File" and f.get("type") not in NON_SECRET_TYPES
    ]
    forbidden_files = [f for f in findings if f.get("type") == "Forbidden Sensitive File"]

    verified = [s for s in all_secrets if s.get("verified")]
    high_conf = [s for s in all_secrets if s.get("confidence", 0) >= 80 and not s.get("verified")]

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_secrets + forbidden_files:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    if verified:
        status = "fail"
        overall_sev = "critical"
        title = f"{len(verified)} ACTIVE secret(s) found!"
    elif high_conf:
        status = "fail"
        overall_sev = "high"
        title = f"{len(high_conf)} high‑confidence secrets"
    elif all_secrets:
        status = "warning"
        overall_sev = "medium"
        title = f"{len(all_secrets)} potential secrets"
    elif forbidden_files:
        status = "warning"
        overall_sev = "low"
        title = f"Sensitive files detected (403) – {len(forbidden_files)} forbidden"
    else:
        status = "pass"
        overall_sev = "info"
        title = "No secrets detected"

    # FIX #1: Include fetch_failures in summary so callers can see incomplete results
    tech_detected = _fingerprint_from_headers(resp_headers, raw_set_cookies) if resp_headers else []

    return {
        "test_name": "secrets_detection",
        "status": status,
        "severity": overall_sev,
        "title": title,
        "description": "Deep scanning of client‑side code with active verification, deobfuscation, and header fingerprinting.",
        "summary": {
            "total_secrets": len(all_secrets),
            "verified_active": len(verified),
            "high_confidence_unverified": len(high_conf),
            "forbidden_files_count": len(forbidden_files),
            "severity_breakdown": severity_counts,
            "resources_scanned": resources_scanned,
            "scanned_urls": scanned_urls,
            "fetch_failures": fetch_failures,  # FIX #1: Track failed fetches
            "tech_stack_detected": tech_detected,
        },
        "evidence": findings,
        "remediation": "Rotate verified keys immediately. For high‑confidence matches, manual inspection is strongly recommended."
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Bravo6 Ultimate Secrets Hunter')
    parser.add_argument('url', nargs='?', default='https://example.com', help='Target URL')
    parser.add_argument('--verify-live', action='store_true', help='Enable live Anthropic API verification (costs money)')
    parser.add_argument('--min-confidence', type=int, default=DEFAULT_MIN_CONFIDENCE,
                        help=f'Minimum confidence score (0–100, default {DEFAULT_MIN_CONFIDENCE})')
    args = parser.parse_args()
    print(json.dumps(
        asyncio.run(run(args.url, verify_live=args.verify_live, min_confidence=args.min_confidence)),
        indent=2, ensure_ascii=False
    ))