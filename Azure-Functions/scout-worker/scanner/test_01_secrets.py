#!/usr/bin/env python3
"""
Bravo6 Ultimate Secrets Hunter (v5.3 – Shared Page & Rate‑Limit Enhanced)
============================================================================
- Fully leverages shared_page: uses pre‑parsed soup & HTTP headers.
- Adds technology fingerprinting from headers (cookies, server info).
- Implements semaphore‑limited JS fetching to respect server limits.
- All other detection logic (patterns, entropy, active verification) unchanged.
- Fix: lambda-in-loop bug for inline scripts.
- Pre-filter external JS files by Content-Length (skip >500KB).
- Guard Anthropic live verification behind --verify-live flag.
"""

import argparse
import asyncio
import base64
import json
import math
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────
USER_AGENT = "Bravo6-SecretsHunter/5.3"
VERIFY_USER_AGENT = "Bravo6-Verification/2.0"
TIMEOUT = aiohttp.ClientTimeout(total=15)
VERIFY_TIMEOUT = aiohttp.ClientTimeout(total=8)
MAX_CONCURRENT_VERIFIES = 8
MAX_CONCURRENT_JS_FETCHES = 5       # limit parallel JS downloads
MAX_JS_FILES = 15                   # reduced from 30
MAX_INLINE_SCRIPTS = 40
FETCH_MAX_BYTES_HTML = 2 * 1024 * 1024
FETCH_MAX_BYTES_JS   = 1 * 1024 * 1024
JS_SIZE_LIMIT = 500 * 1024          # 500 KB pre-filter

SENSITIVE_PATHS = [
    "/.env", "/config.js", "/credentials.json",
    "/secrets.yaml", "/app.config", "/settings.py",
    "/.git/config", "/config/secrets.yml"
]

GENERIC_403_TEST_PATH = "/Bravo6-Nonexistent-Test-404"

# ──────────────────────────────────────────────────────────────────────────────
# False‑positive filters (unchanged)
# ──────────────────────────────────────────────────────────────────────────────
PLACEHOLDER_MARKERS = (
    "test", "demo", "fake", "example", "sample", "placeholder", "dummy",
    "changeme", "your_", "insert_", "redacted", "xxxxxxxx", "00000000",
    "1234567890", "abcdefgh", "<key>", "<token>", "{api_key}", "${",
    "process.env", "lorem", "foobar", "asdf", "yourkey", "your-api-key",
    "api_key_here", "secret_key_here", "put_your", "replace_me",
)
KNOWN_TEST_PREFIXES = (
    "sk_test_", "pk_test_", "sk_live_",
    "ghp_", "gho_", "ghu_", "ghs_",
    "xoxb-", "xoxp-",
    "SG.",
)
CONTEXT_KEYWORDS = ("key", "secret", "token", "auth", "credential",
                    "password", "api", "access")
HIGH_ENTROPY_EXCLUDES = re.compile(
    r'(encrypted.slate|csrf|nonce|analytics|tracking|gtag|google_tag)',
    re.IGNORECASE
)

def _looks_like_placeholder(value: str) -> bool:
    if not value:
        return True
    low = value.lower()
    for marker in PLACEHOLDER_MARKERS:
        if marker in low:
            return True
    if len(set(low)) <= 3 and len(low) > 5:
        return True
    if value.isdigit() and len(value) < 12:
        return True
    return False

def _is_known_test_key(value: str) -> bool:
    return any(value.startswith(p) for p in KNOWN_TEST_PREFIXES)

def _has_credential_context(text: str, match_start: int, match_end: int) -> bool:
    window_start = max(0, match_start - 40)
    window_end = min(len(text), match_end + 40)
    window = text[window_start:window_end]
    return any(re.search(rf'\b{kw}\b', window, re.IGNORECASE) for kw in CONTEXT_KEYWORDS)

def _is_in_comment(text: str, match_start: int) -> bool:
    line_start = text.rfind('\n', 0, match_start) + 1
    line = text[line_start:match_start].strip()
    return line.startswith('//') or '<!--' in line

def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in freq.values())

def _is_soft_404(html: str) -> bool:
    if not html:
        return False
    if re.search(r'<title>(?:404|Not\s+Found)</title>', html, re.IGNORECASE):
        return True
    if re.search(r'<h1>404</h1>|<p>The page you requested was not found</p>', html, re.IGNORECASE):
        return True
    return False

# ──────────────────────────────────────────────────────────────────────────────
# Active Verification
# ──────────────────────────────────────────────────────────────────────────────
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
            if resp.status in (200, 403):
                return {"verified": True, "status": resp.status, "preview": body[:300]}
            elif resp.status in (404, 401):
                return {"verified": False, "status": resp.status, "preview": body[:300]}
            else:
                return {"verified": False, "status": resp.status, "preview": body[:300]}
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

# ──────────────────────────────────────────────────────────────────────────────
# Secret Patterns (unchanged)
# ──────────────────────────────────────────────────────────────────────────────
SECRET_PATTERNS = [
    ("OpenAI API Key",          re.compile(r'sk-proj-[A-Za-z0-9_\-]{20,}'), 0),
    ("OpenAI API Key",          re.compile(r'sk-(?!ant-|live_|test_|proj-)[A-Za-z0-9]{20,}'), 0),
    ("Anthropic API Key",       re.compile(r'sk-ant-(?:api03-)?[A-Za-z0-9_\-]{20,}'), 0),
    ("Stripe Live Secret Key",  re.compile(r'sk_live_[0-9a-zA-Z]{16,}'), 0),
    ("GitHub Token",            re.compile(r'gh[pusr]_[A-Za-z0-9]{36,}'), 0),
    ("GitHub App Token",        re.compile(r'ghs_[A-Za-z0-9]{36,}'), 0),
    ("GitHub OAuth Token",      re.compile(r'gho_[A-Za-z0-9]{36,}'), 0),
    ("npm Token",               re.compile(r'npm_[A-Za-z0-9]{36,}'), 0),
    ("Docker Token",            re.compile(r'dckr_[A-Za-z0-9]{40,}'), 0),
    ("Slack Token",             re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,48}'), 0),
    ("SendGrid API Key",        re.compile(r'SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}'), 0),
    ("Heroku API Key",          re.compile(r'(HEROKU_API_KEY|heroku_[A-Za-z0-9]{20,})'), 0),
    ("Mailgun API Key",         re.compile(r'key-[a-zA-Z0-9]{32}'), 0),
    ("Supabase Key",            re.compile(r'sb-[a-z0-9]{20,}-[a-z0-9]{20,}'), 0),
    ("Vercel Token",            re.compile(r'[a-zA-Z0-9]{24}\.[a-zA-Z0-9_]{60,70}'), 0),
    ("Cloudflare API Token",    re.compile(r'[A-Za-z0-9_-]{40}'), 0),
    ("MapBox API Key",          re.compile(r'(pk|sk)\.eyJ1Ijoi[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+'), 0),
    ("Google API Key",          re.compile(r'AIza[0-9A-Za-z\-_]{35}'), 0),
    ("Firebase API Key",        re.compile(r'AIza[0-9A-Za-z\-_]{35}'), 0),
    ("Twilio Auth Token",       re.compile(r'SK[0-9a-fA-F]{32}'), 0),
    ("Twilio Account SID",      re.compile(r'AC[0-9a-fA-F]{32}'), 0),
    ("Algolia Application ID",  re.compile(r'[A-Z0-9]{10}'), 0),
    ("Algolia API Key",         re.compile(r'[a-fA-F0-9]{32}'), 0),
    ("AWS Access Key ID",       re.compile(r'AKIA[0-9A-Z]{16}'), 0),
    ("AWS Secret Access Key",   re.compile(r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']'), 1),
    ("AWS4-HMAC-SHA256",        re.compile(r'AWS4-HMAC-SHA256\s+Credential=([A-Z0-9]{16})/[0-9]+/[a-z0-9-]+/[a-z0-9]+/aws4_request'), 1),
    ("AWS Signed Header",       re.compile(r'x-amz-[a-z0-9-]+:\s*([A-Za-z0-9+/=]{30,})'), 1),
    ("Private Key",             re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), 0),
    ("Database Connection",     re.compile(r'(?i)(mongodb(?:\+srv)?|mysql|postgresql|redis|amqp):\/\/[^:\/\s"\'<>]+:[^@\/\s"\'<>]+@[^\s"\'<>]+'), 0),
    ("Bearer Token",            re.compile(r'Bearer\s+([A-Za-z0-9\-_\.]+)'), 1),
    ("JWT Token",               re.compile(r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'), 0),
]

FIREBASE_CONFIG = re.compile(
    r'apiKey\s*:\s*["\'](AIza[0-9A-Za-z\-_]{35})["\'][^}]*projectId\s*:\s*["\']([a-z0-9-]+)["\']',
    re.DOTALL
)

ENTROPY_CANDIDATE = re.compile(r'["\'`]([A-Za-z0-9+/_\-=]{40,})["\'`]')
ENTROPY_CONTEXT = re.compile(r'(?i)(key|token|secret|auth|credential|passwd)')

# ──────────────────────────────────────────────────────────────────────────────
# Helpers (unchanged)
# ──────────────────────────────────────────────────────────────────────────────
def _mask(value: str, keep_start: int = 4, keep_end: int = 4) -> str:
    if len(value) <= keep_start + keep_end:
        return "*" * len(value)
    return f"{value[:keep_start]}...{value[-keep_end:]}"

def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1

def _extract_context(text: str, start: int, end: int) -> str:
    lines = text.splitlines()
    ln = _line_number(text, start) - 1
    ctx = []
    for i in range(max(0, ln-2), min(len(lines), ln+3)):
        ctx.append(f"{i+1}: {lines[i].strip()}")
    return "\n".join(ctx)

def _poc_command(secret_type: str, key: str, url: str = "") -> str:
    if "OpenAI" in secret_type:
        return f'curl https://api.openai.com/v1/models -H "Authorization: Bearer {key}"'
    if "Stripe" in secret_type:
        return f'curl https://api.stripe.com/v1/balance -H "Authorization: Bearer {key}"'
    if "GitHub" in secret_type:
        return f'curl https://api.github.com/user -H "Authorization: token {key}"'
    if "Slack" in secret_type:
        return f'curl https://slack.com/api/auth.test -H "Authorization: Bearer {key}"'
    if "SendGrid" in secret_type:
        return f'curl https://api.sendgrid.com/v3/user/profile -H "Authorization: Bearer {key}"'
    if "Mailgun" in secret_type:
        return f'curl -u "api:{key}" https://api.mailgun.net/v3/domains'
    if "MapBox" in secret_type:
        return f'curl "https://api.mapbox.com/tokens/v1?access_token={key}"'
    if "Database" in secret_type:
        return f"Use connection string: {key}"
    if "Bearer" in secret_type or "JWT" in secret_type:
        return f'curl -H "Authorization: Bearer {key}" <TARGET_URL>'
    if "AWS" in secret_type:
        if "Secret" in secret_type:
            return f"aws sts get-caller-identity --secret-access-key {key} (needs Access Key)"
        return f"aws sts get-caller-identity --access-key-id {key} (needs Secret Key)"
    if "AWS4" in secret_type:
        return f"AWS4 signing key: {key}. Needs secret access key for full verification."
    return f"Manual verification for {secret_type}."

def _risk_description(secret_type: str, verified: bool, note: str = "") -> str:
    if verified:
        return f"ACTIVE CREDENTIAL: {secret_type} grants unauthorised access."
    if note:
        return f"Unverified {secret_type}: {note}"
    return f"High‑confidence pattern for {secret_type}; manual verification needed."

# ──────────────────────────────────────────────────────────────────────────────
# Deobfuscation (unchanged)
# ──────────────────────────────────────────────────────────────────────────────
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

# ──────────────────────────────────────────────────────────────────────────────
# Header‑based technology fingerprinting (NEW)
# ──────────────────────────────────────────────────────────────────────────────
def _fingerprint_from_headers(resp_headers: Dict[str, str]) -> List[str]:
    """Return a list of detected technologies from HTTP response headers."""
    tech = []
    server = resp_headers.get("server", "")
    powered = resp_headers.get("x-powered-by", "")
    generator = resp_headers.get("x-generator", "")
    cookies = resp_headers.get("set-cookie", "")

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

    # Session cookies hints
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
            tech.append(name.capitalize() if name != "aspnet" else "ASP.NET")
            break  # avoid duplicate

    return list(set(tech))

# ──────────────────────────────────────────────────────────────────────────────
# Scanning core
# ──────────────────────────────────────────────────────────────────────────────
async def _scan_content(content: str, location_fn, session: aiohttp.ClientSession,
                        is_script: bool, semaphore: asyncio.Semaphore,
                        decoded_method: Optional[str] = None,
                        verify_live: bool = False) -> List[dict]:
    findings = []
    matched_spans = []
    aws_access_keys: Dict[str, dict] = {}
    aws_secret_keys: Dict[str, dict] = {}

    for label, pattern, group_idx in SECRET_PATTERNS:
        for match in pattern.finditer(content):
            try:
                value = match.group(group_idx) if group_idx else match.group(0)
                start, end = match.start(group_idx) if group_idx else match.start(), match.end()
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

            if label == "Cloudflare API Token":
                ctx = content[max(0, start-40):start] + content[end:end+40]
                if not re.search(r'(cloudflare|cf_)', ctx, re.IGNORECASE):
                    continue
            if label == "Vercel Token":
                ctx = content[max(0, start-40):start] + content[end:end+40]
                if not re.search(r'vercel', ctx, re.IGNORECASE):
                    continue
            if label in ("Twilio Auth Token", "Twilio Account SID"):
                if not _has_credential_context(content, start, end):
                    continue
            if label in ("Algolia Application ID", "Algolia API Key"):
                ctx = content[max(0, start-40):start] + content[end:end+40]
                if not re.search(r'algolia', ctx, re.IGNORECASE):
                    continue
            if label == "Bearer Token":
                win = content[max(0, start-80):end+80]
                if not re.search(r'(?:Authorization|auth)', win, re.IGNORECASE):
                    continue

            if _shannon_entropy(value) < 4.0 and label not in (
                "AWS Access Key ID", "AWS4-HMAC-SHA256", "AWS Signed Header"
            ):
                continue

            if label in ("AWS Access Key ID", "AWS Secret Access Key"):
                if label == "AWS Access Key ID":
                    aws_access_keys[value] = {"start": start, "end": end, "line": _line_number(content, start)}
                else:
                    aws_secret_keys[value] = {"start": start, "end": end, "line": _line_number(content, start)}
                matched_spans.append((start, end))
                continue

            # Guard for Anthropic live verification
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

            confidence = 100 if verified else 80 if label in (
                "Bearer Token", "JWT Token", "Database Connection", "Private Key",
                "AWS Secret Access Key", "AWS Access Key ID", "Heroku API Key",
                "Cloudflare API Token", "Vercel Token", "Supabase Key", "Docker Token",
                "npm Token", "AWS4-HMAC-SHA256", "AWS Signed Header"
            ) else 60
            severity = "critical" if verified else "high" if confidence >= 80 else "medium"

            line_no = _line_number(content, start)
            context = _extract_context(content, start, end)
            poc = _poc_command(label, value)

            evidence = {
                "type": label,
                "location": location_fn(line_no),
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

    if aws_access_keys and aws_secret_keys:
        for ak, ak_data in aws_access_keys.items():
            for sk, sk_data in aws_secret_keys.items():
                if abs(ak_data["start"] - sk_data["start"]) < 3000:
                    findings.append({
                        "type": "AWS Key Pair",
                        "location": f"AK line {ak_data['line']}, SK line {sk_data['line']}",
                        "value_masked": f"{_mask(ak)} & {_mask(sk)}",
                        "verified": False,
                        "confidence": 90,
                        "severity": "critical",
                        "poc": f"aws sts get-caller-identity --access-key-id {ak} --secret-access-key {sk}",
                        "risk": "AWS Access + Secret Key found – possible full account compromise.",
                        "context": _extract_context(content, ak_data["start"], sk_data["end"]),
                    })
                    break

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
        severity_fb = "critical" if verified_fb else "medium"
        line_no = _line_number(content, start)
        evidence = {
            "type": "Firebase Configuration",
            "location": location_fn(line_no),
            "value_masked": f"apiKey={_mask(apikey)}, projectId={project_id}",
            "verified": verified_fb,
            "confidence": confidence_fb,
            "severity": severity_fb,
            "poc": f"Firebase project {project_id} with key {_mask(apikey)}",
            "risk": "Firebase configuration verified – API key is active." if verified_fb else "Firebase config exposed – may allow unauthorised access.",
            "context": _extract_context(content, start, end),
        }
        if verify_resp_fb:
            evidence["verification_response"] = verify_resp_fb
        findings.append(evidence)
        matched_spans.append((start, end))

    for match in ENTROPY_CANDIDATE.finditer(content):
        start, end = match.start(), match.end()
        if any(start < e and end > s for s, e in matched_spans):
            continue
        candidate = match.group(1)
        if len(candidate) < 30 or _looks_like_placeholder(candidate):
            continue
        if _shannon_entropy(candidate) < 5.0:
            continue
        if not ENTROPY_CONTEXT.search(content[max(0, start-30):start]):
            continue
        ctx_window = content[max(0, start-50):start] + content[end:end+50]
        if HIGH_ENTROPY_EXCLUDES.search(ctx_window):
            continue
        line_no = _line_number(content, start)
        findings.append({
            "type": "High‑Entropy Secret",
            "location": location_fn(line_no),
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

# ──────────────────────────────────────────────────────────────────────────────
# Fetch helpers
# ──────────────────────────────────────────────────────────────────────────────
async def _fetch_text(session, url, max_bytes=FETCH_MAX_BYTES_JS, timeout=8):
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=True) as resp:
            if resp.status != 200:
                return None, resp.status, "Not 200"
            content = await resp.read()
            if len(content) > max_bytes:
                return None, resp.status, "Too large"
            return content.decode("utf-8", errors="replace"), resp.status, None
    except Exception as e:
        return None, None, str(e)

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
            if content:
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
                if any(abs_url.endswith(ext) for ext in (".env", ".json", ".yaml", ".yml", ".config", ".conf", ".properties", ".xml", ".toml")) or "secret" in abs_url.lower():
                    risky.add(abs_url)
    if isinstance(soup_or_html, str):
        for m in re.finditer(r'https?://[^\s"\'<>]+', soup_or_html):
            u = m.group(0)
            if any(u.endswith(ext) for ext in (".env", ".json", ".yaml", ".yml", ".config", ".conf", ".properties", ".xml", ".toml")) or "secret" in u.lower():
                risky.add(u)
    return list(risky)[:10]

async def _server_returns_403_for_everything(session, base_url):
    test_url = urljoin(base_url, GENERIC_403_TEST_PATH)
    try:
        _, status, _ = await _fetch_text(session, test_url, max_bytes=1024, timeout=5)
        return status == 403
    except:
        return False

# ──────────────────────────────────────────────────────────────────────────────
# Main entry point
# ──────────────────────────────────────────────────────────────────────────────
async def run(url: str, shared_page: dict = None, verify_live: bool = False) -> Dict[str, Any]:
    target = url.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    print(f"[*] Secrets Hunter scanning {target}")
    connector = aiohttp.TCPConnector(ssl=True, limit=10, limit_per_host=5)
    headers = {"User-Agent": USER_AGENT}
    findings = []
    resources_scanned = 0
    scanned_urls = []
    sem_verify = asyncio.Semaphore(MAX_CONCURRENT_VERIFIES)
    sem_js_fetch = asyncio.Semaphore(MAX_CONCURRENT_JS_FETCHES)

    try:
        async with aiohttp.ClientSession(connector=connector, headers=headers, timeout=TIMEOUT) as session:
            html = None
            status = None
            resp_headers = {}
            soup_obj = None

            if shared_page and not shared_page.get("error") and shared_page.get("status") == 200:
                html = shared_page.get("html", "")
                status = shared_page.get("status", 0)
                soup_obj = shared_page.get("soup")
                raw_headers = shared_page.get("headers", {})
                resp_headers = {k.lower(): v for k, v in raw_headers.items()}
            else:
                async with session.get(target, timeout=aiohttp.ClientTimeout(total=20), ssl=True, allow_redirects=True) as resp:
                    status = resp.status
                    if status != 200:
                        return {
                            "test_name": "secrets_detection",
                            "status": "warning",
                            "title": f"HTTP {status} – could not fetch target",
                            "evidence": []
                        }
                    html = await resp.text(errors="replace")
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    soup_obj = BeautifulSoup(html, "html.parser")

            if not html:
                return {
                    "test_name": "secrets_detection",
                    "status": "warning",
                    "title": "Empty response body",
                    "evidence": []
                }

            # Technology fingerprint from headers
            tech_stack = _fingerprint_from_headers(resp_headers)
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

            generic_403 = await _server_returns_403_for_everything(session, target)

            ext_urls, inline_scripts = _extract_scripts(html, target, soup_obj=soup_obj)

            # Inline scripts (fixed lambda-in-loop bug)
            for idx, script in enumerate(inline_scripts):
                resources_scanned += 1
                loc_fn = lambda ln, i=idx: f"Inline script #{i+1} line {ln}"
                f = await _scan_content(script, loc_fn, session, True, sem_verify, verify_live=verify_live)
                findings.extend(f)

                decoded_strings, method = _extract_decoded_strings(script)
                if decoded_strings:
                    combined = "\n".join(decoded_strings)
                    dec_loc_fn = lambda ln, i=idx, m=method: f"Inline script #{i+1} (decoded {m}) line {ln}"
                    f_dec = await _scan_content(combined, dec_loc_fn, session, True, sem_verify, decoded_method=method, verify_live=verify_live)
                    findings.extend(f_dec)

            # External JS files with Content-Length pre-filter
            async def _fetch_limited(js_url):
                async with sem_js_fetch:
                    # HEAD request to check size
                    try:
                        async with session.head(js_url, timeout=aiohttp.ClientTimeout(total=5)) as head_resp:
                            if head_resp.status == 200:
                                cl = head_resp.content_length
                                if cl is not None and cl > JS_SIZE_LIMIT:
                                    return None, 200, "Skipped: Content-Length > 500KB"
                    except Exception:
                        pass
                    return await _fetch_text(session, js_url)

            tasks = [_fetch_limited(u) for u in ext_urls]
            fetched = await asyncio.gather(*tasks, return_exceptions=True)

            for i, result in enumerate(fetched):
                if isinstance(result, Exception) or result is None or result[0] is None:
                    continue
                js_content, status_code, _ = result
                if status_code != 200:
                    continue
                resources_scanned += 1
                scanned_urls.append(ext_urls[i])
                filename = urlparse(ext_urls[i]).path.split("/")[-1] or "external.js"
                loc_fn = lambda ln, fn=filename: f"{fn} line {ln}"
                f = await _scan_content(js_content, loc_fn, session, True, sem_verify, verify_live=verify_live)
                findings.extend(f)

                decoded_strings, method = _extract_decoded_strings(js_content)
                if decoded_strings:
                    combined = "\n".join(decoded_strings)
                    dec_loc_fn = lambda ln, fn=filename, m=method: f"{fn} (decoded {m}) line {ln}"
                    f_dec = await _scan_content(combined, dec_loc_fn, session, True, sem_verify, decoded_method=method, verify_live=verify_live)
                    findings.extend(f_dec)

            # Raw HTML scan
            f = await _scan_content(html, lambda ln: f"HTML line {ln}", session, False, sem_verify, verify_live=verify_live)
            findings.extend(f)

            # Risky files
            risky_urls = _find_risky_files(html, target, soup_obj=soup_obj)
            for path in SENSITIVE_PATHS:
                risky_urls.append(urljoin(target, path))
            risky_urls = list(set(risky_urls))

            risky_tasks = [_fetch_limited(furl) for furl in risky_urls]
            risky_results = await asyncio.gather(*risky_tasks, return_exceptions=True)
            for i, result in enumerate(risky_results):
                if isinstance(result, Exception) or result is None:
                    continue
                content, status_code, error = result
                file_url = risky_urls[i]
                if status_code in (403, 401):
                    if status_code == 403 and generic_403:
                        continue
                    parsed_path = urlparse(file_url).path
                    is_builtin = any(parsed_path == p for p in SENSITIVE_PATHS)
                    confidence = 80 if is_builtin else (70 if status_code == 403 else 60)
                    severity = "low"
                    findings.append({
                        "type": "Forbidden Sensitive File",
                        "location": f"{parsed_path} (HTTP {status_code})",
                        "value_masked": file_url,
                        "verified": False,
                        "confidence": confidence,
                        "severity": severity,
                        "poc": f"Check if file is accessible: {file_url}",
                        "risk": f"Sensitive configuration file appears to exist but is forbidden (HTTP {status_code}).",
                        "context": "",
                    })
                    resources_scanned += 1
                    scanned_urls.append(file_url)
                elif content and status_code == 200:
                    if _is_soft_404(content):
                        continue
                    resources_scanned += 1
                    scanned_urls.append(file_url)
                    filename = urlparse(file_url).path.split("/")[-1] or "config"
                    loc_fn = lambda ln, fn=filename: f"{fn} line {ln}"
                    f = await _scan_content(content, loc_fn, session, False, sem_verify, verify_live=verify_live)
                    findings.extend(f)

    except Exception as e:
        return {"test_name": "secrets_detection", "status": "error", "title": f"Error: {e}", "evidence": []}

    # Summary
    verified = [f for f in findings if f.get("verified")]
    high_conf = [f for f in findings if f.get("confidence", 0) >= 80 and not f.get("verified")]
    forbidden_files = [f for f in findings if f.get("type") == "Forbidden Sensitive File"]
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    if verified:
        status, overall_sev, title = "fail", "critical", f"{len(verified)} ACTIVE secret(s) found!"
    elif high_conf:
        status, overall_sev, title = "fail", "high", f"{len(high_conf)} high‑confidence secrets"
    elif findings:
        status, overall_sev, title = "warning", "medium", f"{len(findings)} potential secrets"
    else:
        status, overall_sev, title = "pass", "info", "No secrets detected"

    print(f"[+] Done. {len(findings)} findings, {len(verified)} verified.")
    return {
        "test_name": "secrets_detection",
        "status": status,
        "severity": overall_sev,
        "title": title,
        "description": "Deep scanning of client‑side code with active verification, deobfuscation, and header fingerprinting.",
        "summary": {
            "total_secrets": len(findings),
            "verified_active": len(verified),
            "high_confidence_unverified": len(high_conf),
            "forbidden_files_count": len(forbidden_files),
            "severity_breakdown": severity_counts,
            "resources_scanned": resources_scanned,
            "scanned_urls": scanned_urls,
            "tech_stack_detected": _fingerprint_from_headers(resp_headers) if 'resp_headers' in locals() else [],
        },
        "evidence": findings,
        "remediation": "Rotate verified keys immediately. For high‑confidence matches, manual inspection is strongly recommended."
    }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Bravo6 Ultimate Secrets Hunter')
    parser.add_argument('url', nargs='?', default='https://example.com', help='Target URL')
    parser.add_argument('--verify-live', action='store_true', help='Enable live Anthropic API verification (costs money)')
    args = parser.parse_args()
    print(json.dumps(asyncio.run(run(args.url, verify_live=args.verify_live)), indent=2, ensure_ascii=False))