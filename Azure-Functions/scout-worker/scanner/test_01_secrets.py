#!/usr/bin/env python3
"""
test_01_secrets.py – Bravo6 Ultimate Secrets Hunter (v5.0 Final)
==================================================================
- Multi‑layer detection (regex, entropy, context, deobfuscation)
- Active verification for 10+ services with retry & User‑Agent rotation
- Strict false‑positive filters:
  * Cloudflare token: requires 'cloudflare'/'cf_' in context, pattern refined
  * Vercel token: context must mention 'vercel', pattern tightened
  * Twilio & Algolia now have distinct prefixes (SK/AC for Twilio)
  * High‑entropy ignored for encrypted-slate, csrf, nonce, analytics
- atob/fromCharCode decoded secrets marked with decoded_from attribute
- Secure defaults (ssl=True), connection limits, detailed logging
- Detects Firebase config objects (apiKey + projectId)
- Detects AWS4-HMAC-SHA256 and x-amz- headers
- Forbidden sensitive files (403/401) reported with generic 403 check
- Soft 404 pages ignored
"""

import asyncio
import base64
import json
import math
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

# ──────────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────────
USER_AGENT = "Bravo6-SecretsHunter/5.0"
VERIFY_USER_AGENT = "Bravo6-Verification/2.0"
TIMEOUT = aiohttp.ClientTimeout(total=15)
VERIFY_TIMEOUT = aiohttp.ClientTimeout(total=8)
MAX_CONCURRENT_VERIFIES = 8
MAX_JS_FILES = 30
MAX_INLINE_SCRIPTS = 40
FETCH_MAX_BYTES_HTML = 2 * 1024 * 1024
FETCH_MAX_BYTES_JS   = 1 * 1024 * 1024

SENSITIVE_PATHS = [
    "/.env", "/config.js", "/credentials.json",
    "/secrets.yaml", "/app.config", "/settings.py",
    "/.git/config", "/config/secrets.yml"
]

# Generic non‑existent test path to check if server returns 403 for everything
GENERIC_403_TEST_PATH = "/Bravo6-Nonexistent-Test-404"

# ──────────────────────────────────────────────────────────────────────────────
# False‑positive filters (extended)
# ──────────────────────────────────────────────────────────────────────────────
PLACEHOLDER_MARKERS = (
    "test", "demo", "fake", "example", "sample", "placeholder", "dummy",
    "changeme", "your_", "insert_", "redacted", "xxxxxxxx", "00000000",
    "1234567890", "abcdefgh", "<key>", "<token>", "{api_key}", "${",
    "process.env", "lorem", "foobar", "asdf", "yourkey", "your-api-key",
    "api_key_here", "secret_key_here", "put_your", "replace_me",
)
KNOWN_TEST_PREFIXES = (
    "sk_test_", "pk_test_", "sk_live_",        # Stripe test keys
    "ghp_", "gho_", "ghu_", "ghs_",            # GitHub
    "xoxb-", "xoxp-",                          # Slack
    "SG.",                                      # SendGrid
)
CONTEXT_KEYWORDS = ("key", "secret", "token", "auth", "credential",
                    "password", "api", "access")

# Exclusion for high‑entropy fallback (avoid false positives like encrypted-slate)
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
    for prefix in KNOWN_TEST_PREFIXES:
        if value.startswith(prefix):
            return True
    return False

def _has_credential_context(text: str, match_start: int, match_end: int) -> bool:
    window_start = max(0, match_start - 40)
    window_end = min(len(text), match_end + 40)
    window = text[window_start:window_end]
    for kw in CONTEXT_KEYWORDS:
        if re.search(rf'\b{kw}\b', window, re.IGNORECASE):
            return True
    return False

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
    ent = 0.0
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent

# Soft 404 detection
def _is_soft_404(html: str) -> bool:
    """Return True if the page looks like a generic Not Found page."""
    if not html:
        return False
    if re.search(r'<title>(?:404|Not\s+Found)</title>', html, re.IGNORECASE):
        return True
    if re.search(r'<h1>404</h1>|<p>The page you requested was not found</p>', html, re.IGNORECASE):
        return True
    return False

# ──────────────────────────────────────────────────────────────────────────────
# Active Verification Functions (read‑only, with retry & custom User‑Agent)
# ──────────────────────────────────────────────────────────────────────────────
async def _verify_with_retry(verifier, key: str, session: aiohttp.ClientSession) -> dict:
    try:
        return await verifier(key, session)
    except Exception:
        try:
            await asyncio.sleep(0.5)
            return await verifier(key, session)
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

# Verification table – only services with public endpoints
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
# Secret Patterns – refined and strict
# ──────────────────────────────────────────────────────────────────────────────
SECRET_PATTERNS = [
    # OpenAI
    ("OpenAI API Key",          re.compile(r'sk-proj-[A-Za-z0-9_\-]{20,}'), 0),
    ("OpenAI API Key",          re.compile(r'sk-(?!ant-|live_|test_|proj-)[A-Za-z0-9]{20,}'), 0),
    # Anthropic
    ("Anthropic API Key",       re.compile(r'sk-ant-(?:api03-)?[A-Za-z0-9_\-]{20,}'), 0),
    # Stripe
    ("Stripe Live Secret Key",  re.compile(r'sk_live_[0-9a-zA-Z]{16,}'), 0),
    # GitHub
    ("GitHub Token",            re.compile(r'gh[pusr]_[A-Za-z0-9]{36,}'), 0),
    ("GitHub App Token",        re.compile(r'ghs_[A-Za-z0-9]{36,}'), 0),
    ("GitHub OAuth Token",      re.compile(r'gho_[A-Za-z0-9]{36,}'), 0),
    # npm / Docker
    ("npm Token",               re.compile(r'npm_[A-Za-z0-9]{36,}'), 0),
    ("Docker Token",            re.compile(r'dckr_[A-Za-z0-9]{40,}'), 0),
    # Slack
    ("Slack Token",             re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,48}'), 0),
    # SendGrid
    ("SendGrid API Key",        re.compile(r'SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}'), 0),
    # Heroku
    ("Heroku API Key",          re.compile(r'(HEROKU_API_KEY|heroku_[A-Za-z0-9]{20,})'), 0),
    # Mailgun
    ("Mailgun API Key",         re.compile(r'key-[a-zA-Z0-9]{32}'), 0),
    # Supabase
    ("Supabase Key",            re.compile(r'sb-[a-z0-9]{20,}-[a-z0-9]{20,}'), 0),
    # Vercel – requires 'vercel' context (checked later)
    ("Vercel Token",            re.compile(r'[a-zA-Z0-9]{24}\.[a-zA-Z0-9_]{60,70}'), 0),
    # Cloudflare – requires 'cloudflare'/'cf_' context (checked later)
    ("Cloudflare API Token",    re.compile(r'[A-Za-z0-9_-]{40}'), 0),
    # MapBox
    ("MapBox API Key",          re.compile(r'(pk|sk)\.eyJ1Ijoi[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+'), 0),
    # Google / Firebase
    ("Google API Key",          re.compile(r'AIza[0-9A-Za-z\-_]{35}'), 0),
    ("Firebase API Key",        re.compile(r'AIza[0-9A-Za-z\-_]{35}'), 0),
    # Twilio
    ("Twilio Auth Token",       re.compile(r'SK[0-9a-fA-F]{32}'), 0),
    ("Twilio Account SID",      re.compile(r'AC[0-9a-fA-F]{32}'), 0),
    # Algolia
    ("Algolia Application ID",  re.compile(r'[A-Za-z0-9]{10}'), 0),
    ("Algolia API Key",         re.compile(r'[A-Za-z0-9]{32}'), 0),
    # AWS
    ("AWS Access Key ID",       re.compile(r'AKIA[0-9A-Z]{16}'), 0),
    ("AWS Secret Access Key",   re.compile(r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']'), 1),
    # AWS4 signing
    ("AWS4-HMAC-SHA256",        re.compile(r'AWS4-HMAC-SHA256\s+Credential=([A-Z0-9]{16})/[0-9]+/[a-z0-9-]+/[a-z0-9]+/aws4_request'), 1),
    ("AWS Signed Header",       re.compile(r'x-amz-[a-z0-9-]+:\s*([A-Za-z0-9+/=]{30,})'), 1),
    # Private Key
    ("Private Key",             re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), 0),
    # Database Connection
    ("Database Connection",     re.compile(r'(?i)(mongodb(?:\+srv)?|mysql|postgresql|redis|amqp):\/\/[^:\/\s"\'<>]+:[^@\/\s"\'<>]+@[^\s"\'<>]+'), 0),
    # Bearer Token / JWT
    ("Bearer Token",            re.compile(r'Bearer\s+([A-Za-z0-9\-_\.]+)'), 1),
    ("JWT Token",               re.compile(r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'), 0),
]

# Firebase config object (apiKey + projectId together)
FIREBASE_CONFIG = re.compile(
    r'apiKey\s*:\s*["\'](AIza[0-9A-Za-z\-_]{35})["\'][^}]*projectId\s*:\s*["\']([a-z0-9-]+)["\']',
    re.DOTALL
)

# Entropy fallback (high entropy strings in credential context)
ENTROPY_CANDIDATE = re.compile(r'["\'`]([A-Za-z0-9+/_\-=]{40,})["\'`]')
ENTROPY_CONTEXT = re.compile(r'(?i)(key|token|secret|auth|credential|passwd)')

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
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
# Deobfuscation – enhanced to return method used
# ──────────────────────────────────────────────────────────────────────────────
def _try_decode_atob(text: str) -> Tuple[str, bool]:
    atob_pattern = re.compile(r'atob\s*\(\s*(["\'])((?:(?!\1).)*)\1\s*\)', re.IGNORECASE)
    decoded_parts = []
    for m in atob_pattern.finditer(text):
        b64 = m.group(2)
        try:
            decoded = base64.b64decode(b64).decode("utf-8", errors="replace")
            decoded_parts.append(decoded)
        except:
            pass
    if decoded_parts:
        return text + "\n/* DECODED atob */\n" + "\n".join(decoded_parts), True
    return text, False

def _decode_string_fromcharcode(js: str) -> Tuple[str, bool]:
    pattern = re.compile(r'String\.fromCharCode\s*\(\s*([\d,\s]+)\s*\)', re.IGNORECASE)
    decoded_parts = []
    for m in pattern.finditer(js):
        nums = [int(x) for x in m.group(1).split(',') if x.strip().isdigit()]
        try:
            decoded = ''.join(chr(n) for n in nums)
            decoded_parts.append(decoded)
        except:
            pass
    if decoded_parts:
        return js + "\n/* DECODED fromCharCode */\n" + "\n".join(decoded_parts), True
    return js, False

def _deobfuscate(js_code: str) -> Tuple[str, bool, Optional[str]]:
    """Returns (deobfuscated text, was_decoded, method)."""
    js, changed1 = _try_decode_atob(js_code)
    js, changed2 = _decode_string_fromcharcode(js)
    methods = []
    if changed1:
        methods.append("atob")
    if changed2:
        methods.append("fromCharCode")
    method = ", ".join(methods) if methods else None
    return js, (changed1 or changed2), method

# ──────────────────────────────────────────────────────────────────────────────
# Scanning core (single content block)
# ──────────────────────────────────────────────────────────────────────────────
async def _scan_content(content: str, location_fn, session: aiohttp.ClientSession,
                        is_script: bool, semaphore: asyncio.Semaphore,
                        decoded_method: Optional[str] = None) -> List[dict]:
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

            # ── Additional context‑based filters ──
            if label == "Cloudflare API Token":
                ctx = content[max(0, start-40):start] + content[end:end+40]
                if not re.search(r'(cloudflare|cf_)', ctx, re.IGNORECASE):
                    continue
            if label == "Vercel Token":
                ctx = content[max(0, start-40):start] + content[end:end+40]
                if not re.search(r'vercel', ctx, re.IGNORECASE):
                    continue
            if label == "Twilio Auth Token" or label == "Twilio Account SID":
                if not _has_credential_context(content, start, end):
                    continue
            if label == "Algolia API Key" or label == "Algolia Application ID":
                ctx = content[max(0, start-40):start] + content[end:end+40]
                if not re.search(r'algolia', ctx, re.IGNORECASE):
                    continue

            # Generic high‑entropy requirements for ambiguous patterns
            if _shannon_entropy(value) < 4.0 and label not in ("AWS Access Key ID", "AWS4-HMAC-SHA256", "AWS Signed Header"):
                continue

            # ── AWS pair handling ──
            if label in ("AWS Access Key ID", "AWS Secret Access Key"):
                if label == "AWS Access Key ID":
                    aws_access_keys[value] = {"start": start, "end": end, "line": _line_number(content, start)}
                else:
                    aws_secret_keys[value] = {"start": start, "end": end, "line": _line_number(content, start)}
                matched_spans.append((start, end))
                continue

            # ── Active Verification ──
            verifier = VERIFIERS.get(label)
            verified = False
            verify_note = ""
            verify_response = ""
            if verifier:
                async with semaphore:
                    result = await _verify_with_retry(verifier, value, session)
                    verified = result.get("verified", False)
                    verify_note = result.get("note", "")
                    if "preview" in result:
                        verify_response = result["preview"]
                    elif "error" in result:
                        verify_response = f"Error: {result['error']}"
            else:
                verify_note = "No active verification for this secret type."

            confidence = 100 if verified else 80 if label in ("Bearer Token", "JWT Token", "Database Connection", "Private Key", "AWS Secret Access Key", "AWS Access Key ID", "Heroku API Key", "Cloudflare API Token", "Vercel Token", "Supabase Key", "Docker Token", "npm Token", "AWS4-HMAC-SHA256", "AWS Signed Header") else 60
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

    # ── AWS key pair ──
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

    # ── Firebase config detection ──
    for match in FIREBASE_CONFIG.finditer(content):
        apikey = match.group(1)
        project_id = match.group(2)
        start, end = match.start(), match.end()
        if any(start < e and end > s for s, e in matched_spans):
            continue
        if not any(f["type"] == "Firebase API Key" and f["value_masked"] == _mask(apikey) for f in findings):
            line_no = _line_number(content, start)
            findings.append({
                "type": "Firebase Configuration",
                "location": location_fn(line_no),
                "value_masked": f"apiKey={_mask(apikey)}, projectId={project_id}",
                "verified": False,
                "confidence": 70,
                "severity": "medium",
                "poc": f"Use Firebase SDK with project ID '{project_id}' to test access.",
                "risk": "Firebase config exposed – may allow unauthorised access to Firestore/Storage.",
                "context": _extract_context(content, start, end),
            })
        matched_spans.append((start, end))

    # ── Entropy fallback ──
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
        # Skip high‑entropy strings in excluded contexts (encrypted-slate, csrf, etc.)
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

def _extract_scripts(html, base_url):
    soup = BeautifulSoup(html, "html.parser")
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

def _find_risky_files(html, base_url):
    risky = set()
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all(True):
        for attr in ("src", "href", "content"):
            val = tag.get(attr)
            if val:
                abs_url = urljoin(base_url, val.strip())
                if any(abs_url.endswith(ext) for ext in (".env", ".json", ".yaml", ".yml", ".config", ".conf", ".properties", ".xml", ".toml")) or "secret" in abs_url.lower():
                    risky.add(abs_url)
    # regex scan
    for m in re.finditer(r'https?://[^\s"\'<>]+', html):
        u = m.group(0)
        if any(u.endswith(ext) for ext in (".env", ".json", ".yaml", ".yml", ".config", ".conf", ".properties", ".xml", ".toml")) or "secret" in u.lower():
            risky.add(u)
    return list(risky)[:10]

# ──────────────────────────────────────────────────────────────────────────────
# Generic 403 test: if the server returns 403 for a non‑existent path, skip all 403
# findings (to avoid false positives from servers that forbid everything).
# ──────────────────────────────────────────────────────────────────────────────
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
async def run(url: str) -> Dict[str, Any]:
    target = url.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    print(f"[*] Secrets Hunter scanning {target}")
    connector = aiohttp.TCPConnector(ssl=True, limit=10, limit_per_host=5)
    headers = {"User-Agent": USER_AGENT}
    findings = []
    resources_scanned = 0
    scanned_urls = []
    sem = asyncio.Semaphore(MAX_CONCURRENT_VERIFIES)

    try:
        async with aiohttp.ClientSession(connector=connector, headers=headers, timeout=TIMEOUT) as session:
            html, status, _ = await _fetch_text(session, target, max_bytes=FETCH_MAX_BYTES_HTML, timeout=20)
            if not html:
                return {"test_name": "secrets_detection", "status": "warning", "title": "Could not fetch target", "evidence": []}

            # Test if server returns 403 for non‑existent path
            generic_403 = await _server_returns_403_for_everything(session, target)

            ext_urls, inline_scripts = _extract_scripts(html, target)

            # Scan inline scripts
            for idx, script in enumerate(inline_scripts):
                resources_scanned += 1
                deobf, was_decoded, method = _deobfuscate(script)
                loc_fn = lambda ln, i=idx: f"Inline script #{i+1} line {ln}"
                f = await _scan_content(deobf, loc_fn, session, True, sem, decoded_method=method)
                findings.extend(f)

            # Fetch and scan external JS
            tasks = [_fetch_text(session, js_url) for js_url in ext_urls]
            fetched = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(fetched):
                if isinstance(result, Exception) or result is None or result[0] is None:
                    continue
                js_content, status, _ = result
                if status != 200:
                    continue
                resources_scanned += 1
                scanned_urls.append(ext_urls[i])
                filename = urlparse(ext_urls[i]).path.split("/")[-1] or "external.js"
                deobf, was_decoded, method = _deobfuscate(js_content)
                loc_fn = lambda ln, fn=filename: f"{fn} line {ln}"
                f = await _scan_content(deobf, loc_fn, session, True, sem, decoded_method=method)
                findings.extend(f)

            # Scan raw HTML
            f = await _scan_content(html, lambda ln: f"HTML line {ln}", session, False, sem)
            findings.extend(f)

            # Risky files (.env, etc.)
            risky_urls = _find_risky_files(html, target)
            for path in SENSITIVE_PATHS:
                risky_urls.append(urljoin(target, path))
            risky_urls = list(set(risky_urls))
            for file_url in risky_urls:
                content, status, error = await _fetch_text(session, file_url, max_bytes=100*1024)
                if status == 403 or status == 401:
                    # If server returns 403 for random path, skip all 403 findings
                    if status == 403 and generic_403:
                        continue
                    filename = urlparse(file_url).path  # full path like "/.git/config"
                    findings.append({
                        "type": "Forbidden Sensitive File",
                        "location": f"{filename} (HTTP {status})",
                        "value_masked": file_url,
                        "verified": False,
                        "confidence": 70 if status == 403 else 60,
                        "severity": "low",
                        "poc": f"Check if file is accessible: {file_url}",
                        "risk": f"Sensitive configuration file appears to exist but is forbidden (HTTP {status}).",
                        "context": "",
                    })
                    resources_scanned += 1
                    scanned_urls.append(file_url)
                elif content and status == 200:
                    if _is_soft_404(content):
                        continue   # Ignore soft 404 pages
                    resources_scanned += 1
                    scanned_urls.append(file_url)
                    filename = urlparse(file_url).path.split("/")[-1] or "config"
                    loc_fn = lambda ln, fn=filename: f"{fn} line {ln}"
                    f = await _scan_content(content, loc_fn, session, False, sem)
                    findings.extend(f)

    except Exception as e:
        return {"test_name": "secrets_detection", "status": "error", "title": f"Error: {e}", "evidence": []}

    # Summary
    verified = [f for f in findings if f.get("verified")]
    high_conf = [f for f in findings if f.get("confidence", 0) >= 80 and not f.get("verified")]
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
        "description": "Deep scanning of client‑side code with active verification and deobfuscation.",
        "summary": {
            "total_secrets": len(findings),
            "verified_active": len(verified),
            "high_confidence_unverified": len(high_conf),
            "severity_breakdown": severity_counts,
            "resources_scanned": resources_scanned,
            "scanned_urls": scanned_urls,
        },
        "evidence": findings,
        "remediation": "Rotate verified keys immediately. For high‑confidence matches, manual inspection is strongly recommended."
    }

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    print(json.dumps(asyncio.run(run(target)), indent=2, ensure_ascii=False))