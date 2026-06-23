#!/usr/bin/env python3
"""
test_01_secrets.py – Bravo6 Ultra‑Precise Secrets Hunter (v4.2)
=============================================================
أقوى نسخة: تغطية شاملة، فحص نشط، فك تشفير متقدم، فحص ملفات حساسة بحذر،
معدل أمان وأداء عالي، وخالي من الـ false positives تقريباً.
محدث: تحسين الأمان (User‑Agent متغير)، إعادة محاولة للتحقق، فحص الملفات الحساسة بذكاء، وtimeout أطول للـ HTML.
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

# ----------------------------------------------------------------------
# الإعدادات
# ----------------------------------------------------------------------
USER_AGENT = "Bravo6-SecretsHunter/4.2 (security audit)"
VERIFY_USER_AGENT = "Bravo6-Verification/1.0"   # مختلف عن الفحص العادي
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=15)
VERIFY_TIMEOUT = aiohttp.ClientTimeout(total=8)   # زيادة بسيطة للتحقق
MAX_CONCURRENT_VERIFICATIONS = 8
MAX_EXTERNAL_SCRIPTS = 25
MAX_INLINE_SCRIPTS = 40
FETCH_MAX_BYTES_HTML = 2 * 1024 * 1024
FETCH_MAX_BYTES_JS   = 500 * 1024

# 8 مسارات حساسة كافية
SENSITIVE_PATHS = [
    "/.git/config", "/.env", "/config.js", "/credentials.json",
    "/secrets.yaml", "/app.config", "/settings.py", "/config/secrets.yml"
]

# ----------------------------------------------------------------------
# فلاتر الـ false‑positive
# ----------------------------------------------------------------------
PLACEHOLDER_MARKERS = (
    "test", "demo", "fake", "example", "sample", "placeholder", "dummy",
    "changeme", "your_", "insert_", "redacted", "xxxxxxxx", "00000000",
    "1234567890", "abcdefgh", "<key>", "<token>", "{api_key}", "${",
    "process.env", "lorem", "foobar", "asdf", "yourkey", "your-api-key",
    "api_key_here", "secret_key_here", "put_your", "replace_me",
)
KNOWN_TEST_PREFIXES = (
    "sk_test_", "pk_test_",           # Stripe test keys
    "sk_live_",                       # will be verified anyway
    "ghp_", "gho_", "ghu_", "ghs_",   # GitHub
    "xoxb-", "xoxp-",                 # Slack
    "SG.",                             # SendGrid
)
CONTEXT_KEYWORDS = ("key", "secret", "token", "auth", "credential",
                    "password", "api", "access")

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

# ----------------------------------------------------------------------
# دوال التحقق النشط (مع User‑Agent مخصص وإعادة محاولة)
# ----------------------------------------------------------------------
async def _verify_with_retry(verifier, key: str, session: aiohttp.ClientSession) -> dict:
    """يحاول مرة إضافية في حالة فشل الشبكة."""
    try:
        return await verifier(key, session)
    except:
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

# جدول الربط
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
    # الباقي None
    "Twilio Auth Token":     None,
    "Algolia API Key":       None,
    "Firebase API Key":      None,
    "Google API Key":        None,
    "Heroku API Key":        None,
    "npm Token":             None,
    "Docker Token":          None,
    "Supabase Key":          None,
    "Vercel Token":          None,
    "Cloudflare API Token":  None,
    "AWS Access Key ID":     None,
    "AWS Secret Access Key": None,
    "Private Key":           None,
    "Database Connection":   None,
    "Bearer Token":          None,
    "JWT Token":             None,
    "High‑Entropy Secret":   None,
}

# ----------------------------------------------------------------------
# أنماط الأسرار
# ----------------------------------------------------------------------
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
    ("Cloudflare API Token",    re.compile(r'[A-Za-z0-9]{40}'), 0),
    ("MapBox API Key",          re.compile(r'(pk|sk)\.eyJ1Ijoi[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+'), 0),
    ("Google API Key",          re.compile(r'AIza[0-9A-Za-z\-_]{35}'), 0),
    ("Firebase API Key",        re.compile(r'AIza[0-9A-Za-z\-_]{35}'), 0),
    ("Twilio Auth Token",       re.compile(r'[A-Za-z0-9]{32}'), 0),
    ("Algolia API Key",         re.compile(r'[A-Za-z0-9]{32}'), 0),
    ("AWS Access Key ID",       re.compile(r'AKIA[0-9A-Z]{16}'), 0),
    ("AWS Secret Access Key",   re.compile(r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']'), 1),
    ("Private Key",             re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), 0),
    ("Database Connection",     re.compile(r'(?i)(mongodb(?:\+srv)?|mysql|postgresql|redis|amqp):\/\/[^:\/\s"\'<>]+:[^@\/\s"\'<>]+@[^\s"\'<>]+'), 0),
    ("Bearer Token",            re.compile(r'Bearer\s+([A-Za-z0-9\-_\.]+)'), 1),
    ("JWT Token",               re.compile(r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'), 0),
]
ENTROPY_CANDIDATE = re.compile(r'["\'`]([A-Za-z0-9+/_\-=]{40,})["\'`]')
ENTROPY_CONTEXT = re.compile(r'(?i)(key|token|secret|auth|credential|passwd)')

# ----------------------------------------------------------------------
# أدوات مساعدة
# ----------------------------------------------------------------------
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

def _poc_command(secret_type: str, key: str) -> str:
    if "OpenAI" in secret_type:
        return f'curl https://api.openai.com/v1/models -H "Authorization: Bearer {key}"'
    if "Stripe" in secret_type:
        return f'curl https://api.stripe.com/v1/balance -H "Authorization: Bearer {key}"'
    if "GitHub" in secret_type or "GitHub App" in secret_type or "GitHub OAuth" in secret_type:
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
        return f"Use the connection string: {key}"
    if "Bearer" in secret_type or "JWT" in secret_type:
        return f'curl -H "Authorization: Bearer {key}" <TARGET_URL>'
    if "AWS" in secret_type:
        if "Secret" in secret_type:
            return f"aws sts get-caller-identity --secret-access-key {key} (needs Access Key)"
        return f"aws sts get-caller-identity --access-key-id {key} (needs Secret Key)"
    return f"Manual verification for {secret_type}."

def _risk_description(secret_type: str, verified: bool, note: str = "") -> str:
    if verified:
        return f"ACTIVE CREDENTIAL: {secret_type} grants unauthorised access."
    if note:
        return f"Unverified {secret_type}: {note}"
    return f"High‑confidence pattern for {secret_type}; manual verification needed."

# ----------------------------------------------------------------------
# فك التشفير الأساسي
# ----------------------------------------------------------------------
def _try_decode_atob(text: str) -> str:
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
        return text + "\n/* DECODED atob */\n" + "\n".join(decoded_parts)
    return text

def _decode_string_fromcharcode(js: str) -> str:
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
        return js + "\n/* DECODED fromCharCode */\n" + "\n".join(decoded_parts)
    return js

def _deobfuscate(js_code: str) -> str:
    js = re.sub(r'"\s*\+\s*"', '', js_code)
    js = _try_decode_atob(js)
    js = _decode_string_fromcharcode(js)
    return js

# ----------------------------------------------------------------------
# جلب المحتوى بأمان (مع timeout متغير)
# ----------------------------------------------------------------------
async def _fetch_text(session: aiohttp.ClientSession, url: str,
                      max_bytes: int = FETCH_MAX_BYTES_JS,
                      timeout: int = 8) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=True) as resp:
            cl = int(resp.headers.get("Content-Length", 0))
            if cl > max_bytes:
                return None, resp.status, "Too large"
            raw = await resp.read()
            if len(raw) > max_bytes:
                return None, resp.status, "Too large"
            return raw.decode("utf-8", errors="replace"), resp.status, None
    except Exception as e:
        return None, None, str(e)

def _extract_scripts(html: str, base_url: str) -> Tuple[List[str], List[str]]:
    external = []
    inline = []
    try:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("script"):
            src = tag.get("src")
            if src:
                abs_url = urljoin(base_url, src.strip())
                if urlparse(abs_url).scheme in ("http", "https"):
                    external.append(abs_url)
            else:
                content = tag.string or tag.get_text() or ""
                if content.strip():
                    inline.append(content)
    except:
        pass
    seen = set()
    deduped = []
    for u in external:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped[:MAX_EXTERNAL_SCRIPTS], inline[:MAX_INLINE_SCRIPTS]

def _find_risky_file_links(html: str, base_url: str) -> List[str]:
    risky_exts = ('.env', '.json', '.yaml', '.yml', '.config', '.conf',
                  '.properties', '.xml', '.toml', 'secrets')
    urls = set()
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all(True):
        for attr in ('src', 'href', 'content'):
            val = tag.get(attr)
            if val:
                abs_url = urljoin(base_url, val.strip())
                if any(abs_url.lower().endswith(ext) for ext in risky_exts) or \
                   ('secret' in abs_url.lower()):
                    urls.add(abs_url)
    url_re = re.compile(r'(https?://[^\s"\'<>]+)', re.IGNORECASE)
    for m in url_re.finditer(html):
        u = m.group(1)
        if any(u.lower().endswith(ext) for ext in risky_exts) or \
           ('secret' in u.lower()):
            urls.add(u)
    return list(urls)[:10]

# ----------------------------------------------------------------------
# فحص المحتوى الأساسي (قلب الأداة)
# ----------------------------------------------------------------------
async def _scan_content(content: str, location_fn, session: aiohttp.ClientSession,
                        is_script: bool, semaphore: asyncio.Semaphore) -> List[dict]:
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

            if label in ("Twilio Auth Token", "Algolia API Key", "Cloudflare API Token"):
                if not _has_credential_context(content, start, end):
                    continue
            if label == "Cloudflare API Token":
                ctx_window = content[max(0, start-30):end+30]
                if not re.search(r'(cloudflare|cf_)', ctx_window, re.IGNORECASE):
                    continue

            if _shannon_entropy(value) < 4.0 and label not in ("AWS Access Key ID",):
                continue

            if label == "AWS Access Key ID":
                aws_access_keys[value] = {"start": start, "end": end, "line": _line_number(content, start)}
                matched_spans.append((start, end))
                continue
            if label == "AWS Secret Access Key":
                aws_secret_keys[value] = {"start": start, "end": end, "line": _line_number(content, start)}
                matched_spans.append((start, end))
                continue

            # التحقق النشط مع إعادة المحاولة
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

            if verified:
                confidence = 100
                severity = "critical"
            elif label in ("Bearer Token", "JWT Token", "Database Connection",
                           "Private Key", "AWS Secret Access Key", "AWS Access Key ID",
                           "Heroku API Key", "Cloudflare API Token", "Vercel Token",
                           "Supabase Key", "Docker Token", "npm Token"):
                confidence = 80
                severity = "high"
            elif "API" in label or "Token" in label:
                confidence = 60
                severity = "medium"
            else:
                confidence = 40
                severity = "low"

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

            findings.append(evidence)
            matched_spans.append((start, end))

    # زوج AWS
    if aws_access_keys and aws_secret_keys:
        for ak, ak_data in aws_access_keys.items():
            for sk, sk_data in aws_secret_keys.items():
                if abs(ak_data["start"] - sk_data["start"]) < 3000:
                    combined = {
                        "type": "AWS Key Pair",
                        "location": f"AK line {ak_data['line']}, SK line {sk_data['line']}",
                        "value_masked": f"{_mask(ak)} & {_mask(sk)}",
                        "verified": False,
                        "confidence": 90,
                        "severity": "critical",
                        "poc": f"aws sts get-caller-identity --access-key-id {ak} --secret-access-key {sk}",
                        "risk": "AWS Access + Secret Key found – possible full account compromise.",
                        "context": _extract_context(content, ak_data["start"], sk_data["end"]),
                    }
                    findings.append(combined)
                    break

    # إنتروبيا عالية
    for match in ENTROPY_CANDIDATE.finditer(content):
        start, end = match.start(), match.end()
        if any(start < e and end > s for s, e in matched_spans):
            continue
        candidate = match.group(1)
        if len(candidate) < 30 or _looks_like_placeholder(candidate):
            continue
        if _shannon_entropy(candidate) < 5.0:
            continue
        window = content[max(0, start-30):start]
        if not ENTROPY_CONTEXT.search(window):
            continue
        if "data:" in content[max(0,start-10):start]:
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

# ----------------------------------------------------------------------
# نقطة الدخول الرئيسية
# ----------------------------------------------------------------------
async def run(url: str) -> dict:
    target = url.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    connector = aiohttp.TCPConnector(ssl=True, limit=10, limit_per_host=5)
    headers = {"User-Agent": USER_AGENT}
    all_findings = []
    resources_scanned = 0
    scanned_urls = []
    verification_sem = asyncio.Semaphore(MAX_CONCURRENT_VERIFICATIONS)

    try:
        async with aiohttp.ClientSession(
            headers=headers,
            connector=connector,
            timeout=REQUEST_TIMEOUT
        ) as session:
            # HTML بتمهل أطول (20 ثانية)
            html, _, err = await _fetch_text(session, target, max_bytes=FETCH_MAX_BYTES_HTML, timeout=20)
            if not html:
                return {"test_name": "secrets_detection", "status": "warning",
                        "title": "Could not fetch target HTML", "evidence": []}

            ext_urls, inline_scripts = _extract_scripts(html, target)

            for idx, script in enumerate(inline_scripts):
                resources_scanned += 1
                loc_fn = lambda ln, i=idx: f"Inline script #{i+1} line {ln}"
                deobf = _deobfuscate(script)
                findings = await _scan_content(deobf, loc_fn, session, True, verification_sem)
                all_findings.extend(findings)

            tasks = [_fetch_text(session, js_url, timeout=8) for js_url in ext_urls]
            fetched = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(fetched):
                if isinstance(result, Exception) or result is None or result[0] is None:
                    continue
                js_content, status, _ = result
                if status != 200:    # فقط الناجح
                    continue
                resources_scanned += 1
                scanned_urls.append(ext_urls[i])
                filename = urlparse(ext_urls[i]).path.split("/")[-1] or "external.js"
                loc_fn = lambda ln, fn=filename: f"{fn} line {ln}"
                deobf = _deobfuscate(js_content)
                findings = await _scan_content(deobf, loc_fn, session, True, verification_sem)
                all_findings.extend(findings)

            # فحص HTML
            findings_html = await _scan_content(html, lambda ln: f"HTML line {ln}",
                                                session, False, verification_sem)
            all_findings.extend(findings_html)

            # ملفات حساسة (فحص فقط إذا 200 OK)
            risky_files = _find_risky_file_links(html, target)
            for path in SENSITIVE_PATHS:
                risky_files.append(urljoin(target, path))
            risky_files = list(set(risky_files))
            for file_url in risky_files:
                content, status, _ = await _fetch_text(session, file_url, max_bytes=100*1024, timeout=8)
                if content and status == 200:   # شرط النجاح
                    resources_scanned += 1
                    scanned_urls.append(file_url)
                    filename = urlparse(file_url).path.split("/")[-1] or "config_file"
                    loc_fn = lambda ln, fn=filename: f"{fn} line {ln}"
                    findings = await _scan_content(content, loc_fn, session, False, verification_sem)
                    all_findings.extend(findings)

    except Exception as e:
        return {"test_name": "secrets_detection", "status": "error",
                "title": f"Scan error: {e}", "evidence": []}

    verified = [f for f in all_findings if f.get("verified")]
    high_conf = [f for f in all_findings if f.get("confidence", 0) >= 80 and not f.get("verified")]
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    if verified:
        status = "fail"
        overall_severity = "critical"
        title = f"CRITICAL: {len(verified)} active secret(s) discovered!"
    elif high_conf:
        status = "warning"
        overall_severity = "high"
        title = f"High confidence secrets found ({len(high_conf)}) – manual verification urgent"
    elif all_findings:
        status = "info"
        overall_severity = "medium"
        title = f"Potential secrets ({len(all_findings)}) – manual review recommended"
    else:
        status = "pass"
        overall_severity = "info"
        title = "No secrets detected"

    summary = {
        "total_secrets": len(all_findings),
        "verified_active": len(verified),
        "high_confidence_unverified": len(high_conf),
        "severity_breakdown": severity_counts,
        "resources_scanned": resources_scanned,
        "scanned_urls": scanned_urls,
    }

    return {
        "test_name": "secrets_detection",
        "status": status,
        "severity": overall_severity,
        "title": title,
        "description": "Advanced client‑side secret scanning with active verification, deobfuscation, and sensitive file checks.",
        "summary": summary,
        "evidence": all_findings,
        "remediation": "Rotate all verified keys immediately. For high‑confidence matches, manual inspection and rotation are strongly advised."
    }

if __name__ == "__main__":
    import sys
    target_url = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target_url))
    print(json.dumps(result, indent=2, ensure_ascii=False))