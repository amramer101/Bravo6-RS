#!/usr/bin/env python3
"""
Bravo6 Ultimate Secrets Hunter (v8.5.0 – Enterprise Grade)
=========================================================
- Content-based secret discovery engine with enhanced accuracy.
- Zero brute-forcing: strictly relies on referenced content and extracted context.
- Fixed 403 handling: correctly interprets access denials as informational/protected.
- Strict context-driven detection: avoids generic tech word noise.
- Live verification strictly opt-in, properly tiered confidence scores.
- Fully adheres to Bravo6 Unified Plugin Contract v8.5.
"""

import argparse
import asyncio
import base64
import json
import logging
import math
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────── Configuration ──────────────────────────────────────────────
USER_AGENT = "Bravo6-SecretsHunter/8.5.0"
VERIFY_USER_AGENT = "Bravo6-Verification/2.0"
VERIFY_TIMEOUT = aiohttp.ClientTimeout(total=8)
MAX_CONCURRENT_VERIFIES = 8
MAX_JS_FILES = 20
INLINE_SCRIPT_MAX_BYTES = 500 * 1024
FETCH_MAX_BYTES_HTML = 3 * 1024 * 1024

# Stop scanning known third-party libraries (prevents noise & saves time)
BENIGN_DOMAINS_RE = re.compile(
    r'(?i)(google-analytics\.com|googletagmanager\.com|recaptcha|sentry\.io|cloudflare\.com|'
    r'unpkg\.com|cdnjs\.cloudflare\.com|jsdelivr\.net|stripe\.com/v3|paypal\.com|'
    r'jquery|bootstrap|react|angular|vue|lodash|moment)'
)

# ────────────────────────────────────────────── False‑positive filters ──────────────────────────────────────
PLACEHOLDER_REGEX = re.compile(
    r'^(test|demo|dummy|example|changeme|placeholder|your[_\-]?api[_\-]?key|insert[_\-]?key|'
    r'redacted|<key>|<token>|replace_me|your[_\-]?secret|api_key_here|secret_key_here|\$\{.*?\})$',
    re.IGNORECASE
)

# Requires credential-shaped context with assignment (e.g., api_key = "...", "secret": "...")
CREDENTIAL_CONTEXT_RE = re.compile(
    r'(?i)\b(?:api[_\-]?key|secret|token|password|passwd|auth[_\-]?token|credential|dsn|access[_\-]?key)\b\s*["\']?\s*[:=]\s*["\']?'
)

# ────────────────────────────────────────────── Secret Metadata ──────────────────────────────────────────────
SECRET_METADATA = {
    "OpenAI API Key": {"cwe": "CWE-798", "owasp": "A07:2021", "remediation": "Remove the key from source code. Use environment variables or a secrets manager."},
    "Anthropic API Key": {"cwe": "CWE-798", "owasp": "A07:2021", "remediation": "Remove the key from source code. Use environment variables or a secrets manager."},
    "Stripe Live Secret Key": {"cwe": "CWE-798", "owasp": "A07:2021", "remediation": "Rotate the Stripe secret key immediately. Use environment variables."},
    "GitHub Token": {"cwe": "CWE-798", "owasp": "A07:2021", "remediation": "Revoke the GitHub token and generate a new one. Use GitHub Actions secrets."},
    "Slack Token": {"cwe": "CWE-798", "owasp": "A07:2021", "remediation": "Revoke the Slack token and rotate it. Use environment variables."},
    "SendGrid API Key": {"cwe": "CWE-798", "owasp": "A07:2021", "remediation": "Delete the SendGrid API key and create a new one. Store securely."},
    "Mailgun API Key": {"cwe": "CWE-798", "owasp": "A07:2021", "remediation": "Rotate the Mailgun API key. Use environment variables."},
    "MapBox API Key": {"cwe": "CWE-798", "owasp": "A07:2021", "remediation": "Rotate the MapBox token. Restrict URL scopes if possible."},
    "AWS Access Key ID": {"cwe": "CWE-798", "owasp": "A07:2021", "remediation": "Deactivate the AWS access key. Use IAM roles or AWS Secrets Manager."},
    "AWS Secret Access Key": {"cwe": "CWE-798", "owasp": "A07:2021", "remediation": "Deactivate the AWS secret key. Use IAM roles or AWS Secrets Manager."},
    "Database Connection": {"cwe": "CWE-798", "owasp": "A07:2021", "remediation": "Rotate database credentials. Use environment variables or a secrets manager."},
    "Generic High-Entropy Secret": {"cwe": "CWE-798", "owasp": "A07:2021", "remediation": "Verify if this is a real secret. If so, rotate it and move to a secrets manager."},
}

# ────────────────────────────────────────────── Helper Functions ──────────────────────────────────────────────
def _looks_like_placeholder(value: str) -> bool:
    if not value:
        return True
    if PLACEHOLDER_REGEX.match(value):
        return True
    if re.match(r'^(.)\1+$', value):  # Catches "xxxxxxxx", "00000000"
        return True
    if re.match(r'^[0-9]+$', value) and len(value) < 20:  # Pure numbers (often IDs, not secrets)
        return True
    if "00000000-0000-0000-0000-000000000000" in value:
        return True
    if "example.com" in value.lower():
        return True
    # If string is entirely 2 alternating characters, it's a dummy (e.g. "abababab")
    if len(set(value.lower())) <= 2 and len(value) > 5:
        return True
    return False

def _has_credential_context(text: str, match_start: int, window: int = 80) -> bool:
    start_win = max(0, match_start - window)
    snippet = text[start_win:match_start]
    return bool(CREDENTIAL_CONTEXT_RE.search(snippet))

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

def _mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"

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

# ────────────────────────────────────────────── Active Verification ──────────────────────────────────────────
async def _verify_with_retry(verifier, key, session, *args) -> dict:
    max_attempts = 2
    for i in range(max_attempts):
        try:
            result = await verifier(key, session, *args)
            if result.get("status") == 429 and i < max_attempts - 1:
                await asyncio.sleep(1.0)
                continue
            return result
        except Exception as e:
            if i < max_attempts - 1:
                await asyncio.sleep(1.0)
                continue
            return {"verified": False, "error": str(e), "status": 0}
    return {"verified": False, "status": 0}

async def _verify_openai(key: str, session: aiohttp.ClientSession) -> dict:
    url = "https://api.openai.com/v1/models"
    headers = {"Authorization": f"Bearer {key}", "User-Agent": VERIFY_USER_AGENT}
    async with session.get(url, headers=headers, timeout=VERIFY_TIMEOUT) as resp:
        return {"verified": resp.status == 200, "status": resp.status}

async def _verify_stripe(key: str, session: aiohttp.ClientSession) -> dict:
    url = "https://api.stripe.com/v1/balance"
    headers = {"Authorization": f"Bearer {key}", "User-Agent": VERIFY_USER_AGENT}
    async with session.get(url, headers=headers, timeout=VERIFY_TIMEOUT) as resp:
        return {"verified": resp.status == 200, "status": resp.status}

async def _verify_github(key: str, session: aiohttp.ClientSession) -> dict:
    url = "https://api.github.com/rate_limit"
    headers = {"Authorization": f"token {key}", "User-Agent": VERIFY_USER_AGENT}
    async with session.get(url, headers=headers, timeout=VERIFY_TIMEOUT) as resp:
        return {"verified": resp.status == 200, "status": resp.status}

VERIFIERS = {
    "OpenAI API Key": _verify_openai,
    "Stripe Live Secret Key": _verify_stripe,
    "GitHub Token": _verify_github,
}

# ────────────────────────────────────────────── Secret Patterns ──────────────────────────────────────────────
SECRET_PATTERNS = [
    ("OpenAI API Key",          re.compile(r'sk-[A-Za-z0-9_\-]{20,}'), 0, True),
    ("Anthropic API Key",       re.compile(r'sk-ant-[A-Za-z0-9_\-]{20,}'), 0, True),
    ("Stripe Live Secret Key",  re.compile(r'sk_live_[0-9a-zA-Z]{16,}'), 0, True),
    ("GitHub Token",            re.compile(r'gh[pusr]_[A-Za-z0-9]{36,}'), 0, True),
    ("Slack Token",             re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,48}'), 0, True),
    ("SendGrid API Key",        re.compile(r'SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}'), 0, True),
    ("Mailgun API Key",         re.compile(r'key-[a-zA-Z0-9]{32}'), 0, True),
    ("AWS Access Key ID",       re.compile(r'AKIA[0-9A-Z]{16}'), 0, True),
    ("AWS Secret Access Key",   re.compile(r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']'), 1, True),
    ("Database Connection",     re.compile(r'(?i)(mongodb(?:\+srv)?|mysql|postgresql|redis|amqp):\/\/[^:\/\s"\'<>]+:[^@\/\s"\'<>]+@[^\s"\'<>]+'), 0, True),
    ("Generic High-Entropy Secret", re.compile(r'["\'`]([A-Za-z0-9+/_\-=]{32,})["\'`]'), 1, False)
]

# ────────────────────────────────────────────── Extraction / Deobfuscation ───────────────────────────────────
def _extract_decoded_strings(content: str) -> Tuple[List[str], Optional[str]]:
    decoded = []
    methods = []
    
    atob_pat = re.compile(r'atob\s*\(\s*(["\'])((?:(?!\1).)*)\1\s*\)', re.IGNORECASE)
    for m in atob_pat.finditer(content):
        b64 = m.group(2)
        try:
            decoded.append(base64.b64decode(b64).decode("utf-8", errors="replace"))
            if "atob" not in methods: methods.append("atob")
        except: pass
    
    hex_pat = re.compile(r'((?:\\x[0-9a-fA-F]{2}){4,})')
    for m in hex_pat.finditer(content):
        try:
            decoded.append(bytes(m.group(1), 'utf-8').decode('unicode_escape'))
            if "hex_escape" not in methods: methods.append("hex_escape")
        except: pass
    
    uni_pat = re.compile(r'((?:\\u[0-9a-fA-F]{4}){4,})')
    for m in uni_pat.finditer(content):
        try:
            decoded.append(bytes(m.group(1), 'utf-8').decode('unicode_escape'))
            if "unicode_escape" not in methods: methods.append("unicode_escape")
        except: pass
    
    unique = list(set([s for s in decoded if len(s) > 10]))
    method_str = ", ".join(methods) if methods else None
    return unique, method_str

def _extract_scripts(soup: BeautifulSoup, base_url: str):
    external, inline = [], []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            abs_url = urljoin(base_url, src.strip())
            if not BENIGN_DOMAINS_RE.search(abs_url) and urlparse(abs_url).scheme in ("http", "https"):
                external.append(abs_url)
        else:
            content = (tag.string or "").strip()
            if content and len(content) <= INLINE_SCRIPT_MAX_BYTES:
                inline.append(content)
    return list(dict.fromkeys(external))[:MAX_JS_FILES], inline

def _find_referenced_configs(soup: BeautifulSoup, html: str, base_url: str) -> List[str]:
    risky = set()
    for tag in soup.find_all(True):
        for attr in ("src", "href", "content", "data-url"):
            val = tag.get(attr)
            if val and isinstance(val, str):
                parsed = urlparse(urljoin(base_url, val.strip()))
                if any(parsed.path.lower().endswith(ext) for ext in (".env", ".json", ".yaml", ".yml", ".config", ".conf", ".properties")):
                    risky.add(parsed.geturl())
    return list(risky)[:10]

# ────────────────────────────────────────────── Core Scanning ────────────────────────────────────────────────
async def _scan_content(
    content: str,
    source_name: str,
    source_url: str,
    session: aiohttp.ClientSession,
    is_script: bool,
    semaphore: asyncio.Semaphore,
    verify_live: bool = False
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
            if is_script and _is_in_comment(content, start):
                continue
            
            if not is_high_conf:
                if not _has_credential_context(content, start):
                    continue
                if _shannon_entropy(value) < 4.0:
                    continue
            
            if label == "AWS Access Key ID":
                aws_access_keys[value] = {"start": start, "end": end, "line": _line_number(content, start), "consumed": False}
                matched_spans.append((start, end))
                continue
            if label == "AWS Secret Access Key":
                aws_secret_keys[value] = {"start": start, "end": end, "line": _line_number(content, start), "consumed": False}
                matched_spans.append((start, end))
                continue

            verifier = VERIFIERS.get(label)
            verified_result = None
            
            if verifier and verify_live:
                async with semaphore:
                    verified_result = await _verify_with_retry(verifier, value, session)
            
            confidence_tier = "verified-static"
            severity = "high"
            title = f"{label} Exposed in {source_name}"
            
            if verified_result:
                if verified_result.get("verified"):
                    confidence_tier = "verified-live"
                    severity = "critical"
                elif verified_result.get("status") in (400, 401, 403):
                    confidence_tier = "informational"
                    severity = "info"
                    title = f"Revoked/Invalid {label} found in {source_name}"
            elif not is_high_conf:
                confidence_tier = "plausible-unconfirmed"
            
            line_no = _line_number(content, start)
            context = _extract_context(content, start, end)
            metadata = SECRET_METADATA.get(label, {"cwe": "CWE-798", "owasp": "A07:2021", "remediation": "Rotate immediately."})
            poc = f"curl -s '{source_url}' | grep -F '{_mask(value)[:4]}'" if not verified_result else "See verification API response"
            
            finding = {
                "title": title,
                "severity": severity,
                "confidence": confidence_tier,
                "cwe": metadata.get("cwe", "CWE-798"),
                "owasp": metadata.get("owasp", "A07:2021"),
                "location": f"{source_url} (line {line_no})",
                "evidence": f"Matched value: {_mask(value)}\nContext:\n{context}",
                "poc": poc,
                "remediation": metadata.get("remediation"),
                "detection_method": "Regex Pattern Match" if is_high_conf else "Entropy + Context Analysis",
            }
            findings.append(finding)
            matched_spans.append((start, end))

    for ak_val, ak_data in aws_access_keys.items():
        for sk_val, sk_data in aws_secret_keys.items():
            if abs(ak_data["start"] - sk_data["start"]) < 3000:
                findings.append({
                    "title": f"AWS Key Pair Exposed in {source_name}",
                    "severity": "critical",
                    "confidence": "verified-static",
                    "cwe": "CWE-798",
                    "owasp": "A07:2021",
                    "location": f"{source_url} (lines {ak_data['line']} and {sk_data['line']})",
                    "evidence": f"Access Key: {_mask(ak_val)}\nSecret Key: {_mask(sk_val)}\nContext:\n{_extract_context(content, ak_data['start'], sk_data['end'])}",
                    "poc": f"aws sts get-caller-identity --access-key-id {ak_val} --secret-access-key <SECRET>",
                    "remediation": "Deactivate the AWS access key and secret key immediately.",
                    "detection_method": "Secret Correlation",
                })
                ak_data["consumed"] = True
                sk_data["consumed"] = True

    for label, keys_dict in [("AWS Access Key ID", aws_access_keys), ("AWS Secret Access Key", aws_secret_keys)]:
        for key_val, key_data in keys_dict.items():
            if not key_data["consumed"]:
                line_no = key_data["line"]
                findings.append({
                    "title": f"{label} Exposed in {source_name}",
                    "severity": "high",
                    "confidence": "verified-static",
                    "cwe": "CWE-798",
                    "owasp": "A07:2021",
                    "location": f"{source_url} (line {line_no})",
                    "evidence": f"Matched value: {_mask(key_val)}\nContext:\n{_extract_context(content, key_data['start'], key_data['end'])}",
                    "poc": f"curl -s '{source_url}' | grep -F '{_mask(key_val)[:4]}'",
                    "remediation": "Deactivate the exposed key immediately.",
                    "detection_method": "Regex Pattern Match",
                })

    return findings

# ────────────────────────────────────────────── Main Entry Point ──────────────────────────────────────────────
async def run(ctx: Any) -> Dict[str, Any]:
    """Entry point for the scout utilizing the v8.5 ScannerContext."""
    try:
        target = ctx.url
        own_session = ctx.session
        shared_page = getattr(ctx, "main_page_cache", {})
        js_cache = getattr(ctx, "js_cache", {})
        verify_live = ctx.config.get("verify_live", False) if hasattr(ctx, "config") else False

        # Scope Validation Check
        if not getattr(ctx, "page_is_representative", True):
            return {"fatal_error": "Page is not representative (e.g., 4xx/5xx or WAF). Blocked from reading page content."}

        findings = []
        sem_verify = asyncio.Semaphore(MAX_CONCURRENT_VERIFIES)
        requests_made = 0
        html = None
        soup_obj = None

        # Base Page Processing (Utilizing pre-computed Orchestrator Cache)
        status = shared_page.get("status", 0)
        if status in (401, 403, 406, 429, 500, 502, 503, 504):
            return {"fatal_error": f"Base URL returned HTTP {status}. Scanner blocked from reading page content."}
        
        if status == 200:
            html = shared_page.get("html", "")
            soup_obj = shared_page.get("soup") or BeautifulSoup(html, "html.parser")
        
        if not html:
            return {"fatal_error": "Empty response body from target."}

        ext_urls, inline_scripts = _extract_scripts(soup_obj, target)

        # 1. Scan Inline Scripts
        for idx, script in enumerate(inline_scripts):
            source_name = f"Inline script #{idx+1}"
            f = await _scan_content(script, source_name, target, own_session, True, sem_verify, verify_live)
            findings.extend(f)
            
            # Deobfuscation pass
            decoded_strings, method = _extract_decoded_strings(script)
            if decoded_strings:
                combined = "\n".join(decoded_strings)
                f_dec = await _scan_content(combined, f"{source_name} (deobfuscated via {method})", target, own_session, True, sem_verify, verify_live)
                findings.extend(f_dec)

        # 2. Scan External Scripts
        for u in ext_urls:
            js_content = None
            if js_cache and u in js_cache:
                js_content = js_cache[u]
            else:
                try:
                    js_content = await ctx.fetch_js(u)
                except Exception:
                    pass

            if js_content:
                filename = urlparse(u).path.split("/")[-1] or "external.js"
                f = await _scan_content(js_content, filename, u, own_session, True, sem_verify, verify_live)
                findings.extend(f)
                
                decoded_strings, method = _extract_decoded_strings(js_content)
                if decoded_strings:
                    combined = "\n".join(decoded_strings)
                    f_dec = await _scan_content(combined, f"{filename} (deobfuscated via {method})", u, own_session, True, sem_verify, verify_live)
                    findings.extend(f_dec)

        # 3. Scan Referenced Configuration Files
        forbidden_referenced_paths = []
        referenced_configs = _find_referenced_configs(soup_obj, html, target)
        
        for r_url in referenced_configs:
            try:
                async with own_session.get(r_url, timeout=aiohttp.ClientTimeout(total=5)) as cr:
                    requests_made += 1
                    if cr.status in (401, 403):
                        forbidden_referenced_paths.append(r_url)
                    elif cr.status == 200:
                        conf_body = (await cr.content.read(FETCH_MAX_BYTES_HTML)).decode("utf-8", errors="replace")
                        filename = urlparse(r_url).path.split("/")[-1] or "config.file"
                        f = await _scan_content(conf_body, filename, r_url, own_session, False, sem_verify, verify_live)
                        findings.extend(f)
            except Exception:
                continue
        
        # Bug 2 Fix: Consolidate 403 responses into a single informational finding matching v8.5 schema
        if forbidden_referenced_paths:
            findings.append({
                "title": f"Access restricted to {len(forbidden_referenced_paths)} referenced configuration file(s)",
                "severity": "info",  # Adhering to the specific severity strings (critical/high/medium/low/info)
                "confidence": "informational",
                "cwe": "CWE-538",
                "owasp": "A01:2021",
                "location": ", ".join(urlparse(p).path for p in forbidden_referenced_paths[:3]) + ("..." if len(forbidden_referenced_paths) > 3 else ""),
                "evidence": f"The page references files that successfully return HTTP 401/403 (Protected):\n" + "\n".join(forbidden_referenced_paths),
                "poc": f"curl -s -o /dev/null -w '%{{http_code}}' {forbidden_referenced_paths[0]}",
                "remediation": "No action required. Files appear to be appropriately protected by access controls.",
                "detection_method": "Referenced Path Enumeration",
            })

        return {
            "findings": findings,
            "details": {
                "requests_made": requests_made,
                "inline_scripts_scanned": len(inline_scripts),
                "external_scripts_scanned": len(ext_urls),
                "referenced_configs_scanned": len(referenced_configs)
            }
        }

    except Exception as e:
        logger.error(f"Error in secrets_hunter: {e}")
        return {"fatal_error": f"Internal plugin exception: {type(e).__name__} - {str(e)}"}

# ────────────────────────────────────────────── Standalone Testing ──────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    from dataclasses import dataclass, field

    @dataclass
    class DummyContext:
        url: str
        session: aiohttp.ClientSession
        config: dict = field(default_factory=dict)
        page_is_representative: bool = True
        waf_challenge_detected: Optional[str] = None
        sensitive_paths: list = field(default_factory=list)
        main_page_cache: dict = field(default_factory=dict)
        js_cache: dict = field(default_factory=dict)
        
        async def fetch_js(self, js_url: str) -> str:
            if js_url in self.js_cache:
                return self.js_cache[js_url]
            try:
                async with self.session.get(js_url, timeout=8) as resp:
                    if resp.status == 200:
                        content = (await resp.content.read()).decode("utf-8", errors="replace")
                        self.js_cache[js_url] = content
                        return content
            except Exception:
                pass
            return ""

    parser = argparse.ArgumentParser(description='Bravo6 Secrets Hunter Plugin')
    parser.add_argument('url', nargs='?', default='https://example.com', help='Target URL')
    parser.add_argument('--verify-live', action='store_true', help='Opt-in to verify discovered secrets against live APIs')
    parser.add_argument('--test', action='store_true', help='Run Scout Regression Tests')
    args = parser.parse_args()

    if args.test:
        import unittest

        class TestSeveritySchema(unittest.IsolatedAsyncioTestCase):
            """Regression test: severity must use the shared {critical, high, medium,
            low, info} vocabulary. The 'informational' string belongs to the separate
            `confidence` tier field only, never to `severity`."""

            async def test_revoked_secret_severity_is_info_not_informational(self):
                content = 'const token = "ghp_' + 'A' * 40 + '";'

                async def fake_verify_github(key, session):
                    return {"verified": False, "status": 403}

                original = VERIFIERS["GitHub Token"]
                VERIFIERS["GitHub Token"] = fake_verify_github
                try:
                    findings = await _scan_content(
                        content, "test.js", "https://example.com/test.js",
                        session=None, is_script=True,
                        semaphore=asyncio.Semaphore(1), verify_live=True
                    )
                finally:
                    VERIFIERS["GitHub Token"] = original

                self.assertEqual(len(findings), 1, "Expected exactly one finding for the revoked GitHub token.")
                finding = findings[0]
                self.assertEqual(finding["severity"], "info", "severity must be 'info', not 'informational'.")
                self.assertEqual(finding["confidence"], "informational", "confidence tier must remain 'informational'.")
                self.assertNotEqual(finding["severity"], "informational")

        sys.argv = [sys.argv[0]]
        unittest.main()
    else:
        async def main():
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(connector=connector) as session:
                # Fetch the main page to populate the dummy cache
                try:
                    async with session.get(args.url) as resp:
                        html = (await resp.content.read()).decode("utf-8", errors="replace")
                        main_page_cache = {
                            "status": resp.status,
                            "html": html,
                            "soup": BeautifulSoup(html, "html.parser"),
                            "headers": dict(resp.headers)
                        }
                except Exception as e:
                    main_page_cache = {"error": str(e)}

                ctx = DummyContext(
                    url=args.url,
                    session=session,
                    config={"verify_live": args.verify_live},
                    main_page_cache=main_page_cache
                )
                result = await run(ctx)
                print(json.dumps(result, indent=2, ensure_ascii=False))

        asyncio.run(main())