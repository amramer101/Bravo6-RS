#!/usr/bin/env python3
"""
test_06_info_disclosure.py - Bravo6 Info Disclosure Scanner (v12.8 - Fixed Timeout & False Positives)
==============================================================================================
What it does:
  - Sensitive file discovery (.env, .git/HEAD, backups, etc.)
  - Source map detection & API enumeration
  - Cloud bucket (S3) listing checks
  - JavaScript credential leaks (hardcoded keys, entropy)
  - Technology fingerprinting (high-precision HTML patterns only)

v12.8 Changes:
  - FIX #1 (CRITICAL): Increased MAX_CONCURRENT from 8 to 25 and added INTERNAL_SCAN_BUDGET_SECONDS=50
    to prevent orchestrator timeout kills. Path probing now returns partial results when deadline
    is reached. Retry backoff for path probes reduced to single short retry.
    NOTE: Orchestrator timeout in main_scanner.py should be raised from 60s to 90-120s for this module.
  - FIX #2 (HIGH): Broadened HTML comment noise filter to catch SSR/bundler markers (sp:*, webpack,
    React/Vue hydration, CMS markers). Replaced naive keyword matching with precise credential
    patterns. Added detection_method field and adjusted confidence (keyword-only <=40, pattern >=70).
  - FIX #3 (MEDIUM): Reordered BASE_SENSITIVE_PATHS to prioritize high-value paths (.git/HEAD,
    .env, wp-config.php, id_rsa, credentials.json) in first concurrent batch.
  - FIX #4 (LOW): Added partial scan tracking in output (partial flag, paths_checked, paths_total).
  - All previous fixes (WAF bonus, phpinfo evidence, IDE config, dedup, soft-404, etc.) retained.
"""

import asyncio
import difflib
import json
import math
import os
import random
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Set, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup, Comment

# -- Constants ---------------------------------------------------------------------------
SCANNER_NAME = "info_disclosure"
USER_AGENT = "Bravo6-InfoDisclosure/12.8"
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=15)
HEAD_TIMEOUT = aiohttp.ClientTimeout(total=5)
MAX_CONCURRENT = 25  # FIX #1: Increased from 8 to 25 for better throughput
INTERNAL_SCAN_BUDGET_SECONDS = 50  # FIX #1: Soft deadline for path probing phase
PATH_RATE = 10
PATH_PROBE_RETRY_MAX = 1  # FIX #1: Reduced retry for path probing
PATH_PROBE_BACKOFF_BASE = 0.1  # FIX #1: Reduced backoff for path probing
RETRY_MAX = 3
RETRY_BACKOFF_BASE = 1
EXT_AGGREGATION_THRESHOLD = 5
DIR_AGGREGATION_THRESHOLD = 3

CWE_MAP = {"sensitive_file": "CWE-538", "source_map": "CWE-200", "api_endpoint": "CWE-200",
           "cloud_bucket": "CWE-200", "graphql": "CWE-200", "dir_listing": "CWE-548",
           "backup": "CWE-530", "user_enum": "CWE-200"}
OWASP_MAP = {"sensitive_file": "A01:2021", "source_map": "A01:2021", "api_endpoint": "A01:2021",
             "cloud_bucket": "A06:2021", "graphql": "A01:2021", "dir_listing": "A05:2021",
             "backup": "A05:2021", "user_enum": "A01:2021"}
EXPECTED_403_PATHS = {"wp-content/uploads/", "wp-content/uploads", ".well-known/", ".well-known", "cgi-bin/", "cgi-bin"}

def _normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def _get_header(headers, name):
    for key, val in headers.items():
        if key.lower() == name.lower():
            return val
    return None

async def retry_async(func, max_retries=RETRY_MAX, base_delay=RETRY_BACKOFF_BASE):
    last_exc = None
    for attempt in range(max_retries + 1):
        try:
            return await func()
        except (asyncio.TimeoutError, ConnectionError, OSError) as e:
            last_exc = e
            if attempt == max_retries:
                raise
            delay = base_delay * (2 ** attempt) + random.uniform(0, 0.5)
            await asyncio.sleep(delay)
    raise last_exc

# FIX #1: Separate retry for path probing with reduced backoff
async def retry_path_probe(func, max_retries=PATH_PROBE_RETRY_MAX, base_delay=PATH_PROBE_BACKOFF_BASE):
    last_exc = None
    for attempt in range(max_retries + 1):
        try:
            return await func()
        except (asyncio.TimeoutError, ConnectionError, OSError) as e:
            last_exc = e
            if attempt == max_retries:
                raise
            delay = base_delay * (2 ** attempt) + random.uniform(0, 0.05)
            await asyncio.sleep(delay)
    raise last_exc

def _log_error(msg):
    print(f"[{SCANNER_NAME}] ERROR: {msg}", file=sys.stderr)

def _entropy(s):
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def _parse_version(version_str):
    parts = re.split(r'[.-]', version_str)
    return tuple(int(p) for p in parts if p.isdigit())

def _version_in_range(version, min_ver, max_ver):
    if not version:
        return False
    try:
        v = _parse_version(version)
        if min_ver and v < _parse_version(min_ver):
            return False
        if max_ver and v >= _parse_version(max_ver):
            return False
        return True
    except Exception:
        return False

async def _detect_waf(hostname, port=443, html=None, headers=None):
    if headers:
        if 'cf-ray' in {k.lower() for k in headers}:
            return 'cloudflare'
        if 'x-sucuri-id' in {k.lower() for k in headers}:
            return 'sucuri'
        if 'x-akamai-request-id' in {k.lower() for k in headers}:
            return 'akamai'
        if headers.get('server', '').lower().startswith('cloudflare'):
            return 'cloudflare'
        return None
    try:
        ssl_ctx = __import__('ssl').create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = __import__('ssl').CERT_NONE
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8),
                                         headers={"User-Agent": USER_AGENT}) as session:
            async with session.get(f"https://{hostname}:{port}", ssl=ssl_ctx) as resp:
                headers = resp.headers
                if 'cf-ray' in headers: return 'cloudflare'
                if 'x-sucuri-id' in headers: return 'sucuri'
                if 'x-akamai-request-id' in headers: return 'akamai'
                if headers.get('server', '').lower().startswith('cloudflare'): return 'cloudflare'
    except Exception as e:
        _log_error(f"WAF detection failed: {e}")
    return None

SITE_CATEGORIES = {
    "bank": ["bank", "online banking"],
    "ecommerce": ["shop", "store", "buy", "cart", "checkout", "shopping", "amazon", "ebay", "etsy", "aliexpress"],
    "healthcare": ["hospital"], "login": ["sign in", "login"],
    "blog": ["blog", "articles"], "internal": ["intranet", "internal"],
}

async def _categorize_site(hostname, port=443, html=None, headers=None):
    result = {"categories": [], "has_login_form": False, "title": "", "meta_keywords": "",
              "is_login_page": False, "is_ecommerce": False, "is_internal": False, "is_api": False}
    if html:
        text = html
    else:
        try:
            ssl_ctx = __import__('ssl').create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = __import__('ssl').CERT_NONE
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10),
                                             headers={"User-Agent": USER_AGENT}) as session:
                async with session.get(f"https://{hostname}:{port}", ssl=ssl_ctx) as resp:
                    text = await resp.text()
        except Exception as e:
            _log_error(f"Site categorization failed: {e}")
            return result
    title_match = re.search(r'<title>(.*?)</title>', text, re.IGNORECASE)
    if title_match: result["title"] = title_match.group(1)
    meta_match = re.search(r'<meta\s+name="keywords"\s+content="(.*?)"', text, re.IGNORECASE)
    if meta_match: result["meta_keywords"] = meta_match.group(1)
    if re.search(r'<input\s+[^>]*type=["\']?password["\']?', text, re.IGNORECASE):
        result["has_login_form"] = True
    text_lower = (result["title"] + " " + result["meta_keywords"]).lower()
    for category, keywords in SITE_CATEGORIES.items():
        if any(k in text_lower for k in keywords):
            result["categories"].append(category)
    result["is_login_page"] = ("login" in result["categories"] or result["has_login_form"])
    result["is_ecommerce"] = "ecommerce" in result["categories"]
    result["is_internal"] = "internal" in result["categories"]
    return result

def _make_finding(title, description, severity, confidence, location="", evidence="", remediation="",
                 cwe="", owasp="", poc=None, category="passive", detection_method="pattern_match"):
    return {
        "title": title, "description": description, "severity": severity,
        "confidence": confidence, "location": location, "evidence": evidence,
        "remediation": remediation, "cwe": cwe, "owasp": owasp, "poc": poc,
        "category": category, "detection_method": detection_method
    }

def calculate_score_v2(findings, context, waf_detected):
    base = 100
    deductions = 0
    for f in findings:
        sev = f.get("severity", "info")
        if sev == "critical": deductions -= 25
        elif sev == "high": deductions -= 15
        elif sev == "medium": deductions -= 6
        elif sev == "low": deductions -= 3
    if context.get("is_login_page") or context.get("is_ecommerce"):
        base += 15
    if context.get("is_internal"):
        base -= 15
    if waf_detected and not any(f.get("severity") == "critical" for f in findings):
        base += 5
    score = base + deductions
    return max(0, min(100, score))

def _score_to_grade(score):
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"

TECH_COOKIES = {
    "PHPSESSID": "PHP", "JSESSIONID": "Java", "connect.sid": "Express",
    "laravel_session": "Laravel", "ASP.NET_SessionId": "ASP.NET",
    "ci_session": "CodeIgniter", "wp-settings-": "WordPress",
    "wordpress_logged_in_": "WordPress", "drupal_session": "Drupal", "Magento": "Magento",
}

HEADER_FINGERPRINTS = {
    "Server": {"nginx": "Nginx", "Apache": "Apache", "IIS": "IIS", "cloudflare": "Cloudflare", "Express": "Express.js"},
    "X-Powered-By": {"PHP": "PHP", "ASP.NET": "ASP.NET", "Express": "Express.js", "Next.js": "Next.js",
                     "Laravel": "Laravel", "Django": "Django", "Flask": "Flask", "Ruby": "Ruby on Rails"},
    "X-Generator": {"WordPress": "WordPress", "Joomla": "Joomla", "Drupal": "Drupal", "Magento": "Magento"},
}

HTML_TECH_SIGNATURES = {
    "WordPress": [r'/wp-content/', r'/wp-includes/', r'wp-json'],
    "Django": [r'csrfmiddlewaretoken'],
    "Ruby on Rails": [r'<meta\s+name="csrf-param"'],
    "Laravel": [r'<meta\s+name="csrf-token"'],
    "React": [r'react\.(production|development)\.min\.js'],
    "Vue.js": [r'v-app', r'v-bind', r'v-on'],
    "Angular": [r'ng-app', r'ng-controller', r'ng-version'],
    "Bootstrap": [r'bootstrap\.min\.css', r'bootstrap\.bundle'],
    "jQuery": [r'jquery\.min\.js', r'jquery\.js'],
    "ASP.NET": [r'__VIEWSTATE', r'__EVENTVALIDATION'],
    "Next.js": [r'/_next/static/', r'__NEXT_DATA__'],
    "Nuxt.js": [r'/_nuxt/', r'window\.__NUXT__'],
}

# FIX #3: Reordered BASE_SENSITIVE_PATHS - highest value paths first
BASE_SENSITIVE_PATHS = [
    ".git/HEAD", ".git/config",
    ".env", ".env.production", ".env.local", ".env.staging", ".env.development", ".env.backup",
    "wp-config.php", "wp-config.php~", "wp-config.php.save", "wp-config.php.bak",
    "config.php", "settings.py", "web.config", ".htaccess",
    "id_rsa", "id_rsa.pub", "authorized_keys", "private.key", "cert.pem",
    "credentials.json", "secret_key.txt", "secrets.json",
    "composer.json", "package.json", "Gemfile", "requirements.txt",
    "yarn.lock", "pnpm-lock.yaml", "Gemfile.lock",
    "phpinfo.php", "info.php", "test.php",
    "database.sql", "dump.sql", "db.sql", "db.sqlite3",
    "aws-exports.js", "firebase.json", "supabase.json", "vercel.json", "amplify.yml",
    "google-services.json", "sftp-config.json", ".htpasswd",
    ".npmrc", ".yarnrc.yml", ".pypirc", "config.yml",
    "config/database.yml", "config/secrets.yml", "parameters.yml", "services.yml",
    "backup.zip", "backup.tar.gz", "backup.sql", "backup.bak", "backup.tar",
    "backup.7z", "backup.rar", "backup.gz", "backup.bz2", ".bak", "config.bak", "web.config.bak",
    "error.log", "debug.log", "storage/logs/laravel.log", "log/production.log", "tmp/restart.txt",
    ".idea/workspace.xml", ".vscode/settings.json", ".DS_Store", "Thumbs.db", ".bash_history",
    "swagger-ui.html", "v3/api-docs", "api-docs", "swagger.json",
    "graphql", "graphiql", "playground",
    "server-status", "server-info", "status", "healthcheck",
    "phpMyAdmin/", "adminer.php", "pma/", "crossdomain.xml", "clientaccesspolicy.xml",
    "wp-content/debug.log", "wp-content/backup/", "wp-content/uploads/", "xmlrpc.php",
    "wp-login.php", "administrator/index.php",
    "Dockerfile", "docker-compose.yml", ".gitlab-ci.yml", ".travis.yml", "Jenkinsfile",
    ".github/workflows/", ".circleci/config.yml",
    "server.js", "app.js", "main.py", "manage.py",
    ".next/", "out/", "staticfiles/", "build/", "dist/", "node_modules/", "vendor/",
    "robots.txt", "sitemap.xml",
    ".well-known/security.txt", ".well-known/openid-configuration",
    "admin.php", "login.php", "user.php", "api.php", "cron.php", "user/login",
    "next.config.js", "nuxt.config.js",
]

BACKUP_EXTS = [".zip", ".tar.gz", ".sql", ".bak", ".tar", ".7z", ".rar", ".gz", ".bz2"]

TECH_SPECIFIC_PATHS = {
    "WordPress": ["wp-config.php", "wp-content/backup/", "wp-content/uploads/", "wp-content/debug.log", "xmlrpc.php"],
    "Laravel": ["storage/logs/laravel.log", ".env.example", "composer.lock", "vendor/", "storage/framework/views/", "storage/app/"],
    "Django": ["settings.py", "db.sqlite3", "manage.py", "requirements.txt", "staticfiles/", "media/"],
    "ASP.NET": ["web.config", "elmah.axd", "trace.axd", "bin/", "appsettings.json"],
    "PHP": ["phpinfo.php", "config.php", "adminer.php", "info.php"],
    "Express": ["package.json", "node_modules/", ".env", "app.js"],
    "Java": ["WEB-INF/web.xml", "WEB-INF/classes/", "actuator/health", "actuator/env", "swagger-ui.html"],
    "Flask": ["app.py", "config.py", "requirements.txt", "instance/"],
    "Ruby": ["Gemfile", "config/database.yml", "config/secrets.yml"],
    "React": [".env", ".env.production", "build/", "node_modules/"],
    "Vue.js": [".env", ".env.production", "dist/", "node_modules/"],
    "Next.js": [".next/", "out/", ".env.local", "next.config.js"],
    "Nuxt.js": [".nuxt/", ".output/", ".env", "nuxt.config.js"],
}

API_ENDPOINTS = [
    "graphql", "/api/v1/users", "/api/v1/products", "/api/v1/orders",
    "/api/v2/users", "/debug", "/admin", "/dashboard", "/login",
    "/wp-json/wp/v2/users", "/rest/user", "/oauth/token",
    "/.well-known/openid-configuration", "/actuator/health", "/actuator/env",
    "/graphql/console", "/swagger-resources", "/v2/api-docs", "/v3/api-docs",
]

def _is_soft_404(body, homepage_body):
    if not body:
        return False
    if re.search(r'(404\s*(Not Found|Page Not Found)|File not found|Page not found|Not Found)', body, re.IGNORECASE):
        return True
    if not homepage_body:
        return False
    if abs(len(body) - len(homepage_body)) <= max(len(homepage_body) * 0.1, 100):
        if body[:500] == homepage_body[:500]:
            return True
    if len(body) > 500 and len(homepage_body) > 500:
        title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE)
        home_title = re.search(r'<title>(.*?)</title>', homepage_body, re.IGNORECASE)
        if title_match and home_title and title_match.group(1) == home_title.group(1):
            if abs(len(body) - len(homepage_body)) <= max(len(homepage_body) * 0.15, 200):
                return True
    try:
        ratio = difflib.SequenceMatcher(None, body[:2000], homepage_body[:2000]).ratio()
        if ratio > 0.85:
            return True
    except Exception:
        pass
    return False

class ResponsePlaceholder:
    def __init__(self, status, headers):
        self.status = status
        self.headers = headers

class LeakyBucketLimiter:
    def __init__(self, rate=PATH_RATE):
        self.min_interval = 1.0 / rate
        self.last_request = 0.0
        self._lock = asyncio.Lock()

    async def wait(self):
        async with self._lock:
            now = asyncio.get_running_loop().time()
            wait_time = self.last_request + self.min_interval - now
            if wait_time > 0:
                await asyncio.sleep(wait_time)
            self.last_request = max(now, self.last_request + self.min_interval)

class RateLimiter:
    def __init__(self, max_concurrent=MAX_CONCURRENT, min_delay=0.01, max_delay=0.05):
        self.sem = asyncio.Semaphore(max_concurrent)
        self.min_delay = min_delay
        self.max_delay = max_delay

    async def probe(self, session, url, method='GET'):
        async with self.sem:
            await asyncio.sleep(random.uniform(self.min_delay, self.max_delay))
            try:
                if method == 'HEAD':
                    async with session.head(url, timeout=HEAD_TIMEOUT, allow_redirects=True) as resp:
                        return ResponsePlaceholder(resp.status, resp.headers)
                else:
                    resp = await asyncio.wait_for(session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True),
                                                  timeout=REQUEST_TIMEOUT.total)
                    return resp
            except Exception as e:
                _log_error(f"Probe failed for {url}: {e}")
                return None

def _generate_backup_names(domain):
    names = []
    base = domain.split('.')[0]
    patterns = [f"{domain}", f"{base}", f"{base}_backup", f"backup_{base}", f"{base}-backup",
               f"db", f"database", f"{base}_old", f"{base}_new", f"2024", f"2025", f"2026"]
    for pattern in patterns:
        for ext in BACKUP_EXTS:
            names.append(f"{pattern}{ext}")
    for ext in BACKUP_EXTS:
        names.append(f"{domain}_backup_{datetime.now().strftime('%Y%m%d')}{ext}")
    return names

ENTROPY_EXCLUDE_DOMAINS = [
    "googletagmanager.com", "google-analytics.com", "facebook.net",
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    "polyfill.io", "static.cloudflareinsights.com",
]
JS_SAFE_TOKENS = ['localStorage', 'getToken', 'setToken', 'removeToken', 'clearToken',
                  'token_type', 'grant_type', 'access_token', 'refresh_token']
JS_CODE_KEYWORDS = ['function', 'var', 'let', 'const', 'return']
HIGH_CONFIDENCE_SECRET_PATTERNS = [
    r'(?:AKIA|ASIA)[A-Z0-9]{16}', r'sk-[a-zA-Z0-9]{32,}',
    r'github_pat_[a-zA-Z0-9_]{22,}', r'AIza[0-9A-Za-z\-_]{35}',
    r'eyJ[a-zA-Z0-9\-_]{10,}\.[a-zA-Z0-9\-_]{10,}\.[a-zA-Z0-9\-_]{10,}',
    r'pk_(live|test)_[a-zA-Z0-9]{24,}',
]
BROAD_SECRET_PATTERN = re.compile(
    r'(?:api[_-]?key|apikey|secret|password|token|auth)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{8,})["\']?', re.IGNORECASE
)

async def _fetch_js_cached(session, url, rate_limiter, js_cache):
    if url in js_cache:
        return js_cache[url]
    resp = await rate_limiter.probe(session, url, 'GET')
    if resp and resp.status == 200:
        content = await resp.text(errors='replace')
        js_cache[url] = content
        return content
    js_cache[url] = None
    return None

async def _check_js_source_maps(session, base_url, html, rate_limiter, findings):
    if not html:
        return
    try:
        soup = BeautifulSoup(html, "html.parser")
        js_links = []
        for script in soup.find_all("script", src=True):
            js_links.append(urljoin(base_url, script["src"]))
        for script in soup.find_all("script"):
            if script.string and 'sourceMappingURL' in script.string:
                map_match = re.search(r'//# sourceMappingURL=(.*)', script.string)
                if map_match:
                    map_url = urljoin(base_url, map_match.group(1).strip())
                    findings.append(_make_finding(
                        title="Source map referenced inline", description=f"Found sourceMappingURL: {map_url}",
                        severity="high", confidence=90, location="Inline script", evidence=map_url,
                        remediation="Remove sourceMappingURL from production scripts.",
                        cwe=CWE_MAP["source_map"], owasp=OWASP_MAP["source_map"],
                        poc="View page source and search 'sourceMappingURL'",
                        category="js", detection_method="pattern_match",
                    ))
        for js_url in js_links:
            if js_url.endswith('.js'):
                map_url = js_url + '.map'
                resp_map = await rate_limiter.probe(session, map_url, 'GET')
                if resp_map and resp_map.status == 200:
                    body = await resp_map.text()
                    if body.strip() and ('"sources"' in body or '"mappings"' in body):
                        findings.append(_make_finding(
                            title="Source map exposed", description=f"Source map found at {map_url}",
                            severity="high", confidence=95, location=map_url, evidence=body[:300],
                            remediation="Disable source maps in production.",
                            cwe=CWE_MAP["source_map"], owasp=OWASP_MAP["source_map"],
                            poc=f"curl {map_url}", category="js", detection_method="pattern_match",
                        ))
    except Exception as e:
        _log_error(f"JS source map check failed: {e}")

async def _check_js_leaked_credentials(session, base_url, html, rate_limiter, findings, js_cache):
    if not html:
        return
    try:
        soup = BeautifulSoup(html, "html.parser")
        js_urls = set()
        for script in soup.find_all("script", src=True):
            js_urls.add(urljoin(base_url, script["src"]))
        for js_url in js_urls:
            content = await _fetch_js_cached(session, js_url, rate_limiter, js_cache)
            if not content:
                continue
            for pat in HIGH_CONFIDENCE_SECRET_PATTERNS:
                for m in re.findall(pat, content):
                    findings.append(_make_finding(
                        title="Hardcoded credential / API key in JavaScript",
                        description=f"High-confidence secret found: {m}",
                        severity="critical", confidence=95, location=js_url, evidence=f"Matched: {m}",
                        remediation="Remove all secrets from client-side code.",
                        cwe="CWE-798", owasp="A07:2021", poc=f"Inspect {js_url}",
                        category="js", detection_method="pattern_match",
                    ))
            for match in BROAD_SECRET_PATTERN.finditer(content):
                val = match.group(1)
                if any(safe in val.lower() for safe in JS_SAFE_TOKENS):
                    continue
                if any(kw in val.lower() for kw in JS_CODE_KEYWORDS):
                    continue
                if len(val) < 40:
                    continue
                findings.append(_make_finding(
                    title="Potential credential in JavaScript",
                    description=f"Broad pattern matched: {val}",
                    severity="medium", confidence=50, location=js_url, evidence=f"Secret: {val}",
                    remediation="Review code for hardcoded secrets.",
                    cwe="CWE-798", owasp="A07:2021", poc=f"Inspect {js_url}",
                    category="js", detection_method="pattern_match",
                ))
            parsed = urlparse(js_url)
            if not any(domain in parsed.netloc for domain in ENTROPY_EXCLUDE_DOMAINS):
                for match in re.finditer(r'["\']([a-zA-Z0-9_\-+/=]{20,})["\']', content):
                    candidate = match.group(1)
                    if _entropy(candidate) > 5.0:
                        start = max(0, match.start() - 200)
                        context_window = content[start:match.end() + 50]
                        if not re.search(r'(api[ _\s]?key|secret|token|auth|password|private[ _\s]?key)',
                                         context_window, re.IGNORECASE):
                            continue
                        findings.append(_make_finding(
                            title="High-entropy string detected (possible API key)",
                            description=f"High-entropy string: {candidate}",
                            severity="medium", confidence=60, location=js_url,
                            evidence=f"Entropy: {_entropy(candidate):.2f}",
                            remediation="Verify if this is a hardcoded secret.",
                            cwe="CWE-798", owasp="A07:2021", poc=f"Inspect {js_url}",
                            category="js", detection_method="entropy_match",
                        ))
    except Exception as e:
        _log_error(f"JS leaked credential check failed: {e}")

async def _check_interesting_files_from_headers(session, base_url, main_headers, findings):
    if not _get_header(main_headers, "ETag") and not _get_header(main_headers, "Last-Modified"):
        return
    interesting = ["/robots.txt", "/sitemap.xml", "/favicon.ico", "/.well-known/security.txt",
                   "/crossdomain.xml", "/clientaccesspolicy.xml"]
    rl = RateLimiter(max_concurrent=5)
    for path in interesting:
        url = urljoin(base_url, path)
        resp = await rl.probe(session, url, 'HEAD')
        if resp and resp.status == 200:
            findings.append(_make_finding(
                title=f"Interesting file found: {path}",
                description="Static file accessible, may reveal information.",
                severity="low", confidence=70, location=path,
                remediation="Review if exposure is intentional.",
                poc=f"curl {url}", category="active", detection_method="header_check",
            ))

async def _enumerate_api_endpoints(session, base_url, rate_limiter, findings):
    reported_user_enum = False
    for endpoint in API_ENDPOINTS:
        url = urljoin(base_url, endpoint)
        resp = await rate_limiter.probe(session, url, 'GET')
        if resp is None:
            continue
        if resp.status == 200:
            content_type = resp.headers.get('Content-Type', '')
            try:
                body = await asyncio.wait_for(resp.text(), timeout=10)
            except Exception:
                continue
            if endpoint == "/wp-json/wp/v2/users":
                if not reported_user_enum and '"id"' in body and '"name"' in body and '"slug"' in body:
                    findings.append(_make_finding(
                        title="WordPress User Enumeration",
                        description="The WordPress REST API endpoint exposes user names, slugs, and IDs.",
                        severity="medium", confidence=100, location=endpoint, evidence=body[:300],
                        remediation="Disable anonymous access to the users endpoint.",
                        cwe=CWE_MAP["user_enum"], owasp=OWASP_MAP["user_enum"],
                        poc=f"curl {url}", category="api", detection_method="pattern_match",
                    ))
                    reported_user_enum = True
                continue
            if 'graphql' in endpoint.lower():
                try:
                    async with session.post(url, json={"query": "query { __schema { types { name } } }"},
                                            timeout=REQUEST_TIMEOUT) as intro_resp:
                        if intro_resp.status == 200 and 'application/json' in intro_resp.headers.get('Content-Type', ''):
                            data = await intro_resp.json()
                            if data.get("data", {}).get("__schema"):
                                findings.append(_make_finding(
                                    title="GraphQL introspection enabled",
                                    description=f"GraphQL endpoint at {endpoint} exposes full schema.",
                                    severity="high", confidence=100, location=endpoint,
                                    evidence="Introspection query returned schema data.",
                                    remediation="Disable introspection in production.",
                                    cwe=CWE_MAP["graphql"], owasp=OWASP_MAP["graphql"],
                                    poc=f'curl -X POST {url} -d \'{{"query":"{{__schema{{types{{name}}}}}}}}\'',
                                    category="api", detection_method="introspection",
                                ))
                            continue
                except Exception as e:
                    _log_error(f"GraphQL check failed: {e}")
                continue
            if any(kw in body.lower() for kw in ['swagger', 'openapi', 'api-docs']):
                findings.append(_make_finding(
                    title="API documentation exposed",
                    description=f"Possible Swagger/OpenAPI spec at {endpoint}",
                    severity="high", confidence=90, location=endpoint,
                    remediation="Restrict access to API docs.",
                    cwe=CWE_MAP["api_endpoint"], owasp=OWASP_MAP["api_endpoint"],
                    poc=f"curl {url}", category="api", detection_method="pattern_match",
                ))
            elif 'application/json' in content_type:
                findings.append(_make_finding(
                    title=f"Potential API endpoint: {endpoint}",
                    description="Endpoint returns JSON, may expose data.",
                    severity="medium", confidence=60, location=endpoint, evidence=body[:200],
                    remediation="Verify endpoint requires authentication.",
                    cwe=CWE_MAP["api_endpoint"], owasp=OWASP_MAP["api_endpoint"],
                    category="api", detection_method="content_type",
                ))
        elif resp.status in (401, 403):
            sev = "low" if "wp-json" in endpoint and "users" in endpoint else "info"
            findings.append(_make_finding(
                title=f"Protected API endpoint: {endpoint}",
                description="Endpoint exists but requires authentication - verify access controls.",
                severity=sev, confidence=85, location=endpoint,
                remediation="Ensure the endpoint requires authentication and test with a real unauthenticated request.",
                category="api", detection_method="status_code",
            ))

HIGH_SENSITIVE_PATHS = [
    "/.git/head", "/.env", "/wp-config.php", "/config.php", "/database.sql",
    "/dump.sql", "/db.sql", "/credentials.json", "/secrets.", "/private.key",
    "/id_rsa", "/id_rsa.pub", "/.pem", "/.htpasswd", "/config/database.yml",
    "/config/secrets.yml", "/.env.backup",
]
MEDIUM_SENSITIVE_PATHS = [
    ".sql", ".bak", "/backup", "/error.log", "/debug.log", "/.DS_Store",
    "/web.config", "/composer.json", "/package.json", "/Gemfile.lock",
    "/yarn.lock", "/config", "/settings.py", "/.env.example",
    "/appsettings.json", "/parameters.yml", "/.npmrc",
]

def _forbidden_sensitivity(path):
    path_lower = path.lower()
    for high_pat in HIGH_SENSITIVE_PATHS:
        if high_pat in path_lower:
            return ("high", 90)
    for med_pat in MEDIUM_SENSITIVE_PATHS:
        if med_pat in path_lower:
            return ("medium", 80)
    return ("low", 60)

def _detect_wordpress_from_findings(findings):
    for f in findings:
        loc = f.get("location", "")
        if 'wp-json' in loc or 'wp-content' in loc or 'wp-admin' in loc or 'wp-login' in loc:
            return True
    return False

async def _fetch_generic_403_body(session, base_url, limiter, ext=".html"):
    random_path = f"/nonexistent-{random.randint(10000,99999)}{ext}"
    url = urljoin(base_url, random_path)
    await limiter.wait()
    try:
        async with session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True) as resp:
            if resp.status == 403:
                return await resp.text()
    except Exception:
        pass
    return None

async def _fetch_body(session, url):
    try:
        async with session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True) as resp:
            if resp.status == 200:
                return await resp.text(errors="replace")
    except Exception as e:
        _log_error(f"Failed to fetch body for {url}: {e}")
    return None

def _body_matches_generic(body, generic_body):
    if not generic_body or not body:
        return False
    b_stripped, g_stripped = body.strip(), generic_body.strip()
    if abs(len(b_stripped) - len(g_stripped)) <= max(len(g_stripped) * 0.1, 50):
        if b_stripped == g_stripped:
            return True
    return False

def _is_robots_sensitive(body):
    sensitive_patterns = [r'admin', r'backup', r'config', r'\.git', r'\.env', r'wp-admin', r'login', r'dashboard']
    for pattern in sensitive_patterns:
        if re.search(r'Disallow:\s*/' + pattern, body, re.IGNORECASE):
            return True
    return False

def _is_sensitive_content(path, body):
    if ".git/HEAD" in path:
        return "ref: refs/heads/" in body
    if ".env" in path:
        return any(kw in body for kw in ["DB_", "PASSWORD", "API_KEY", "SECRET", "APP_KEY"])
    if "composer.json" in path:
        return '"require"' in body
    if "package.json" in path:
        return '"dependencies"' in body
    if "robots.txt" in path:
        return True
    if "sitemap.xml" in path:
        return "<urlset" in body or "<sitemapindex" in body
    if any(x in path for x in ["CHANGELOG", "VERSION", "RELEASE"]):
        return bool(re.search(r'\d+\.\d+\.\d+', body))
    if "phpinfo" in path:
        return "PHP Version" in body
    if ".htaccess" in path:
        return any(kw in body for kw in ["RewriteRule", "Deny"])
    if "swagger" in path:
        return "swagger" in body.lower() or "openapi" in body.lower()
    if path.endswith(".sql"):
        return "CREATE TABLE" in body
    if path.endswith((".zip", ".tar.gz", ".tar", ".bak", ".7z", ".rar")):
        return True
    if ".vscode" in path or ".idea" in path:
        return True
    if "web.config" in path or "appsettings.json" in path:
        return "<configuration" in body or "<appSettings" in body
    if "parameters.yml" in path:
        return "parameters:" in body
    return False

def _is_directory_listing(body, homepage_body):
    if not body or not homepage_body:
        return False
    listing_indicators = ["Index of /", "Parent Directory", "<title>Index of", '<h1>Index of', "Directory Listing"]
    if not any(ind in body for ind in listing_indicators):
        return False
    if body.strip() == homepage_body.strip():
        return False
    if body[:500] == homepage_body[:500] and len(body) == len(homepage_body):
        return False
    if not re.search(r'<a\s+href="[^"]*"[^>]*>', body, re.IGNORECASE):
        return False
    return True

def _is_real_path_traversal(body, homepage_body, orig_dir_body):
    if not body or not homepage_body:
        return False
    if body[:500] == homepage_body[:500]:
        return False
    if orig_dir_body and body[:300] == orig_dir_body[:300]:
        return False
    return "Parent Directory" in body or "Index of" in body

def _detect_tech_from_html(html):
    if not html:
        return set()
    detected = set()
    for tech, patterns in HTML_TECH_SIGNATURES.items():
        for pat in patterns:
            if re.search(pat, html, re.IGNORECASE):
                detected.add(tech)
                break
    return detected

# FIX #2: Enhanced HTML comment noise filter
HTML_COMMENT_NOISE_PATTERNS = [
    r'^sp:(start-|end-)?feature', r'^sp:', r'data-(react|vue|angular|svelte)-',
    r'__webpack_', r'__webpack_hash__', r'webpackJsonp', r'window\.__',
    r'hydration', r'SSR:', r'CSR:', r'chunk-', r'[0-9a-f]{8,}\.chunk',
    r'vendor\.[0-9a-f]{8,}', r'build/', r'google\.com/recaptcha',
    r'Async Google Analytics', r'googletagmanager\.com', r'GoogleAnalyticsObject',
    r'ga\(', r'gtag\(', r'facebook\.net', r'fbq\(', r'cdn\.(jsdelivr|cloudflare|unpkg)\.',
    r'polyfill\.io', r'static\.cloudflareinsights\.com',
    r'Generated by', r'Do not edit', r'Do not remove', r'Copyright',
    r'License:', r'SPDX-License-Identifier',
]

CREDENTIAL_PATTERNS = [
    r'(?:password|pass|pwd|secret|api[_-]?key|token|auth|private[_-]?key|access[_-]?key)\s*[:=]\s*["\']?[A-Za-z0-9_\-+/=]{8,}["\']?',
    r'(?:aws|gcp|azure|heroku|sendgrid|stripe|twilio)[_-]?(?:access[_-]?key|secret|token|password)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}["\']?',
    r'(?:AKIA|ASIA)[A-Z0-9]{16}', r'sk-[a-zA-Z0-9]{32,}',
    r'github_pat_[a-zA-Z0-9_]{22,}', r'AIza[0-9A-Za-z\-_]{35}',
    r'eyJ[a-zA-Z0-9\-_]{10,}\.[a-zA-Z0-9\-_]{10,}\.[a-zA-Z0-9\-_]{10,}',
]
DEVELOPER_NOTE_KEYWORDS = ['TODO', 'FIXME', 'BUG', 'HACK', 'XXX', 'NOTE', 'DEBUG']

async def run(url: str, shared_page: dict = None):
    target = _normalize_url(url)
    parsed = urlparse(target)
    hostname = parsed.hostname or ""
    port = parsed.port or 443
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    domain = hostname

    findings = []
    tech_stack = set()
    rate_limiter = RateLimiter(max_concurrent=MAX_CONCURRENT)
    js_cache = {}
    paths_checked = 0
    paths_total = 0
    is_partial = False
    scan_note = ""

    if shared_page and not shared_page.get("error") and shared_page.get("status") == 200:
        main_body = shared_page["html"]
        main_headers = shared_page["headers"]
        soup = shared_page.get("soup")
        if soup is None:
            soup = BeautifulSoup(main_body, "html.parser")
        site_context = await _categorize_site(hostname, port, html=main_body, headers=main_headers)
        waf_detected = await _detect_waf(hostname, port, headers=main_headers)
        js_cache = shared_page.get("js_cache", {})
    else:
        connector = aiohttp.TCPConnector(ssl=True, limit=MAX_CONCURRENT + 5)
        async with aiohttp.ClientSession(
            timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT}, connector=connector
        ) as session:
            main_resp = await retry_async(lambda: rate_limiter.probe(session, target, 'GET'))
            if main_resp is None or main_resp.status != 200:
                return {
                    "scanner": SCANNER_NAME, "target": target, "status": "error",
                    "severity": "info", "confidence": 0, "score": 0, "grade": "F",
                    "summary": "Could not fetch main page.", "findings": [], "remediation": [],
                    "details": {
                        "tech_stack": [], "waf_detected": None, "context": {},
                        "summary_stats": {"total_findings": 0, "by_severity": {}, "by_category": {}},
                        "partial": False, "paths_checked": 0, "paths_total": 0, "note": "",
                    }
                }
            main_body = await main_resp.text()
            main_headers = dict(main_resp.headers)
            soup = BeautifulSoup(main_body, "html.parser")
            site_context = await _categorize_site(hostname, port, html=main_body, headers=main_headers)
            waf_detected = await _detect_waf(hostname, port, headers=main_headers)

    site_context["is_api"] = hostname.startswith("api.") or "/api/" in parsed.path

    try:
        async with aiohttp.ClientSession(
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            connector=aiohttp.TCPConnector(ssl=True, limit=MAX_CONCURRENT + 10)
        ) as session:
            for header_name, patterns in HEADER_FINGERPRINTS.items():
                val = _get_header(main_headers, header_name)
                if val:
                    for keyword, label in patterns.items():
                        if keyword.lower() in val.lower():
                            tech_stack.add(label)
                            findings.append(_make_finding(
                                title=f"Technology identified: {label}",
                                description=f"Header {header_name} reveals {val}",
                                severity="low", confidence=80, location=f"Header: {header_name}",
                                evidence=val, remediation="Remove or obscure version headers.",
                                cwe="CWE-200", category="passive", detection_method="header_match",
                            ))
                            break
            set_cookie = _get_header(main_headers, "Set-Cookie") or ""
            for cookie_key, tech in TECH_COOKIES.items():
                if cookie_key in set_cookie:
                    tech_stack.add(tech)
                    findings.append(_make_finding(
                        title=f"Technology identified: {tech}",
                        description=f"Cookie {cookie_key} present",
                        severity="info", confidence=100, location=f"Cookie: {cookie_key}",
                        category="passive", detection_method="cookie_match",
                    ))
            for specific in ["X-AspNet-Version", "X-AspNetMvc-Version"]:
                val = _get_header(main_headers, specific)
                if val:
                    findings.append(_make_finding(
                        title=f"Exact version disclosed", description=f"{specific}: {val}",
                        severity="medium", confidence=90, location=f"Header: {specific}", evidence=val,
                        remediation="Remove version headers.", cwe="CWE-200",
                        category="config", detection_method="version_header",
                    ))

            html_techs = _detect_tech_from_html(main_body)
            for tech in html_techs:
                tech_stack.add(tech)
                findings.append(_make_finding(
                    title=f"Technology identified: {tech}",
                    description="Detected from HTML signature",
                    severity="info", confidence=75, location="HTML body",
                    category="passive", detection_method="html_signature",
                ))

            if soup:
                for meta in soup.find_all("meta", attrs={"name": "generator"}):
                    content = meta.get("content", "")
                    if "WordPress" in content:
                        tech_stack.add("WordPress")
                        findings.append(_make_finding(
                            title="Technology identified: WordPress",
                            description=f"Meta generator: {content}",
                            severity="info", confidence=100, location="Meta generator", evidence=content,
                            category="passive", detection_method="meta_tag",
                        ))
                if re.search(r'(wp-content|wp-includes)', main_body):
                    tech_stack.add("WordPress")
                for meta in soup.find_all("meta", attrs={"name": lambda x: x and x.lower() in ("author",)}):
                    content = meta.get("content", "")
                    if content:
                        findings.append(_make_finding(
                            title=f"Meta tag {meta.get('name')} reveals author",
                            description=content, severity="low", confidence=90,
                            location=f"Meta: {meta.get('name')}", evidence=content,
                            category="passive", detection_method="meta_tag",
                        ))

                for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
                    comm = comment.strip()
                    if comm.startswith('<') or comm.startswith('function') or comm.startswith('$') or \
                       comm.startswith('var ') or comm.startswith('const ') or comm.startswith('let ') or \
                       comm.startswith('('):
                        continue
                    parent = getattr(comment, 'parent', None)
                    if parent and getattr(parent, 'name', '') in ('script', 'style', 'noscript'):
                        continue
                    is_noise = False
                    for noise_pat in HTML_COMMENT_NOISE_PATTERNS:
                        if re.search(noise_pat, comm, re.IGNORECASE):
                            is_noise = True
                            break
                    if is_noise:
                        continue
                    credential_match = False
                    for cred_pat in CREDENTIAL_PATTERNS:
                        if re.search(cred_pat, comm, re.IGNORECASE):
                            findings.append(_make_finding(
                                title="Sensitive HTML comment: Credential pattern detected",
                                description=f"Credential-like pattern in comment: {comm[:100]}",
                                severity="high", confidence=90, location="HTML comment", evidence=comm[:200],
                                remediation="Remove sensitive data from HTML comments.",
                                cwe="CWE-538", owasp="A01:2021", category="passive",
                                detection_method="pattern_match",
                            ))
                            credential_match = True
                            break
                    if credential_match:
                        continue
                    comm_lower = comm.lower()
                    for kw in DEVELOPER_NOTE_KEYWORDS:
                        if kw.lower() in comm_lower:
                            findings.append(_make_finding(
                                title=f"Developer note in HTML comment: {kw}",
                                description=f"Developer note found: {comm[:100]}",
                                severity="info", confidence=30, location="HTML comment", evidence=comm[:200],
                                remediation="Review comments before production deployment.",
                                cwe="CWE-200", category="passive",
                                detection_method="keyword_match",
                            ))
                            break

            await _check_js_source_maps(session, base_url, main_body, rate_limiter, findings)
            await _check_js_leaked_credentials(session, base_url, main_body, rate_limiter, findings, js_cache)
            await _enumerate_api_endpoints(session, base_url, rate_limiter, findings)
            await _check_interesting_files_from_headers(session, base_url, main_headers, findings)

            all_paths = []
            all_paths.extend(BASE_SENSITIVE_PATHS)
            for tech in tech_stack:
                if tech in TECH_SPECIFIC_PATHS:
                    for tp in TECH_SPECIFIC_PATHS[tech]:
                        if tp not in all_paths:
                            all_paths.append(tp)
            for ep in API_ENDPOINTS:
                if ep not in all_paths:
                    all_paths.append(ep)
            for bn in _generate_backup_names(domain):
                if bn not in all_paths:
                    all_paths.append(bn)
            paths_total = len(all_paths)

            try:
                async def _probe_all_paths():
                    nonlocal paths_checked
                    checked = 0
                    for path in all_paths:
                        url = urljoin(base_url, path)
                        try:
                            resp = await retry_path_probe(lambda: session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True))
                            if resp is None:
                                checked += 1
                                continue
                            status = resp.status
                            resp_headers = dict(resp.headers)
                            if status == 200:
                                try:
                                    body = await asyncio.wait_for(resp.text(errors='replace'), timeout=5)
                                except Exception:
                                    body = ""
                                if _is_sensitive_content(path, body):
                                    sensitivity, confidence = _forbidden_sensitivity(path)
                                    findings.append(_make_finding(
                                        title=f"Sensitive file exposed: {path}",
                                        description=f"Sensitive file accessible at {path}",
                                        severity="critical" if sensitivity == "high" else "high",
                                        confidence=confidence, location=path, evidence=body[:300],
                                        remediation=f"Restrict access to {path}.",
                                        cwe=CWE_MAP["sensitive_file"], owasp=OWASP_MAP["sensitive_file"],
                                        poc=f"curl {url}", category="active",
                                        detection_method="content_analysis",
                                    ))
                                if _is_directory_listing(body, main_body):
                                    findings.append(_make_finding(
                                        title=f"Directory listing enabled: {path}",
                                        description=f"Directory listing found at {path}",
                                        severity="medium", confidence=90, location=path,
                                        remediation="Disable directory listing.",
                                        cwe=CWE_MAP["dir_listing"], owasp=OWASP_MAP["dir_listing"],
                                        poc=f"curl {url}", category="active",
                                        detection_method="listing_detection",
                                    ))
                                if path == "robots.txt" and _is_robots_sensitive(body):
                                    findings.append(_make_finding(
                                        title="Sensitive paths in robots.txt",
                                        description="robots.txt reveals sensitive paths.",
                                        severity="medium", confidence=85, location="/robots.txt",
                                        evidence=body[:300],
                                        remediation="Review robots.txt for sensitive path disclosure.",
                                        cwe=CWE_MAP["sensitive_file"], owasp=OWASP_MAP["sensitive_file"],
                                        poc=f"curl {url}", category="active",
                                        detection_method="robots_analysis",
                                    ))
                                if not _is_soft_404(body, main_body) and path not in ["/robots.txt", "/sitemap.xml", "/favicon.ico"]:
                                    findings.append(_make_finding(
                                        title=f"Accessible file: {path}",
                                        description=f"File accessible at {path}",
                                        severity="low", confidence=70, location=path,
                                        remediation="Review if exposure is intentional.",
                                        poc=f"curl {url}", category="active",
                                        detection_method="file_accessible",
                                    ))
                            elif status == 403:
                                if path not in EXPECTED_403_PATHS:
                                    sensitivity, confidence = _forbidden_sensitivity(path)
                                    findings.append(_make_finding(
                                        title=f"Forbidden access to sensitive path: {path}",
                                        description=f"Path {path} returned 403 Forbidden",
                                        severity="low" if sensitivity == "low" else "medium",
                                        confidence=confidence - 10, location=path,
                                        remediation=f"Verify access controls for {path}.",
                                        cwe=CWE_MAP["sensitive_file"], owasp=OWASP_MAP["sensitive_file"],
                                        poc=f"curl -I {url}", category="active",
                                        detection_method="status_code",
                                    ))
                            elif status == 401:
                                findings.append(_make_finding(
                                    title=f"Unauthorized access to: {path}",
                                    description=f"Path {path} returned 401 Unauthorized",
                                    severity="info", confidence=75, location=path,
                                    remediation="Verify authentication requirements.",
                                    category="active", detection_method="status_code",
                                ))
                            checked += 1
                            paths_checked = checked
                        except asyncio.TimeoutError:
                            checked += 1
                            paths_checked = checked
                            continue
                        except Exception as e:
                            _log_error(f"Path probe failed for {path}: {e}")
                            checked += 1
                            paths_checked = checked
                            continue
                    return checked

                paths_checked = await asyncio.wait_for(_probe_all_paths(), timeout=INTERNAL_SCAN_BUDGET_SECONDS)
            except asyncio.TimeoutError:
                is_partial = True
                scan_note = f"Scan budget reached; results are partial. Checked {paths_checked}/{paths_total} paths."
                _log_error(f"[FIX #1] Internal scan budget reached: {paths_checked}/{paths_total} paths checked")

            paths_checked = min(paths_checked, paths_total)

            seen = set()
            unique_findings = []
            for f in findings:
                key = (f["title"], f["location"], f["category"])
                if key not in seen:
                    seen.add(key)
                    unique_findings.append(f)
            findings = unique_findings

    except Exception as e:
        _log_error(f"Scanner error: {e}")
        is_partial = True
        scan_note = f"Scanner error: {str(e)}"

    by_severity = defaultdict(int)
    by_category = defaultdict(int)
    for f in findings:
        by_severity[f["severity"]] += 1
        by_category[f["category"]] += 1

    summary_stats = {
        "total_findings": len(findings), "by_severity": dict(by_severity), "by_category": dict(by_category),
        "partial": is_partial, "paths_checked": paths_checked, "paths_total": paths_total,
    }

    score = calculate_score_v2(findings, site_context, waf_detected or False)
    grade = _score_to_grade(score)

    if is_partial:
        summary = f"Partial scan (budget reached). Found {len(findings)} findings. {scan_note}"
    elif len(findings) == 0:
        summary = "No information disclosure vulnerabilities detected."
    else:
        summary = f"Found {len(findings)} information disclosure findings across {len(by_category)} categories."

    remediation = []
    if any(f["severity"] in ("critical", "high") for f in findings):
        remediation.append("Address critical and high severity findings immediately.")
    if is_partial:
        remediation.append("Scan was partial due to timeout; consider increasing scan budget or reducing target scope.")

    return {
        "scanner": SCANNER_NAME, "target": target,
        "status": "partial" if is_partial else "success",
        "severity": max((f.get("severity", "info") for f in findings), default="info"),
        "confidence": max((f.get("confidence", 0) for f in findings), default=0),
        "score": score, "grade": grade, "summary": summary,
        "findings": findings, "remediation": remediation,
        "details": {
            "tech_stack": list(tech_stack), "waf_detected": waf_detected, "context": site_context,
            "summary_stats": summary_stats, "partial": is_partial,
            "paths_checked": paths_checked, "paths_total": paths_total, "note": scan_note,
        }
    }