#!/usr/bin/env python3
"""
test_06_info_disclosure.py – Bravo6 Info Disclosure Scanner (v12.7 – Accurate Tech Detection)
==============================================================================================
What it does:
  - Sensitive file discovery (.env, .git/HEAD, backups, etc.)
  - Source map detection & API enumeration
  - Cloud bucket (S3) listing checks
  - JavaScript credential leaks (hardcoded keys, entropy)
  - Technology fingerprinting (high‑precision HTML patterns only)

v12.7 Changes:
  - Eliminated false‑positive technology detections (Django, Rails, Laravel, React)
    by removing generic patterns (e.g., /assets/, /static/, id="root").
  - Added precise HTML signatures: csrfmiddlewaretoken for Django, meta csrf-param for Rails,
    meta csrf-token for Laravel, react.*.min.js for React.
  - Lowered confidence of HTML‑based technology findings to 75 (passive, no network verification).
  - Fixed false HTML comment detection (script/style content mistaken as Comment objects).
  - All previous fixes (WAF bonus, phpinfo evidence, IDE config, dedup, soft‑404, etc.) retained.
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

# ── Constants ──────────────────────────────────────────────────────────────
SCANNER_NAME = "info_disclosure"
USER_AGENT = "Bravo6-InfoDisclosure/12.7"
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=15)
HEAD_TIMEOUT = aiohttp.ClientTimeout(total=5)
MAX_CONCURRENT = 8
RETRY_MAX = 3
RETRY_BACKOFF_BASE = 1
PATH_RATE = 10

EXT_AGGREGATION_THRESHOLD = 5
DIR_AGGREGATION_THRESHOLD = 3

CWE_MAP = {
    "sensitive_file": "CWE-538",
    "source_map": "CWE-200",
    "api_endpoint": "CWE-200",
    "cloud_bucket": "CWE-200",
    "graphql": "CWE-200",
    "dir_listing": "CWE-548",
    "backup": "CWE-530",
    "user_enum": "CWE-200",
}
OWASP_MAP = {
    "sensitive_file": "A01:2021",
    "source_map": "A01:2021",
    "api_endpoint": "A01:2021",
    "cloud_bucket": "A06:2021",
    "graphql": "A01:2021",
    "dir_listing": "A05:2021",
    "backup": "A05:2021",
    "user_enum": "A01:2021",
}

# Paths that are normal to see 403 on
EXPECTED_403_PATHS = {
    "wp-content/uploads/",
    "wp-content/uploads",
    ".well-known/",
    ".well-known",
    "cgi-bin/",
    "cgi-bin",
}

# ── Helpers ───────────────────────────────────────────────────────────────
def _normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def _get_header(headers: Dict[str, str], name: str) -> Optional[str]:
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

def _log_error(msg: str):
    print(f"[{SCANNER_NAME}] ERROR: {msg}", file=sys.stderr)

# ── Shannon Entropy ────────────────────────────────────────────────────────
def _entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

# ── Version comparison ─────────────────────────────────────────────────────
def _parse_version(version_str: str) -> Tuple[int, ...]:
    parts = re.split(r'[.-]', version_str)
    return tuple(int(p) for p in parts if p.isdigit())

def _version_in_range(version: str, min_ver: Optional[str], max_ver: Optional[str]) -> bool:
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

# ── WAF Detection ─────────────────────────────────────────────────────────
async def _detect_waf(hostname: str, port: int = 443,
                      html: str = None, headers: dict = None) -> Optional[str]:
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

# ── Site Categorization ───────────────────────────────────────────────────
SITE_CATEGORIES = {
    "bank": ["bank", "online banking"],
    "ecommerce": ["shop", "store", "buy", "cart", "checkout", "shopping", "amazon", "ebay", "etsy", "aliexpress"],
    "healthcare": ["hospital"],
    "login": ["sign in", "login"],
    "blog": ["blog", "articles"],
    "internal": ["intranet", "internal"],
}

async def _categorize_site(hostname: str, port: int = 443,
                          html: str = None, headers: dict = None) -> Dict:
    result = {
        "categories": [],
        "has_login_form": False,
        "title": "",
        "meta_keywords": "",
        "is_login_page": False,
        "is_ecommerce": False,
        "is_internal": False,
        "is_api": False,
    }

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

# ── Finding Factory ────────────────────────────────────────────────────────
def _make_finding(
    title: str,
    description: str,
    severity: str,
    confidence: int,
    location: str = "",
    evidence: str = "",
    remediation: str = "",
    cwe: str = "",
    owasp: str = "",
    poc: Optional[str] = None,
    category: str = "passive",
) -> Dict:
    return {
        "title": title,
        "description": description,
        "severity": severity,
        "confidence": confidence,
        "location": location,
        "evidence": evidence,
        "remediation": remediation,
        "cwe": cwe,
        "owasp": owasp,
        "poc": poc,
        "category": category,
    }

# ── Risk Scoring ───────────────────────────────────────────────────────────
def calculate_score_v2(findings: List[Dict], context: Dict, waf_detected: bool) -> int:
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
    # WAF bonus (+5) unless a critical finding exists
    if waf_detected and not any(f.get("severity") == "critical" for f in findings):
        base += 5
    score = base + deductions
    return max(0, min(100, score))

def _score_to_grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"

# ══════════════════════════════════════════════════════════════════════════════
# Technology Fingerprinting & Smart Wordlist
# ══════════════════════════════════════════════════════════════════════════════
TECH_COOKIES = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java",
    "connect.sid": "Express",
    "laravel_session": "Laravel",
    "ASP.NET_SessionId": "ASP.NET",
    "ci_session": "CodeIgniter",
    "wp-settings-": "WordPress",
    "wordpress_logged_in_": "WordPress",
    "drupal_session": "Drupal",
    "Magento": "Magento",
}

HEADER_FINGERPRINTS = {
    "Server": {
        "nginx": "Nginx", "Apache": "Apache", "IIS": "IIS",
        "cloudflare": "Cloudflare", "Express": "Express.js",
    },
    "X-Powered-By": {
        "PHP": "PHP", "ASP.NET": "ASP.NET", "Express": "Express.js",
        "Next.js": "Next.js", "Laravel": "Laravel", "Django": "Django",
        "Flask": "Flask", "Ruby": "Ruby on Rails",
    },
    "X-Generator": {
        "WordPress": "WordPress", "Joomla": "Joomla", "Drupal": "Drupal",
        "Magento": "Magento",
    },
}

# HTML‑based technology fingerprints (v12.7 – strict, no false positives)
HTML_TECH_SIGNATURES = {
    # Only extremely specific patterns that don't appear in other frameworks
    "WordPress": [r'/wp-content/', r'/wp-includes/', r'wp-json'],  # very WordPress specific
    "Django":    [r'csrfmiddlewaretoken'],  # hidden form field unique to Django
    "Ruby on Rails": [r'<meta\s+name="csrf-param"'],  # Rails‑specific meta tag
    "Laravel":   [r'<meta\s+name="csrf-token"'],  # Laravel's CSRF meta tag
    "React":     [r'react\.(production|development)\.min\.js'],  # React library file in script src
    "Vue.js":    [r'v-app', r'v-bind', r'v-on'],  # Vue directives (still somewhat specific)
    "Angular":   [r'ng-app', r'ng-controller', r'ng-version'],  # AngularJS attributes
    "Bootstrap": [r'bootstrap\.min\.css', r'bootstrap\.bundle'],  # Bootstrap file names
    "jQuery":    [r'jquery\.min\.js', r'jquery\.js'],  # jQuery library
    "ASP.NET":   [r'__VIEWSTATE', r'__EVENTVALIDATION'],  # ASP.NET WebForms hidden fields
    "Next.js":   [r'/_next/static/', r'__NEXT_DATA__'],  # Next.js specific
    "Nuxt.js":   [r'/_nuxt/', r'window\.__NUXT__'],  # Nuxt.js specific
}

# Expansive sensitive path list (static, no extra requests)
BASE_SENSITIVE_PATHS = [
    ".git/HEAD", ".env", ".env.production", ".env.local",
    "composer.json", "package.json", "Gemfile", "requirements.txt",
    "phpinfo.php", "info.php", "test.php",
    "config.php", "settings.py", "web.config", ".htaccess",
    "robots.txt", "sitemap.xml",
    "swagger-ui.html", "v3/api-docs", "api-docs", "swagger.json",
    ".idea/workspace.xml", ".vscode/settings.json",
    "backup.zip", "dump.sql", "db.sql",
    "wp-config.php", "wp-config.php~", "wp-config.php.save", "wp-config.php.bak",
    "wp-content/debug.log", "wp-content/backup/", "wp-content/uploads/",
    "xmlrpc.php",
    ".DS_Store", "Thumbs.db", "error.log",
    ".env.backup", "config.bak",
    ".well-known/security.txt", ".well-known/openid-configuration",
    "firebase.json", "supabase.json", "vercel.json", "amplify.yml",
    "aws-exports.js", "google-services.json",
    "Dockerfile", "docker-compose.yml", ".gitlab-ci.yml", ".travis.yml",
    "Jenkinsfile", ".github/workflows/", ".circleci/config.yml",
    "Gemfile.lock", "yarn.lock", "pnpm-lock.yaml",
    "server.js", "app.js", "main.py", "manage.py",
    "db.sqlite3", "storage/logs/laravel.log",
    ".next/", "out/", "staticfiles/",
    "id_rsa", "id_rsa.pub", "authorized_keys",
    ".config", "appsettings.json", "web.config.bak", "config.yml",
    "parameters.yml", "services.yml", ".env.staging", ".env.development",
    "admin.php", "login.php", "user.php", "api.php", "cron.php",
    "wp-login.php", "administrator/index.php", "user/login",
    "graphql", "graphiql", "playground",
    "server-status", "server-info", "status", "healthcheck",
    "phpMyAdmin/", "adminer.php", "pma/",
    "crossdomain.xml", "clientaccesspolicy.xml",
    "sftp-config.json", ".htpasswd", ".bash_history",
    "config/database.yml", "config/secrets.yml", "config/initializers/secret_token.rb",
    "db/development.sqlite3", "log/production.log", "tmp/restart.txt",
    ".npmrc", ".yarnrc.yml", ".pypirc",
    "credentials.json", "secret_key.txt", "private.key", "cert.pem",
]

BACKUP_EXTS = [".zip", ".tar.gz", ".sql", ".bak", ".tar", ".7z", ".rar", ".gz", ".bz2"]

TECH_SPECIFIC_PATHS = {
    "WordPress": [
        "wp-config.php", "wp-content/backup/", "wp-content/uploads/",
        "wp-content/debug.log", "xmlrpc.php",
    ],
    "Laravel": [
        "storage/logs/laravel.log", ".env.example", "composer.lock",
        "vendor/", "storage/framework/views/", "storage/app/",
    ],
    "Django": [
        "settings.py", "db.sqlite3", "manage.py", "requirements.txt",
        "staticfiles/", "media/",
    ],
    "ASP.NET": [
        "web.config", "elmah.axd", "trace.axd", "bin/", "appsettings.json",
    ],
    "PHP": [
        "phpinfo.php", "config.php", "adminer.php", "info.php",
    ],
    "Express": [
        "package.json", "node_modules/", ".env", "app.js",
    ],
    "Java": [
        "WEB-INF/web.xml", "WEB-INF/classes/", "actuator/health",
        "actuator/env", "swagger-ui.html",
    ],
    "Flask": [
        "app.py", "config.py", "requirements.txt", "instance/",
    ],
    "Ruby": [
        "Gemfile", "config/database.yml", "config/secrets.yml",
    ],
    "React": [
        ".env", ".env.production", "build/", "node_modules/",
    ],
    "Vue.js": [
        ".env", ".env.production", "dist/", "node_modules/",
    ],
    "Next.js": [
        ".next/", "out/", ".env.local", "next.config.js",
    ],
    "Nuxt.js": [
        ".nuxt/", ".output/", ".env", "nuxt.config.js",
    ],
}

API_ENDPOINTS = [
    "graphql", "/api/v1/users", "/api/v1/products", "/api/v1/orders",
    "/api/v2/users", "/debug", "/admin", "/dashboard", "/login",
    "/wp-json/wp/v2/users", "/rest/user", "/oauth/token",
    "/.well-known/openid-configuration", "/actuator/health", "/actuator/env",
    "/graphql/console", "/swagger-resources", "/v2/api-docs",
]

# ── Soft 404 Detection (enhanced with difflib) ────────────────────────────
def _is_soft_404(body: str, homepage_body: str) -> bool:
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
    # difflib similarity for custom error pages
    try:
        ratio = difflib.SequenceMatcher(None, body[:2000], homepage_body[:2000]).ratio()
        if ratio > 0.85:
            return True
    except Exception:
        pass
    return False

# ── Response Placeholder ──────────────────────────────────────────────────
class ResponsePlaceholder:
    def __init__(self, status, headers):
        self.status = status
        self.headers = headers

# ── Rate Limiters ──────────────────────────────────────────────────────────
class LeakyBucketLimiter:
    def __init__(self, rate: float = PATH_RATE):
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
    def __init__(self, max_concurrent=8, min_delay=0.05, max_delay=0.2):
        self.sem = asyncio.Semaphore(max_concurrent)
        self.min_delay = min_delay
        self.max_delay = max_delay

    async def probe(self, session, url: str, method='GET') -> Optional[Any]:
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

# ── Backup Name Generation ────────────────────────────────────────────────
def _generate_backup_names(domain: str) -> List[str]:
    names = []
    base = domain.split('.')[0]
    patterns = [
        f"{domain}", f"{base}", f"{base}_backup", f"backup_{base}",
        f"{base}-backup", f"db", f"database",
        f"{base}_old", f"{base}_new",
        f"2024", f"2025", f"2026",
    ]
    for pattern in patterns:
        for ext in BACKUP_EXTS:
            names.append(f"{pattern}{ext}")
    for ext in BACKUP_EXTS:
        names.append(f"{domain}_backup_{datetime.now().strftime('%Y%m%d')}{ext}")
    return names

# ── JS exclusion list ──────────────────────────────────────────────────────
ENTROPY_EXCLUDE_DOMAINS = [
    "googletagmanager.com", "google-analytics.com", "facebook.net",
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
    "polyfill.io", "static.cloudflareinsights.com",
]

# ── JS Leaked Credentials ──────────────────────────────────────────────────
JS_SAFE_TOKENS = [
    'localStorage', 'getToken', 'setToken', 'removeToken', 'clearToken',
    'token_type', 'grant_type', 'access_token', 'refresh_token',
]
JS_CODE_KEYWORDS = ['function', 'var', 'let', 'const', 'return']

HIGH_CONFIDENCE_SECRET_PATTERNS = [
    r'(?:AKIA|ASIA)[A-Z0-9]{16}',
    r'sk-[a-zA-Z0-9]{32,}',
    r'github_pat_[a-zA-Z0-9_]{22,}',
    r'AIza[0-9A-Za-z\-_]{35}',
    r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
    r'pk_(live|test)_[a-zA-Z0-9]{24,}',
]
BROAD_SECRET_PATTERN = re.compile(
    r'(?:api[_-]?key|apikey|secret|password|token|auth)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{8,})["\']?',
    re.IGNORECASE
)

async def _fetch_js_cached(session, url: str, rate_limiter, js_cache: Dict[str, Optional[str]]) -> Optional[str]:
    if url in js_cache:
        return js_cache[url]
    resp = await rate_limiter.probe(session, url, 'GET')
    if resp and resp.status == 200:
        content = await resp.text(errors='replace')
        js_cache[url] = content
        return content
    else:
        js_cache[url] = None
        return None

async def _check_js_source_maps(session, base_url, html: str, rate_limiter, findings):
    if not html:
        return
    try:
        soup = BeautifulSoup(html, "html.parser")
        js_links = []
        for script in soup.find_all("script", src=True):
            full_url = urljoin(base_url, script["src"])
            js_links.append(full_url)
        for script in soup.find_all("script"):
            if script.string and 'sourceMappingURL' in script.string:
                map_match = re.search(r'//# sourceMappingURL=(.*)', script.string)
                if map_match:
                    map_url = urljoin(base_url, map_match.group(1).strip())
                    findings.append(_make_finding(
                        title="Source map referenced inline",
                        description=f"Found sourceMappingURL: {map_url}",
                        severity="high", confidence=90,
                        location="Inline script", evidence=map_url,
                        remediation="Remove sourceMappingURL from production scripts.",
                        cwe=CWE_MAP["source_map"], owasp=OWASP_MAP["source_map"],
                        poc="View page source and search 'sourceMappingURL'",
                        category="js"
                    ))
        for js_url in js_links:
            if js_url.endswith('.js'):
                map_url = js_url + '.map'
                resp_map = await rate_limiter.probe(session, map_url, 'GET')
                if resp_map and resp_map.status == 200:
                    body = await resp_map.text()
                    if body.strip() and ('"sources"' in body or '"mappings"' in body):
                        findings.append(_make_finding(
                            title="Source map exposed",
                            description=f"Source map found at {map_url}",
                            severity="high", confidence=95,
                            location=map_url, evidence=body[:300],
                            remediation="Disable source maps in production.",
                            cwe=CWE_MAP["source_map"], owasp=OWASP_MAP["source_map"],
                            poc=f"curl {map_url}",
                            category="js"
                        ))
    except Exception as e:
        _log_error(f"JS source map check failed: {e}")

async def _check_js_leaked_credentials(session, base_url, html: str, rate_limiter, findings,
                                       js_cache: Dict[str, Optional[str]]):
    if not html:
        return
    try:
        soup = BeautifulSoup(html, "html.parser")
        js_urls = set()
        for script in soup.find_all("script", src=True):
            full = urljoin(base_url, script["src"])
            js_urls.add(full)
        for js_url in js_urls:
            content = await _fetch_js_cached(session, js_url, rate_limiter, js_cache)
            if not content:
                continue

            for pat in HIGH_CONFIDENCE_SECRET_PATTERNS:
                for m in re.findall(pat, content):
                    findings.append(_make_finding(
                        title="Hardcoded credential / API key in JavaScript",
                        description=f"High-confidence secret found: {m}",
                        severity="critical", confidence=95,
                        location=js_url, evidence=f"Matched: {m}",
                        remediation="Remove all secrets from client-side code.",
                        cwe="CWE-798", owasp="A07:2021",
                        poc=f"Inspect {js_url}",
                        category="js"
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
                    severity="medium", confidence=50,
                    location=js_url, evidence=f"Secret: {val}",
                    remediation="Review code for hardcoded secrets.",
                    cwe="CWE-798", owasp="A07:2021",
                    poc=f"Inspect {js_url}",
                    category="js"
                ))
            parsed = urlparse(js_url)
            if not any(domain in parsed.netloc for domain in ENTROPY_EXCLUDE_DOMAINS):
                for match in re.finditer(r'["\']([a-zA-Z0-9_\-+/=]{20,})["\']', content):
                    candidate = match.group(1)
                    if _entropy(candidate) > 5.0:
                        start = max(0, match.start() - 200)
                        context_window = content[start:match.end() + 50]
                        if not re.search(r'(api[_\s]?key|secret|token|auth|password|private[_\s]?key)',
                                         context_window, re.IGNORECASE):
                            continue
                        findings.append(_make_finding(
                            title="High-entropy string detected (possible API key)",
                            description=f"High-entropy string: {candidate}",
                            severity="medium", confidence=60,
                            location=js_url, evidence=f"Entropy: {_entropy(candidate):.2f}",
                            remediation="Verify if this is a hardcoded secret.",
                            cwe="CWE-798", owasp="A07:2021",
                            poc=f"Inspect {js_url}",
                            category="js"
                        ))
    except Exception as e:
        _log_error(f"JS leaked credential check failed: {e}")

# ── Interesting Files from Headers ─────────────────────────────────────────
async def _check_interesting_files_from_headers(session, base_url, main_headers, findings):
    etag = _get_header(main_headers, "ETag")
    last_mod = _get_header(main_headers, "Last-Modified")
    if not etag and not last_mod: return
    interesting = ["/robots.txt", "/sitemap.xml", "/favicon.ico", "/.well-known/security.txt",
                   "/crossdomain.xml", "/clientaccesspolicy.xml"]
    rate_limiter = RateLimiter(max_concurrent=5)
    for path in interesting:
        url = urljoin(base_url, path)
        resp = await rate_limiter.probe(session, url, 'HEAD')
        if resp and resp.status == 200:
            findings.append(_make_finding(
                title=f"Interesting file found: {path}",
                description="Static file accessible, may reveal information.",
                severity="low", confidence=70,
                location=path,
                remediation="Review if exposure is intentional.",
                poc=f"curl {url}",
                category="active"
            ))

# ── API Endpoint Enumeration (with timeout on body read) ─────────────────
async def _enumerate_api_endpoints(session, base_url, rate_limiter, findings):
    reported_user_enum = False
    for endpoint in API_ENDPOINTS:
        url = urljoin(base_url, endpoint)
        resp = await rate_limiter.probe(session, url, 'GET')
        if resp is None: continue
        if resp.status == 200:
            content_type = resp.headers.get('Content-Type', '')
            try:
                body = await asyncio.wait_for(resp.text(), timeout=10)  # safe read timeout
            except Exception:
                continue
            if endpoint == "/wp-json/wp/v2/users":
                if not reported_user_enum and '"id"' in body and '"name"' in body and '"slug"' in body:
                    findings.append(_make_finding(
                        title="WordPress User Enumeration",
                        description="The WordPress REST API endpoint exposes user names, slugs, and IDs.",
                        severity="medium", confidence=100,
                        location=endpoint, evidence=body[:300],
                        remediation="Disable anonymous access to the users endpoint.",
                        cwe=CWE_MAP["user_enum"], owasp=OWASP_MAP["user_enum"],
                        poc=f"curl {url}",
                        category="api"
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
                                    severity="high", confidence=100,
                                    location=endpoint,
                                    evidence="Introspection query returned schema data.",
                                    remediation="Disable introspection in production.",
                                    cwe=CWE_MAP["graphql"], owasp=OWASP_MAP["graphql"],
                                    poc=f"curl -X POST {url} -d '{{\"query\":\"{{__schema{{types{{name}}}}}}\"}}'",
                                    category="api"
                                ))
                            continue
                except Exception as e:
                    _log_error(f"GraphQL introspection check failed for {endpoint}: {e}")
                continue
            if any(kw in body.lower() for kw in ['swagger', 'openapi', 'api-docs']):
                findings.append(_make_finding(
                    title="API documentation exposed",
                    description=f"Possible Swagger/OpenAPI spec at {endpoint}",
                    severity="high", confidence=90,
                    location=endpoint,
                    remediation="Restrict access to API docs.",
                    cwe=CWE_MAP["api_endpoint"], owasp=OWASP_MAP["api_endpoint"],
                    poc=f"curl {url}",
                    category="api"
                ))
            elif 'application/json' in content_type:
                findings.append(_make_finding(
                    title=f"Potential API endpoint: {endpoint}",
                    description="Endpoint returns JSON, may expose data.",
                    severity="medium", confidence=60,
                    location=endpoint, evidence=body[:200],
                    remediation="Verify endpoint requires authentication.",
                    cwe=CWE_MAP["api_endpoint"], owasp=OWASP_MAP["api_endpoint"],
                    category="api"
                ))
        elif resp.status in (401, 403):
            sev = "low" if "wp-json" in endpoint and "users" in endpoint else "info"
            findings.append(_make_finding(
                title=f"Protected API endpoint: {endpoint}",
                description="Endpoint exists but requires authentication — verify access controls are correctly enforced.",
                severity=sev, confidence=85,
                location=endpoint,
                remediation="Ensure the endpoint requires authentication and test with a real unauthenticated request.",
                category="api"
            ))

# ══════════════════════════════════════════════════════════════════════════════
# Forbidden File Sensitivity and Aggregation Logic
# ══════════════════════════════════════════════════════════════════════════════
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

def _forbidden_sensitivity(path: str) -> Tuple[str, int]:
    path_lower = path.lower()
    for high_pat in HIGH_SENSITIVE_PATHS:
        if high_pat in path_lower:
            return ("high", 90)
    for med_pat in MEDIUM_SENSITIVE_PATHS:
        if med_pat in path_lower:
            return ("medium", 80)
    return ("low", 60)

def _detect_wordpress_from_findings(findings: List[Dict]) -> bool:
    for f in findings:
        loc = f.get("location", "")
        if 'wp-json' in loc or 'wp-content' in loc or 'wp-admin' in loc or 'wp-login' in loc:
            return True
    return False

async def _fetch_generic_403_body(session, base_url: str, limiter: LeakyBucketLimiter,
                                   ext: str = ".html") -> Optional[str]:
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

async def _fetch_body(session, url: str) -> Optional[str]:
    try:
        async with session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True) as resp:
            if resp.status == 200:
                return await resp.text(errors="replace")
    except Exception as e:
        _log_error(f"Failed to fetch body for {url}: {e}")
    return None

def _body_matches_generic(body: str, generic_body: Optional[str]) -> bool:
    if not generic_body or not body:
        return False
    b_stripped = body.strip()
    g_stripped = generic_body.strip()
    if abs(len(b_stripped) - len(g_stripped)) <= max(len(g_stripped) * 0.1, 50):
        if b_stripped == g_stripped:
            return True
    return False

def _is_robots_sensitive(body: str) -> bool:
    sensitive_patterns = [r'admin', r'backup', r'config', r'\.git', r'\.env', r'wp-admin', r'login', r'dashboard']
    for pattern in sensitive_patterns:
        if re.search(r'Disallow:\s*/' + pattern, body, re.IGNORECASE):
            return True
    return False

def _is_sensitive_content(path: str, body: str) -> bool:
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
    if "CHANGELOG" in path or "VERSION" in path or "RELEASE" in path:
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

def _is_directory_listing(body: str, homepage_body: str) -> bool:
    if not body or not homepage_body:
        return False
    listing_indicators = [
        "Index of /", "Parent Directory", "<title>Index of",
        '<h1>Index of', "Directory Listing"
    ]
    if not any(ind in body for ind in listing_indicators):
        return False
    if body.strip() == homepage_body.strip():
        return False
    if body[:500] == homepage_body[:500] and len(body) == len(homepage_body):
        return False
    if not re.search(r'<a\s+href="[^"]*"[^>]*>', body, re.IGNORECASE):
        return False
    return True

def _is_real_path_traversal(body: str, homepage_body: str, orig_dir_body: Optional[str]) -> bool:
    if not body or not homepage_body:
        return False
    if body[:500] == homepage_body[:500]:
        return False
    if orig_dir_body and body[:300] == orig_dir_body[:300]:
        return False
    if "Parent Directory" in body or "Index of" in body:
        return True
    return False

# ══════════════════════════════════════════════════════════════════════════════
# Smart Tech Detection from HTML (v12.7 – high precision)
# ══════════════════════════════════════════════════════════════════════════════
def _detect_tech_from_html(html: str) -> Set[str]:
    """Passive technology detection using only highly specific HTML patterns."""
    if not html:
        return set()
    detected = set()
    for tech, patterns in HTML_TECH_SIGNATURES.items():
        for pat in patterns:
            if re.search(pat, html, re.IGNORECASE):
                detected.add(tech)
                break
    return detected

# ── Main Scanner ───────────────────────────────────────────────────────────
async def run(url: str, shared_page: dict = None) -> Dict[str, Any]:
    target = _normalize_url(url)
    parsed = urlparse(target)
    hostname = parsed.hostname or ""
    port = parsed.port or 443
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    domain = hostname

    findings: List[Dict] = []
    tech_stack: Set[str] = set()
    rate_limiter = RateLimiter(max_concurrent=MAX_CONCURRENT)

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
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            connector=connector
        ) as session:
            main_resp = await retry_async(lambda: rate_limiter.probe(session, target, 'GET'))
            if main_resp is None or main_resp.status != 200:
                return {
                    "scanner": SCANNER_NAME,
                    "target": target,
                    "status": "error",
                    "severity": "info",
                    "confidence": 0,
                    "score": 0,
                    "grade": "F",
                    "summary": "Could not fetch main page.",
                    "findings": [],
                    "remediation": [],
                    "details": {}
                }
            main_body = await main_resp.text()
            main_headers = dict(main_resp.headers)
            soup = BeautifulSoup(main_body, "html.parser")
            site_context = await _categorize_site(hostname, port, html=main_body, headers=main_headers)
            waf_detected = await _detect_waf(hostname, port, headers=main_headers)
            js_cache = {}

    site_context["is_api"] = hostname.startswith("api.") or "/api/" in parsed.path

    try:
        async with aiohttp.ClientSession(
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            connector=aiohttp.TCPConnector(ssl=True, limit=MAX_CONCURRENT + 10)
        ) as session:

            # ── Passive technology fingerprint (headers) ───────────────
            for header_name, patterns in HEADER_FINGERPRINTS.items():
                val = _get_header(main_headers, header_name)
                if val:
                    for keyword, label in patterns.items():
                        if keyword.lower() in val.lower():
                            tech_stack.add(label)
                            findings.append(_make_finding(
                                title=f"Technology identified: {label}",
                                description=f"Header {header_name} reveals {val}",
                                severity="low", confidence=80,
                                location=f"Header: {header_name}",
                                evidence=val,
                                remediation="Remove or obscure version headers.",
                                cwe="CWE-200",
                                category="passive"
                            ))
                            break
            set_cookie = _get_header(main_headers, "Set-Cookie") or ""
            for cookie_key, tech in TECH_COOKIES.items():
                if cookie_key in set_cookie:
                    tech_stack.add(tech)
                    findings.append(_make_finding(
                        title=f"Technology identified: {tech}",
                        description=f"Cookie {cookie_key} present",
                        severity="info", confidence=100,
                        location=f"Cookie: {cookie_key}",
                        category="passive"
                    ))
            for specific in ["X-AspNet-Version", "X-AspNetMvc-Version"]:
                val = _get_header(main_headers, specific)
                if val:
                    findings.append(_make_finding(
                        title=f"Exact version disclosed",
                        description=f"{specific}: {val}",
                        severity="medium", confidence=90,
                        location=f"Header: {specific}", evidence=val,
                        remediation="Remove version headers.",
                        cwe="CWE-200",
                        category="config"
                    ))

            # ── HTML-based tech fingerprinting (high precision) ─────────
            html_techs = _detect_tech_from_html(main_body)
            for tech in html_techs:
                tech_stack.add(tech)
                findings.append(_make_finding(
                    title=f"Technology identified: {tech}",
                    description="Detected from HTML signature",
                    severity="info", confidence=75,   # reduced confidence for passive detection
                    location="HTML body",
                    category="passive"
                ))

            # ── HTML meta / comments ────────────────────────────────────
            if soup:
                for meta in soup.find_all("meta", attrs={"name": "generator"}):
                    content = meta.get("content", "")
                    if "WordPress" in content:
                        tech_stack.add("WordPress")
                        findings.append(_make_finding(
                            title="Technology identified: WordPress",
                            description=f"Meta generator: {content}",
                            severity="info", confidence=100,
                            location="Meta generator", evidence=content,
                            category="passive"
                        ))
                if re.search(r'(wp-content|wp-includes)', main_body):
                    tech_stack.add("WordPress")
                for meta in soup.find_all("meta", attrs={"name": lambda x: x and x.lower() in ("author",)}):
                    content = meta.get("content", "")
                    if content:
                        findings.append(_make_finding(
                            title=f"Meta tag {meta.get('name')} reveals author",
                            description=content,
                            severity="low", confidence=90,
                            location=f"Meta: {meta.get('name')}", evidence=content,
                            category="passive"
                        ))
                noise_patterns = [r'sp:feature', r'google\.com/recaptcha', r'Async Google Analytics']
                for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
                    comm = comment.strip()
                    # ── Fix: filter out non‑comment strings that BS erroneously classifies as Comment ──
                    # Skip if looks like JS/CSS or other tag content
                    if comm.startswith('<') or comm.startswith('function') or comm.startswith('$') or comm.startswith('var ') or comm.startswith('const ') or comm.startswith('let ') or comm.startswith('('):
                        continue
                    parent = getattr(comment, 'parent', None)
                    if parent and getattr(parent, 'name', '') in ('script', 'style', 'noscript'):
                        continue
                    # ── End fix ──────────────────────────────────────────────────────────────────────
                    if any(re.search(p, comm) for p in noise_patterns):
                        continue
                    if any(kw.lower() in comm.lower() for kw in ["TODO", "FIXME", "BUG", "HACK", "password",
                                                                   "secret", "api", "token", "admin", "debug"]):
                        findings.append(_make_finding(
                            title="Sensitive HTML comment",
                            description=comm[:200],
                            severity="info", confidence=60,
                            location="HTML comment", evidence=comm[:200],
                            category="passive"
                        ))

            # ── Build wordlist (smart tech_stack now accurate) ─────────
            all_paths = set(BASE_SENSITIVE_PATHS)
            for bn in _generate_backup_names(domain):
                all_paths.add(bn)

            if not tech_stack:
                for wp_path in TECH_SPECIFIC_PATHS.get("WordPress", []):
                    all_paths.add(wp_path)
            else:
                for tech in tech_stack:
                    for tpaths in TECH_SPECIFIC_PATHS.get(tech, []):
                        all_paths.add(tpaths)
            all_paths.update(["wp-config.php", "wp-content/debug.log", "xmlrpc.php"])

            # Generic 403 bodies
            path_limiter = LeakyBucketLimiter(rate=PATH_RATE)
            generic_403_html = await _fetch_generic_403_body(session, base_url, path_limiter, ".html")
            generic_403_by_ext = {}
            for ext in BACKUP_EXTS:
                body = await _fetch_generic_403_body(session, base_url, path_limiter, f".{ext.lstrip('.')}")
                if body:
                    generic_403_by_ext[ext] = body

            forbidden_candidates = []
            raw_403_by_ext = []

            async def probe_path(path):
                full_url = urljoin(base_url, path)
                head_resp = await rate_limiter.probe(session, full_url, 'HEAD')
                if head_resp is None or head_resp.status == 405:
                    head_resp = await rate_limiter.probe(session, full_url, 'GET')
                    if head_resp is None:
                        return
                    if head_resp.status == 200:
                        try:
                            body = await head_resp.text()
                        except:
                            body = None
                        status = 200
                    else:
                        status = head_resp.status
                        body = None
                else:
                    status = head_resp.status
                    body = None

                if status == 200:
                    if body is None:
                        body = await _fetch_body(session, full_url)
                    if body:
                        if main_body and _is_soft_404(body, main_body):
                            return
                        if any(ide in path for ide in (".vscode/", ".idea/")):
                            findings.append(_make_finding(
                                title=f"IDE configuration file exposed: {path}",
                                description="IDE config files may contain local paths, database URIs, or project secrets.",
                                severity="medium", confidence=85,
                                location=path, evidence=body[:300],
                                remediation="Add .vscode/ and .idea/ to your .gitignore and remove from the web root.",
                                cwe="CWE-200", owasp="A01:2021",
                                poc=f"curl {full_url}",
                                category="active"
                            ))
                            return
                        if path == "robots.txt":
                            if _is_robots_sensitive(body):
                                findings.append(_make_finding(
                                    title="robots.txt exposes sensitive paths",
                                    description="robots.txt contains disallowed admin/backup paths.",
                                    severity="medium", confidence=90,
                                    location=path, evidence=body[:1000],
                                    remediation="Review robots.txt and remove sensitive entries.",
                                    category="config"
                                ))
                            return
                        if path == "sitemap.xml":
                            if "<urlset" not in body and "<sitemapindex" not in body:
                                findings.append(_make_finding(
                                    title="Suspicious sitemap.xml",
                                    description="File exists but lacks standard sitemap structure.",
                                    severity="low", confidence=50,
                                    location=path, evidence=body[:300],
                                    remediation="Check if this file is intentionally exposed.",
                                    category="config"
                                ))
                            return
                        if _is_sensitive_content(path, body):
                            sev, conf, risk = "critical", 100, "Sensitive file exposed and verified."
                            if "phpinfo" in path.lower():
                                ver_match = re.search(r'PHP Version\s+([\d.]+)', body)
                                evidence_str = f"PHP Version: {ver_match.group(1)}" if ver_match else body[:300]
                            else:
                                evidence_str = body[:300]
                        else:
                            sev, conf, risk = "info", 50, "File exists but content does not match expected sensitive pattern."
                            evidence_str = body[:300]
                        findings.append(_make_finding(
                            title=f"Exposed file: {path}",
                            description=risk,
                            severity=sev, confidence=conf,
                            location=path, evidence=evidence_str,
                            remediation="Restrict access or remove file.",
                            cwe=CWE_MAP.get("sensitive_file", "CWE-538"),
                            owasp=OWASP_MAP.get("sensitive_file", "A01:2021"),
                            poc=f"curl {full_url}",
                            category="active"
                        ))
                elif status == 403:
                    path_norm = path.strip("/")
                    if path_norm in EXPECTED_403_PATHS:
                        return
                    ext_for_body = None
                    for e in BACKUP_EXTS:
                        if path.endswith(e):
                            ext_for_body = e
                            break
                    generic_body = generic_403_by_ext.get(ext_for_body) if ext_for_body else generic_403_html
                    if generic_body:
                        if body is None:
                            body = await _fetch_body(session, full_url)
                        if body and _body_matches_generic(body, generic_body):
                            raw_403_by_ext.append({"path": path, "ext": ext_for_body or "unknown"})
                            return
                    sev, conf = _forbidden_sensitivity(path)
                    ext_agg = ext_for_body or ('.' + path.rsplit('.', 1)[-1] if '.' in path else path)
                    forbidden_candidates.append({
                        "path": path,
                        "ext": ext_agg,
                        "severity": sev,
                        "confidence": conf,
                    })

            tasks = [probe_path(p) for p in all_paths]
            await asyncio.gather(*tasks, return_exceptions=True)

            # ── Post‑process forbidden candidates ────────────────────────
            ext_groups = defaultdict(list)
            for cand in forbidden_candidates:
                ext_groups[cand["ext"]].append(cand)

            for ext, cands in ext_groups.items():
                if len(cands) > EXT_AGGREGATION_THRESHOLD:
                    high_cands = [c for c in cands if c["severity"] == "high"]
                    other_cands = [c for c in cands if c["severity"] != "high"]
                    for c in high_cands:
                        findings.append(_make_finding(
                            title=f"Protected sensitive file: {c['path']}",
                            description="Highly sensitive file exists but is protected (403).",
                            severity=c["severity"],
                            confidence=c["confidence"],
                            location=c["path"],
                            remediation="Ensure strong access controls are in place.",
                            cwe="CWE-538",
                            owasp="A01:2021",
                            category="config"
                        ))
                    if other_cands:
                        paths = [c["path"] for c in other_cands]
                        findings.append(_make_finding(
                            title=f"Multiple {ext} files are blocked (403)",
                            description=f"{len(other_cands)} {ext} paths return 403. "
                                        f"Examples: {', '.join(paths[:5])}",
                            severity="info",
                            confidence=90,
                            location=f"Multiple paths (*{ext})",
                            evidence=f"{len(other_cands)} blocked files",
                            remediation="Verify sensitive files are not accidentally exposed.",
                            category="config"
                        ))
                    for c in cands:
                        if c in forbidden_candidates:
                            forbidden_candidates.remove(c)

            dir_groups = defaultdict(list)
            for cand in forbidden_candidates:
                if cand["severity"] == "low":
                    first_dir = cand["path"].split('/')[0] if '/' in cand["path"] else ""
                    dir_groups[first_dir].append(cand)

            for dir_name, cands in dir_groups.items():
                if len(cands) > DIR_AGGREGATION_THRESHOLD:
                    paths = [c["path"] for c in cands]
                    findings.append(_make_finding(
                        title=f"Directory {dir_name}/ is protected (403) for multiple files",
                        description=f"{len(paths)} low‑sensitivity files in /{dir_name} return 403.",
                        severity="info",
                        confidence=85,
                        location=f"/{dir_name}/",
                        evidence=f"Examples: {', '.join(paths[:5])}",
                        remediation="This is likely intended.",
                        category="config"
                    ))
                    for c in cands:
                        if c in forbidden_candidates:
                            forbidden_candidates.remove(c)

            for cand in forbidden_candidates:
                sev, conf = cand["severity"], cand["confidence"]
                if sev == "high":
                    title = f"Protected sensitive file: {cand['path']}"
                elif sev == "medium":
                    title = f"Protected file: {cand['path']}"
                else:
                    title = f"Forbidden file: {cand['path']}"
                findings.append(_make_finding(
                    title=title,
                    description="File exists but returns 403 Forbidden.",
                    severity=sev,
                    confidence=conf,
                    location=cand["path"],
                    remediation="Ensure proper access controls.",
                    cwe="CWE-538",
                    owasp="A01:2021",
                    category="config"
                ))

            ext_block_groups = defaultdict(list)
            for item in raw_403_by_ext:
                ext_block_groups[item["ext"]].append(item["path"])
            for ext, paths in ext_block_groups.items():
                findings.append(_make_finding(
                    title=f"Server blocks access to {ext} files",
                    description=f"Blanket 403 for {ext} paths.",
                    severity="info", confidence=90,
                    location=f"Multiple paths (*{ext})",
                    evidence=f"Examples: {', '.join(paths[:5])}",
                    remediation="Verify backups are not exposed.",
                    category="config"
                ))

            # Directory listing & traversal
            dir_paths = ["/assets/", "/static/", "/uploads/", "/files/", "/images/", "/css/", "/js/"]
            dir_urls = [urljoin(base_url, d) for d in dir_paths]
            trav_urls = [urljoin(base_url, d + "../") for d in dir_paths]

            dir_bodies, trav_bodies = await asyncio.gather(
                asyncio.gather(*[_fetch_body(session, url) for url in dir_urls]),
                asyncio.gather(*[_fetch_body(session, url) for url in trav_urls])
            )

            for d, body, tbody in zip(dir_paths, dir_bodies, trav_bodies):
                if body and _is_directory_listing(body, main_body):
                    findings.append(_make_finding(
                        title=f"Directory listing enabled: {d}",
                        description="Directory listing allows attackers to see file structure.",
                        severity="critical", confidence=95,
                        location=d, evidence=body[:200],
                        remediation="Disable directory listing.",
                        cwe=CWE_MAP["dir_listing"], owasp=OWASP_MAP["dir_listing"],
                        poc=f"curl {urljoin(base_url, d)}",
                        category="active"
                    ))
                if tbody and _is_real_path_traversal(tbody, main_body, body):
                    findings.append(_make_finding(
                        title="Path traversal possible",
                        description="Parent directory accessible.",
                        severity="critical", confidence=95,
                        location=d + "../", evidence=tbody[:200],
                        remediation="Configure web server to prevent directory traversal.",
                        poc=f"curl {urljoin(base_url, d + '../')}",
                        category="active"
                    ))

            # Cloud storage
            bucket_links = re.findall(r'https?://([a-zA-Z0-9.-]+\.s3\.amazonaws\.com/[^\s"\']+)', main_body)
            for link in bucket_links[:3]:
                list_url = f"https://{link}?list-type=2"
                body = await _fetch_body(session, list_url)
                if body and "ListBucketResult" in body:
                    findings.append(_make_finding(
                        title="Public S3 bucket listing",
                        description=f"Bucket {link} is listable.",
                        severity="critical", confidence=100,
                        location=link, evidence=body[:200],
                        remediation="Remove public ACL from bucket.",
                        cwe=CWE_MAP["cloud_bucket"], owasp=OWASP_MAP["cloud_bucket"],
                        poc=f"curl {list_url}",
                        category="active"
                    ))

            await _check_interesting_files_from_headers(session, base_url, main_headers, findings)
            await _check_js_source_maps(session, base_url, main_body, rate_limiter, findings)
            await _check_js_leaked_credentials(session, base_url, main_body, rate_limiter, findings, js_cache)
            await _enumerate_api_endpoints(session, base_url, rate_limiter, findings)

    except Exception as e:
        _log_error(f"Scan failed: {e}")
        return {
            "scanner": SCANNER_NAME,
            "target": target,
            "status": "error",
            "severity": "info",
            "confidence": 0,
            "score": 0,
            "grade": "F",
            "summary": f"Scan error: {str(e)[:100]}",
            "findings": [],
            "remediation": [],
            "details": {}
        }

    # Post‑processing
    if _detect_wordpress_from_findings(findings):
        tech_stack.add("WordPress")

    unique = []
    seen = set()
    for f in findings:
        key = (f.get("title", "").strip(), f.get("location", "").strip().rstrip("/"))
        if key not in seen:
            seen.add(key)
            unique.append(f)
    findings = unique

    score = calculate_score_v2(findings, site_context, waf_detected)
    grade = _score_to_grade(score)

    sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    worst_sev = max((f["severity"] for f in findings), key=lambda s: sev_order.get(s, 0), default="info")
    status = "fail" if any(sev_order.get(f["severity"], 0) >= 3 for f in findings) else "warning" if findings else "pass"

    confidences = [f["confidence"] for f in findings if f["severity"] != "info"]
    avg_conf = round(sum(confidences) / len(confidences)) if confidences else 50

    remediation_list = list(set(f.get("remediation", "") for f in findings if f.get("remediation")))
    if not remediation_list:
        remediation_list = ["No action needed."]

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1

    details = {
        "tech_stack": sorted(list(tech_stack)),
        "waf_detected": waf_detected,
        "context": {
            "is_login_page": site_context["is_login_page"],
            "is_ecommerce": site_context["is_ecommerce"],
            "is_internal": site_context["is_internal"],
            "is_api": site_context["is_api"],
        },
        "summary_stats": {
            "total_findings": len(findings),
            "critical_count": counts["critical"],
            "high_count": counts["high"],
            "medium_count": counts["medium"],
            "low_count": counts["low"],
            "info_count": counts["info"],
        }
    }

    return {
        "scanner": SCANNER_NAME,
        "target": target,
        "status": status,
        "severity": worst_sev,
        "confidence": avg_conf,
        "score": score,
        "grade": grade,
        "summary": f"Info Disclosure – {len(findings)} findings | Score {score}/100 | Grade {grade}",
        "findings": findings,
        "remediation": remediation_list,
        "details": details,
    }

if __name__ == "__main__":
    target_url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    result = asyncio.run(run(target_url))
    print(json.dumps(result, indent=2, ensure_ascii=False))