#!/usr/bin/env python3
"""
test_06_info_disclosure.py - Bravo6 Info Disclosure Scanner (v13.0 - Enterprise Grade)
======================================================================================
Enterprise-grade Information Exposure Detection Engine.
Refactored to comply with BRAVO6 UNIFIED PLUGIN CONTRACT — SHARED RULES v2.2.
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
USER_AGENT = "Bravo6-InfoDisclosure/13.0"
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=15)
HEAD_TIMEOUT = aiohttp.ClientTimeout(total=5)
MAX_CONCURRENT = 25
INTERNAL_SCAN_BUDGET_SECONDS = 50
PRE_PHASE_BUDGET_SECONDS = 15
TOTAL_INTERNAL_BUDGET_SECONDS = 50
SAFETY_NET_SECONDS = 55
PATH_RATE = 10
PATH_PROBE_RETRY_MAX = 1
PATH_PROBE_BACKOFF_BASE = 0.1
RETRY_MAX = 3
RETRY_BACKOFF_BASE = 1

# -- Severity Ranking Map ----------------------------------------------------------------
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# -- CWE / OWASP Maps --------------------------------------------------------------------
CWE_MAP = {
    "sensitive_file": "CWE-538", "source_map": "CWE-200", "api_endpoint": "CWE-200",
    "cloud_bucket": "CWE-200", "graphql": "CWE-200", "dir_listing": "CWE-548",
    "backup": "CWE-530", "user_enum": "CWE-200", "k8s_exposure": "CWE-200",
    "docker_exposure": "CWE-200", "terraform_exposure": "CWE-538", "ide_config": "CWE-200",
    "js_route": "CWE-200", "cloud_storage": "CWE-200",
}
OWASP_MAP = {
    "sensitive_file": "A01:2021", "source_map": "A01:2021", "api_endpoint": "A01:2021",
    "cloud_bucket": "A06:2021", "graphql": "A01:2021", "dir_listing": "A05:2021",
    "backup": "A05:2021", "user_enum": "A01:2021", "k8s_exposure": "A05:2021",
    "docker_exposure": "A05:2021", "terraform_exposure": "A01:2021", "ide_config": "A01:2021",
    "js_route": "A01:2021", "cloud_storage": "A06:2021",
}

EXPECTED_403_PATHS = {
    "wp-content/uploads/", "wp-content/uploads", ".well-known/", ".well-known",
    "cgi-bin/", "cgi-bin"
}

# -- Severity Matrix (risk-based) --------------------------------------------------------
SEVERITY_MATRIX = {
    ".env": ("critical", 95), ".env.production": ("critical", 95), ".env.local": ("critical", 95),
    ".env.staging": ("critical", 95), ".git/HEAD": ("critical", 95), ".git/config": ("critical", 90),
    "wp-config.php": ("critical", 95), "config.php": ("critical", 90), "credentials.json": ("critical", 95),
    "secrets.json": ("critical", 95), "id_rsa": ("critical", 95), "id_rsa.pub": ("high", 85),
    "private.key": ("critical", 95), ".htpasswd": ("critical", 95), "database.sql": ("critical", 95),
    "dump.sql": ("critical", 95), "db.sql": ("critical", 95), "aws-exports.js": ("critical", 90),
    "firebase.json": ("high", 85), "supabase.json": ("high", 85), ".npmrc": ("critical", 90),
    ".pypirc": ("critical", 90), "config/secrets.yml": ("critical", 95), "config/database.yml": ("high", 85),
    "parameters.yml": ("high", 85), "web.config": ("high", 85), "appsettings.json": ("high", 85),
    "source_map": ("high", 90), "graphql_introspection": ("high", 95), "swagger_openapi": ("high", 90),
    ".vscode/settings.json": ("high", 85), ".vscode/launch.json": ("high", 85), ".idea/workspace.xml": ("high", 85),
    "terraform.tfstate": ("critical", 95), "terraform.tfvars": ("critical", 95), ".terraform/": ("high", 85),
    "docker-compose.yml": ("high", 85), "Dockerfile": ("medium", 75), ".docker/config.json": ("critical", 95),
    "k8s_api": ("critical", 95), "k8s_version": ("medium", 70), "phpinfo": ("high", 90),
    "error.log": ("medium", 75), "debug.log": ("medium", 75), "dir_listing": ("medium", 80),
    "api_doc": ("medium", 75), "robots_sensitive": ("medium", 75), "backup_file": ("high", 85),
    "composer.json": ("low", 65), "package.json": ("low", 65), "accessible_file": ("low", 60),
    "forbidden_path": ("low", 55), "robots_txt": ("low", 50), "sitemap_xml": ("low", 50),
    "tech_disclosure": ("info", 80), "user_enum": ("medium", 85),
}

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

def _log_debug(msg):
    print(f"[{SCANNER_NAME}] DEBUG: {msg}", file=sys.stderr)

def _entropy(s):
    if not s: return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

def _parse_version(version_str):
    parts = re.split(r'[.-]', version_str)
    return tuple(int(p) for p in parts if p.isdigit())

def _version_in_range(version, min_ver, max_ver):
    if not version: return False
    try:
        v = _parse_version(version)
        if min_ver and v < _parse_version(min_ver): return False
        if max_ver and v >= _parse_version(max_ver): return False
        return True
    except Exception:
        return False

SITE_CATEGORIES = {
    "bank": ["bank", "online banking"],
    "ecommerce": ["shop", "store", "buy", "cart", "checkout", "shopping", "amazon", "ebay", "etsy", "aliexpress"],
    "healthcare": ["hospital"], "login": ["sign in", "login"],
    "blog": ["blog", "articles"], "internal": ["intranet", "internal"],
}

async def _categorize_site(hostname, port=443, html=None, headers=None):
    result = {"categories": [], "has_login_form": False, "title": "", "meta_keywords": "",
              "is_login_page": False, "is_ecommerce": False, "is_internal": False, "is_api": False}
    if not html:
        return result
    text = html
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

def _make_finding(title, description, severity, confidence, location="", evidence="",
                  remediation="", cwe="", owasp="", poc=None, category="passive",
                  detection_method="pattern_match", response_status=None,
                  response_headers=None, response_size=None, extracted_info=None,
                  exact_url=None):
    """Create a standardized finding with full evidence."""
    finding = {
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "cwe": cwe,
        "owasp": owasp,
        "evidence": evidence or description,
        "poc": poc or "Manual verification required.",
        "remediation": remediation or "No remediation specified.",
        "detection_method": detection_method,
        "location": location,
    }
    if exact_url:
        finding["exact_url"] = exact_url
    if response_status is not None:
        finding["response_status"] = response_status
    if response_headers:
        safe_headers = {k: v for k, v in response_headers.items()
                        if k.lower() in ("content-type", "content-length", "server",
                                         "x-powered-by", "x-generator", "set-cookie",
                                         "etag", "last-modified", "x-frame-options",
                                         "strict-transport-security", "x-content-type-options")}
        finding["response_headers"] = safe_headers
    if response_size is not None:
        finding["response_size"] = response_size
    if extracted_info:
        finding["extracted_info"] = extracted_info[:500]
    return finding

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

HIGH_SENSITIVE_PATHS = {
    ".git/HEAD": ("critical", 95), ".git/config": ("critical", 90), ".env": ("critical", 95),
    ".env.production": ("critical", 95), ".env.local": ("critical", 95), ".env.staging": ("critical", 95),
    ".env.development": ("high", 85), ".env.backup": ("critical", 95), "wp-config.php": ("critical", 95),
    "wp-config.php~": ("critical", 95), "wp-config.php.save": ("critical", 95), "wp-config.php.bak": ("critical", 95),
    "config.php": ("critical", 90), "settings.py": ("high", 85), "credentials.json": ("critical", 95),
    "secrets.json": ("critical", 95), "secret_key.txt": ("critical", 95), "id_rsa": ("critical", 95),
    "id_rsa.pub": ("high", 85), "authorized_keys": ("critical", 95), "private.key": ("critical", 95),
    "cert.pem": ("high", 85), ".htpasswd": ("critical", 95), "database.sql": ("critical", 95),
    "dump.sql": ("critical", 95), "db.sql": ("critical", 95), "db.sqlite3": ("high", 85),
    "aws-exports.js": ("critical", 90), "firebase.json": ("high", 85), "supabase.json": ("high", 85),
    "vercel.json": ("medium", 70), "google-services.json": ("high", 85), "sftp-config.json": ("critical", 90),
    ".npmrc": ("critical", 90), ".yarnrc.yml": ("medium", 65), ".pypirc": ("critical", 90),
    "config/database.yml": ("high", 85), "config/secrets.yml": ("critical", 95), "parameters.yml": ("high", 85),
    "services.yml": ("medium", 70), "web.config": ("high", 85), "appsettings.json": ("high", 85),
    "terraform.tfstate": ("critical", 95), "terraform.tfstate.backup": ("critical", 95),
    "terraform.tfvars": ("critical", 95), ".terraform/terraform.tfstate": ("critical", 95),
    "docker-compose.yml": ("high", 85), "docker-compose.yaml": ("high", 85),
    ".docker/config.json": ("critical", 95), ".docker/.env": ("critical", 95),
    ".vscode/settings.json": ("high", 85), ".vscode/launch.json": ("high", 85),
    ".vscode/tasks.json": ("medium", 70), ".idea/workspace.xml": ("high", 85),
    ".idea/dataSources.xml": ("high", 85), ".idea/httpRequests/": ("medium", 70),
}
MEDIUM_SENSITIVE_PATHS = {
    "phpinfo.php": ("high", 90), "info.php": ("high", 90), "test.php": ("medium", 65),
    "error.log": ("medium", 75), "debug.log": ("medium", 75), "storage/logs/laravel.log": ("medium", 75),
    "log/production.log": ("medium", 75), "wp-content/debug.log": ("medium", 75), "composer.json": ("low", 65),
    "composer.lock": ("low", 60), "package.json": ("low", 65), "yarn.lock": ("low", 60),
    "pnpm-lock.yaml": ("low", 60), "Gemfile": ("low", 60), "Gemfile.lock": ("low", 60),
    "requirements.txt": ("low", 60), "Dockerfile": ("medium", 75), ".gitlab-ci.yml": ("medium", 70),
    ".travis.yml": ("medium", 70), "Jenkinsfile": ("medium", 70), ".github/workflows/": ("medium", 70),
    ".circleci/config.yml": ("medium", 70), "swagger-ui.html": ("high", 85), "swagger.json": ("high", 85),
    "v2/api-docs": ("high", 85), "v3/api-docs": ("high", 85), "api-docs": ("high", 85),
    "graphql": ("high", 85), "graphiql": ("high", 85), "playground": ("high", 85),
}
LOW_SENSITIVE_PATHS = {
    "robots.txt": ("low", 50), "sitemap.xml": ("low", 50), ".well-known/security.txt": ("low", 55),
    ".well-known/openid-configuration": ("medium", 70), "crossdomain.xml": ("low", 50),
    "clientaccesspolicy.xml": ("low", 50), "server-status": ("medium", 75), "server-info": ("medium", 75),
    "status": ("low", 60), "healthcheck": ("low", 55), ".DS_Store": ("low", 60), "Thumbs.db": ("low", 55),
    ".bash_history": ("high", 85), "tmp/restart.txt": ("low", 50),
}
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
K8S_PATHS = [
    "api/v1/namespaces", "api/v1/pods", "api/v1/services", "api/v1/configmaps",
    "api/v1/secrets", "version", "healthz", "readyz", "livez", "metrics", ".kube/config",
]
CLOUD_STORAGE_PATTERNS = [
    (r'https?://([a-z0-9\-]+)\.s3\.amazonaws\.com/?', 'AWS S3'),
    (r'https?://storage\.cloud\.google\.com/([a-z0-9\-_]+)/?', 'GCS'),
    (r'https?://([a-z0-9\-]+)\.blob\.core\.windows\.net/?', 'Azure Blob'),
    (r'https?://([a-z0-9\-]+)\.digitaloceanspaces\.com/?', 'DigitalOcean Spaces'),
]

def _get_path_severity(path):
    path_lower = path.lower().lstrip('/')
    if path_lower in HIGH_SENSITIVE_PATHS: return HIGH_SENSITIVE_PATHS[path_lower]
    if path_lower in MEDIUM_SENSITIVE_PATHS: return MEDIUM_SENSITIVE_PATHS[path_lower]
    if path_lower in LOW_SENSITIVE_PATHS: return LOW_SENSITIVE_PATHS[path_lower]
    if path_lower.endswith((".bak", ".backup", ".old", ".orig", ".save", "~")): return ("high", 80)
    if any(ext in path_lower for ext in BACKUP_EXTS): return ("high", 85)
    if ".sql" in path_lower: return ("critical", 90)
    if any(x in path_lower for x in [".env", "secret", "credential", "password", "private"]): return ("critical", 90)
    if any(x in path_lower for x in [".git", ".svn", ".hg"]): return ("critical", 90)
    if any(x in path_lower for x in [".vscode", ".idea"]): return ("high", 80)
    if any(x in path_lower for x in ["terraform", "k8s", "kubernetes", "docker"]): return ("high", 85)
    return ("low", 60)

def _is_soft_404(body, homepage_body):
    if not body: return False
    if re.search(r'(404\s*(Not Found|Page Not Found)|File not found|Page not found|Not Found)', body, re.IGNORECASE): return True
    if not homepage_body: return False
    if abs(len(body) - len(homepage_body)) <= max(len(homepage_body) * 0.1, 100):
        if body[:500] == homepage_body[:500]: return True
    if len(body) > 500 and len(homepage_body) > 500:
        title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE)
        home_title = re.search(r'<title>(.*?)</title>', homepage_body, re.IGNORECASE)
        if title_match and home_title and title_match.group(1) == home_title.group(1):
            if abs(len(body) - len(homepage_body)) <= max(len(homepage_body) * 0.15, 200): return True
    try:
        ratio = difflib.SequenceMatcher(None, body[:2000], homepage_body[:2000]).ratio()
        if ratio > 0.85: return True
    except Exception:
        pass
    return False

class ResponsePlaceholder:
    def __init__(self, status, headers):
        self.status = status
        self.headers = headers

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
                _log_debug(f"Probe failed for {url}: {e}")
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
JS_ROUTE_PATTERNS = [
    re.compile(r'fetch\s*\(\s*["\']([^"\']+/api/[^"\']+)["\']', re.IGNORECASE),
    re.compile(r'fetch\s*\(\s*`([^`]+/api/[^`]+)`', re.IGNORECASE),
    re.compile(r'axios\.(?:get|post|put|delete|patch)\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'axios\s*\(\s*\{\s*url:\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'\$\.(?:ajax|get|post)\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'\.open\s*\(\s*["\'](?:GET|POST|PUT|DELETE)["\']\s*,\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/api/v[0-9]+/[^"\']+)["\']', re.IGNORECASE),
    re.compile(r'["\'](/graphql[^"\']*)["\']', re.IGNORECASE),
    re.compile(r'["\'](/rest/[^"\']+)["\']', re.IGNORECASE),
]

async def _fetch_js_cached(session, url, rate_limiter, js_cache, fetch_js=None):
    if url in js_cache:
        return js_cache[url]
    if fetch_js:
        try:
            content = await fetch_js(url)
            js_cache[url] = content
            return content
        except Exception:
            pass
    resp = await rate_limiter.probe(session, url, 'GET')
    if resp and resp.status == 200:
        content = await resp.text(errors='replace')
        js_cache[url] = content
        return content
    js_cache[url] = None
    return None

async def _check_js_source_maps(session, base_url, html, rate_limiter, findings):
    if not html: return
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
                        title="Source map referenced inline",
                        description=f"Source map URL disclosed in inline script: {map_url}",
                        severity="high", confidence=90, location="Inline script",
                        evidence=f"sourceMappingURL: {map_url}",
                        remediation="Remove sourceMappingURL from production scripts.",
                        cwe=CWE_MAP["source_map"], owasp=OWASP_MAP["source_map"],
                        poc=f"curl -s {map_url} | head -c 500",
                        detection_method="pattern_match",
                    ))
        async def check_js_map(js_url):
            if not js_url.endswith('.js'): return None
            map_url = js_url + '.map'
            resp_map = await rate_limiter.probe(session, map_url, 'GET')
            if resp_map and resp_map.status == 200:
                try:
                    body = await asyncio.wait_for(resp_map.text(), timeout=5)
                except Exception:
                    return None
                if body.strip() and ('"sources"' in body or '"mappings"' in body):
                    return _make_finding(
                        title="Source map exposed",
                        description=f"Source map accessible at {map_url}, revealing original source code structure",
                        severity="high", confidence=95, location=map_url,
                        evidence=f"Source map size: {len(body)} bytes, contains source references",
                        remediation="Disable source maps in production builds.",
                        cwe=CWE_MAP["source_map"], owasp=OWASP_MAP["source_map"],
                        poc=f"curl -s {map_url} | python3 -m json.tool | head -50",
                        detection_method="source_map_probe",
                        response_status=resp_map.status,
                        response_headers=dict(resp_map.headers) if hasattr(resp_map, 'headers') else None,
                        response_size=len(body),
                        exact_url=map_url,
                    )
            return None
        tasks = [check_js_map(js_url) for js_url in js_links]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception): _log_debug(f"JS source map check failed for one URL: {result}")
            elif result is not None: findings.append(result)
    except Exception as e:
        _log_error(f"JS source map check failed: {e}")

async def _check_js_leaked_credentials(session, base_url, html, rate_limiter, findings, js_cache, fetch_js=None):
    if not html: return
    try:
        soup = BeautifulSoup(html, "html.parser")
        js_urls = set()
        for script in soup.find_all("script", src=True):
            js_urls.add(urljoin(base_url, script["src"]))
        async def check_js_file(js_url):
            content = await _fetch_js_cached(session, js_url, rate_limiter, js_cache, fetch_js)
            if not content: return []
            local_findings = []
            for pat in HIGH_CONFIDENCE_SECRET_PATTERNS:
                for m in re.findall(pat, content):
                    local_findings.append(_make_finding(
                        title="Hardcoded credential / API key in JavaScript",
                        description=f"High-confidence secret pattern found in JS file",
                        severity="critical", confidence=95, location=js_url,
                        evidence=f"Matched pattern in {js_url}: {m[:30]}...",
                        remediation="Remove all secrets from client-side code.",
                        cwe="CWE-798", owasp="A07:2021",
                        poc=f"curl -s {js_url} | grep -E '{pat}'",
                        detection_method="pattern_match",
                        exact_url=js_url,
                    ))
            for match in BROAD_SECRET_PATTERN.finditer(content):
                val = match.group(1)
                if any(safe in val.lower() for safe in JS_SAFE_TOKENS): continue
                if any(kw in val.lower() for kw in JS_CODE_KEYWORDS): continue
                if len(val) < 40: continue
                local_findings.append(_make_finding(
                    title="Potential credential in JavaScript",
                    description=f"Broad secret pattern matched in JS",
                    severity="medium", confidence=50, location=js_url,
                    evidence=f"Matched value: {val[:40]}...",
                    remediation="Review code for hardcoded secrets.",
                    cwe="CWE-798", owasp="A07:2021",
                    poc=f"curl -s {js_url} | grep -i 'secret\\|password\\|token'",
                    detection_method="pattern_match",
                    exact_url=js_url,
                ))
            parsed = urlparse(js_url)
            if not any(domain in parsed.netloc for domain in ENTROPY_EXCLUDE_DOMAINS):
                for match in re.finditer(r'["\']([a-zA-Z0-9_\-+/=]{20,})["\']', content):
                    candidate = match.group(1)
                    if _entropy(candidate) > 5.0:
                        start = max(0, match.start() - 200)
                        context_window = content[start:match.end() + 50]
                        if not re.search(r'(api[ _\s]?key|secret|token|auth|password|private[ _\s]?key)', context_window, re.IGNORECASE):
                            continue
                        local_findings.append(_make_finding(
                            title="High-entropy string detected (possible API key)",
                            description=f"High-entropy string in credential context",
                            severity="medium", confidence=60, location=js_url,
                            evidence=f"Entropy: {_entropy(candidate):.2f}, value: {candidate[:30]}...",
                            remediation="Verify if this is a hardcoded secret.",
                            cwe="CWE-798", owasp="A07:2021",
                            poc=f"curl -s {js_url} | grep -E '[a-zA-Z0-9_+/=]{{20,}}'",
                            detection_method="entropy_match",
                            exact_url=js_url,
                        ))
            return local_findings
        tasks = [check_js_file(js_url) for js_url in js_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception): _log_debug(f"JS leaked credential check failed for one URL: {result}")
            elif isinstance(result, list): findings.extend(result)
    except Exception as e:
        _log_error(f"JS leaked credential check failed: {e}")

async def _extract_js_routes(session, base_url, html, rate_limiter, findings, js_cache, fetch_js=None):
    if not html: return
    try:
        soup = BeautifulSoup(html, "html.parser")
        js_urls = set()
        for script in soup.find_all("script", src=True):
            js_urls.add(urljoin(base_url, script["src"]))
        inline_scripts = []
        for script in soup.find_all("script"):
            if not script.get("src") and script.string:
                inline_scripts.append(script.string)
        extracted_routes = set()
        def extract_from_content(content, source_label):
            for pattern in JS_ROUTE_PATTERNS:
                for match in pattern.finditer(content):
                    route = match.group(1).strip()
                    if route.startswith('//'): continue
                    if not route.startswith('/'): continue
                    if any(x in route.lower() for x in ['example.com', 'localhost', '${', 'http://', 'https://']): continue
                    if len(route) > 200: continue
                    extracted_routes.add((route, source_label))
        for inline in inline_scripts:
            extract_from_content(inline, "inline_script")
        async def process_js(js_url):
            content = await _fetch_js_cached(session, js_url, rate_limiter, js_cache, fetch_js)
            if content:
                extract_from_content(content, js_url)
        tasks = [process_js(url) for url in js_urls]
        await asyncio.gather(*tasks, return_exceptions=True)
        routes_by_path = defaultdict(list)
        for route, source in extracted_routes:
            routes_by_path[route].append(source)
        for route, sources in list(routes_by_path.items())[:20]:
            probe_url = urljoin(base_url, route)
            try:
                resp = await rate_limiter.probe(session, probe_url, 'GET')
                if resp and resp.status in (200, 401, 403, 405):
                    severity = "medium" if resp.status == 200 else "low"
                    confidence = 85 if resp.status == 200 else 70
                    try:
                        body = await asyncio.wait_for(resp.text(), timeout=3) if resp.status == 200 else ""
                    except Exception:
                        body = ""
                    findings.append(_make_finding(
                        title=f"API route discovered via JS analysis: {route}",
                        description=f"API endpoint extracted from JavaScript, responded with HTTP {resp.status}",
                        severity=severity, confidence=confidence, location=route,
                        evidence=f"Found in: {', '.join(sources[:3])}, HTTP {resp.status}",
                        remediation="Ensure API endpoints have proper authentication and authorization.",
                        cwe=CWE_MAP["js_route"], owasp=OWASP_MAP["js_route"],
                        poc=f"curl -s -o /dev/null -w '%{{http_code}}' {probe_url}",
                        detection_method="js_route_extraction",
                        response_status=resp.status,
                        response_headers=dict(resp.headers) if hasattr(resp, 'headers') else None,
                        response_size=len(body) if body else None,
                        exact_url=probe_url,
                    ))
            except Exception:
                pass
    except Exception as e:
        _log_error(f"JS route extraction failed: {e}")

async def _enumerate_api_endpoints(session, base_url, rate_limiter, findings):
    try:
        async def check_endpoint(endpoint):
            url = urljoin(base_url, endpoint)
            resp = await rate_limiter.probe(session, url, 'GET')
            if resp is None: return None
            if resp.status == 200:
                content_type = resp.headers.get('Content-Type', '')
                try:
                    body = await asyncio.wait_for(resp.text(), timeout=10)
                except Exception:
                    return None
                if endpoint == "/wp-json/wp/v2/users":
                    if '"id"' in body and '"name"' in body and '"slug"' in body:
                        user_names = re.findall(r'"name"\s*:\s*"([^"]+)"', body)[:5]
                        return _make_finding(
                            title="WordPress User Enumeration",
                            description="WordPress REST API exposes user names, slugs, and IDs",
                            severity="medium", confidence=100, location=endpoint,
                            evidence=f"Users found: {', '.join(user_names)}",
                            remediation="Disable anonymous access to the users endpoint.",
                            cwe=CWE_MAP["user_enum"], owasp=OWASP_MAP["user_enum"],
                            poc=f"curl -s {url} | jq '.[].name'",
                            detection_method="pattern_match",
                            response_status=resp.status,
                            response_headers=dict(resp.headers) if hasattr(resp, 'headers') else None,
                            response_size=len(body),
                            extracted_info=f"Users: {', '.join(user_names)}",
                            exact_url=url,
                        )
                if 'graphql' in endpoint.lower():
                    try:
                        async with rate_limiter.sem:
                            await asyncio.sleep(random.uniform(rate_limiter.min_delay, rate_limiter.max_delay))
                            intro_resp = await session.post(
                                url, json={"query": "query { __schema { types { name } } }"},
                                timeout=REQUEST_TIMEOUT
                            )
                            if intro_resp.status == 200 and 'application/json' in intro_resp.headers.get('Content-Type', ''):
                                data = await intro_resp.json()
                                if data.get("data", {}).get("__schema"):
                                    types = data["data"]["__schema"].get("types", [])
                                    type_names = [t.get("name") for t in types[:10] if t.get("name")]
                                    return _make_finding(
                                        title="GraphQL introspection enabled",
                                        description=f"GraphQL endpoint exposes full schema with {len(types)} types",
                                        severity="high", confidence=100, location=endpoint,
                                        evidence=f"Types exposed: {', '.join(type_names)}",
                                        remediation="Disable introspection in production.",
                                        cwe=CWE_MAP["graphql"], owasp=OWASP_MAP["graphql"],
                                        poc=f'curl -s -X POST {url} -H "Content-Type: application/json" -d \'{{"query":"{{__schema{{types{{name}}}}}}}}\'',
                                        detection_method="introspection",
                                        response_status=resp.status,
                                        response_headers=dict(resp.headers) if hasattr(resp, 'headers') else None,
                                        response_size=len(body),
                                        extracted_info=f"Types: {', '.join(type_names)}",
                                        exact_url=url,
                                    )
                    except Exception as e:
                        _log_debug(f"GraphQL check failed for {endpoint}: {e}")
                    return None
                if any(kw in body.lower() for kw in ['swagger', 'openapi', 'api-docs']):
                    is_openapi = False
                    version = None
                    try:
                        data = json.loads(body)
                        if isinstance(data, dict):
                            if 'openapi' in data:
                                is_openapi = True
                                version = data['openapi']
                            elif 'swagger' in data:
                                is_openapi = True
                                version = data['swagger']
                            elif 'info' in data and 'paths' in data:
                                is_openapi = True
                    except Exception:
                        if re.search(r'(swagger|openapi)\s*[:=]\s*["\']?[\d.]+', body, re.IGNORECASE):
                            is_openapi = True
                    if is_openapi:
                        path_count = 0
                        try:
                            data = json.loads(body)
                            if isinstance(data, dict) and 'paths' in data:
                                path_count = len(data['paths'])
                        except Exception:
                            pass
                        return _make_finding(
                            title="OpenAPI/Swagger specification exposed",
                            description=f"Full API specification accessible at {endpoint}" + (f" (version {version})" if version else ""),
                            severity="high", confidence=95, location=endpoint,
                            evidence=f"OpenAPI spec with {path_count} paths" if path_count else "OpenAPI/Swagger spec detected",
                            remediation="Restrict access to API documentation in production.",
                            cwe=CWE_MAP["api_endpoint"], owasp=OWASP_MAP["api_endpoint"],
                            poc=f"curl -s {url} | head -100",
                            detection_method="openapi_validation",
                            response_status=resp.status,
                            response_headers=dict(resp.headers) if hasattr(resp, 'headers') else None,
                            response_size=len(body),
                            extracted_info=f"Version: {version}, Paths: {path_count}" if version else None,
                            exact_url=url,
                        )
                if 'application/json' in content_type:
                    return _make_finding(
                        title=f"Potential API endpoint: {endpoint}",
                        description="Endpoint returns JSON, may expose data",
                        severity="medium", confidence=60, location=endpoint,
                        evidence=f"Content-Type: {content_type}, size: {len(body)} bytes",
                        remediation="Verify endpoint requires authentication.",
                        cwe=CWE_MAP["api_endpoint"], owasp=OWASP_MAP["api_endpoint"],
                        poc=f"curl -s {url}",
                        detection_method="content_type",
                        response_status=resp.status,
                        response_headers=dict(resp.headers) if hasattr(resp, 'headers') else None,
                        response_size=len(body),
                        exact_url=url,
                    )
            elif resp.status in (401, 403):
                sev = "low" if "wp-json" in endpoint and "users" in endpoint else "info"
                return _make_finding(
                    title=f"Protected API endpoint: {endpoint}",
                    description="Endpoint exists but requires authentication",
                    severity=sev, confidence=85, location=endpoint,
                    evidence=f"HTTP {resp.status} response",
                    remediation="Ensure the endpoint requires authentication and test with a real unauthenticated request.",
                    detection_method="status_code",
                    response_status=resp.status,
                    response_headers=dict(resp.headers) if hasattr(resp, 'headers') else None,
                    exact_url=url,
                )
            return None
        tasks = [check_endpoint(endpoint) for endpoint in API_ENDPOINTS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Exception): _log_debug(f"API endpoint check failed for one endpoint: {result}")
            elif result is not None: findings.append(result)
    except Exception as e:
        _log_error(f"API endpoint enumeration failed: {e}")

async def _check_kubernetes_exposure(session, base_url, rate_limiter, findings):
    k8s_endpoints = [
        ("api", "Kubernetes API root"), ("api/v1", "Kubernetes API v1"), ("version", "Kubernetes version"),
        ("healthz", "Kubernetes health check"), ("api/v1/namespaces", "Kubernetes namespaces"),
        ("api/v1/pods", "Kubernetes pods"), ("api/v1/services", "Kubernetes services"),
        ("api/v1/configmaps", "Kubernetes configmaps"), ("api/v1/secrets", "Kubernetes secrets"),
    ]
    async def check_k8s(path, description):
        url = urljoin(base_url, path)
        try:
            resp = await rate_limiter.probe(session, url, 'GET')
            if resp and resp.status == 200:
                try:
                    body = await asyncio.wait_for(resp.text(), timeout=5)
                except Exception:
                    return None
                if any(kw in body.lower() for kw in ['kind', 'apiversion', 'metadata', 'kubernetes']):
                    severity = "critical" if "secrets" in path or "configmaps" in path else "high"
                    if path in ("healthz", "version"): severity = "medium"
                    version_match = re.search(r'"gitVersion"\s*:\s*"([^"]+)"', body)
                    kind_match = re.search(r'"kind"\s*:\s*"([^"]+)"', body)
                    extracted = []
                    if version_match: extracted.append(f"Version: {version_match.group(1)}")
                    if kind_match: extracted.append(f"Kind: {kind_match.group(1)}")
                    return _make_finding(
                        title=f"Kubernetes API exposed: {description}",
                        description=f"Kubernetes endpoint accessible at {path}",
                        severity=severity, confidence=95 if "secrets" in path else 85,
                        location=path,
                        evidence=f"Kubernetes response detected, size: {len(body)} bytes",
                        remediation="Restrict Kubernetes API access with proper authentication and network policies.",
                        cwe=CWE_MAP["k8s_exposure"], owasp=OWASP_MAP["k8s_exposure"],
                        poc=f"curl -s {url} | head -50",
                        detection_method="k8s_api_probe",
                        response_status=resp.status,
                        response_headers=dict(resp.headers) if hasattr(resp, 'headers') else None,
                        response_size=len(body),
                        extracted_info="; ".join(extracted) if extracted else None,
                        exact_url=url,
                    )
        except Exception:
            pass
        return None
    tasks = [check_k8s(p, d) for p, d in k8s_endpoints]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, Exception): _log_debug(f"K8s check failed: {result}")
        elif result is not None: findings.append(result)

async def _check_docker_terraform(session, base_url, rate_limiter, findings):
    paths = [
        ("docker-compose.yml", "Docker Compose configuration", "docker_exposure"),
        ("docker-compose.yaml", "Docker Compose configuration", "docker_exposure"),
        (".docker/config.json", "Docker registry credentials", "docker_exposure"),
        ("Dockerfile", "Docker build configuration", "docker_exposure"),
        ("terraform.tfstate", "Terraform state with secrets", "terraform_exposure"),
        ("terraform.tfstate.backup", "Terraform state backup", "terraform_exposure"),
        ("terraform.tfvars", "Terraform variables (may contain secrets)", "terraform_exposure"),
        (".terraform/terraform.tfstate", "Terraform state in hidden dir", "terraform_exposure"),
        (".terraform.lock.hcl", "Terraform lock file", "terraform_exposure"),
    ]
    async def check_path(path, description, category):
        url = urljoin(base_url, path)
        try:
            resp = await rate_limiter.probe(session, url, 'GET')
            if resp and resp.status == 200:
                try:
                    body = await asyncio.wait_for(resp.text(), timeout=5)
                except Exception:
                    return None
                is_valid = False
                extracted = []
                if "docker-compose" in path:
                    if "version:" in body or "services:" in body:
                        is_valid = True
                        services = re.findall(r'^\s{2}(\w+):\s*$', body, re.MULTILINE)
                        if services: extracted.append(f"Services: {', '.join(services[:5])}")
                elif ".docker/config.json" in path:
                    try:
                        data = json.loads(body)
                        if "auths" in data or "credsStore" in data:
                            is_valid = True
                            if "auths" in data: extracted.append(f"Registries: {', '.join(data['auths'].keys())}")
                    except Exception:
                        pass
                elif "Dockerfile" in path:
                    if re.search(r'^FROM\s+', body, re.MULTILINE):
                        is_valid = True
                        from_match = re.search(r'^FROM\s+([^\s]+)', body, re.MULTILINE)
                        if from_match: extracted.append(f"Base image: {from_match.group(1)}")
                elif "terraform" in path.lower():
                    if any(kw in body for kw in ['"version"', '"serial"', '"lineage"', 'resource "', 'variable "']):
                        is_valid = True
                        if re.search(r'(password|secret|key|token)\s*[:=]', body, re.IGNORECASE):
                            extracted.append("Contains potential secrets")
                        resources = re.findall(r'resource\s+"([^"]+)"', body)
                        if resources: extracted.append(f"Resources: {', '.join(set(resources)[:5])}")
                if is_valid:
                    severity, confidence = _get_path_severity(path)
                    return _make_finding(
                        title=f"{description} exposed: {path}",
                        description=f"{description} accessible at {path}",
                        severity=severity, confidence=confidence, location=path,
                        evidence=f"Valid {description} content, size: {len(body)} bytes",
                        remediation=f"Restrict access to {path} and ensure no secrets are stored in plain text.",
                        cwe=CWE_MAP.get(category, "CWE-200"),
                        owasp=OWASP_MAP.get(category, "A01:2021"),
                        poc=f"curl -s {url} | head -50",
                        detection_method="content_validation",
                        response_status=resp.status,
                        response_headers=dict(resp.headers) if hasattr(resp, 'headers') else None,
                        response_size=len(body),
                        extracted_info="; ".join(extracted) if extracted else None,
                        exact_url=url,
                    )
        except Exception:
            pass
        return None
    tasks = [check_path(p, d, c) for p, d, c in paths]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, Exception): _log_debug(f"Docker/Terraform check failed: {result}")
        elif result is not None: findings.append(result)

async def _check_cloud_storage(session, base_url, html, rate_limiter, findings):
    bucket_urls = set()
    if html:
        for pattern, provider in CLOUD_STORAGE_PATTERNS:
            for match in re.finditer(pattern, html):
                bucket_urls.add((match.group(0), provider))
    parsed = urlparse(base_url)
    domain = parsed.netloc.replace('www.', '')
    common_names = [domain, domain.split('.')[0], f"{domain}-assets", f"{domain}-static",
                    f"{domain}-uploads", f"{domain}-media"]
    for name in common_names:
        bucket_urls.add((f"https://s3.amazonaws.com/{name}/", "AWS S3"))
        bucket_urls.add((f"https://storage.googleapis.com/{name}/", "GCS"))
    async def check_bucket(bucket_url, provider):
        try:
            resp = await rate_limiter.probe(session, bucket_url, 'GET')
            if resp and resp.status == 200:
                try:
                    body = await asyncio.wait_for(resp.text(), timeout=5)
                except Exception:
                    return None
                is_listing = False
                if 'application/xml' in resp.headers.get('Content-Type', ''):
                    if '<ListBucketResult' in body or '<Contents>' in body: is_listing = True
                elif 'application/json' in resp.headers.get('Content-Type', ''):
                    if '"items"' in body or '"prefixes"' in body: is_listing = True
                elif 'text/html' in resp.headers.get('Content-Type', ''):
                    if 'Index of' in body or '<table' in body: is_listing = True
                if is_listing:
                    items = len(re.findall(r'<Key>([^<]+)</Key>', body))
                    return _make_finding(
                        title=f"{provider} bucket listing exposed",
                        description=f"Cloud storage bucket is publicly listable at {bucket_url}",
                        severity="high", confidence=95, location=bucket_url,
                        evidence=f"Bucket listing with {items} items visible",
                        remediation="Disable public listing on the cloud storage bucket.",
                        cwe=CWE_MAP["cloud_storage"], owasp=OWASP_MAP["cloud_storage"],
                        poc=f"curl -s {bucket_url} | head -50",
                        detection_method="cloud_storage_probe",
                        response_status=resp.status,
                        response_headers=dict(resp.headers) if hasattr(resp, 'headers') else None,
                        response_size=len(body),
                        extracted_info=f"Provider: {provider}, Items: {items}",
                        exact_url=bucket_url,
                    )
        except Exception:
            pass
        return None
    tasks = [check_bucket(url, provider) for url, provider in list(bucket_urls)[:15]]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, Exception): _log_debug(f"Cloud storage check failed: {result}")
        elif result is not None: findings.append(result)

async def _check_interesting_files_from_headers(session, base_url, main_headers, rate_limiter, findings):
    if not _get_header(main_headers, "ETag") and not _get_header(main_headers, "Last-Modified"):
        return
    interesting = ["/robots.txt", "/sitemap.xml", "/favicon.ico", "/.well-known/security.txt",
                   "/crossdomain.xml", "/clientaccesspolicy.xml"]
    async def check_file(path):
        url = urljoin(base_url, path)
        resp = await rate_limiter.probe(session, url, 'HEAD')
        if resp and resp.status == 200:
            return _make_finding(
                title=f"Interesting file found: {path}",
                description="Static file accessible, may reveal information",
                severity="low", confidence=70, location=path,
                evidence=f"HTTP {resp.status} response, Content-Type: {resp.headers.get('Content-Type', 'unknown')}",
                remediation="Review if exposure is intentional.",
                poc=f"curl -I {url}",
                detection_method="header_check",
                response_status=resp.status,
                response_headers=dict(resp.headers) if hasattr(resp, 'headers') else None,
                exact_url=url,
            )
        return None
    tasks = [check_file(path) for path in interesting]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, Exception): _log_debug(f"Interesting file check failed for {path}: {result}")
        elif result is not None: findings.append(result)

def _is_sensitive_content(path, body):
    if ".git/HEAD" in path: return "ref: refs/heads/" in body
    if ".env" in path: return any(kw in body for kw in ["DB_", "PASSWORD", "API_KEY", "SECRET", "APP_KEY"])
    if "composer.json" in path: return '"require"' in body
    if "package.json" in path: return '"dependencies"' in body
    if "robots.txt" in path: return True
    if "sitemap.xml" in path: return "<urlset" in body or "<sitemapindex" in body
    if any(x in path for x in ["CHANGELOG", "VERSION", "RELEASE"]): return bool(re.search(r'\d+\.\d+\.\d+', body))
    if "phpinfo" in path: return "PHP Version" in body
    if ".htaccess" in path: return any(kw in body for kw in ["RewriteRule", "Deny"])
    if "swagger" in path: return "swagger" in body.lower() or "openapi" in body.lower()
    if path.endswith(".sql"): return "CREATE TABLE" in body
    if path.endswith((".zip", ".tar.gz", ".tar", ".bak", ".7z", ".rar")): return True
    if ".vscode" in path or ".idea" in path: return True
    if "web.config" in path or "appsettings.json" in path: return "<configuration" in body or "<appSettings" in body
    if "parameters.yml" in path: return "parameters:" in body
    if "terraform" in path.lower(): return any(kw in body for kw in ['"version"', '"serial"', 'resource "', 'variable "'])
    if "docker" in path.lower(): return any(kw in body for kw in ['version:', 'services:', 'FROM ', '"auths"'])
    return False

def _is_directory_listing(body, homepage_body):
    if not body or not homepage_body: return False
    listing_indicators = ["Index of /", "Parent Directory", "<title>Index of", '<h1>Index of', "Directory Listing"]
    if not any(ind in body for ind in listing_indicators): return False
    if body.strip() == homepage_body.strip(): return False
    if body[:500] == homepage_body[:500] and len(body) == len(homepage_body): return False
    if not re.search(r'<a\s+href="[^"]*"[^>]*>', body, re.IGNORECASE): return False
    return True

def _is_robots_sensitive(body):
    sensitive_patterns = [r'admin', r'backup', r'config', r'\.git', r'\.env', r'wp-admin', r'login', r'dashboard',
                          r'staging', r'debug', r'test', r'internal', r'private']
    found = []
    for pattern in sensitive_patterns:
        matches = re.findall(r'Disallow:\s*/(' + pattern + r'[^\s]*)', body, re.IGNORECASE)
        found.extend(matches)
    return found

def _detect_tech_from_html(html):
    if not html: return set()
    detected = set()
    for tech, patterns in HTML_TECH_SIGNATURES.items():
        for pat in patterns:
            if re.search(pat, html, re.IGNORECASE):
                detected.add(tech)
                break
    return detected

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

async def run(url: str, **kwargs) -> Dict[str, Any]:
    try:
        target = _normalize_url(url)
        parsed = urlparse(target)
        hostname = parsed.hostname or ""
        port = parsed.port or 443
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        domain = hostname

        shared_page = kwargs.get("shared_page")
        session = kwargs.get("session")
        js_cache = kwargs.get("js_cache", {})
        fetch_js = kwargs.get("fetch_js")
        waf_detected = kwargs.get("waf_detected") or (shared_page.get("waf_detected") if shared_page else None)
        min_confidence = kwargs.get("min_confidence", 50)

        findings = []
        tech_stack = set()
        rate_limiter = RateLimiter(max_concurrent=MAX_CONCURRENT)
        paths_checked = 0
        paths_total = 0
        is_partial = False
        scan_note = ""
        partial_phases = []

        main_body = ""
        main_headers = {}
        soup = None
        needs_fetch = True

        if shared_page and not shared_page.get("error") and shared_page.get("status") == 200:
            main_body = shared_page.get("html", "")
            main_headers = shared_page.get("headers", {})
            soup = shared_page.get("soup")
            if soup is None and main_body:
                soup = BeautifulSoup(main_body, "html.parser")
            js_cache = shared_page.get("js_cache", js_cache)
            needs_fetch = False

        temp_session = False
        if not session:
            session = aiohttp.ClientSession(
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": USER_AGENT},
                connector=aiohttp.TCPConnector(ssl=True, limit=MAX_CONCURRENT + 10)
            )
            temp_session = True

        try:
            if needs_fetch:
                main_resp = await retry_async(lambda: rate_limiter.probe(session, target, 'GET'))
                if main_resp and main_resp.status == 200:
                    main_body = await main_resp.text()
                    main_headers = dict(main_resp.headers)
                    soup = BeautifulSoup(main_body, "html.parser")

            site_context = await _categorize_site(hostname, port, html=main_body, headers=main_headers)
            site_context["is_api"] = hostname.startswith("api.") or "/api/" in parsed.path

            async def main_work():
                nonlocal findings, tech_stack, js_cache, paths_checked, paths_total, is_partial, scan_note, partial_phases
                
                # -- Technology fingerprinting ------------------------------------------------
                for header_name, patterns in HEADER_FINGERPRINTS.items():
                    val = _get_header(main_headers, header_name)
                    if val:
                        for keyword, label in patterns.items():
                            if keyword.lower() in val.lower():
                                tech_stack.add(label)
                                findings.append(_make_finding(
                                    title=f"Technology identified: {label}",
                                    description=f"Header {header_name} reveals {val}",
                                    severity="info", confidence=80, location=f"Header: {header_name}",
                                    evidence=val, remediation="Remove or obscure version headers.",
                                    cwe="CWE-200", detection_method="header_match",
                                    response_headers=dict(main_headers),
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
                            evidence=f"Detected via Set-Cookie: {cookie_key}",
                            detection_method="cookie_match",
                            response_headers=dict(main_headers),
                        ))
                for specific in ["X-AspNet-Version", "X-AspNetMvc-Version"]:
                    val = _get_header(main_headers, specific)
                    if val:
                        findings.append(_make_finding(
                            title=f"Exact version disclosed", description=f"{specific}: {val}",
                            severity="medium", confidence=90, location=f"Header: {specific}", evidence=val,
                            remediation="Remove version headers.", cwe="CWE-200",
                            detection_method="version_header",
                            response_headers=dict(main_headers),
                        ))
                for tech, patterns in HTML_TECH_SIGNATURES.items():
                    for pat in patterns:
                        if re.search(pat, main_body, re.IGNORECASE):
                            tech_stack.add(tech)
                            findings.append(_make_finding(
                                title=f"Technology identified: {tech}",
                                description="Detected from HTML signature",
                                severity="info", confidence=75, location="HTML body",
                                evidence=f"Detected via HTML signature: {pat}",
                                detection_method="html_signature",
                            ))
                            break
                if soup:
                    for meta in soup.find_all("meta", attrs={"name": "generator"}):
                        content = meta.get("content", "")
                        if "WordPress" in content:
                            tech_stack.add("WordPress")
                            findings.append(_make_finding(
                                title="Technology identified: WordPress",
                                description=f"Meta generator: {content}",
                                severity="info", confidence=100, location="Meta generator", evidence=content,
                                detection_method="meta_tag",
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
                                detection_method="meta_tag",
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
                        if is_noise: continue
                        credential_match = False
                        for cred_pat in CREDENTIAL_PATTERNS:
                            if re.search(cred_pat, comm, re.IGNORECASE):
                                findings.append(_make_finding(
                                    title="Sensitive HTML comment: Credential pattern detected",
                                    description=f"Credential-like pattern in comment: {comm[:100]}",
                                    severity="high", confidence=90, location="HTML comment", evidence=comm[:200],
                                    remediation="Remove sensitive data from HTML comments.",
                                    cwe="CWE-538", owasp="A01:2021",
                                    detection_method="pattern_match",
                                ))
                                credential_match = True
                                break
                        if credential_match: continue
                        comm_lower = comm.lower()
                        for kw in DEVELOPER_NOTE_KEYWORDS:
                            if kw.lower() in comm_lower:
                                findings.append(_make_finding(
                                    title=f"Developer note in HTML comment: {kw}",
                                    description=f"Developer note found: {comm[:100]}",
                                    severity="info", confidence=30, location="HTML comment", evidence=comm[:200],
                                    remediation="Review comments before production deployment.",
                                    cwe="CWE-200",
                                    detection_method="keyword_match",
                                ))
                                break

                # -- Pre-phase with budget ----------------------------------------------------
                pre_phase_start = asyncio.get_running_loop().time()
                pre_phase_partial = False
                try:
                    await asyncio.wait_for(
                        asyncio.gather(
                            _check_js_source_maps(session, base_url, main_body, rate_limiter, findings),
                            _check_js_leaked_credentials(session, base_url, main_body, rate_limiter, findings, js_cache, fetch_js),
                            _enumerate_api_endpoints(session, base_url, rate_limiter, findings),
                            _check_interesting_files_from_headers(session, base_url, main_headers, rate_limiter, findings),
                            _extract_js_routes(session, base_url, main_body, rate_limiter, findings, js_cache, fetch_js),
                            _check_kubernetes_exposure(session, base_url, rate_limiter, findings),
                            _check_docker_terraform(session, base_url, rate_limiter, findings),
                            _check_cloud_storage(session, base_url, main_body, rate_limiter, findings),
                            return_exceptions=True
                        ),
                        timeout=PRE_PHASE_BUDGET_SECONDS
                    )
                except asyncio.TimeoutError:
                    pre_phase_partial = True
                    partial_phases.append("pre_phase")
                    _log_debug("[FIX #2] Pre-phase timeout after 15s; continuing with partial pre-phase results")
                finally:
                    pre_phase_elapsed = asyncio.get_running_loop().time() - pre_phase_start

                # -- Path probing with adaptive budget ---------------------------------------
                remaining_budget = max(10, TOTAL_INTERNAL_BUDGET_SECONDS - pre_phase_elapsed)
                all_paths = []
                all_paths.extend(HIGH_SENSITIVE_PATHS.keys())
                all_paths.extend(MEDIUM_SENSITIVE_PATHS.keys())
                all_paths.extend(LOW_SENSITIVE_PATHS.keys())
                for tech in tech_stack:
                    if tech in TECH_SPECIFIC_PATHS:
                        for tp in TECH_SPECIFIC_PATHS[tech]:
                            if tp not in all_paths: all_paths.append(tp)
                for ep in API_ENDPOINTS:
                    if ep not in all_paths: all_paths.append(ep)
                for bn in _generate_backup_names(domain):
                    if bn not in all_paths: all_paths.append(bn)
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
                                    severity, confidence = _get_path_severity(path)
                                    sensitive_file_emitted = False
                                    if _is_sensitive_content(path, body):
                                        if path in ("robots.txt", "sitemap.xml"):
                                            pass
                                        elif "phpinfo" in path:
                                            sensitive_file_emitted = True
                                            findings.append(_make_finding(
                                                title="PHP configuration disclosure via phpinfo.php",
                                                description="phpinfo.php discloses full server configuration, loaded extensions, versions, and potentially environment variables.",
                                                severity="critical", confidence=95, location=path,
                                                evidence=f"Content verified as phpinfo, HTTP {status}, size: {len(body)} bytes",
                                                remediation="Remove phpinfo.php from the web root or restrict access at the web server level.",
                                                cwe="CWE-200", owasp="A01:2021",
                                                poc=f"curl -s {url} | head -50",
                                                detection_method="content_analysis",
                                                response_status=status, response_headers=resp_headers,
                                                response_size=len(body), exact_url=url,
                                            ))
                                        else:
                                            sensitive_file_emitted = True
                                            if ".env" in path and any(kw in body for kw in ["PASSWORD", "SECRET", "API_KEY"]):
                                                severity = "critical"
                                                confidence = 98
                                            findings.append(_make_finding(
                                                title=f"Sensitive file exposed: {path}",
                                                description=f"Sensitive file accessible at {path}",
                                                severity=severity, confidence=confidence, location=path,
                                                evidence=f"Content verified, HTTP {status}, size: {len(body)} bytes",
                                                remediation=f"Restrict access to {path}.",
                                                cwe=CWE_MAP.get("sensitive_file", "CWE-538"),
                                                owasp=OWASP_MAP.get("sensitive_file", "A01:2021"),
                                                poc=f"curl -s {url} | head -50",
                                                detection_method="content_analysis",
                                                response_status=status,
                                                response_headers=resp_headers,
                                                response_size=len(body),
                                                exact_url=url,
                                            ))
                                    if _is_directory_listing(body, main_body):
                                        sensitive_file_emitted = True
                                        findings.append(_make_finding(
                                            title=f"Directory listing enabled: {path}",
                                            description=f"Directory listing found at {path}",
                                            severity="medium", confidence=90, location=path,
                                            evidence=f"HTTP {status} response, Content-Length: {len(body) if body else 'unknown'}",
                                            remediation="Disable directory listing.",
                                            cwe=CWE_MAP["dir_listing"], owasp=OWASP_MAP["dir_listing"],
                                            poc=f"curl -s {url} | head -50",
                                            detection_method="listing_detection",
                                            response_status=status,
                                            response_headers=resp_headers,
                                            response_size=len(body),
                                            exact_url=url,
                                        ))
                                    if path == "robots.txt":
                                        sensitive_paths = _is_robots_sensitive(body)
                                        if sensitive_paths:
                                            findings.append(_make_finding(
                                                title="Sensitive paths disclosed in robots.txt",
                                                description=f"robots.txt reveals sensitive paths: {', '.join(sensitive_paths[:5])}",
                                                severity="medium", confidence=85, location="/robots.txt",
                                                evidence=f"Disallowed paths: {', '.join(sensitive_paths[:10])}",
                                                remediation="Review robots.txt for sensitive path disclosure.",
                                                cwe=CWE_MAP["sensitive_file"], owasp=OWASP_MAP["sensitive_file"],
                                                poc=f"curl -s {url}",
                                                detection_method="robots_analysis",
                                                response_status=status,
                                                response_headers=resp_headers,
                                                response_size=len(body),
                                                extracted_info=f"Paths: {', '.join(sensitive_paths[:10])}",
                                                exact_url=url,
                                            ))
                                        else:
                                            findings.append(_make_finding(
                                                title=f"Accessible file: {path}",
                                                description=f"robots.txt accessible (no sensitive paths disclosed)",
                                                severity="info", confidence=60, location=path,
                                                evidence=f"HTTP {status} response, size: {len(body)} bytes",
                                                remediation="Review if exposure is intentional.",
                                                poc=f"curl -s {url}",
                                                detection_method="file_accessible",
                                                response_status=status,
                                                response_headers=resp_headers,
                                                response_size=len(body),
                                                exact_url=url,
                                            ))
                                    elif path == "sitemap.xml":
                                        sensitive = any(s in body.lower() for s in ['admin', 'backup', 'internal', 'private', 'debug'])
                                        findings.append(_make_finding(
                                            title=f"Accessible file: {path}",
                                            description=f"sitemap.xml accessible" + (" and may reveal internal paths" if sensitive else ""),
                                            severity="info", confidence=70 if sensitive else 55,
                                            location=path,
                                            evidence=f"HTTP {status} response, size: {len(body)} bytes",
                                            remediation="Review if exposure is intentional.",
                                            poc=f"curl -s {url} | head -30",
                                            detection_method="file_accessible",
                                            response_status=status,
                                            response_headers=resp_headers,
                                            response_size=len(body),
                                            exact_url=url,
                                        ))
                                    elif not sensitive_file_emitted and not _is_soft_404(body, main_body) and path not in ["/robots.txt", "/sitemap.xml", "/favicon.ico"]:
                                        findings.append(_make_finding(
                                            title=f"Accessible file: {path}",
                                            description=f"File accessible at {path}",
                                            severity=severity if severity in ("critical", "high") else "low",
                                            confidence=confidence if severity in ("critical", "high") else 65,
                                            location=path,
                                            evidence=f"HTTP {status} response, size: {len(body)} bytes",
                                            remediation="Review if exposure is intentional.",
                                            poc=f"curl -s {url} | head -30",
                                            detection_method="file_accessible",
                                            response_status=status,
                                            response_headers=resp_headers,
                                            response_size=len(body),
                                            exact_url=url,
                                        ))
                                elif status == 403:
                                    if path not in EXPECTED_403_PATHS:
                                        severity, confidence = _get_path_severity(path)
                                        findings.append(_make_finding(
                                            title=f"Forbidden access to sensitive path: {path}",
                                            description=f"Path {path} returned 403 Forbidden",
                                            severity="low" if severity == "low" else "medium",
                                            confidence=confidence - 10, location=path,
                                            evidence=f"HTTP {status} response",
                                            remediation=f"Verify access controls for {path}.",
                                            cwe=CWE_MAP["sensitive_file"], owasp=OWASP_MAP["sensitive_file"],
                                            poc=f"curl -I {url}",
                                            detection_method="status_code",
                                            response_status=status,
                                            response_headers=resp_headers,
                                            exact_url=url,
                                        ))
                                elif status == 401:
                                    findings.append(_make_finding(
                                        title=f"Unauthorized access to: {path}",
                                        description=f"Path {path} returned 401 Unauthorized",
                                        severity="info", confidence=75, location=path,
                                        evidence=f"HTTP {status} response",
                                        remediation="Verify authentication requirements.",
                                        poc=f"curl -I {url}",
                                        detection_method="status_code",
                                        response_status=status,
                                        response_headers=resp_headers,
                                        exact_url=url,
                                    ))
                                checked += 1
                                paths_checked = checked
                            except asyncio.TimeoutError:
                                checked += 1
                                paths_checked = checked
                                continue
                            except Exception as e:
                                _log_debug(f"Path probe failed for {path}: {e}")
                                checked += 1
                                paths_checked = checked
                                continue
                        return checked

                    paths_checked = await asyncio.wait_for(_probe_all_paths(), timeout=remaining_budget)
                except asyncio.TimeoutError:
                    is_partial = True
                    scan_note = f"Path probing budget reached; results are partial. Checked {paths_checked}/{paths_total} paths."
                    _log_debug(f"[FIX #1/#3] Path probing budget reached: {paths_checked}/{paths_total} paths checked")
                    partial_phases.append("path_probing")
                    paths_checked = min(paths_checked, paths_total)

                # -- Deduplicate --------------------------------------------------------------
                seen = set()
                unique_findings = []
                for f in findings:
                    key = (f["title"], f.get("location", ""), f.get("detection_method", ""))
                    if key not in seen:
                        seen.add(key)
                        unique_findings.append(f)
                findings = unique_findings

                if pre_phase_partial:
                    is_partial = True
                    if scan_note: scan_note += "; "
                    scan_note += "Pre-phase was cut short (15s budget)."

            try:
                await asyncio.wait_for(main_work(), timeout=SAFETY_NET_SECONDS)
            except asyncio.TimeoutError:
                is_partial = True
                scan_note = "Safety net timeout after 55s; returning all accumulated findings."
                partial_phases.append("safety_net")
                _log_debug("[FIX #5] Safety net timeout; returning partial results")

        finally:
            if temp_session:
                await session.close()

        # Filter by min_confidence
        findings = [f for f in findings if f.get("confidence", 100) >= min_confidence]

        details = {
            "tech_stack": list(tech_stack),
            "waf_detected": waf_detected,
            "context": site_context,
            "paths_checked": paths_checked,
            "paths_total": paths_total,
            "partial": is_partial,
            "partial_phases": partial_phases,
            "note": scan_note,
        }

        return {
            "findings": findings,
            "details": details
        }

    except Exception as e:
        return {
            "findings": [],
            "details": {"error": str(e), "error_type": type(e).__name__}
        }

if __name__ == "__main__":
    target_url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    result = asyncio.run(run(target_url))
    print(json.dumps(result, indent=2, ensure_ascii=False))