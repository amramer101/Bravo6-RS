#!/usr/bin/env python3
"""
test_06_info_disclosure.py – Bravo6 Ultimate Info Disclosure Scanner (v8.5 – Final)
================================================================================
- _is_sensitive_content returns False by default (minimizes false positives).
- Reduced backup name generation (fewer patterns) to limit requests.
- JS entropy threshold raised to 5.0 (reduces noise from high-entropy strings).
- Modern sensitive paths added (.well-known, Firebase, Supabase, Vercel, Amplify).
- All core features: smart wordlist, soft 404, API enumeration, GraphQL check,
  source map detection, leaked credentials, cloud bucket listing, etc.
- Unified JSON output with scoring, context, and summary statistics.
"""

import asyncio
import json
import math
import random
import re
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup, Comment

# ── Constants ──────────────────────────────────────────────────────────────
SCANNER_NAME = "info_disclosure"
USER_AGENT = "Bravo6-InfoDisclosure/8.5"
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=15)
HEAD_TIMEOUT = aiohttp.ClientTimeout(total=5)
MAX_CONCURRENT = 8
RETRY_MAX = 3
RETRY_BACKOFF_BASE = 1

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

# ── Helpers ────────────────────────────────────────────────────────────────
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

async def retry_async(coro, max_retries=RETRY_MAX, base_delay=RETRY_BACKOFF_BASE):
    last_exc = None
    for attempt in range(max_retries + 1):
        try:
            return await coro
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

# ── WAF Detection ──────────────────────────────────────────────────────────
async def _detect_waf(hostname: str, port: int = 443) -> Optional[str]:
    try:
        ssl_ctx = __import__('ssl').create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = __import__('ssl').CERT_NONE
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=8),
            headers={"User-Agent": USER_AGENT}
        ) as session:
            async with session.get(f"https://{hostname}:{port}", ssl=ssl_ctx) as resp:
                headers = resp.headers
                if 'cf-ray' in headers: return 'cloudflare'
                if 'x-sucuri-id' in headers: return 'sucuri'
                if 'x-akamai-request-id' in headers: return 'akamai'
                if headers.get('server', '').lower().startswith('cloudflare'): return 'cloudflare'
    except Exception as e:
        _log_error(f"WAF detection failed: {e}")
    return None

# ── Site Categorization ────────────────────────────────────────────────────
SITE_CATEGORIES = {
    "bank": ["bank", "online banking"],
    "ecommerce": ["shop", "store", "buy", "cart", "checkout", "shopping", "amazon", "ebay", "etsy", "aliexpress"],
    "healthcare": ["hospital"],
    "login": ["sign in", "login"],
    "blog": ["blog", "articles"],
    "internal": ["intranet", "internal"],
}
async def _categorize_site(hostname: str, port: int = 443) -> Dict:
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
    try:
        ssl_ctx = __import__('ssl').create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = __import__('ssl').CERT_NONE
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10),
                                          headers={"User-Agent": USER_AGENT}) as session:
            async with session.get(f"https://{hostname}:{port}", ssl=ssl_ctx) as resp:
                html = await resp.text()
                title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
                if title_match: result["title"] = title_match.group(1)
                meta_match = re.search(r'<meta\s+name="keywords"\s+content="(.*?)"', html, re.IGNORECASE)
                if meta_match: result["meta_keywords"] = meta_match.group(1)
                if re.search(r'<input\s+[^>]*type=["\']?password["\']?', html, re.IGNORECASE):
                    result["has_login_form"] = True
    except Exception as e:
        _log_error(f"Site categorization failed: {e}")
    text = (result["title"] + " " + result["meta_keywords"]).lower()
    for category, keywords in SITE_CATEGORIES.items():
        if any(k in text for k in keywords):
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

# ── Risk Scoring Engine (v3) ───────────────────────────────────────────────
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
    if waf_detected:
        base -= 12
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

# Modern sensitive paths added
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
    # Modern platforms
    ".well-known/security.txt", ".well-known/openid-configuration",
    "firebase.json", "supabase.json", "vercel.json", "amplify.yml",
    "aws-exports.js", "google-services.json",
]

BACKUP_EXTS = [".zip", ".tar.gz", ".tgz", ".rar", ".7z", ".sql", ".bak", ".tar", ".gz", ".bz2"]

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
        "web.config", "elmah.axd", "trace.axd", "bin/",
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
}

API_ENDPOINTS = [
    "graphql", "/api/v1/users", "/api/v1/products", "/api/v1/orders",
    "/api/v2/users", "/debug", "/admin", "/dashboard", "/login",
    "/wp-json/wp/v2/users", "/rest/user", "/oauth/token",
    "/.well-known/openid-configuration", "/actuator/health", "/actuator/env",
    "/graphql/console", "/swagger-resources", "/v2/api-docs",
]

# ── Soft 404 Detection ────────────────────────────────────────────────────
def _is_soft_404(body: str, homepage_body: str) -> bool:
    if not body or not homepage_body:
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
    return False

# ── Rate Limiter ──────────────────────────────────────────────────────────
class RateLimiter:
    def __init__(self, max_concurrent=8, min_delay=0.1, max_delay=0.5):
        self.sem = asyncio.Semaphore(max_concurrent)
        self.min_delay = min_delay
        self.max_delay = max_delay

    async def probe(self, session, url: str, method='GET') -> Optional[aiohttp.ClientResponse]:
        async with self.sem:
            await asyncio.sleep(random.uniform(self.min_delay, self.max_delay))
            try:
                if method == 'HEAD':
                    resp = await asyncio.wait_for(session.head(url, timeout=HEAD_TIMEOUT, allow_redirects=True),
                                                  timeout=HEAD_TIMEOUT.total)
                else:
                    resp = await asyncio.wait_for(session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True),
                                                  timeout=REQUEST_TIMEOUT.total)
                return resp
            except Exception as e:
                _log_error(f"Probe failed for {url}: {e}")
                return None

# ── Backup Name Generation (reduced) ───────────────────────────────────────
def _generate_backup_names(domain: str) -> List[str]:
    """Generate a reduced set of backup filenames to avoid excessive probing."""
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

# ── JS Leaked Credentials (v3 with entropy) ────────────────────────────────
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

async def _check_js_source_maps(session, base_url, rate_limiter, findings):
    try:
        resp = await rate_limiter.probe(session, base_url, 'GET')
        if not resp or resp.status != 200: return
        html = await resp.text()
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

async def _check_js_leaked_credentials(session, base_url, rate_limiter, findings):
    try:
        resp = await rate_limiter.probe(session, base_url, 'GET')
        if not resp or resp.status != 200: return
        html = await resp.text()
        soup = BeautifulSoup(html, "html.parser")
        js_urls = set()
        for script in soup.find_all("script", src=True):
            full = urljoin(base_url, script["src"])
            js_urls.add(full)
        for js_url in js_urls:
            resp_js = await rate_limiter.probe(session, js_url, 'GET')
            if resp_js and resp_js.status == 200:
                content = await resp_js.text(errors='replace')
                # High-confidence patterns
                for pat in HIGH_CONFIDENCE_SECRET_PATTERNS:
                    matches = re.findall(pat, content)
                    for m in matches:
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
                # Broad pattern with strict filtering
                broad_matches = BROAD_SECRET_PATTERN.findall(content)
                for match in broad_matches:
                    val = match[0] if isinstance(match, tuple) else match
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
                # Entropy check for long strings (raised threshold to 5.0 to reduce noise)
                for match in re.finditer(r'["\']([a-zA-Z0-9_\-+/=]{20,})["\']', content):
                    candidate = match.group(1)
                    if _entropy(candidate) > 5.0:   # was 4.5, raised to suppress false positives
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

# ── API Endpoint Enumeration ──────────────────────────────────────────────
async def _enumerate_api_endpoints(session, base_url, rate_limiter, findings):
    reported_user_enum = False
    for endpoint in API_ENDPOINTS:
        url = urljoin(base_url, endpoint)
        resp = await rate_limiter.probe(session, url, 'GET')
        if resp is None: continue
        if resp.status == 200:
            content_type = resp.headers.get('Content-Type', '')
            body = await resp.text()
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
            findings.append(_make_finding(
                title=f"Protected API endpoint: {endpoint}",
                description="Endpoint exists but requires authentication.",
                severity="info", confidence=85,
                location=endpoint,
                remediation="Ensure strong authentication.",
                category="api"
            ))

# ── Forbidden file sensitivity upgrade ────────────────────────────────────
def _is_highly_sensitive_path(path: str) -> str:
    """Returns severity level: 'high', 'medium', or 'low'"""
    ultra = ['.git/HEAD', '.env', 'wp-config.php', 'wp-config']
    if any(u in path.lower() for u in ultra):
        return "high"
    high = ['.env', 'backup', 'dump', '.sql', 'config.php', 'web.config', 'error.log', '.ds_store']
    if any(h in path.lower() for h in high):
        return "medium"
    return "low"

# ── Auto-detect WordPress ──────────────────────────────────────────────────
def _detect_wordpress_from_findings(findings: List[Dict]) -> bool:
    for f in findings:
        loc = f.get("location", "")
        if 'wp-json' in loc or 'wp-content' in loc or 'wp-admin' in loc or 'wp-login' in loc:
            return True
    return False

# ── Fetch generic 403 body ─────────────────────────────────────────────────
async def _fetch_generic_403_body(session, base_url: str, rate_limiter: RateLimiter) -> Optional[str]:
    random_path = f"/nonexistent-{random.randint(10000,99999)}.html"
    url = urljoin(base_url, random_path)
    resp = await rate_limiter.probe(session, url, 'GET')
    if resp and resp.status == 403:
        try:
            return await resp.text()
        except Exception:
            pass
    return None

# ══════════════════════════════════════════════════════════════════════════════
# Main Scanner
# ══════════════════════════════════════════════════════════════════════════════
async def run(url: str) -> Dict[str, Any]:
    target = _normalize_url(url)
    parsed = urlparse(target)
    hostname = parsed.hostname or ""
    port = parsed.port or 443
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    domain = hostname

    is_api = hostname.startswith("api.") or "/api/" in parsed.path
    site_context = await _categorize_site(hostname, port)
    site_context["is_api"] = is_api
    waf_detected = await _detect_waf(hostname, port)

    findings: List[Dict] = []
    tech_stack: Set[str] = set()
    rate_limiter = RateLimiter(max_concurrent=MAX_CONCURRENT)

    try:
        async with aiohttp.ClientSession(
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            connector=aiohttp.TCPConnector(ssl=True, limit=MAX_CONCURRENT + 5)
        ) as session:

            # 1. Fetch main page
            main_resp = await retry_async(rate_limiter.probe(session, target, 'GET'))
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

            # ── Passive technology fingerprint ────────────────────────────
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

            # ── HTML meta / comments ──────────────────────────────────────
            if main_body:
                soup = BeautifulSoup(main_body, "html.parser")
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

            # 2. Build smart wordlist
            all_paths = set(BASE_SENSITIVE_PATHS)
            for bn in _generate_backup_names(domain):
                all_paths.add(bn)
            for tech in tech_stack:
                for tpaths in TECH_SPECIFIC_PATHS.get(tech, []):
                    all_paths.add(tpaths)
            all_paths.update(["wp-config.php", "wp-content/debug.log", "xmlrpc.php"])

            # 3. Obtain generic 403 body
            generic_403_body = await _fetch_generic_403_body(session, base_url, rate_limiter)

            # 4. Probe paths with rate limiting
            homepage_length = len(main_body) if main_body else 0
            sem = asyncio.Semaphore(MAX_CONCURRENT)

            async def probe_path(path):
                async with sem:
                    await asyncio.sleep(random.uniform(0.05, 0.2))
                full_url = urljoin(base_url, path)
                try:
                    async with session.head(full_url, timeout=HEAD_TIMEOUT, allow_redirects=True) as head_resp:
                        status = head_resp.status
                except Exception:
                    return
                if status == 200:
                    body = await _fetch_body(session, full_url)
                    if body:
                        if main_body and _is_soft_404(body, main_body):
                            return
                        if path == "robots.txt":
                            if _is_robots_sensitive(body):
                                findings.append(_make_finding(
                                    title="robots.txt exposes sensitive paths",
                                    description="robots.txt contains disallowed admin/backup paths.",
                                    severity="medium", confidence=90,
                                    location=path, evidence=body[:200],
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
                        else:
                            sev, conf, risk = "info", 50, "File exists but content does not match expected sensitive pattern."
                        findings.append(_make_finding(
                            title=f"Exposed file: {path}",
                            description=risk,
                            severity=sev, confidence=conf,
                            location=path, evidence=body[:300],
                            remediation="Restrict access or remove file.",
                            cwe=CWE_MAP.get("sensitive_file", "CWE-538"),
                            owasp=OWASP_MAP.get("sensitive_file", "A01:2021"),
                            poc=f"curl {full_url}",
                            category="active"
                        ))
                elif status == 403:
                    if generic_403_body:
                        body = await _fetch_body(session, full_url)
                        if body and body.strip() == generic_403_body.strip():
                            return
                    sev = _is_highly_sensitive_path(path)
                    findings.append(_make_finding(
                        title=f"Forbidden file: {path}",
                        description="File exists but is protected." + (" (highly sensitive)" if sev in ("high","medium") else ""),
                        severity=sev, confidence=80,
                        location=path,
                        remediation="Ensure protection is adequate.",
                        category="active"
                    ))

            tasks = [probe_path(p) for p in all_paths]
            await asyncio.gather(*tasks, return_exceptions=True)

            # 5. Directory listing & traversal
            dir_paths = ["/assets/", "/static/", "/uploads/", "/files/", "/images/", "/css/", "/js/"]
            for d in dir_paths:
                full = urljoin(base_url, d)
                body = await _fetch_body(session, full)
                if body and ("Index of /" in body or "Parent Directory" in body):
                    findings.append(_make_finding(
                        title=f"Directory listing enabled: {d}",
                        description="Directory listing allows attackers to see file structure.",
                        severity="critical", confidence=95,
                        location=d, evidence=body[:200],
                        remediation="Disable directory listing.",
                        cwe=CWE_MAP["dir_listing"], owasp=OWASP_MAP["dir_listing"],
                        poc=f"curl {full}",
                        category="active"
                    ))
                traversal = urljoin(base_url, d + "../")
                tbody = await _fetch_body(session, traversal)
                if tbody and ("Index of /" in tbody) and tbody != body:
                    findings.append(_make_finding(
                        title="Path traversal possible",
                        description="Parent directory accessible.",
                        severity="critical", confidence=95,
                        location=traversal, evidence=tbody[:200],
                        remediation="Configure web server to prevent directory traversal.",
                        poc=f"curl {traversal}",
                        category="active"
                    ))

            # 6. Cloud storage
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

            # 7. Other advanced scans
            await _check_interesting_files_from_headers(session, base_url, main_headers, findings)
            await _check_js_source_maps(session, base_url, rate_limiter, findings)
            await _check_js_leaked_credentials(session, base_url, rate_limiter, findings)
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

    # Post-processing
    if _detect_wordpress_from_findings(findings):
        tech_stack.add("WordPress")

    # Deduplicate
    unique = []
    seen = set()
    for f in findings:
        key = (f.get("title"), f.get("location", "")[:150])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    findings = unique

    # Score & grade
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

# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════
async def _fetch_body(session, url: str) -> Optional[str]:
    try:
        async with session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True) as resp:
            if resp.status == 200:
                return await resp.text(errors="replace")
    except Exception as e:
        _log_error(f"Failed to fetch body for {url}: {e}")
    return None

def _is_robots_sensitive(body: str) -> bool:
    sensitive_patterns = [r'admin', r'backup', r'config', r'\.git', r'\.env', r'wp-admin', r'login', r'dashboard']
    for pattern in sensitive_patterns:
        if re.search(r'Disallow:\s*/' + pattern, body, re.IGNORECASE):
            return True
    return False

def _is_sensitive_content(path: str, body: str) -> bool:
    """Check if the content matches the expected pattern for a sensitive file.
    Returns True only if the file content is clearly sensitive; otherwise False."""
    if ".git/HEAD" in path:
        return "ref: refs/heads/" in body
    if ".env" in path:
        return any(kw in body for kw in ["DB_", "PASSWORD", "API_KEY", "SECRET", "APP_KEY"])
    if "composer.json" in path:
        return '"require"' in body
    if "package.json" in path:
        return '"dependencies"' in body
    if "robots.txt" in path:
        return True  # robots.txt itself is not really sensitive, but we handle it separately before calling this
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
    if path.endswith((".zip", ".tar.gz", ".tgz", ".rar", ".7z", ".bak")):
        return True
    # All other files are not considered sensitive by default
    return False

# ── CLI ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    target_url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    result = asyncio.run(run(target_url))
    print(json.dumps(result, indent=2, ensure_ascii=False))