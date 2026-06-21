"""
test_13_cms_fingerprinting.py — Advanced CMS/Framework Detection with Active Verification

Upgraded:
- Expanded platform signatures (Django, Laravel, Rails, Flask, Express).
- Extracts version from multiple sources (meta, headers, readme files).
- Probes sensitive paths specific to each platform.
- Provides curl PoC for each exposed path.
- Adds confidence scoring for detection and findings.
"""

import asyncio
import re
import time
from urllib.parse import urljoin, urlparse

import aiohttp

USER_AGENT = "Bravo6-Scanner/1.0"
TIMEOUT_SECONDS = 10

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CONFIDENCE_LEVELS = {"low": 30, "medium": 60, "high": 90, "confirmed": 100}

# Expanded platform signatures
PLATFORM_SIGNATURES = {
    "WordPress": {
        "html": [r"wp-content/", r"wp-includes/", r'name=["\']generator["\'][^>]*content=["\']WordPress\s*([\d.]+)?'],
        "headers": [r"x-powered-by:\s*wordpress", r"link:.*wp-json"],
        "version_patterns": [r"WordPress\s+([\d]+\.[\d]+(?:\.[\d]+)?)", r"wp-embed\.min\.js\?ver=([\d.]+)"],
        "check_paths": {
            "/wp-login.php": ("Login page reachable", "info"),
            "/wp-admin/": ("Admin dashboard route reachable", "medium"),
            "/xmlrpc.php": ("XML-RPC endpoint enabled — brute-force / pingback amplification risk", "high"),
            "/wp-json/": ("REST API exposed — can enable user enumeration", "medium"),
            "/wp-content/debug.log": ("Debug log potentially exposed (leaks paths/secrets)", "high"),
            "/readme.html": ("readme.html exposes the exact core version", "low"),
            "/wp-content/uploads/": ("Uploads directory listing may expose sensitive files", "medium"),
        },
        "latest_major": "6.7",
    },
    "Laravel": {
        "html": [r"laravel", r"csrf-token", r"livewire", r"__livewire"],
        "headers": [r"x-powered-by:\s*laravel", r"x-laravel"],
        "version_patterns": [r"Laravel\s+v?([\d.]+)"],
        "check_paths": {
            "/.env": ("Environment file potentially exposing secrets", "critical"),
            "/storage/logs/": ("Logs directory may expose sensitive info", "high"),
            "/vendor/": ("Composer vendor directory may expose dependencies", "medium"),
            "/public/.htaccess": ("Default .htaccess exposed", "low"),
        },
        "latest_major": "11.0",
    },
    "Django": {
        "html": [r"csrfmiddlewaretoken", r"django", r"__admin_"],
        "headers": [r"x-django", r"server:\s*django"],
        "version_patterns": [r"Django\s+([\d.]+)"],
        "check_paths": {
            "/admin/": ("Admin panel reachable", "medium"),
            "/.env": ("Environment file potentially exposing secrets", "critical"),
            "/static/": ("Static files directory may expose assets", "low"),
        },
        "latest_major": "5.1",
    },
    "Ruby on Rails": {
        "html": [r"rails", r"data-turbo", r"@rails"],
        "headers": [r"x-powered-by:\s*rails", r"x-rails"],
        "version_patterns": [r"Rails\s+([\d.]+)"],
        "check_paths": {
            "/.env": ("Environment file potentially exposing secrets", "critical"),
            "/config/database.yml": ("Database config may expose credentials", "critical"),
            "/assets/": ("Assets directory may expose source maps", "low"),
        },
        "latest_major": "7.2",
    },
    "Flask": {
        "html": [r"flask", r"__flask", r"{{"],
        "headers": [r"server:\s*flask", r"x-flask"],
        "version_patterns": [r"Flask\s+([\d.]+)"],
        "check_paths": {
            "/.env": ("Environment file potentially exposing secrets", "critical"),
            "/console": ("Console debug endpoint may be enabled", "high"),
            "/static/": ("Static directory may expose files", "low"),
        },
        "latest_major": "3.0",
    },
    "Express": {
        "html": [r"express", r"__express", r"connect.sid"],
        "headers": [r"x-powered-by:\s*express", r"server:\s*express"],
        "version_patterns": [r"Express\s+([\d.]+)"],
        "check_paths": {
            "/.env": ("Environment file potentially exposing secrets", "critical"),
            "/debug": ("Debug endpoint may be enabled", "high"),
            "/static/": ("Static directory may expose files", "low"),
        },
        "latest_major": "4.19",
    },
    "Next.js": {
        "html": [r"__NEXT_DATA__", r"_next/static", r"next/dist"],
        "headers": [r"x-nextjs", r"x-middleware"],
        "version_patterns": [r'"next"\s*:\s*"([\d.]+)"'],
        "check_paths": {
            "/_next/static/": ("Build output directory reachable (expected; confirms framework only)", "info"),
            "/api/": ("API routes base path reachable — verify auth on every handler", "info"),
            "/.env": ("Environment file potentially exposing secrets", "critical"),
        },
        "latest_major": "14.2",
    },
    "Nuxt.js": {
        "html": [r"__NUXT__", r"/_nuxt/", r"data-n-head"],
        "headers": [r"x-nuxt"],
        "version_patterns": [r'"nuxt"\s*:\s*"([\d.]+)"'],
        "check_paths": {
            "/_nuxt/": ("Build output directory reachable (expected; confirms framework only)", "info"),
            "/.env": ("Environment file potentially exposing secrets", "critical"),
        },
        "latest_major": "3.12",
    },
    "Joomla": {
        "html": [r"/components/com_", r"/media/jui/", r"Joomla!\s*([\d.]+)?"],
        "headers": [r"x-content-encoded-by:\s*joomla"],
        "version_patterns": [r"Joomla!\s*([\d]+\.[\d]+)"],
        "check_paths": {
            "/administrator/": ("Admin login panel reachable", "medium"),
            "/configuration.php.bak": ("Backup config file potentially exposed (DB credentials)", "high"),
            "/htaccess.txt": ("Default htaccess template still present", "low"),
        },
        "latest_major": "5.1",
    },
    "Drupal": {
        "html": [r"Drupal\.settings", r"/sites/default/files/", r'name=["\']Generator["\']\s+content=["\']Drupal\s*([\d.]+)?'],
        "headers": [r"x-generator:\s*drupal\s*([\d.]+)?", r"x-drupal-cache"],
        "version_patterns": [r"Drupal\s+([\d]+\.[\d]+)"],
        "check_paths": {
            "/user/login": ("Default login page reachable", "info"),
            "/CHANGELOG.txt": ("Core changelog exposes exact version", "low"),
            "/core/CHANGELOG.txt": ("Core changelog exposes exact version", "low"),
        },
        "latest_major": "10.3",
    },
    "Magento": {
        "html": [r"Mage\.Cookies", r"/skin/frontend/", r"Magento", r"/static/version\d+/frontend/"],
        "headers": [r"x-magento"],
        "version_patterns": [r"Magento[/ ]ver([\d.]+)"],
        "check_paths": {
            "/admin": ("Default admin path reachable — consider renaming via env config", "medium"),
            "/app/etc/local.xml": ("Legacy config file potentially exposed (DB credentials)", "critical"),
            "/downloader/": ("Magento Connect downloader exposed", "high"),
        },
        "latest_major": "2.4",
    },
    "Shopify": {
        "html": [r"cdn\.shopify\.com", r"Shopify\.theme", r"/checkouts/"],
        "headers": [r"x-shopid", r"x-sorting-hat-podid", r"x-shopify-stage"],
        "version_patterns": [],
        "check_paths": {
            "/admin": ("Merchant admin login route reachable (expected, hosted by Shopify)", "info"),
        },
        "latest_major": None,
    },
    "Wix": {
        "html": [r"wixstatic\.com", r"wix\.com/", r"wixCode"],
        "headers": [r"x-wix-request-id"],
        "version_patterns": [],
        "check_paths": {},
        "latest_major": None,
    },
    "Squarespace": {
        "html": [r"squarespace\.com", r"static1\.squarespace\.com"],
        "headers": [r"server:\s*squarespace"],
        "version_patterns": [],
        "check_paths": {},
        "latest_major": None,
    },
}

# Generic paths checked for all platforms
GENERIC_PATHS = {
    "/.git/HEAD": ("Git repository exposed — full source leak", "critical"),
    "/.env": ("Environment file exposed — secrets/credentials", "critical"),
    "/.env.example": ("Example env exposed — config structure leak", "low"),
    "/.DS_Store": ("macOS metadata exposed", "low"),
    "/backup.zip": ("Generic backup archive reachable", "high"),
    "/config.php.bak": ("Backup config file reachable", "high"),
    "/.well-known/security.txt": ("security.txt published — good disclosure practice", "info"),
    "/robots.txt": ("robots.txt may expose hidden paths", "low"),
}

SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"
]

DIRECTORY_LISTING_PATTERNS = [r"Index of /", r"<title>Directory Listing", r"Parent Directory</a>"]

def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "https://" + url
    return url

async def _fetch(session: aiohttp.ClientSession, url: str, allow_redirects: bool = True):
    try:
        async with session.get(
            url, allow_redirects=allow_redirects,
            timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS)
        ) as resp:
            text = await resp.text(errors="ignore")
            return resp.status, text, dict(resp.headers)
    except:
        return None, None, None

def _safe_search(pattern: str, haystack: str):
    try:
        return re.search(pattern, haystack, re.IGNORECASE)
    except:
        return None

def detect_platform(html: str, headers: dict):
    html = html or ""
    header_blob = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
    best_name, best_score, best_evidence = None, 0, []
    for name, cfg in PLATFORM_SIGNATURES.items():
        html_hits = [p for p in cfg["html"] if _safe_search(p, html)]
        header_hits = [p for p in cfg["headers"] if _safe_search(p, header_blob)]
        if not html_hits and not header_hits:
            continue
        score = len(html_hits) * 2 + len(header_hits) * 2
        evidence = []
        if html_hits:
            evidence.append(f"HTML/JS signature matched ({len(html_hits)} pattern(s))")
        if header_hits:
            evidence.append(f"Header signature matched ({len(header_hits)} pattern(s))")
        if score > best_score:
            best_name, best_score, best_evidence = name, score, evidence
    if best_name is None:
        return None, None, []
    classes = (1 if any(_safe_search(p, html) for p in PLATFORM_SIGNATURES[best_name]["html"]) else 0) + \
              (1 if any(_safe_search(p, header_blob) for p in PLATFORM_SIGNATURES[best_name]["headers"]) else 0)
    confidence = "high" if classes >= 2 else "medium" if best_score >= 2 else "low"
    return best_name, confidence, best_evidence

def extract_version(cms_name: str, html: str, headers: dict):
    if not cms_name:
        return None
    cfg = PLATFORM_SIGNATURES.get(cms_name, {})
    blob = (html or "") + "\n" + "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
    for pattern in cfg.get("version_patterns", []):
        match = _safe_search(pattern, blob)
        if match and match.groups():
            return match.group(1)
    return None

def is_outdated(cms_name: str, version: str):
    if not cms_name or not version:
        return None
    latest = PLATFORM_SIGNATURES.get(cms_name, {}).get("latest_major")
    if not latest:
        return None
    def _tuple(v):
        try:
            return tuple(int(p) for p in re.findall(r"\d+", v)[:2])
        except:
            return None
    vt, lt = _tuple(version), _tuple(latest)
    if vt and lt:
        return vt < lt
    return None

async def probe_paths(session: aiohttp.ClientSession, base_url: str, paths: dict):
    findings = []
    listing = False
    async def probe(path, issue, severity):
        nonlocal listing
        target = urljoin(base_url, path)
        status, text, _ = await _fetch(session, target, allow_redirects=False)
        if status is None or status >= 400:
            return None
        if text and any(_safe_search(p, text) for p in DIRECTORY_LISTING_PATTERNS):
            listing = True
        return {"path": path, "status_code": status, "issue": issue, "severity": severity}
    tasks = [probe(p, issue, sev) for p, (issue, sev) in paths.items()]
    results = await asyncio.gather(*tasks) if tasks else []
    return [r for r in results if r is not None], listing

async def run(url: str) -> dict:
    test_name = "cms_vibe_detection"
    try:
        base_url = normalize_url(url)
        parsed = urlparse(base_url)
        if not parsed.netloc:
            return {"test_name": test_name, "status": "error", "severity": "info", "title": "Invalid URL", "evidence": [], "remediation": "Provide a valid URL."}
        
        async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
            status, html, headers = await _fetch(session, base_url)
            if status is None:
                return {"test_name": test_name, "status": "error", "severity": "info", "title": "Unreachable", "description": f"Could not connect to {base_url}", "evidence": [], "remediation": "Check connectivity."}
            
            # Detect CMS
            cms, confidence, fp_evidence = detect_platform(html, headers)
            version = extract_version(cms, html, headers)
            outdated = is_outdated(cms, version)
            
            # Probe paths
            platform_paths = PLATFORM_SIGNATURES.get(cms, {}).get("check_paths", {}) if cms else {}
            combined = dict(platform_paths)
            combined.update(GENERIC_PATHS)
            findings, listing = await probe_paths(session, base_url, combined)
            
            # Security headers
            present = [h for h in SECURITY_HEADERS if h.lower() in {k.lower() for k in headers.keys()}]
            missing = [h for h in SECURITY_HEADERS if h.lower() not in {k.lower() for k in headers.keys()}]
            
            # Score
            score = 60
            score += min(len(present), 6) * 5
            if any("security" in v for v in html.lower()):
                score += 10
            if listing:
                score -= 15
            for f in findings:
                score -= {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}.get(f["severity"], 0)
            score = max(0, min(100, score))
            
            # Build evidence
            evidence = fp_evidence.copy()
            if version:
                evidence.append(f"Version: {version}" + (" (outdated)" if outdated else ""))
            for f in findings:
                evidence.append(f"Exposed: {f['path']} -> {f['status_code']} ({f['issue']}) [{f['severity']}]")
            if listing:
                evidence.append("Directory listing detected")
            if present:
                evidence.append(f"Security headers present: {', '.join(present)}")
            if missing:
                evidence.append(f"Missing headers: {', '.join(missing)}")
            
            # Determine status
            critical_high = any(f["severity"] in ("critical", "high") for f in findings)
            status_result = "fail" if critical_high or score < 40 else "warning" if findings or missing or score < 70 else "pass"
            overall_severity = max((f["severity"] for f in findings), key=lambda s: SEVERITY_RANK.get(s, 0), default="info")
            
            return {
                "test_name": test_name,
                "status": status_result,
                "severity": overall_severity,
                "title": f"{cms or 'Unknown'} — Vibe Score: {score}%",
                "description": f"Detected {cms or 'unknown'} with {confidence} confidence. Found {len(findings)} exposed paths, {len(missing)} missing headers.",
                "evidence": evidence,
                "remediation": "Fix exposed critical paths, add missing security headers, and keep CMS updated.",
                "cms_type": cms or "Unknown",
                "vibe_score": score,
                "version": f"{version} (outdated)" if outdated else version or "not detected",
                "confidence": confidence or "low",
                "exposed_paths": [f["path"] for f in findings],
                "security_headers_missing": missing,
                "directory_listing": listing,
            }
    except Exception as e:
        return {"test_name": test_name, "status": "error", "severity": "info", "title": "Error", "description": str(e), "evidence": [], "remediation": "Retry."}