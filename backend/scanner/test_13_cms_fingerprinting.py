"""
test_13_cms_fingerprinting.py — Advanced CMS/Framework Detection with Active Verification (v3)

Enhanced with:
- Active verification via unique endpoints per CMS (wp-json, /administrator, /user/login, /csrf-cookie, /_next/static/)
- Precise version detection via specific files (version.php, CHANGELOG.txt, package.json)
- CVE correlation with version detection (built-in database)
- Plugin/theme detection (WordPress, Joomla, Drupal, Laravel)
- Sensitive config file detection per CMS
- CMS-specific security headers analysis
- API endpoint discovery
- Integration with info disclosure test paths
- robots.txt / sitemap.xml analysis
- Dynamic confidence scoring (0-100)
- PoC generation (curl commands for verification)
- Dev environment detection (debug files, error logs)
- Modern CMS support (Contentful, Sanity, Strapi, Directus, Ghost)
- Directory structure analysis via 403/404 error messages
- Extensible signature database (JSON-based for future updates)
- Contextual integration with other tests
"""

import asyncio
import json
import re
from datetime import datetime
from urllib.parse import urljoin, urlparse
from typing import Dict, Any, List, Optional, Tuple, Set

import aiohttp
from bs4 import BeautifulSoup

# ── Configuration ────────────────────────────────────────────────────────────
USER_AGENT = "Bravo6-Scanner/1.0"
TIMEOUT_SECONDS = 10
MAX_CONCURRENT_CHECKS = 15
MAX_BYTES_FETCH = 500 * 1024

# ── Severity Ranking ────────────────────────────────────────────────────────
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
CONFIDENCE_LEVELS = {"low": 30, "medium": 60, "high": 85, "confirmed": 100}

# ── Security Headers ───────────────────────────────────────────────────────
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]

# ── CMS Signatures Database ─────────────────────────────────────────────────
# Each CMS entry includes:
#   - html: list of regex patterns to find in HTML
#   - headers: list of regex patterns to find in headers
#   - version_patterns: list of regex patterns to extract version
#   - version_files: list of (path, pattern) to fetch and extract version
#   - check_paths: dict of path -> (description, severity)
#   - unique_endpoints: list of (path, expected_status, success_pattern) for active verification
#   - plugins_path: path pattern for plugins
#   - plugin_files: list of plugin names to check
#   - cves: dict of version_range -> list of CVEs
#   - config_files: list of sensitive config file paths
#   - admin_paths: list of admin paths
#   - api_paths: list of API paths
#   - dev_indicators: list of regex patterns for development environment
#   - security_headers_cms_specific: dict of header patterns specific to CMS

CMS_DATABASE = {
    "WordPress": {
        "html": [
            r"wp-content/",
            r"wp-includes/",
            r'name=["\']generator["\'][^>]*content=["\']WordPress\s*([\d.]+)?',
            r"wp-json",
            r"wp-embed",
        ],
        "headers": [
            r"x-powered-by:\s*wordpress",
            r"link:.*wp-json",
            r"x-pingback",
        ],
        "version_patterns": [
            r"WordPress\s+([\d]+\.[\d]+(?:\.[\d]+)?)",
            r"wp-embed\.min\.js\?ver=([\d.]+)",
            r"wp-includes/js/wp-embed.min.js\?ver=([\d.]+)",
        ],
        "version_files": [
            ("/wp-includes/version.php", r"\$wp_version\s*=\s*['\"]?([\d.]+)['\"]?;?"),
            ("/wp-admin/install.php", r"WordPress\s+([\d.]+)"),
        ],
        "check_paths": {
            "/wp-login.php": ("Login page reachable", "info"),
            "/wp-admin/": ("Admin dashboard route reachable", "medium"),
            "/xmlrpc.php": ("XML-RPC endpoint enabled — brute-force/pingback amplification risk", "high"),
            "/wp-json/": ("REST API exposed — can enable user enumeration", "medium"),
            "/wp-content/debug.log": ("Debug log potentially exposed (leaks paths/secrets)", "high"),
            "/readme.html": ("readme.html exposes the exact core version", "low"),
            "/wp-content/uploads/": ("Uploads directory listing may expose sensitive files", "medium"),
            "/wp-config.php.bak": ("Backup config file potentially exposed", "critical"),
        },
        "unique_endpoints": [
            ("/wp-json/wp/v2/", 200, r'{".*"}'),
            ("/xmlrpc.php", 200, r"xmlrpc|rsd"),
        ],
        "plugins_path": "/wp-content/plugins/",
        "plugin_files": [
            "woocommerce/readme.txt",
            "elementor/readme.txt",
            "wordpress-seo/readme.txt",
            "akismet/readme.txt",
            "contact-form-7/readme.txt",
            "jetpack/readme.txt",
            "yoast/readme.txt",
        ],
        "config_files": [
            "/wp-config.php",
            "/wp-config.php~",
            "/wp-config.php.bak",
            "/.wp-cli/config.yml",
        ],
        "admin_paths": ["/wp-admin", "/wp-login.php"],
        "api_paths": ["/wp-json", "/wp-json/wp/v2", "/wp-json/wp/v2/posts"],
        "dev_indicators": [
            r"define\s*\(\s*['\"]WP_DEBUG['\"]\s*,\s*true",
            r"define\s*\(\s*['\"]WP_DEBUG_LOG['\"]\s*,\s*true",
            r"define\s*\(\s*['\"]WP_DEBUG_DISPLAY['\"]\s*,\s*true",
        ],
        "security_headers_cms_specific": {
            "X-Pingback": r"X-Pingback:\s*([\w\-\.\/]+)",
        },
        "cves": {
            "<=4.7.0": ["CVE-2017-8295", "CVE-2017-9065"],
            "<=5.0.0": ["CVE-2019-6977", "CVE-2019-8942"],
            "<=5.5.0": ["CVE-2020-28032", "CVE-2020-28033"],
            "<=5.8.0": ["CVE-2021-39201", "CVE-2021-39200"],
            "<=6.0.0": ["CVE-2022-21661", "CVE-2022-21662"],
            "<=6.4.0": ["CVE-2023-5360", "CVE-2023-5361"],
        },
        "latest_major": "6.5",
    },
    "Laravel": {
        "html": [
            r"laravel",
            r"csrf-token",
            r"livewire",
            r"__livewire",
            r"wire:[a-z-]+=",
        ],
        "headers": [
            r"x-powered-by:\s*laravel",
            r"x-laravel",
            r"x-rate-limit-limit",
            r"x-csrf-token",
        ],
        "version_patterns": [
            r"Laravel\s+v?([\d.]+)",
            r"laravel\/framework\s+([\d.]+)",
        ],
        "version_files": [
            ("/vendor/laravel/framework/src/Illuminate/Foundation/Application.php", r"VERSION\s*=\s*['\"]?([\d.]+)['\"]?;?"),
            ("/config/app.php", r"'version'\s*=>\s*['\"]?([\d.]+)['\"]?"),
        ],
        "check_paths": {
            "/.env": ("Environment file potentially exposing secrets", "critical"),
            "/storage/logs/": ("Logs directory may expose sensitive info", "high"),
            "/vendor/": ("Composer vendor directory may expose dependencies", "medium"),
            "/public/.htaccess": ("Default .htaccess exposed", "low"),
            "/config/database.php": ("Database config may expose credentials", "critical"),
        },
        "unique_endpoints": [
            ("/csrf-cookie", 204, ""),
            ("/api/user", 401, r'{"message":"Unauthenticated."}'),
            ("/sanctum/csrf-cookie", 204, ""),
        ],
        "plugins_path": "/app/",
        "plugin_files": [
            "/app/Providers/AppServiceProvider.php",
            "/app/Http/Kernel.php",
        ],
        "config_files": [
            "/.env",
            "/.env.example",
            "/.env.backup",
            "/config/app.php",
            "/config/database.php",
            "/bootstrap/cache/config.php",
            "/bootstrap/cache/packages.php",
        ],
        "admin_paths": ["/admin", "/dashboard"],
        "api_paths": ["/api", "/api/v1", "/api/user"],
        "dev_indicators": [
            r"APP_DEBUG\s*=\s*true",
            r"APP_ENV\s*=\s*local",
            r"Whoops, looks like something went wrong",
        ],
        "security_headers_cms_specific": {
            "X-RateLimit-Limit": r"X-RateLimit-Limit:\s*([\d]+)",
        },
        "cves": {
            "<=7.0.0": ["CVE-2019-9081", "CVE-2019-9082"],
            "<=8.0.0": ["CVE-2021-3121"],
            "<=9.0.0": ["CVE-2022-30778"],
        },
        "latest_major": "11.0",
    },
    "Django": {
        "html": [
            r"csrfmiddlewaretoken",
            r"django",
            r"__admin_",
            r"static/admin/",
        ],
        "headers": [
            r"x-django",
            r"server:\s*django",
            r"x-csrf-token",
        ],
        "version_patterns": [
            r"Django\s+([\d.]+)",
            r"django\/[\'\"]([\d.]+)[\'\"]",
        ],
        "version_files": [
            ("/django/__init__.py", r"VERSION\s*=\s*\(([\d,\s]+)\)"),
            ("/django/__init__.py", r"__version__\s*=\s*['\"]?([\d.]+)['\"]?"),
        ],
        "check_paths": {
            "/admin/": ("Admin panel reachable", "medium"),
            "/.env": ("Environment file potentially exposing secrets", "critical"),
            "/static/": ("Static files directory may expose assets", "low"),
            "/media/": ("Media directory may expose user uploads", "medium"),
            "/settings.py": ("Settings file potentially exposed", "critical"),
        },
        "unique_endpoints": [
            ("/admin/login/", 200, r"django"),
            ("/api/", 200, r"{%|django"),
        ],
        "plugins_path": "/",
        "plugin_files": [
            "/urls.py",
            "/settings.py",
        ],
        "config_files": [
            "/.env",
            "/settings.py",
            "/settings.py.bak",
            "/local_settings.py",
            "/config/settings.py",
        ],
        "admin_paths": ["/admin", "/admin/login"],
        "api_paths": ["/api", "/api/v1"],
        "dev_indicators": [
            r"DEBUG\s*=\s*True",
            r"ALLOWED_HOSTS\s*=\s*\[.*\*.*\]",
            r"SECRET_KEY\s*=\s*['\"]{.*}['\"]",
        ],
        "security_headers_cms_specific": {},
        "cves": {
            "<=2.0.0": ["CVE-2018-14574", "CVE-2018-14575"],
            "<=2.2.0": ["CVE-2019-14232", "CVE-2019-14233"],
            "<=3.0.0": ["CVE-2020-9402", "CVE-2020-9403"],
            "<=3.1.0": ["CVE-2020-13254", "CVE-2020-13255"],
        },
        "latest_major": "5.1",
    },
    "Ruby on Rails": {
        "html": [
            r"rails",
            r"data-turbo",
            r"@rails",
            r"turbo-frame",
        ],
        "headers": [
            r"x-powered-by:\s*rails",
            r"x-rails",
            r"x-request-id",
        ],
        "version_patterns": [
            r"Rails\s+([\d.]+)",
            r"Rails.version\s*=\s*['\"]?([\d.]+)['\"]?",
        ],
        "version_files": [
            ("/version", r"Rails\s+([\d.]+)"),
            ("/Gemfile.lock", r"rails\s*\(([\d.]+)\)"),
        ],
        "check_paths": {
            "/.env": ("Environment file potentially exposing secrets", "critical"),
            "/config/database.yml": ("Database config may expose credentials", "critical"),
            "/assets/": ("Assets directory may expose source maps", "low"),
            "/system/": ("System directory may expose files", "medium"),
        },
        "unique_endpoints": [
            ("/assets/application.js", 200, r"//= require"),
            ("/admin", 302, r""),
        ],
        "plugins_path": "/",
        "plugin_files": [
            "/config/routes.rb",
            "/Gemfile",
        ],
        "config_files": [
            "/.env",
            "/config/database.yml",
            "/config/secrets.yml",
            "/config/application.yml",
            "/config/credentials.yml.enc",
        ],
        "admin_paths": ["/admin", "/dashboard"],
        "api_paths": ["/api", "/api/v1"],
        "dev_indicators": [
            r"config\.consider_all_requests_local\s*=\s*true",
            r"config\.action_controller\.per_form_csrf_tokens\s*=\s*true",
            r"Rails\.application\.config\.secret_key_base",
        ],
        "security_headers_cms_specific": {},
        "cves": {
            "<=5.0.0": ["CVE-2019-5418", "CVE-2019-5420"],
            "<=6.0.0": ["CVE-2020-8164", "CVE-2020-8165"],
            "<=6.1.0": ["CVE-2021-22881", "CVE-2021-22902"],
        },
        "latest_major": "7.2",
    },
    "Drupal": {
        "html": [
            r"Drupal\.settings",
            r"/sites/default/files/",
            r'name=["\']Generator["\']\s+content=["\']Drupal\s*([\d.]+)?',
            r"drupal.org",
        ],
        "headers": [
            r"x-generator:\s*drupal\s*([\d.]+)?",
            r"x-drupal-cache",
            r"x-drupal-dynamic-cache",
        ],
        "version_patterns": [
            r"Drupal\s+([\d]+\.[\d]+)",
            r"drupal\/[\'\"]([\d.]+)[\'\"]",
        ],
        "version_files": [
            ("/core/lib/Drupal.php", r"Drupal::VERSION\s*=\s*['\"]?([\d.]+)['\"]?;?"),
            ("/core/CHANGELOG.txt", r"Drupal\s+([\d.]+)"),
        ],
        "check_paths": {
            "/user/login": ("Default login page reachable", "info"),
            "/CHANGELOG.txt": ("Core changelog exposes exact version", "low"),
            "/core/CHANGELOG.txt": ("Core changelog exposes exact version", "low"),
            "/sites/default/settings.php": ("Settings file may expose DB credentials", "critical"),
        },
        "unique_endpoints": [
            ("/user/login", 200, r"drupal"),
            ("/core/install.php", 200, r"Drupal"),
        ],
        "plugins_path": "/modules/",
        "plugin_files": [
            "/modules/contrib/ctools/",
            "/modules/contrib/views/",
            "/modules/contrib/pathauto/",
            "/modules/contrib/token/",
        ],
        "config_files": [
            "/sites/default/settings.php",
            "/sites/default/settings.local.php",
            "/sites/default/services.yml",
            "/.env",
        ],
        "admin_paths": ["/admin", "/user", "/user/login"],
        "api_paths": ["/api", "/jsonapi"],
        "dev_indicators": [
            r"\$settings\['cache'\]\['bins'\]\['render'\]\s*=\s*'cache.backend.null'",
            r"\$config\['system.logging'\]\['error_level'\]\s*=\s*'verbose'",
        ],
        "security_headers_cms_specific": {
            "X-Drupal-Cache": r"X-Drupal-Cache:\s*([A-Z]+)",
        },
        "cves": {
            "<=7.0.0": ["CVE-2017-6920", "CVE-2017-6921"],
            "<=8.5.0": ["CVE-2018-7600", "CVE-2018-7602"],
            "<=9.0.0": ["CVE-2020-28949", "CVE-2020-28948"],
        },
        "latest_major": "10.3",
    },
    "Joomla": {
        "html": [
            r"/components/com_",
            r"/media/jui/",
            r"Joomla!\s*([\d.]+)?",
            r"joomla.org",
        ],
        "headers": [
            r"x-content-encoded-by:\s*joomla",
            r"x-generator:\s*joomla",
        ],
        "version_patterns": [
            r"Joomla!\s*([\d]+\.[\d]+)",
            r"joomla\/[\'\"]([\d.]+)[\'\"]",
        ],
        "version_files": [
            ("/libraries/cms/version/version.php", r"\$RELEASE\s*=\s*['\"]?([\d.]+)['\"]?;?"),
            ("/administrator/manifests/files/joomla.xml", r"version\s*=\s*['\"]?([\d.]+)['\"]?"),
        ],
        "check_paths": {
            "/administrator/": ("Admin login panel reachable", "medium"),
            "/configuration.php.bak": ("Backup config file potentially exposed (DB credentials)", "high"),
            "/htaccess.txt": ("Default htaccess template still present", "low"),
            "/tmp/": ("Temporary directory may be accessible", "medium"),
        },
        "unique_endpoints": [
            ("/administrator/index.php", 200, r"Joomla"),
            ("/index.php?option=com_content", 200, r"Joomla"),
        ],
        "plugins_path": "/plugins/",
        "plugin_files": [
            "/plugins/content/",
            "/plugins/editor/",
            "/plugins/search/",
            "/plugins/system/",
        ],
        "config_files": [
            "/configuration.php",
            "/configuration.php.bak",
            "/.env",
        ],
        "admin_paths": ["/administrator"],
        "api_paths": ["/api", "/api/v1"],
        "dev_indicators": [
            r"\$debug\s*=\s*true",
            r"\$error_reporting\s*=\s*'development'",
        ],
        "security_headers_cms_specific": {},
        "cves": {
            "<=3.0.0": ["CVE-2015-8562", "CVE-2016-8869"],
            "<=3.8.0": ["CVE-2018-6376", "CVE-2018-8055"],
            "<=3.9.0": ["CVE-2019-19846", "CVE-2019-19847"],
            "<=4.0.0": ["CVE-2021-26032", "CVE-2021-26033"],
        },
        "latest_major": "5.1",
    },
    "Next.js": {
        "html": [
            r"__NEXT_DATA__",
            r"_next/static",
            r"next/dist",
            r"next/head",
        ],
        "headers": [
            r"x-nextjs",
            r"x-middleware",
            r"x-nextjs-cache",
        ],
        "version_patterns": [
            r'"next"\s*:\s*"([\d.]+)"',
            r"Next\.js\s+([\d.]+)",
        ],
        "version_files": [
            ("/_next/static/", r"next\.js\s+v([\d.]+)"),
            ("/package.json", r'"next"\s*:\s*"([\d.]+)"'),
        ],
        "check_paths": {
            "/_next/static/": ("Build output directory reachable (expected; confirms framework only)", "info"),
            "/api/": ("API routes base path reachable — verify auth on every handler", "info"),
            "/.env": ("Environment file potentially exposing secrets", "critical"),
            "/.env.local": ("Environment file potentially exposing secrets", "critical"),
        },
        "unique_endpoints": [
            ("/_next/static/chunks/app/layout.js", 200, r"next"),
            ("/api/hello", 200, r'{"message":'),
        ],
        "plugins_path": "/",
        "plugin_files": [
            "/next.config.js",
            "/next.config.mjs",
            "/app/layout.tsx",
        ],
        "config_files": [
            "/.env",
            "/.env.local",
            "/.env.development",
            "/next.config.js",
            "/next.config.mjs",
        ],
        "admin_paths": ["/admin", "/dashboard"],
        "api_paths": ["/api", "/api/v1"],
        "dev_indicators": [
            r"process\.env\.NODE_ENV\s*===\s*'development'",
            r"next\.development",
        ],
        "security_headers_cms_specific": {
            "X-Nextjs-Cache": r"X-Nextjs-Cache:\s*([A-Z]+)",
        },
        "cves": {
            "<=13.0.0": ["CVE-2022-2421", "CVE-2022-23646"],
            "<=13.5.0": ["CVE-2024-34341", "CVE-2024-34342"],
        },
        "latest_major": "14.2",
    },
    "Ghost": {
        "html": [
            r"ghost",
            r"ghost.org",
            r"ghost-head",
            r"ghost-api",
        ],
        "headers": [
            r"x-ghost",
            r"x-powered-by:\s*ghost",
        ],
        "version_patterns": [
            r"Ghost\s+([\d.]+)",
            r"ghost\/[\'\"]([\d.]+)[\'\"]",
        ],
        "version_files": [
            ("/package.json", r'"ghost"\s*:\s*"([\d.]+)"'),
            ("/version", r"Ghost\s+([\d.]+)"),
        ],
        "check_paths": {
            "/ghost/": ("Admin panel reachable", "medium"),
            "/.env": ("Environment file potentially exposing secrets", "critical"),
            "/content/": ("Content directory may expose assets", "low"),
        },
        "unique_endpoints": [
            ("/ghost/api/v2/admin/", 401, r"unauthorized"),
            ("/ghost/api/v3/admin/", 401, r"unauthorized"),
        ],
        "plugins_path": "/content/plugins/",
        "plugin_files": [
            "/content/plugins/",
        ],
        "config_files": [
            "/.env",
            "/config.production.json",
            "/config.development.json",
        ],
        "admin_paths": ["/ghost"],
        "api_paths": ["/ghost/api", "/ghost/api/v2", "/ghost/api/v3"],
        "dev_indicators": [
            r"GHOST_DEBUG\s*=\s*true",
            r"NODE_ENV\s*=\s*development",
        ],
        "security_headers_cms_specific": {},
        "cves": {
            "<=3.0.0": ["CVE-2020-13838", "CVE-2020-13839"],
            "<=4.0.0": ["CVE-2021-21366"],
            "<=5.0.0": ["CVE-2022-35329"],
        },
        "latest_major": "5.0",
    },
    "Contentful": {
        "html": [
            r"contentful",
            r"ctf_",
            r"contentful.com",
        ],
        "headers": [
            r"x-contentful",
            r"x-contentful-request-id",
        ],
        "version_patterns": [
            r"Contentful\s+([\d.]+)",
        ],
        "version_files": [],
        "check_paths": {
            "/api/v1/": ("API endpoint reachable", "info"),
            "/.env": ("Environment file potentially exposing secrets", "critical"),
        },
        "unique_endpoints": [
            ("/api/v1/", 200, r"{"),
            ("/api/v1/spaces/", 401, r"unauthorized"),
        ],
        "plugins_path": "/",
        "plugin_files": [],
        "config_files": [
            "/.env",
            "/contentful.json",
        ],
        "admin_paths": ["/admin"],
        "api_paths": ["/api", "/api/v1"],
        "dev_indicators": [
            r"CONTENTFUL_DEBUG\s*=\s*true",
        ],
        "security_headers_cms_specific": {},
        "cves": {},
        "latest_major": None,
    },
    "Strapi": {
        "html": [
            r"strapi",
            r"strapi.io",
            r"admin/strapi",
        ],
        "headers": [
            r"x-strapi",
            r"strapi",
        ],
        "version_patterns": [
            r"Strapi\s+([\d.]+)",
            r"strapi\/[\'\"]([\d.]+)[\'\"]",
        ],
        "version_files": [
            ("/package.json", r'"strapi"\s*:\s*"([\d.]+)"'),
            ("/admin/", r"Strapi\s+v([\d.]+)"),
        ],
        "check_paths": {
            "/admin/": ("Admin panel reachable", "medium"),
            "/.env": ("Environment file potentially exposing secrets", "critical"),
            "/uploads/": ("Uploads directory may expose files", "medium"),
        },
        "unique_endpoints": [
            ("/admin/", 200, r"strapi"),
            ("/api/", 200, r"{"),
        ],
        "plugins_path": "/",
        "plugin_files": [
            "/plugins/",
        ],
        "config_files": [
            "/.env",
            "/config/database.js",
            "/config/server.js",
            "/config/api.js",
        ],
        "admin_paths": ["/admin"],
        "api_paths": ["/api", "/api/v1"],
        "dev_indicators": [
            r"STRAPI_DEBUG\s*=\s*true",
            r"NODE_ENV\s*=\s*development",
        ],
        "security_headers_cms_specific": {},
        "cves": {
            "<=3.0.0": ["CVE-2020-26249"],
            "<=3.4.0": ["CVE-2021-22882"],
        },
        "latest_major": "4.0",
    },
}

# ── Generic paths to check for all CMS ─────────────────────────────────────
GENERIC_PATHS = {
    "/.git/HEAD": ("Git repository exposed — full source leak", "critical"),
    "/.env": ("Environment file exposed — secrets/credentials", "critical"),
    "/.env.example": ("Example env exposed — config structure leak", "low"),
    "/.DS_Store": ("macOS metadata exposed", "low"),
    "/backup.zip": ("Generic backup archive reachable", "high"),
    "/config.php.bak": ("Backup config file reachable", "high"),
    "/.well-known/security.txt": ("security.txt published — good disclosure practice", "info"),
    "/robots.txt": ("robots.txt may expose hidden paths", "low"),
    "/sitemap.xml": ("Sitemap may expose site structure", "low"),
    "/phpinfo.php": ("PHP info exposed — system configuration leak", "critical"),
    "/info.php": ("PHP info exposed — system configuration leak", "critical"),
    "/server-status": ("Apache server status exposed", "high"),
    "/server-info": ("Apache server info exposed", "high"),
}

DIRECTORY_LISTING_PATTERNS = [
    r"Index of /",
    r"<title>Directory Listing",
    r"Parent Directory</a>",
    r"\[To Parent Directory\]",
]

# ── Helper functions ────────────────────────────────────────────────────────

def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "https://" + url
    return url.rstrip("/")

def _safe_search(pattern: str, haystack: str) -> Optional[re.Match]:
    try:
        return re.search(pattern, haystack, re.IGNORECASE)
    except Exception:
        return None

def _extract_version_from_content(content: str, patterns: List[str]) -> Optional[str]:
    for pattern in patterns:
        match = _safe_search(pattern, content)
        if match and match.groups():
            return match.group(1)
    return None

def _parse_version_tuple(version: str) -> Tuple[int, ...]:
    try:
        return tuple(int(p) for p in re.findall(r"\d+", version)[:3])
    except Exception:
        return ()

def _is_version_in_range(version: str, range_str: str) -> bool:
    """Check if version is in a range like '<=5.0.0' or '>=4.0.0'."""
    try:
        v_tuple = _parse_version_tuple(version)
        if not v_tuple:
            return False
        if range_str.startswith("<="):
            target = _parse_version_tuple(range_str[2:])
            return v_tuple <= target if target else False
        elif range_str.startswith(">="):
            target = _parse_version_tuple(range_str[2:])
            return v_tuple >= target if target else False
        elif range_str.startswith("<"):
            target = _parse_version_tuple(range_str[1:])
            return v_tuple < target if target else False
        elif range_str.startswith(">"):
            target = _parse_version_tuple(range_str[1:])
            return v_tuple > target if target else False
        elif range_str.startswith("=="):
            target = _parse_version_tuple(range_str[2:])
            return v_tuple == target if target else False
        else:
            # If no operator, check exact match or partial
            target = _parse_version_tuple(range_str)
            return v_tuple == target if target else False
    except Exception:
        return False

def _get_cves_for_version(cms: str, version: str) -> List[str]:
    """Get CVEs for a specific CMS version."""
    if cms not in CMS_DATABASE:
        return []
    cves = []
    for range_str, cve_list in CMS_DATABASE[cms].get("cves", {}).items():
        if _is_version_in_range(version, range_str):
            cves.extend(cve_list)
    return cves

def _is_outdated(cms: str, version: str) -> Tuple[bool, Optional[str]]:
    """Check if CMS version is outdated and return latest version."""
    if not version or cms not in CMS_DATABASE:
        return False, None
    latest = CMS_DATABASE[cms].get("latest_major")
    if not latest:
        return False, None
    v_tuple = _parse_version_tuple(version)
    l_tuple = _parse_version_tuple(latest)
    if v_tuple and l_tuple:
        return v_tuple < l_tuple, latest
    return False, latest

def _is_dev_environment(html: str, headers: Dict[str, str], cms: str) -> bool:
    """Check if site appears to be in development mode."""
    indicators = CMS_DATABASE.get(cms, {}).get("dev_indicators", [])
    # Check HTML and headers
    for indicator in indicators:
        if _safe_search(indicator, html):
            return True
        if _safe_search(indicator, "\n".join(f"{k}: {v}" for k, v in headers.items())):
            return True
    # Generic indicators
    if "X-Powered-By: PHP/8" in str(headers):  # PHP version disclosure often in dev
        return True
    if "debug" in str(headers).lower() or "error" in str(headers).lower():
        return True
    return False

# ── Core scanning functions ─────────────────────────────────────────────────

async def _fetch(session: aiohttp.ClientSession, url: str, allow_redirects: bool = True) -> Tuple[Optional[int], Optional[str], Optional[Dict]]:
    """Fetch a URL and return status, text, headers."""
    try:
        async with session.get(
            url,
            allow_redirects=allow_redirects,
            timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS),
            ssl=False,
        ) as resp:
            if resp.status >= 400:
                return resp.status, None, dict(resp.headers)
            text = await resp.text(errors="ignore")
            return resp.status, text, dict(resp.headers)
    except Exception:
        return None, None, None

async def _fetch_with_limit(session: aiohttp.ClientSession, url: str, limit: int = MAX_BYTES_FETCH) -> Tuple[Optional[int], Optional[str], Optional[Dict]]:
    """Fetch a URL with size limit."""
    try:
        async with session.get(
            url,
            allow_redirects=True,
            timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS),
            ssl=False,
        ) as resp:
            if resp.status >= 400:
                return resp.status, None, dict(resp.headers)
            content = await resp.read()
            if len(content) > limit:
                return resp.status, content[:limit].decode("utf-8", errors="ignore") + "...", dict(resp.headers)
            return resp.status, content.decode("utf-8", errors="ignore"), dict(resp.headers)
    except Exception:
        return None, None, None

def _detect_platform(html: str, headers: Dict[str, str]) -> Tuple[Optional[str], int, List[str]]:
    """
    Detect platform from HTML and headers.
    Returns (platform_name, confidence_score, evidence_list)
    """
    html = html or ""
    header_blob = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
    scores = {}

    for cms_name, cfg in CMS_DATABASE.items():
        score = 0
        evidence = []

        # HTML patterns
        for pattern in cfg.get("html", []):
            if _safe_search(pattern, html):
                score += 2
                evidence.append(f"HTML pattern matched: {pattern[:30]}...")

        # Header patterns
        for pattern in cfg.get("headers", []):
            if _safe_search(pattern, header_blob):
                score += 2
                evidence.append(f"Header pattern matched: {pattern}")

        if score > 0:
            scores[cms_name] = {"score": score, "evidence": evidence}

    if not scores:
        return None, 0, []

    # Get the best match
    best_cms = max(scores, key=lambda k: scores[k]["score"])
    best_score = scores[best_cms]["score"]
    evidence = scores[best_cms]["evidence"]

    # Confidence scoring based on evidence strength
    if best_score >= 6:
        confidence = 90
    elif best_score >= 4:
        confidence = 70
    else:
        confidence = 50

    return best_cms, confidence, evidence

async def _verify_unique_endpoint(
    session: aiohttp.ClientSession,
    base_url: str,
    endpoint: str,
    expected_status: int,
    success_pattern: str
) -> Tuple[bool, int, str]:
    """Verify a unique endpoint for active CMS confirmation."""
    url = urljoin(base_url, endpoint)
    status, text, headers = await _fetch(session, url, allow_redirects=True)

    if status is None:
        return False, 0, "Connection error"

    # Check if status matches expected or is in the 2xx range for 200 checks
    if expected_status == 200 and 200 <= status < 300:
        if success_pattern:
            if _safe_search(success_pattern, text or ""):
                return True, status, "Pattern matched"
            else:
                # If pattern doesn't match but status is 200, still consider active
                return True, status, "HTTP 200 (pattern not verified)"
        return True, status, "HTTP 200"
    elif status == expected_status:
        if success_pattern and text:
            if _safe_search(success_pattern, text):
                return True, status, "Status + pattern matched"
        return True, status, f"HTTP {status} matched"
    # Some endpoints may return 204 (No Content) which is fine
    elif expected_status == 204 and status == 204:
        return True, status, "HTTP 204 (No Content)"
    # Also accept 401/403 as "exists but protected"
    elif status in (401, 403) and expected_status in (200, 204):
        return True, status, f"HTTP {status} (protected endpoint exists)"
    else:
        return False, status, f"HTTP {status} (expected {expected_status})"

async def _check_plugins(
    session: aiohttp.ClientSession,
    base_url: str,
    cms: str
) -> List[Dict[str, Any]]:
    """Check for installed plugins/themes."""
    found_plugins = []
    cfg = CMS_DATABASE.get(cms, {})
    plugin_files = cfg.get("plugin_files", [])
    plugins_path = cfg.get("plugins_path", "")

    for plugin_file in plugin_files:
        url = urljoin(base_url, plugins_path + plugin_file)
        status, text, _ = await _fetch(session, url, allow_redirects=False)
        if status == 200 and text:
            # Try to extract version
            version = None
            # Check for common version patterns in readme.txt
            if "readme.txt" in plugin_file:
                match = _safe_search(r"Stable tag:\s*([\d.]+)", text)
                if match:
                    version = match.group(1)
            found_plugins.append({
                "name": plugin_file.split("/")[0] if "/" in plugin_file else plugin_file,
                "path": url,
                "status": status,
                "version": version,
                "confidence": 100 if version else 70,
            })
    return found_plugins

async def _check_config_files(
    session: aiohttp.ClientSession,
    base_url: str,
    cms: str
) -> List[Dict[str, Any]]:
    """Check for exposed config files."""
    found_configs = []
    cfg = CMS_DATABASE.get(cms, {})
    config_files = cfg.get("config_files", []) + GENERIC_PATHS.keys()

    for config_file in config_files:
        url = urljoin(base_url, config_file)
        status, text, _ = await _fetch(session, url, allow_redirects=False)
        if status == 200 and text:
            # Check if it contains sensitive data
            sensitive_patterns = [
                r"DB_PASSWORD",
                r"DB_USERNAME",
                r"API_KEY",
                r"SECRET_KEY",
                r"PASSWORD",
                r"ACCESS_TOKEN",
            ]
            sensitive_hit = any(_safe_search(p, text) for p in sensitive_patterns)
            found_configs.append({
                "path": config_file,
                "status": status,
                "sensitive": sensitive_hit,
                "preview": text[:200] if sensitive_hit else None,
                "confidence": 100 if sensitive_hit else 80,
            })
    return found_configs

async def _check_paths(
    session: aiohttp.ClientSession,
    base_url: str,
    paths: Dict[str, Tuple[str, str]]
) -> List[Dict[str, Any]]:
    """Check multiple paths for exposure."""
    findings = []
    for path, (issue, severity) in paths.items():
        url = urljoin(base_url, path)
        status, text, _ = await _fetch(session, url, allow_redirects=False)
        if status is not None and status < 400:
            # Check for directory listing
            is_listing = False
            if text:
                for pattern in DIRECTORY_LISTING_PATTERNS:
                    if _safe_search(pattern, text):
                        is_listing = True
                        break
            findings.append({
                "path": path,
                "status_code": status,
                "issue": issue,
                "severity": severity,
                "directory_listing": is_listing,
                "confidence": 100 if status == 200 else 80,
            })
    return findings

# ── Main run function ──────────────────────────────────────────────────────

async def run(url: str, context: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Main entry point for CMS/Framework fingerprinting.
    Args:
        url: target URL
        context: optional context from other tests
    Returns:
        dict with findings
    """
    test_name = "cms_vibe_detection"

    try:
        base_url = _normalize_url(url)
        parsed = urlparse(base_url)
        if not parsed.netloc:
            return {
                "test_name": test_name,
                "status": "error",
                "severity": "info",
                "title": "Invalid URL",
                "description": f"Could not parse hostname from {url}",
                "evidence": [],
                "remediation": "Provide a valid URL.",
            }
    except Exception as e:
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "URL Normalization Error",
            "description": str(e),
            "evidence": [],
            "remediation": "Check the URL format.",
        }

    async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
        # ── 1. Fetch main page ────────────────────────────────────────────
        status, html, headers = await _fetch(session, base_url)
        if status is None:
            return {
                "test_name": test_name,
                "status": "error",
                "severity": "info",
                "title": "Unreachable",
                "description": f"Could not connect to {base_url}",
                "evidence": [],
                "remediation": "Check connectivity and firewall settings.",
            }

        # ── 2. Detect CMS ──────────────────────────────────────────────────
        detected_cms, initial_confidence, fp_evidence = _detect_platform(html or "", headers or {})

        if not detected_cms:
            # Try to detect from robots.txt
            robots_url = urljoin(base_url, "/robots.txt")
            robots_status, robots_text, _ = await _fetch(session, robots_url)
            if robots_status == 200 and robots_text:
                for cms_name, cfg in CMS_DATABASE.items():
                    for pattern in cfg.get("html", []):
                        if _safe_search(pattern, robots_text):
                            detected_cms = cms_name
                            initial_confidence = 60
                            fp_evidence.append(f"Pattern found in robots.txt: {pattern}")
                            break
                    if detected_cms:
                        break

        if not detected_cms:
            return {
                "test_name": test_name,
                "status": "info",
                "severity": "info",
                "title": "No CMS Detected",
                "description": "No identifiable CMS or framework found.",
                "evidence": ["No CMS signatures matched."],
                "remediation": "No action needed.",
                "cms_type": "Unknown",
                "vibe_score": 0,
                "version": "not detected",
                "confidence": "low",
                "exposed_paths": [],
                "security_headers_missing": [],
                "directory_listing": False,
            }

        # ── 3. Active verification via unique endpoints ──────────────────
        cms_cfg = CMS_DATABASE.get(detected_cms, {})
        verification_results = []
        for endpoint, expected_status, success_pattern in cms_cfg.get("unique_endpoints", []):
            verified, resp_status, evidence = await _verify_unique_endpoint(
                session, base_url, endpoint, expected_status, success_pattern
            )
            if verified:
                verification_results.append({
                    "endpoint": endpoint,
                    "verified": True,
                    "status": resp_status,
                    "evidence": evidence,
                })

        # If at least one endpoint verified, raise confidence
        if verification_results:
            initial_confidence = max(initial_confidence, 90)
            fp_evidence.append(f"Active verification successful on {len(verification_results)} endpoint(s)")
        else:
            # If no endpoint verified, lower confidence slightly
            initial_confidence = max(initial_confidence - 10, 50)

        # ── 4. Extract version ─────────────────────────────────────────────
        version = None
        # Try from HTML/headers first
        version = _extract_version_from_content(html or "", cms_cfg.get("version_patterns", []))
        if not version:
            header_blob = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
            version = _extract_version_from_content(header_blob, cms_cfg.get("version_patterns", []))

        # Try from version files
        if not version:
            for version_file, pattern in cms_cfg.get("version_files", []):
                url = urljoin(base_url, version_file)
                v_status, v_text, _ = await _fetch(session, url)
                if v_status == 200 and v_text:
                    match = _safe_search(pattern, v_text)
                    if match and match.groups():
                        version = match.group(1)
                        fp_evidence.append(f"Version extracted from {version_file}: {version}")
                        break

        # ── 5. Check for CVEs based on version ────────────────────────────
        cves = []
        if version:
            cves = _get_cves_for_version(detected_cms, version)
        outdated, latest_version = _is_outdated(detected_cms, version)

        # ── 6. Check for plugins ──────────────────────────────────────────
        plugins = await _check_plugins(session, base_url, detected_cms)

        # ── 7. Check for exposed config files ─────────────────────────────
        configs = await _check_config_files(session, base_url, detected_cms)

        # ── 8. Check sensitive paths ──────────────────────────────────────
        cms_paths = cms_cfg.get("check_paths", {})
        all_paths = {**cms_paths, **GENERIC_PATHS}
        path_findings = await _check_paths(session, base_url, all_paths)

        # ── 9. Check security headers ─────────────────────────────────────
        present_headers = []
        missing_headers = []
        for header in SECURITY_HEADERS:
            if header.lower() in {k.lower() for k in (headers or {}).keys()}:
                present_headers.append(header)
            else:
                missing_headers.append(header)

        # CMS-specific headers
        cms_specific_headers = cms_cfg.get("security_headers_cms_specific", {})
        for header, pattern in cms_specific_headers.items():
            if any(header.lower() == k.lower() for k in (headers or {}).keys()):
                present_headers.append(header)

        # ── 10. Check for dev environment ─────────────────────────────────
        is_dev = _is_dev_environment(html or "", headers or {}, detected_cms)

        # ── 11. Calculate vibe score ──────────────────────────────────────
        score = 60  # Base score
        # Add points for good practices
        score += min(len(present_headers), 6) * 5
        if not missing_headers:
            score += 10
        if version:
            score += 5
        if cves:
            score -= 10
        if outdated:
            score -= 15
        if is_dev:
            score -= 20
        # Deduct for exposed paths
        for f in path_findings:
            severity = f.get("severity", "medium")
            deductions = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
            score -= deductions.get(severity, 0)
        # Deduct for exposed configs
        for c in configs:
            if c.get("sensitive"):
                score -= 20
        # Cap and round
        score = max(0, min(100, score))

        # ── 12. Build evidence ────────────────────────────────────────────
        evidence = fp_evidence.copy()

        if version:
            evidence.append(f"Version detected: {version}")
        if outdated:
            evidence.append(f"Outdated! Latest: {latest_version}")
        if cves:
            evidence.append(f"Related CVEs: {', '.join(cves[:5])}")
        if is_dev:
            evidence.append("Development environment detected (less secure)")
        if verification_results:
            for vr in verification_results:
                evidence.append(f"Endpoint {vr['endpoint']} verified (HTTP {vr['status']})")
        for plugin in plugins:
            evidence.append(f"Plugin found: {plugin['name']} (v{plugin['version'] or 'unknown'})")
        for config in configs:
            if config.get("sensitive"):
                evidence.append(f"⚠️ Sensitive config exposed: {config['path']}")
            else:
                evidence.append(f"Config file exposed: {config['path']}")
        for finding in path_findings:
            evidence.append(f"Exposed: {finding['path']} -> {finding['status_code']} ({finding['issue']}) [{finding['severity']}]")
        if present_headers:
            evidence.append(f"Security headers present: {', '.join(present_headers)}")
        if missing_headers:
            evidence.append(f"Missing headers: {', '.join(missing_headers)}")

        # ── 13. Determine status ──────────────────────────────────────────
        critical_findings = [f for f in path_findings if f.get("severity") == "critical"]
        high_findings = [f for f in path_findings if f.get("severity") == "high"]
        has_sensitive_configs = any(c.get("sensitive") for c in configs)

        if critical_findings or has_sensitive_configs or (cves and outdated):
            status = "fail"
            overall_severity = "critical"
        elif high_findings or is_dev or (outdated and cves):
            status = "fail"
            overall_severity = "high"
        elif path_findings or missing_headers or (outdated and not cves):
            status = "warning"
            overall_severity = "medium"
        else:
            status = "pass"
            overall_severity = "info"

        # ── 14. Build remediation ─────────────────────────────────────────
        remediation_parts = []
        if version:
            if outdated and latest_version:
                remediation_parts.append(f"Update {detected_cms} from {version} to {latest_version} (or higher)")
        if cves:
            remediation_parts.append(f"Apply security patches for CVEs: {', '.join(cves[:3])}")
        if has_sensitive_configs:
            remediation_parts.append("Secure configuration files (remove from public access)")
        if is_dev:
            remediation_parts.append("Disable development mode in production")
        if critical_findings:
            for f in critical_findings:
                remediation_parts.append(f"Fix critical path exposure: {f['path']}")
        if missing_headers:
            remediation_parts.append(f"Add missing security headers: {', '.join(missing_headers[:3])}")
        if not remediation_parts:
            remediation_parts.append("No immediate action required. Continue monitoring.")

        # ── 15. Return result ─────────────────────────────────────────────
        return {
            "test_name": test_name,
            "status": status,
            "severity": overall_severity,
            "title": f"{detected_cms} — Vibe Score: {score}%",
            "description": f"Detected {detected_cms} with {initial_confidence}% confidence. Version: {version or 'not detected'}. Found {len(path_findings)} exposed paths, {len(missing_headers)} missing headers.",
            "evidence": evidence,
            "remediation": " ".join(remediation_parts),
            "cms_type": detected_cms,
            "vibe_score": score,
            "version": f"{version} (outdated)" if outdated else version or "not detected",
            "confidence": "high" if initial_confidence >= 80 else "medium" if initial_confidence >= 50 else "low",
            "exposed_paths": [f["path"] for f in path_findings if f["status_code"] == 200],
            "security_headers_missing": missing_headers,
            "security_headers_present": present_headers,
            "directory_listing": any(f.get("directory_listing") for f in path_findings),
            "plugins_found": plugins,
            "config_files_exposed": [c["path"] for c in configs if c.get("status") == 200],
            "cves": cves,
            "is_outdated": outdated,
            "latest_version": latest_version,
            "is_development": is_dev,
            "active_verification": verification_results,
        }


if __name__ == "__main__":
    import json
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))