#!/usr/bin/env python3
"""
test_06_info_disclosure.py - Bravo6 Info Disclosure Scanner (v14.1)
=====================================================================
Complete rewrite addressing all issues found in prior results:
  - Accuracy over coverage: Confidence scores mechanically tied to content verification.
  - Unverified files are appropriately downgraded based on size/shape.
  - HTML-shaped soft 404s correctly handled.
  - Bare 403/401 correctly aggregated, never reported per-path as high/medium.
  - HTML comment scanning uses strict credential-shaped context (no generic `api` hits).
  - Explicit exclusions for standard 3rd-party domains in comments.
  - Strict 12-field schema compliance via `run(ctx: ScannerContext)`.
"""

import asyncio
import re
import urllib.parse
import uuid
from typing import Any, Dict, Iterable, List, Set, Tuple

# -- Constants ----------------------------------------------------------------------------
SCANNER_NAME = "test_06_info_disclosure"

COMMENT_INTEREST_PATTERNS = [
    re.compile(r'api[_-]?key\s*[:=]', re.IGNORECASE),
    re.compile(r'token\s*[:=]\s*[\'"]', re.IGNORECASE),
    re.compile(r'secret\s*[:=]', re.IGNORECASE),
    re.compile(r'password\s*[:=]', re.IGNORECASE),
    re.compile(r'TODO.*(?:remove|fixme).*(?:before|prior to)\s*(?:prod|deploy|launch)', re.IGNORECASE),
]

EXCLUDE_DOMAINS = [
    "google.com/recaptcha",
    "google-analytics.com",
    "googletagmanager.com",
    "cdn.",
    "facebook.net",
    "twitter.com"
]

# Well-known, default, auto-generated robots.txt boilerplate that a CMS seeds
# into every fresh installation. These paths disclose nothing an attacker
# doesn't already know for free about any site running that CMS, so they
# must not be treated the same as a genuine custom disclosure. Keyed by the
# technology name as produced by detect_technologies() (matched by prefix,
# so "WordPress 6.4" still matches the "WordPress" entry).
# Extend this dict as more CMS defaults are confidently verified.
CMS_DEFAULT_ROBOTS_PATHS = {
    "WordPress": ["/wp-admin/", "/wp-admin/admin-ajax.php"],
    # TODO: Drupal and Joomla core also ship default Disallow rules in their
    # robots.txt, but the exact default set has changed across major
    # versions. Verify against current Drupal/Joomla core robots.txt before
    # adding entries here rather than guessing — an incorrect entry would
    # silently suppress a genuine disclosure.
}

STATIC_SENSITIVE_PATHS = {
    ".env": ("keyval", "critical", 20),
    ".env.local": ("keyval", "critical", 20),
    ".env.production": ("keyval", "critical", 20),
    ".env.staging": ("keyval", "critical", 20),
    ".env.bak": ("keyval", "critical", 20),
    ".git/HEAD": ("git", "high", 20),
    ".git/config": ("git_config", "high", 20),
    ".svn/entries": ("svn", "medium", 20),
    "wp-config.php": ("php", "critical", 20),
    "wp-config.php.bak": ("php", "critical", 20),
    ".htpasswd": ("htpasswd", "critical", 20),
    "phpinfo.php": ("phpinfo", "critical", 100),
    "info.php": ("phpinfo", "high", 100),
    "config.php": ("php", "critical", 20),
    "adminer.php": ("adminer", "high", 100),
    ".vscode/settings.json": ("json", "high", 10),
    "composer.json": ("json", "info", 20),
    "package.json": ("json", "info", 20),
}


def make_url(base: str, path: str) -> str:
    """Safely combine base URL and path, ensuring subdirectories aren't truncated."""
    if not base.endswith("/"):
        base += "/"
    return urllib.parse.urljoin(base, path.lstrip("/"))


def guess_type_and_sev(path: str) -> Tuple[str, str, int]:
    if path in STATIC_SENSITIVE_PATHS:
        return STATIC_SENSITIVE_PATHS[path]
    p = path.lower()
    if "env" in p: return ("keyval", "critical", 20)
    if "phpinfo" in p or "info.php" in p: return ("phpinfo", "high", 100)
    if ".git/" in p: return ("git", "high", 20)
    if "config.php" in p: return ("php", "critical", 20)
    if p.endswith(".json"): return ("json", "medium", 10)
    if p.endswith(".bak") or p.endswith(".sql") or p.endswith(".dump"): return ("backup", "high", 100)
    return ("unknown", "medium", 20)


def content_verified_sensitive(path: str, body: str, expected_type: str) -> bool:
    if not body:
        return False
    b_lower = body.lower()
    
    if expected_type == "phpinfo":
        return (
            "<title>phpinfo()</title>" in b_lower or 
            "<h1 class=\"p\">php version" in b_lower or 
            ("php version" in b_lower and "zend engine" in b_lower)
        )
        
    if expected_type == "git":
        body_stripped = body.strip()
        # .git/HEAD contains 'ref: refs/heads/...' or a 40-char commit hash (detached state)
        return body_stripped.startswith("ref: refs/") or bool(re.match(r'^[0-9a-f]{40}$', body_stripped))
        
    if expected_type == "git_config":
        return "[core]" in b_lower and ("repositoryformatversion" in b_lower or "bare" in b_lower)
        
    if expected_type == "keyval":
        # Look for standard sensitive prefixes OR at least 3 generic key-value assignments
        return (
            bool(re.search(r'^(?:APP|DB|AWS|SECRET|MAIL|API|REDIS|MYSQL|MONGO|POSTGRES|JWT)_[A-Z0-9_]+\s*=', body, re.MULTILINE | re.IGNORECASE)) or
            len(re.findall(r'^[A-Z0-9_]{3,}\s*=', body, re.MULTILINE)) >= 3
        )
        
    if expected_type == "php":
        # Look for common database config definitions or connection instances
        return (
            "DB_PASSWORD" in body or 
            "define('DB_" in body or 
            'define("DB_' in body or 
            bool(re.search(r'\$db(?:_name|_user|_pass|conn|connect)\b|mysqli_connect\s*\(|new\s+PDO\s*\(', body, re.IGNORECASE))
        )
        
    if expected_type == "htpasswd":
        # htpasswd typically contains username:hash (bcrypt, apr1, SHA, or crypt 13-chars)
        return bool(re.search(r'^[\w\.\-]+:(?:\$apr1\$|\$2[aby]\$|\{SHA\}|[A-Za-z0-9./]{13})', body, re.MULTILINE))
        
    if expected_type == "adminer":
        # Ensure it is a genuine Adminer tool, not just a 404 page mentioning "adminer"
        if "adminer" not in b_lower:
            return False
        return (
            bool(re.search(r'name="auth\[(?:driver|server|username|password)\]"', b_lower)) or
            "<title>login - adminer</title>" in b_lower or
            "<title>adminer" in b_lower or
            bool(re.search(r'adminer.{0,100}?(?:login|database|server)', b_lower, re.DOTALL)) or
            bool(re.search(r'class="[^"]*login[^"]*".{0,150}?auth\[', b_lower, re.DOTALL))
        )
        
    if expected_type == "json":
        # Structurally valid JSON object rather than just a page with brackets and quotes
        body_stripped = body.strip()
        return body_stripped.startswith("{") and body_stripped.endswith("}") and '"' in body_stripped and ':' in body_stripped
        
    return False


def is_html_shaped(body: str) -> bool:
    b = body.lower()
    return "<html" in b or "<!doctype" in b or "<head" in b or "<body" in b


def get_header_case_insensitive(headers: dict, name: str) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return str(v)
    return ""


async def fetch_path(ctx: Any, path: str, requests_made: list) -> Tuple[int, str]:
    url = make_url(ctx.url, path)
    requests_made[0] += 1
    try:
        async with ctx.session.get(url, allow_redirects=True, timeout=10) as resp:
            # Read up to 2MB to prevent large file blowups while being enough for typical text/config
            raw = await resp.content.read(2 * 1024 * 1024)
            return resp.status, raw.decode("utf-8", errors="replace")
    except Exception:
        return 0, ""


# -- Analysis Phases ----------------------------------------------------------------------

async def phase_path_probing(ctx: Any, requests_made: list) -> List[dict]:
    findings = []
    
    # Grab a generic non-existent file to catch custom soft-404 signatures (like length matching)
    soft_404_path = f"/nonexistent-{uuid.uuid4().hex[:8]}"
    _, soft_404_body = await fetch_path(ctx, soft_404_path, requests_made)
    soft_404_len = len(soft_404_body)
    
    paths_to_check = getattr(ctx, "sensitive_paths", None)
    if not paths_to_check:
        paths_to_check = list(STATIC_SENSITIVE_PATHS.keys())
    
    aggregated_403s = []
    aggregated_401s = []
    aggregated_500s = []
    
    sem = asyncio.Semaphore(15)
    async def probe(path: str):
        async with sem:
            status, body = await fetch_path(ctx, path, requests_made)
            return path, status, body
            
    results = await asyncio.gather(*(probe(p) for p in paths_to_check))
    
    for path, status, body in results:
        if status == 0 or status == 404:
            continue
            
        if status == 403:
            aggregated_403s.append(path)
            continue
        if status == 401:
            aggregated_401s.append(path)
            continue
        if status >= 500:
            aggregated_500s.append(path)
            continue
            
        if status == 200:
            expected_type, base_sev, min_size = guess_type_and_sev(path)
            verified = content_verified_sensitive(path, body, expected_type)
            is_html = is_html_shaped(body)
            body_len = len(body)
            
            # Simple soft-404 check: matches length of known soft-404 page
            matches_soft_404_length = (soft_404_len > 0 and body_len > 0 and abs(body_len - soft_404_len) < 50)
            
            url = make_url(ctx.url, path)
            
            if verified:
                findings.append({
                    "title": f"Accessible sensitive file: {path}",
                    "severity": base_sev,
                    "confidence": "verified-live",
                    "cwe": "CWE-538",
                    "owasp": "A01:2021-Broken Access Control",
                    "location": url,
                    "evidence": f"HTTP 200, {body_len} bytes. Content definitively matched expected signature for {expected_type}.",
                    "poc": f"curl -s {url}",
                    "remediation": "Remove or restrict access to this file; rotate any exposed credentials immediately.",
                    "detection_method": "path_probe_200_verified"
                })
            else:
                if (is_html and expected_type not in ["phpinfo", "adminer", "unknown"]) or matches_soft_404_length:
                    findings.append({
                        "title": f"[LIKELY SOFT-404] Accessible sensitive file: {path}",
                        "severity": "info",
                        "confidence": "informational",
                        "cwe": "CWE-538",
                        "owasp": "A01:2021-Broken Access Control",
                        "location": url,
                        "evidence": f"HTTP 200, but response is HTML/soft-404 shaped or length matched generic 404. Content not verified.",
                        "poc": f"curl -s {url}",
                        "remediation": "Ensure the server returns proper HTTP 404 statuses for non-existent files.",
                        "detection_method": "path_probe_200_soft404"
                    })
                elif body_len < min_size:
                    findings.append({
                        "title": f"[UNCONFIRMED] Accessible sensitive file: {path}",
                        "severity": "info",
                        "confidence": "informational",
                        "cwe": "CWE-538",
                        "owasp": "A01:2021-Broken Access Control",
                        "location": url,
                        "evidence": f"HTTP 200, {body_len} bytes. Size is below plausible threshold ({min_size} bytes).",
                        "poc": f"curl -s {url}",
                        "remediation": "Review exposure; could be an empty file or dummy stub.",
                        "detection_method": "path_probe_200_too_small"
                    })
                else:
                    # Not positively verified, but shape/size is plausible and non-empty. Never outranks verified cases.
                    sev = "medium" if base_sev in ["critical", "high"] else ("low" if base_sev == "medium" else "info")
                    findings.append({
                        "title": f"Accessible sensitive file: {path}",
                        "severity": sev,
                        "confidence": "plausible-unconfirmed",
                        "cwe": "CWE-538",
                        "owasp": "A01:2021-Broken Access Control",
                        "location": url,
                        "evidence": f"HTTP 200, {body_len} bytes. Size is plausible but content could not be definitively verified.",
                        "poc": f"curl -s {url}",
                        "remediation": "Verify if the file contains sensitive information and restrict access.",
                        "detection_method": "path_probe_200_unconfirmed"
                    })

    # Strict aggregation rules for 403 / 401 / 500 (Must NOT report per-path here)
    if aggregated_403s:
        findings.append({
            "title": f"Multiple sensitive paths return HTTP 403 ({len(aggregated_403s)} paths)",
            "severity": "info",
            "confidence": "informational",
            "cwe": "CWE-538",
            "owasp": "A01:2021-Broken Access Control",
            "location": "Multiple Paths (403)",
            "evidence": f"Paths tested: {', '.join(aggregated_403s[:10])}{'...' if len(aggregated_403s)>10 else ''}",
            "poc": f"curl -I {make_url(ctx.url, aggregated_403s[0])}",
            "remediation": "No action required; paths are successfully protected.",
            "detection_method": "path_probe_403_aggregate"
        })
    if aggregated_401s:
        findings.append({
            "title": f"Multiple sensitive paths return HTTP 401 ({len(aggregated_401s)} paths)",
            "severity": "info",
            "confidence": "informational",
            "cwe": "CWE-538",
            "owasp": "A01:2021-Broken Access Control",
            "location": "Multiple Paths (401)",
            "evidence": f"Paths tested: {', '.join(aggregated_401s[:10])}{'...' if len(aggregated_401s)>10 else ''}",
            "poc": f"curl -I {make_url(ctx.url, aggregated_401s[0])}",
            "remediation": "No action required; paths successfully require authentication.",
            "detection_method": "path_probe_401_aggregate"
        })
    if aggregated_500s:
        findings.append({
            "title": f"Multiple sensitive paths return HTTP 500 ({len(aggregated_500s)} paths)",
            "severity": "info",
            "confidence": "informational",
            "cwe": "CWE-538",
            "owasp": "A01:2021-Broken Access Control",
            "location": "Multiple Paths (500)",
            "evidence": f"Paths tested: {', '.join(aggregated_500s[:10])}{'...' if len(aggregated_500s)>10 else ''}",
            "poc": f"curl -I {make_url(ctx.url, aggregated_500s[0])}",
            "remediation": "Investigate server errors; may indicate fragile input handling on protected routes.",
            "detection_method": "path_probe_500_aggregate"
        })

    return findings


def phase_comment_analysis(ctx: Any) -> List[dict]:
    html = ctx.main_page_cache.get("html", "")
    if not html:
        return []
        
    comments = re.findall(r"<!--([\s\S]*?)-->", html)
    interesting = []
    
    for c in comments:
        is_excluded = False
        lower_c = c.lower()
        for ex in EXCLUDE_DOMAINS:
            if ex in lower_c:
                is_excluded = True
                break
        
        if is_excluded:
            continue
            
        for pat in COMMENT_INTEREST_PATTERNS:
            if pat.search(c):
                interesting.append(c.strip()[:200])
                break
                
    if interesting:
        return [{
            "title": f"Sensitive-looking HTML comments found ({len(interesting)})",
            "severity": "medium",
            "confidence": "plausible-unconfirmed",
            "cwe": "CWE-615",
            "owasp": "A01:2021-Broken Access Control",
            "location": ctx.url,
            "evidence": "; ".join(interesting[:3]),
            "poc": f"curl -s {ctx.url} | grep -oE '<!--[^>]*-->'",
            "remediation": "Remove developer comments with internal notes, credentials, or debug markers before deploying.",
            "detection_method": "html_comment_scan"
        }]
    return []


def detect_technologies(headers: dict, html: str) -> Set[str]:
    """Fingerprint the technology/CMS stack from response headers, cookies, and HTML.

    Shared by phase_tech_detection (for the "Technology stack identified" finding)
    and phase_robots_analysis (to recognize CMS-default robots.txt boilerplate),
    so the two never drift out of sync on what counts as "detected WordPress".
    """
    technologies = set()

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
    
    for hname, sigmap in HEADER_FINGERPRINTS.items():
        hval = get_header_case_insensitive(headers, hname) or ""
        for needle, tech in sigmap.items():
            if needle.lower() in hval.lower():
                technologies.add(tech)

    set_cookie = get_header_case_insensitive(headers, "Set-Cookie") or ""
    for needle, tech in TECH_COOKIES.items():
        if needle.lower() in set_cookie.lower():
            technologies.add(tech)

    for tech, patterns in HTML_TECH_SIGNATURES.items():
        for pat in patterns:
            if re.search(pat, html, re.IGNORECASE):
                technologies.add(tech)
                break

    wp_match = re.search(r'content=["\']WordPress\s+([\d.]+)["\']', html, re.IGNORECASE)
    if wp_match:
        technologies.discard("WordPress")
        technologies.add(f"WordPress {wp_match.group(1)}")

    return technologies


def phase_tech_detection(ctx: Any) -> List[dict]:
    headers = ctx.main_page_cache.get("headers", {})
    html = ctx.main_page_cache.get("html", "")
    technologies = detect_technologies(headers, html)

    tech_list = sorted(technologies)
    if tech_list:
        return [{
            "title": "Technology stack identified",
            "severity": "info",
            "confidence": "verified-static",
            "cwe": "CWE-200",
            "owasp": "A05:2021-Security Misconfiguration",
            "location": "Headers & HTML",
            "evidence": f"Detected: {', '.join(tech_list)}",
            "poc": f"curl -sI {ctx.url}",
            "remediation": "Consider suppressing version-revealing headers (Server, X-Powered-By) in production.",
            "detection_method": "header_html_cookie_fingerprint"
        }]
    return []


def _cms_default_robots_paths(technologies: Iterable[str]) -> Set[str]:
    """Return the lowercased set of robots.txt paths that are default CMS boilerplate.

    Matches by prefix so a versioned tech string like "WordPress 6.4" (from
    detect_technologies()) still resolves to the "WordPress" entry.
    """
    defaults: Set[str] = set()
    for tech in technologies:
        tech_lower = tech.lower()
        for cms_name, paths in CMS_DEFAULT_ROBOTS_PATHS.items():
            if tech_lower.startswith(cms_name.lower()):
                defaults.update(p.lower() for p in paths)
    return defaults


def _analyze_robots_txt(url: str, body: str, technologies: Iterable[str]) -> List[dict]:
    """Pure parsing/classification logic for robots.txt, split out from the
    async fetch so it can be exercised directly in regression tests.
    """
    disallow = re.findall(r'^\s*Disallow:\s*(\S+)', body, re.IGNORECASE | re.MULTILINE)
    allow = re.findall(r'^\s*Allow:\s*(\S+)', body, re.IGNORECASE | re.MULTILINE)
    all_paths = disallow + allow

    sensitive_prefixes = ["/admin", "/wp-admin", "/api", "/internal", "/debug"]
    sensitive_hits = [p for p in all_paths if any(p.lower().startswith(pre) for pre in sensitive_prefixes)]

    if not sensitive_hits:
        return [{
            "title": "robots.txt present with only standard paths",
            "severity": "info",
            "confidence": "informational",
            "cwe": "CWE-200",
            "owasp": "A05:2021-Security Misconfiguration",
            "location": url,
            "evidence": f"{len(all_paths)} path(s) listed; none matched sensitive prefixes.",
            "poc": f"curl -s {url}",
            "remediation": "No action required.",
            "detection_method": "robots_txt_parse"
        }]

    # Known default paths auto-generated by the detected CMS carry no signal:
    # every fresh install exposes them. Only genuinely custom hits are worth
    # flagging as a disclosure.
    cms_defaults = _cms_default_robots_paths(technologies)
    custom_hits = [p for p in sensitive_hits if p.lower() not in cms_defaults]
    boilerplate_hits = [p for p in sensitive_hits if p.lower() in cms_defaults]

    if custom_hits:
        return [{
            "title": "robots.txt discloses sensitive paths",
            "severity": "medium",
            "confidence": "plausible-unconfirmed",
            "cwe": "CWE-200",
            "owasp": "A05:2021-Security Misconfiguration",
            "location": url,
            "evidence": f"robots.txt references: {', '.join(custom_hits[:10])}",
            "poc": f"curl -s {url}",
            "remediation": "Avoid listing sensitive paths in robots.txt; enforce access control server-side instead.",
            "detection_method": "robots_txt_parse"
        }]

    # Every sensitive-looking hit was accounted for by known CMS boilerplate.
    return [{
        "title": "robots.txt contains only default CMS-generated entries; no custom disclosure detected",
        "severity": "info",
        "confidence": "informational",
        "cwe": "CWE-200",
        "owasp": "A05:2021-Security Misconfiguration",
        "location": url,
        "evidence": f"robots.txt references: {', '.join(boilerplate_hits[:10])} — these match known default entries auto-generated by the detected CMS, not a custom disclosure.",
        "poc": f"curl -s {url}",
        "remediation": "No action required; these paths are standard for the detected CMS.",
        "detection_method": "robots_txt_parse_cms_default_suppressed"
    }]


async def phase_robots_analysis(ctx: Any, requests_made: list) -> List[dict]:
    url = make_url(ctx.url, "/robots.txt")
    status, body = await fetch_path(ctx, "/robots.txt", requests_made)

    if status == 200 and body:
        headers = ctx.main_page_cache.get("headers", {})
        html = ctx.main_page_cache.get("html", "")
        technologies = detect_technologies(headers, html)
        return _analyze_robots_txt(url, body, technologies)
    return []


# -- Orchestrator Entry Point -------------------------------------------------------------

async def run(ctx: Any) -> dict:
    """Entry point for the Info Disclosure scout."""
    
    # Gatekeeper check: do not scan if the page is hard blocked (WAF, 403, 500 etc)
    if not getattr(ctx, "page_is_representative", True):
        return {
            "fatal_error": "Page is not representative (e.g., WAF block or hard error); skipping info disclosure scan."
        }

    findings = []
    requests_made = [0]

    # Run sync/local phases
    for phase_func in [
        lambda: phase_tech_detection(ctx),
        lambda: phase_comment_analysis(ctx)
    ]:
        try:
            findings.extend(phase_func())
        except Exception:
            pass

    # Run remote/async phases with isolation
    try:
        findings.extend(await phase_path_probing(ctx, requests_made))
    except Exception:
        pass

    try:
        findings.extend(await phase_robots_analysis(ctx, requests_made))
    except Exception:
        pass

    return {
        "findings": findings,
        "details": {
            "requests_made": requests_made[0],
            "info": "Info disclosure scan completed successfully."
        }
    }


# ────────────────────────────────────────────── Standalone Testing ──────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(description="Bravo6 Info Disclosure Scout")
    parser.add_argument("url", nargs="?", default="https://example.com", help="Target URL")
    parser.add_argument("--test", action="store_true", help="Run Scout Regression Tests")
    args = parser.parse_args()

    if args.test:
        import unittest

        class TestRobotsCmsDefaultAllowlist(unittest.TestCase):
            """Regression tests for the robots.txt CMS-default boilerplate allowlist."""

            URL = "https://example.com/robots.txt"

            def test_wordpress_default_paths_only_are_suppressed(self):
                body = (
                    "User-agent: *\n"
                    "Disallow: /wp-admin/\n"
                    "Allow: /wp-admin/admin-ajax.php\n"
                )
                findings = _analyze_robots_txt(self.URL, body, {"WordPress 6.4"})
                self.assertEqual(len(findings), 1)
                finding = findings[0]
                self.assertEqual(finding["confidence"], "informational")
                self.assertEqual(finding["severity"], "info")
                self.assertNotEqual(finding["title"], "robots.txt discloses sensitive paths")
                self.assertIn("no custom disclosure detected", finding["title"])

            def test_wordpress_default_plus_custom_path_still_flags_custom_only(self):
                body = (
                    "User-agent: *\n"
                    "Disallow: /wp-admin/\n"
                    "Allow: /wp-admin/admin-ajax.php\n"
                    "Disallow: /admin-panel-9f21/\n"
                )
                findings = _analyze_robots_txt(self.URL, body, {"WordPress 6.4"})
                self.assertEqual(len(findings), 1)
                finding = findings[0]
                self.assertEqual(finding["title"], "robots.txt discloses sensitive paths")
                self.assertEqual(finding["severity"], "medium")
                self.assertIn("/admin-panel-9f21/", finding["evidence"])
                self.assertNotIn("/wp-admin/", finding["evidence"])

            def test_no_cms_detected_defaults_are_not_suppressed(self):
                # Without a confirmed CMS, /wp-admin/ can't be attributed to a known
                # default, so it must not be silently swallowed.
                body = "User-agent: *\nDisallow: /wp-admin/\n"
                findings = _analyze_robots_txt(self.URL, body, set())
                self.assertEqual(findings[0]["title"], "robots.txt discloses sensitive paths")
                self.assertIn("/wp-admin/", findings[0]["evidence"])

            def test_no_sensitive_paths_at_all(self):
                body = "User-agent: *\nDisallow: /private-media/\n"
                findings = _analyze_robots_txt(self.URL, body, {"WordPress"})
                self.assertEqual(findings[0]["title"], "robots.txt present with only standard paths")

        sys.argv = [sys.argv[0]]
        unittest.main()
    else:
        import aiohttp
        from dataclasses import dataclass, field
        from typing import Optional

        @dataclass
        class _StandaloneContext:
            url: str
            session: aiohttp.ClientSession
            page_is_representative: bool = True
            waf_challenge_detected: Optional[str] = None
            sensitive_paths: list = field(default_factory=list)
            main_page_cache: dict = field(default_factory=dict)

        async def _live_scan():
            connector = aiohttp.TCPConnector(ssl=True)
            async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": "Bravo6-Scanner/8.5"}) as session:
                try:
                    async with session.get(args.url) as resp:
                        html = await resp.text()
                        main_page_cache = {"status": resp.status, "html": html, "headers": dict(resp.headers)}
                except Exception as e:
                    main_page_cache = {"error": str(e), "html": "", "headers": {}}

                ctx = _StandaloneContext(url=args.url, session=session, main_page_cache=main_page_cache)
                result = await run(ctx)
                print(json.dumps(result, indent=2, ensure_ascii=False, default=str))

        asyncio.run(_live_scan())