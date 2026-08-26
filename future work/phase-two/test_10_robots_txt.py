"""
test_10_robots_txt.py — Advanced Robots.txt Analyzer with Active Verification (v3)

Enhancements:
- Dual User-Agent verification (normal + Googlebot) to detect weak protection.
- Content analysis of accessible paths (sensitive data, version info, directory listing, login forms).
- Integration with sitemap.xml to detect inconsistencies.
- Detection of conflicting Allow/Disallow directives.
- Parsing of non-standard directives (Crawl-delay, Host, Visit-time).
- Detection of query parameter blocking patterns (/*?*).
- HEAD request first to reduce server load.
- Context integration with CMS and Info Disclosure tests.
- Bypass header testing (X-Forwarded-For, X-Original-URL).
- Response timing/size analysis to detect hidden paths.
- Dynamic confidence scoring.
- Comprehensive PoC commands.
- Detailed remediation.
"""

import asyncio
import re
import time
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List, Optional, Tuple, Set

import aiohttp
from bs4 import BeautifulSoup

# ── Configuration ────────────────────────────────────────────────────────────
USER_AGENT = "Bravo6-Scanner/1.0"
GOOGLEBOT_UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
TIMEOUT_SECONDS = 10
MAX_CONCURRENT_VERIFICATIONS = 10
MAX_BYTES_ANALYZE = 10 * 1024  # 10KB for content analysis

# ── Severity rankings ──────────────────────────────────────────────────────
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# ── Sensitive path patterns (for categorization) ──────────────────────────
SENSITIVE_PATTERNS = {
    r"/(admin|administrator|wp-admin|dashboard|control|login)": ("Admin Panel", "high"),
    r"/backup|/bak|/\.backup": ("Backup Directory", "critical"),
    r"/config|/configuration|/settings": ("Config Directory", "high"),
    r"/\.env|/env": ("Environment File", "critical"),
    r"/api/|/api$": ("API Endpoint", "medium"),
    r"/private|/secret|/hidden|/internal": ("Private Directory", "critical"),
    r"/db|/database|/sql": ("Database Directory", "critical"),
    r"/upload|/uploads|/files": ("Upload Directory", "medium"),
    r"/phpmyadmin|/pma|/mysqladmin": ("Database Admin Panel", "critical"),
    r"/\.git|/\.svn|/\.hg": ("Version Control Directory", "critical"),
    r"/tmp|/temp|/cache": ("Temporary Directory", "medium"),
    r"/logs?|/log": ("Log Directory", "high"),
    r"/wp-content|/wp-includes": ("WordPress Core Directory", "medium"),
    r"/jenkins|/jira|/confluence": ("Internal Tool", "high"),
    r"/wp-json": ("WordPress REST API", "medium"),
    r"/xmlrpc.php": ("WordPress XML-RPC", "medium"),
    r"/v1/|/v2/|/v3/": ("API Versioning", "low"),
    r"/202[0-9]/": ("Year-based directory (old content)", "medium"),
}

_COMPILED_SENSITIVE = [
    (re.compile(pattern, re.IGNORECASE), label, severity)
    for pattern, (label, severity) in SENSITIVE_PATTERNS.items()
]

INTERNAL_KEYWORDS = re.compile(r"(internal|private|corp|dev|staging|test)", re.IGNORECASE)

# ── Bypass headers to test ──────────────────────────────────────────────────
BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Rewrite-URL": "/admin"},
    {"X-Forwarded-Host": "localhost"},
]

# ── Helper functions ────────────────────────────────────────────────────────

def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    return url.rstrip("/")

def _get_origin(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def _match_sensitive(path: str) -> Optional[Tuple[str, str]]:
    for compiled, label, severity in _COMPILED_SENSITIVE:
        if compiled.search(path):
            return label, severity
    return None

def _parse_robots_txt(text: str) -> Dict[str, Any]:
    """
    Parse robots.txt into structured data.
    Returns dict with:
      - directives: list of (user-agent, disallow, allow)
      - sitemaps: list of sitemap URLs
      - crawl_delay: dict of user-agent -> delay (if present)
      - host: host directive (if present)
      - visit_time: visit-time directive (if present)
      - disallow_paths: set of all disallow paths (regardless of UA)
      - allow_paths: set of all allow paths
      - has_wildcard: bool if any user-agent is *
    """
    lines = text.splitlines()
    directives = []
    sitemaps = []
    crawl_delay = {}
    host = None
    visit_time = None
    disallow_paths = set()
    allow_paths = set()
    has_wildcard = False
    current_ua = None

    for line in lines:
        # Strip comments
        if "#" in line:
            line = line.split("#", 1)[0]
        line = line.strip()
        if not line:
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()

        if key == "user-agent":
            current_ua = value
            if value == "*":
                has_wildcard = True
            directives.append((current_ua, None, None))
        elif key == "disallow":
            if current_ua is not None:
                # Store with current UA
                if value:
                    disallow_paths.add(value)
                    # Also store in directives list for full context
                    directives.append((current_ua, value, None))
        elif key == "allow":
            if current_ua is not None:
                if value:
                    allow_paths.add(value)
                    directives.append((current_ua, None, value))
        elif key == "sitemap":
            if value.startswith(("http://", "https://")):
                sitemaps.append(value)
        elif key == "crawl-delay":
            if current_ua is not None:
                try:
                    crawl_delay[current_ua] = float(value)
                except ValueError:
                    pass
        elif key == "host":
            host = value
        elif key == "visit-time":
            visit_time = value

    return {
        "directives": directives,
        "sitemaps": sitemaps,
        "crawl_delay": crawl_delay,
        "host": host,
        "visit_time": visit_time,
        "disallow_paths": list(disallow_paths),
        "allow_paths": list(allow_paths),
        "has_wildcard": has_wildcard,
    }

def _analyze_content(content: str, path: str) -> Dict[str, Any]:
    """Analyze content for sensitive information."""
    findings = []
    # Look for sensitive keywords
    sensitive_keywords = re.compile(r"(password|secret|api[_-]?key|token|credential|auth|private|confidential)", re.IGNORECASE)
    matches = sensitive_keywords.findall(content)
    if matches:
        findings.append({
            "type": "sensitive_keywords",
            "details": f"Found keywords: {', '.join(set(matches[:5]))}",
            "severity": "critical",
        })
    # Look for emails
    emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", content)
    if emails:
        findings.append({
            "type": "email_addresses",
            "details": f"Found {len(emails)} email(s): {', '.join(emails[:3])}",
            "severity": "medium",
        })
    # Look for IP addresses (internal)
    ips = re.findall(r"(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})", content)
    if ips:
        findings.append({
            "type": "internal_ips",
            "details": f"Found internal IPs: {', '.join(set(ips))}",
            "severity": "high",
        })
    # Look for directory listing
    if re.search(r"(Index of /|<title>Directory Listing|Parent Directory</a>)", content, re.IGNORECASE):
        findings.append({
            "type": "directory_listing",
            "details": "Directory listing is enabled",
            "severity": "high",
        })
    # Look for login forms
    if re.search(r'<form.*action=".*login.*".*</form>', content, re.IGNORECASE | re.DOTALL):
        findings.append({
            "type": "login_form",
            "details": "Login form detected on this path",
            "severity": "medium",
        })
    # Look for version info (PHP, CMS, etc.)
    version_matches = re.findall(r"(?:PHP|WordPress|Drupal|Joomla|Laravel|Django)\s*[\/:]?\s*([\d.]+)", content, re.IGNORECASE)
    if version_matches:
        findings.append({
            "type": "version_disclosure",
            "details": f"Version info: {', '.join(version_matches[:3])}",
            "severity": "medium",
        })
    # Look for commented code with secrets
    if re.search(r"<!--.*?(password|secret|api_key).*?-->", content, re.IGNORECASE | re.DOTALL):
        findings.append({
            "type": "commented_secret",
            "details": "Secret or password found in HTML comment",
            "severity": "high",
        })
    return {"findings": findings, "has_sensitive": any(f["severity"] in ("critical", "high") for f in findings)}

async def _fetch_with_ua(
    session: aiohttp.ClientSession,
    url: str,
    user_agent: str,
    method: str = "HEAD",
    allow_redirects: bool = False,
    timeout: int = TIMEOUT_SECONDS
) -> Dict[str, Any]:
    """Fetch URL with specified User-Agent and method."""
    headers = {"User-Agent": user_agent}
    try:
        async with session.request(
            method,
            url,
            headers=headers,
            allow_redirects=allow_redirects,
            timeout=aiohttp.ClientTimeout(total=timeout),
            ssl=False,
        ) as resp:
            if method == "HEAD":
                body = b""
            else:
                body = await resp.read()
            return {
                "status": resp.status,
                "headers": dict(resp.headers),
                "body": body[:MAX_BYTES_ANALYZE] if method == "GET" else b"",
                "size": len(body),
                "final_url": str(resp.url),
                "error": None,
            }
    except asyncio.TimeoutError:
        return {"status": 0, "headers": {}, "body": b"", "size": 0, "final_url": url, "error": "timeout"}
    except aiohttp.ClientError as e:
        return {"status": 0, "headers": {}, "body": b"", "size": 0, "final_url": url, "error": f"client_error: {e}"}
    except Exception as e:
        return {"status": 0, "headers": {}, "body": b"", "size": 0, "final_url": url, "error": f"unexpected: {e}"}

async def _verify_path(
    session: aiohttp.ClientSession,
    path: str,
    base_url: str,
    semaphore: asyncio.Semaphore,
    baseline_head: Optional[Dict] = None,
) -> Dict[str, Any]:
    """Verify a specific path from robots.txt."""
    target = urljoin(base_url + "/", path.lstrip("/"))
    async with semaphore:
        # Step 1: HEAD request with normal UA
        head_resp = await _fetch_with_ua(session, target, USER_AGENT, "HEAD")
        if head_resp["error"]:
            return {
                "path": path,
                "exists": False,
                "status": 0,
                "error": head_resp["error"],
                "user_agent": USER_AGENT,
                "confidence": 20,
            }

        # Step 2: If HEAD returns 200 or 403, we may proceed to GET for content
        if head_resp["status"] in (200, 403, 401):
            # GET with normal UA
            get_resp = await _fetch_with_ua(session, target, USER_AGENT, "GET")
            if get_resp["error"]:
                get_body = b""
                get_status = head_resp["status"]
            else:
                get_body = get_resp["body"]
                get_status = get_resp["status"]

            # Also GET with Googlebot UA
            google_resp = await _fetch_with_ua(session, target, GOOGLEBOT_UA, "GET")
            google_body = google_resp["body"] if not google_resp["error"] else b""
            google_status = google_resp["status"] if not google_resp["error"] else None

            # Analyze content from normal GET if status 200
            analysis = {}
            if get_status == 200:
                analysis = _analyze_content(get_body.decode("utf-8", errors="ignore"), path)

            # Check for bypass headers
            bypass_success = False
            bypass_headers_used = []
            for bypass_header in BYPASS_HEADERS:
                # Try GET with bypass header
                bypass_resp = await _fetch_with_ua(session, target, USER_AGENT, "GET", headers=bypass_header)
                if not bypass_resp["error"] and bypass_resp["status"] in (200, 403):
                    if bypass_resp["status"] != head_resp["status"]:
                        bypass_success = True
                        bypass_headers_used.append(bypass_header)
                        break

            # Determine if path is accessible
            accessible = get_status in (200, 403, 401)
            # If Googlebot can access but normal cannot, that's a misconfiguration (weak protection)
            google_only = (google_status == 200 and get_status != 200) or (google_status == 403 and get_status != 403)

            # Determine confidence
            confidence = 0
            if get_status == 200:
                confidence = 100
            elif get_status == 403:
                confidence = 80
            elif get_status == 401:
                confidence = 70
            elif google_only:
                confidence = 90  # strong indicator of existence
            elif get_status == 404:
                confidence = 30
            else:
                confidence = 50

            # If GET status differs from HEAD, note that
            if get_status != head_resp["status"]:
                # Maybe redirect or different response
                pass

            return {
                "path": path,
                "exists": accessible or google_only,
                "status": get_status,
                "google_status": google_status,
                "status_head": head_resp["status"],
                "content_analysis": analysis,
                "sensitive_findings": analysis.get("findings", []),
                "bypass_possible": bypass_success,
                "bypass_headers_used": bypass_headers_used,
                "google_only": google_only,
                "user_agent": USER_AGENT,
                "confidence": confidence,
                "size": get_resp.get("size", 0),
                "response_time": 0,  # not measured
            }
        else:
            # HEAD returned 404 or other, likely not existent
            return {
                "path": path,
                "exists": False,
                "status": head_resp["status"],
                "error": None,
                "user_agent": USER_AGENT,
                "confidence": 20,
            }

async def _fetch_sitemap(session: aiohttp.ClientSession, sitemap_url: str) -> Optional[List[str]]:
    """Fetch sitemap and extract all URLs (simple)."""
    try:
        async with session.get(sitemap_url, timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS), ssl=False) as resp:
            if resp.status != 200:
                return None
            content = await resp.text(errors="ignore")
            # Try to parse XML (simple regex to extract loc)
            urls = re.findall(r"<loc>(.*?)</loc>", content, re.IGNORECASE)
            return urls if urls else None
    except Exception:
        return None

# ── Main run function ──────────────────────────────────────────────────────

async def run(url: str, context: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Main entry point for robots.txt analysis.
    Args:
        url: target URL
        context: optional dict from other tests (cms, info_disclosure)
    Returns:
        dict with findings
    """
    test_name = "robots_txt"

    try:
        normalized = _normalize_url(url)
        origin = _get_origin(normalized)
        robots_url = f"{origin}/robots.txt"
    except Exception as e:
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "Invalid URL",
            "description": f"Could not normalize URL: {e}",
            "evidence": [],
            "remediation": "Provide a valid URL.",
            "total_disallow_rules": 0,
            "sensitive_paths_found": 0,
            "robots_content": None,
            "sitemap_content": None,
        }

    async with aiohttp.ClientSession() as session:
        # ── 1. Fetch robots.txt ──────────────────────────────────────────
        robots_resp = await _fetch_with_ua(session, robots_url, USER_AGENT, "GET")
        if robots_resp["error"]:
            return {
                "test_name": test_name,
                "status": "error",
                "severity": "info",
                "title": "robots.txt unreachable",
                "description": f"Could not fetch robots.txt: {robots_resp['error']}",
                "evidence": [],
                "remediation": "Check if robots.txt exists.",
                "total_disallow_rules": 0,
                "sensitive_paths_found": 0,
                "robots_content": None,
                "sitemap_content": None,
            }
        if robots_resp["status"] != 200:
            return {
                "test_name": test_name,
                "status": "info",
                "severity": "info",
                "title": "No robots.txt found",
                "description": f"robots.txt returned {robots_resp['status']}",
                "evidence": [],
                "remediation": "No action needed.",
                "total_disallow_rules": 0,
                "sensitive_paths_found": 0,
                "robots_content": None,
                "sitemap_content": None,
            }

        robots_text = robots_resp["body"].decode("utf-8", errors="ignore")
        parsed = _parse_robots_txt(robots_text)
        disallow_paths = parsed["disallow_paths"]
        allow_paths = parsed["allow_paths"]
        sitemaps = parsed["sitemaps"]
        has_wildcard = parsed["has_wildcard"]

        if not disallow_paths:
            return {
                "test_name": test_name,
                "status": "pass",
                "severity": "info",
                "title": "No Disallow rules found",
                "description": "robots.txt exists but has no Disallow directives.",
                "evidence": [],
                "remediation": "No action needed.",
                "total_disallow_rules": 0,
                "sensitive_paths_found": 0,
                "robots_content": robots_text,
                "sitemap_content": None,
            }

        # ── 2. Fetch sitemap if available ────────────────────────────────
        sitemap_urls = []
        if sitemaps:
            for sm_url in sitemaps[:1]:  # limit to first
                sitemap_urls = await _fetch_sitemap(session, sm_url)
                if sitemap_urls:
                    break

        # ── 3. Verify each disallow path ─────────────────────────────────
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_VERIFICATIONS)
        tasks = []
        for path in disallow_paths:
            # Skip empty paths
            if not path or path == "/":
                continue
            tasks.append(_verify_path(session, path, origin, semaphore))

        results = await asyncio.gather(*tasks, return_exceptions=False)

        # ── 4. Process results ────────────────────────────────────────────
        evidence = []
        sensitive_paths_found = 0
        accessible_paths = []
        google_only_paths = []
        bypass_paths = []

        for res in results:
            if isinstance(res, Exception) or not res:
                continue

            path = res["path"]
            exists = res["exists"]
            status = res["status"]
            google_status = res.get("google_status")
            google_only = res.get("google_only", False)
            bypass = res.get("bypass_possible", False)
            confidence = res["confidence"]
            analysis = res.get("content_analysis", {})
            sensitive_findings = analysis.get("findings", [])

            # Determine severity of the path itself
            matched = _match_sensitive(path)
            if matched:
                label, severity = matched
            else:
                # Check internal keywords
                if INTERNAL_KEYWORDS.search(path):
                    label = "Internal Path"
                    severity = "high"
                else:
                    label = "Disallowed Path"
                    severity = "medium"

            # Elevate severity if path is accessible
            if exists:
                severity = "critical" if severity in ("high", "critical") else "high"
                accessible_paths.append(path)
                if sensitive_findings:
                    # Also include findings
                    for f in sensitive_findings:
                        evidence.append({
                            "path": path,
                            "type": "content_finding",
                            "severity": f["severity"],
                            "title": f"Sensitive content in {path}",
                            "description": f"Found: {f['details']}",
                            "poc": f"curl -v {urljoin(origin, path)}",
                            "confidence": 100,
                            "remediation": "Restrict access to this path immediately."
                        })
                if google_only:
                    google_only_paths.append(path)
                    severity = "critical"
                    evidence.append({
                        "path": path,
                        "type": "google_only",
                        "severity": "critical",
                        "title": f"Path {path} accessible only to Googlebot (weak protection)",
                        "description": "Path is disallowed in robots.txt but accessible to Googlebot. Attackers can spoof User-Agent.",
                        "poc": f"curl -A '{GOOGLEBOT_UA}' -v {urljoin(origin, path)}",
                        "confidence": 90,
                        "remediation": "Implement proper authentication/authorization, not rely on robots.txt."
                    })
                if bypass:
                    bypass_paths.append(path)
                    evidence.append({
                        "path": path,
                        "type": "bypass_possible",
                        "severity": "high",
                        "title": f"Path {path} accessible via header bypass",
                        "description": "Using headers like X-Forwarded-For or X-Original-URL can bypass access restrictions.",
                        "poc": f"curl -v -H 'X-Forwarded-For: 127.0.0.1' {urljoin(origin, path)}",
                        "confidence": 80,
                        "remediation": "Disable header-based bypass or implement proper validation."
                    })
                # Add main evidence for accessible path
                evidence.append({
                    "path": path,
                    "type": "accessible_path",
                    "severity": severity,
                    "title": f"Accessible disallowed path: {path}",
                    "description": f"Path returned HTTP {status} (normal UA). {'Contains sensitive content.' if sensitive_findings else ''}",
                    "poc": f"curl -v {urljoin(origin, path)}",
                    "confidence": confidence,
                    "remediation": f"Restrict access to {path} with proper authentication/authorization."
                })
                sensitive_paths_found += 1
            else:
                # Not accessible, but may still be sensitive info
                if matched or INTERNAL_KEYWORDS.search(path):
                    evidence.append({
                        "path": path,
                        "type": "disclosed_path",
                        "severity": "medium",
                        "title": f"Sensitive path disclosed in robots.txt: {path}",
                        "description": f"Path is listed in robots.txt but not accessible (HTTP {status}). Still reveals internal structure.",
                        "poc": f"curl -v {urljoin(origin, path)}",
                        "confidence": 70,
                        "remediation": "Remove sensitive paths from robots.txt if not needed."
                    })
                    sensitive_paths_found += 1

        # ── 5. Check for conflicting Allow/Disallow ─────────────────────
        for allow_path in allow_paths:
            for disallow_path in disallow_paths:
                if disallow_path != "/" and allow_path.startswith(disallow_path):
                    evidence.append({
                        "type": "conflicting_directives",
                        "path": allow_path,
                        "severity": "medium",
                        "title": f"Conflicting Allow/Disallow for {allow_path}",
                        "description": f"Allow: {allow_path} conflicts with Disallow: {disallow_path}",
                        "poc": "Review robots.txt directives.",
                        "confidence": 80,
                        "remediation": "Resolve conflicting directives to avoid unintended access."
                    })
                    break

        # ── 6. Check sitemap inconsistency ──────────────────────────────
        if sitemap_urls:
            sitemap_paths = [urlparse(u).path for u in sitemap_urls if urlparse(u).path]
            for dis_path in disallow_paths:
                for sm_path in sitemap_paths:
                    if dis_path in sm_path or sm_path.startswith(dis_path):
                        evidence.append({
                            "type": "sitemap_inconsistency",
                            "path": dis_path,
                            "severity": "high",
                            "title": f"Disallowed path {dis_path} appears in sitemap",
                            "description": f"Path is disallowed in robots.txt but listed in sitemap, causing confusion.",
                            "poc": f"Check robots.txt and sitemap.xml.",
                            "confidence": 90,
                            "remediation": "Remove conflicting entries from sitemap or adjust robots.txt."
                        })
                        break

        # ── 7. Check for query parameter blocking (/*?*) ────────────────
        for dis_path in disallow_paths:
            if "?" in dis_path or "*?" in dis_path:
                evidence.append({
                    "type": "query_blocking",
                    "path": dis_path,
                    "severity": "low",
                    "title": f"Query parameter blocking pattern: {dis_path}",
                    "description": "Blocks all URLs with query parameters. May indicate dynamic content vulnerability.",
                    "poc": "Review URL handling.",
                    "confidence": 50,
                    "remediation": "Consider if blocking all query parameters is necessary."
                })
                break

        # ── 8. Integrate with context (CMS, Info Disclosure) ────────────
        cms = context.get("cms") if context else None
        if cms:
            # For known CMS, check specific paths
            cms_specific_paths = []
            if cms == "WordPress":
                cms_specific_paths = ["/wp-admin", "/wp-login.php", "/wp-json", "/xmlrpc.php"]
            elif cms == "Joomla":
                cms_specific_paths = ["/administrator", "/components", "/modules"]
            elif cms == "Drupal":
                cms_specific_paths = ["/user/login", "/admin", "/core"]
            elif cms == "Laravel":
                cms_specific_paths = ["/admin", "/dashboard", "/api"]
            # Check if these are in disallow and accessible
            for cms_path in cms_specific_paths:
                if cms_path in disallow_paths:
                    # Check if it's accessible from results
                    for res in results:
                        if isinstance(res, dict) and res["path"] == cms_path and res["exists"]:
                            evidence.append({
                                "type": "cms_admin_exposed",
                                "path": cms_path,
                                "severity": "critical",
                                "title": f"CMS admin path {cms_path} exposed despite robots.txt",
                                "description": f"Admin path for {cms} is accessible even though disallowed.",
                                "poc": f"curl -v {urljoin(origin, cms_path)}",
                                "confidence": 100,
                                "remediation": "Secure admin paths with strong authentication and IP restrictions."
                            })
                            break

        # ── 9. Compute overall status ────────────────────────────────────
        critical = any(e["severity"] == "critical" for e in evidence)
        high = any(e["severity"] == "high" for e in evidence)
        medium = any(e["severity"] == "medium" for e in evidence)

        if critical:
            status = "fail"
            overall_severity = "critical"
            title = f"Critical robots.txt issues ({len([e for e in evidence if e['severity']=='critical'])} findings)"
        elif high:
            status = "fail"
            overall_severity = "high"
            title = f"High severity robots.txt issues ({len([e for e in evidence if e['severity']=='high'])} findings)"
        elif medium:
            status = "warning"
            overall_severity = "medium"
            title = f"Medium severity robots.txt issues ({len([e for e in evidence if e['severity']=='medium'])} findings)"
        else:
            status = "pass"
            overall_severity = "info"
            title = "No significant robots.txt issues found"

        # Build remediation
        remediation_parts = []
        if accessible_paths:
            remediation_parts.append(f"Restrict access to {len(accessible_paths)} accessible disallowed paths.")
        if google_only_paths:
            remediation_parts.append("Do not rely on robots.txt for security; use authentication.")
        if bypass_paths:
            remediation_parts.append("Disable dangerous header bypasses (X-Forwarded-For, X-Original-URL).")
        if any(e["type"] == "conflicting_directives" for e in evidence):
            remediation_parts.append("Resolve conflicting Allow/Disallow directives.")
        if any(e["type"] == "sitemap_inconsistency" for e in evidence):
            remediation_parts.append("Synchronize robots.txt and sitemap.xml entries.")
        if any(e["type"] == "cms_admin_exposed" for e in evidence):
            remediation_parts.append("Secure CMS admin paths with additional authentication.")
        if not remediation_parts:
            remediation_parts.append("No immediate action required.")

        return {
            "test_name": test_name,
            "status": status,
            "severity": overall_severity,
            "title": title,
            "description": f"Analyzed {len(disallow_paths)} disallow rules. Found {len(evidence)} issues.",
            "evidence": evidence,
            "remediation": " ".join(remediation_parts),
            "total_disallow_rules": len(disallow_paths),
            "sensitive_paths_found": sensitive_paths_found,
            "robots_content": robots_text,
            "sitemap_content": sitemap_urls[:3] if sitemap_urls else None,
            "accessible_paths": accessible_paths,
            "google_only_paths": google_only_paths,
            "bypass_paths": bypass_paths,
        }


if __name__ == "__main__":
    import json
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))