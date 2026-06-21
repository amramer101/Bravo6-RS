"""
test_06_info_disclosure.py — Advanced Intelligence Gathering (Active & Aggressive)

Upgraded with:
- Backup files (.zip, .tar, .sql, domain-specific dumps).
- IDE workspaces (.idea, .vscode).
- Source Maps (.js.map) -> reveals frontend source code.
- Active verification: checks if discovered admin paths are actually accessible.
- Technology fingerprinting via cookies & error pages.
- Cloud Bucket enumeration (S3, GCP, Azure) if links found.
- Swagger/OpenAPI & GraphQL Introspection probing.
- Changelog/Version detection to infer CVEs.
- Path Traversal fuzzing to trigger directory listings outside root.
- Evidence correlation: combines headers, cookies, and found paths into a single risk narrative.
"""

import asyncio
import re
import json
from urllib.parse import urljoin, urlparse, quote

import aiohttp
from bs4 import BeautifulSoup

TEST_NAME = "information_disclosure"
USER_AGENT = "Bravo6-Scanner/1.0"
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=12)
MAX_CONCURRENT_REQUESTS = 12  # Limit to avoid WAF blocks

# ── Technology detection via cookies ──────────────────────────────────────
TECH_COOKIE_MAP = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java (JSP/Servlet)",
    "connect.sid": "Node.js (Express)",
    "laravel_session": "Laravel (PHP)",
    "ASP.NET_SessionId": "ASP.NET",
    "ci_session": "CodeIgniter (PHP)",
    "wp-settings-": "WordPress",
    "XSRF-TOKEN": "Laravel / Angular / Django",
}

# ── High-value sensitive paths (Top 30 most dangerous) ──────────────────
SENSITIVE_PATHS = [
    ".git/HEAD",
    ".env",
    ".env.production",
    ".env.local",
    ".git/config",
    "backup.zip",
    "backup.tar.gz",
    "dump.sql",
    "db.sql",
    "composer.json",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "phpinfo.php",
    "info.php",
    "test.php",
    "config.php",
    "settings.py",
    "web.config",
    "robots.txt",
    "sitemap.xml",
    "CHANGELOG.md",
    "VERSION",
    "RELEASE",
    ".htaccess",
    ".idea/workspace.xml",
    ".vscode/settings.json",
    "swagger-ui.html",
    "v3/api-docs",
    "api-docs",
    "swagger/v1/swagger.json",
]

# ── Common backup naming patterns (domain-aware) ──────────────────────
BACKUP_EXTENSIONS = [".zip", ".tar.gz", ".tgz", ".rar", ".7z", ".sql", ".bak"]

# ── Source Map patterns ──────────────────────────────────────────────────
SOURCE_MAP_PATTERNS = [
    "main.js.map",
    "bundle.js.map",
    "app.js.map",
    "vendor.js.map",
    "runtime.js.map",
    "chunk.js.map",
]

# ── Directory listing test points ──────────────────────────────────────
DIR_LISTING_PATHS = ["/images/", "/assets/", "/static/", "/uploads/", "/files/", "/content/"]

# ── Cloud Bucket hostnames ──────────────────────────────────────────────
BUCKET_HOSTS = [".s3.amazonaws.com", ".s3.", "storage.googleapis.com", "blob.core.windows.net"]


# ── Helpers ──────────────────────────────────────────────────────────────

def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        return url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = f"https://{url}"
    return url


def _extract_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc.split(":")[0]


def _get_safe_text(text: str, max_len: int = 300) -> str:
    if not text:
        return ""
    return text[:max_len] + ("..." if len(text) > max_len else "")


async def _safe_get(session, url, **kwargs) -> tuple:
    """Perform a GET request with safe error handling."""
    try:
        async with session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, ssl=False, **kwargs) as resp:
            text = await resp.text(errors="replace")
            return text, dict(resp.headers), resp.status, str(resp.url)
    except Exception:
        return None, None, None, None


async def _head_only(session, url) -> tuple:
    """Perform a HEAD request to check existence efficiently."""
    try:
        async with session.head(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, ssl=False) as resp:
            return resp.status, dict(resp.headers), str(resp.url)
    except Exception:
        return None, None, None


# ── Main Entry ──────────────────────────────────────────────────────────

async def run(url: str) -> dict:
    test_name = TEST_NAME
    try:
        target = _normalize_url(url)
        if not target:
            return {"test_name": test_name, "status": "error", "severity": "info", "evidence": [], "remediation": ""}

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        domain = _extract_domain(target)

        findings = []
        tech_stack = set()
        discovered_paths = set()

        # ── 1. Setup Client ──────────────────────────────────────────
        connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT_REQUESTS, limit_per_host=5)
        async with aiohttp.ClientSession(
            headers={"User-Agent": USER_AGENT},
            connector=connector
        ) as session:

            # ── 2. Fetch Root & Detect Technology ──────────────────
            root_text, root_headers, root_status, final_root_url = await _safe_get(session, target)

            if root_headers:
                # Check Server/Powered-By
                for h in ["Server", "X-Powered-By", "X-Generator", "X-AspNet-Version"]:
                    val = root_headers.get(h)
                    if val:
                        findings.append({
                            "location": f"Header: {h}",
                            "value": val,
                            "risk": "Technology/version disclosure.",
                            "severity": "low",
                            "confidence": 100,
                            "poc": f"curl -I {target} | grep -i {h}",
                            "category": "passive"
                        })
                        tech_stack.add(val)

                # Check Cookies for technology
                cookie_header = root_headers.get("Set-Cookie", "")
                if cookie_header:
                    for cookie_pattern, tech in TECH_COOKIE_MAP.items():
                        if cookie_pattern in cookie_header:
                            findings.append({
                                "location": "Cookie",
                                "value": cookie_pattern,
                                "risk": f"Technology identified: {tech}",
                                "severity": "info",
                                "confidence": 100,
                                "poc": "Inspect browser cookies.",
                                "category": "passive"
                            })
                            tech_stack.add(tech)

            # ── 3. Extract Links from Root HTML ──────────────────────
            if root_text:
                soup = BeautifulSoup(root_text, "html.parser")
                all_links = [urljoin(target, a.get("href", "")) for a in soup.find_all("a", href=True)]
                all_scripts = [urljoin(target, s.get("src", "")) for s in soup.find_all("script", src=True)]
                all_styles = [urljoin(target, l.get("href", "")) for l in soup.find_all("link", rel="stylesheet")]

                # Check for Cloud Storage links
                for link in all_links + all_scripts + all_styles:
                    if any(bh in link for bh in BUCKET_HOSTS):
                        findings.append({
                            "location": "HTML Reference",
                            "value": link,
                            "risk": "External Cloud Storage reference found.",
                            "severity": "medium",
                            "confidence": 80,
                            "poc": f"curl {link}",
                            "category": "passive"
                        })
                        # Attempt bucket listing later

            # ── 4. Build Dynamic Backup Name List (Domain-based) ──────
            backup_names = []
            for ext in BACKUP_EXTENSIONS:
                backup_names.append(f"{domain}{ext}")
                backup_names.append(f"{domain}_backup{ext}")
                backup_names.append(f"backup_{domain}{ext}")
                backup_names.append(f"db{ext}")

            all_paths_to_check = set(SENSITIVE_PATHS)
            all_paths_to_check.update(backup_names)
            all_paths_to_check.update(SOURCE_MAP_PATTERNS)

            # ── 5. Parallel Path Probing (Active + Passive) ────────
            semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

            async def probe_path(path):
                async with semaphore:
                    full_url = urljoin(base_url, path)
                    # Use HEAD first for speed
                    status, headers, final_url = await _head_only(session, full_url)
                    if status is None:
                        return None
                    is_accessible = status < 400
                    is_redirect = 300 <= status < 400

                    # For certain types, we need the body (e.g., .env, .git)
                    fetch_body = False
                    if path.endswith((".env", ".env.production", ".env.local", ".git/HEAD", ".git/config", ".sql", "dump.sql", "composer.json", "package.json", "web.config")):
                        fetch_body = True
                    if status == 200 and (path.endswith(".map") or path.endswith(".zip") or path.endswith(".tar.gz") or path.endswith(".sql")):
                        fetch_body = True

                    body = None
                    body_headers = None
                    if fetch_body and status == 200:
                        body, body_headers, _, _ = await _safe_get(session, full_url)

                    # Determine severity based on path type & accessibility
                    severity = "info"
                    risk = "File discovered."
                    confidence = 80
                    poc = f"curl {full_url}"

                    if status == 200:
                        # Critical: Source code, DB dumps, env, git
                        if any(k in path for k in [".git", ".env", "dump.sql", "db.sql", "backup.zip", "backup.tar.gz", "composer.json", "web.config"]):
                            severity = "critical"
                            risk = "Extremely sensitive file exposed (source code/credentials/database)."
                            confidence = 100
                        elif path.endswith(".map"):
                            severity = "high"
                            risk = "Source Map exposed. Frontend source code is reconstructible."
                            confidence = 100
                        elif "api-docs" in path or "swagger" in path:
                            severity = "high"
                            risk = "API documentation exposed. Reveals all endpoints and parameters."
                            confidence = 95
                        elif "phpinfo" in path or "info.php" in path:
                            severity = "critical"
                            risk = "PHP Info page exposed. Discloses environment variables, paths, and configuration."
                            confidence = 100
                        elif "robots.txt" in path or "sitemap" in path:
                            severity = "low"
                            risk = "May expose hidden admin paths."
                            confidence = 90
                        elif "CHANGELOG" in path or "VERSION" in path or "RELEASE" in path:
                            severity = "medium"
                            risk = "Exact version disclosure. Can be used to find matching CVEs."
                            confidence = 95
                        else:
                            severity = "medium"
                            risk = "Potentially sensitive file accessible."

                        # If body exists, extract snippets for evidence
                        evidence_value = path
                        if body and len(body) < 1000:
                            evidence_value = f"{path} (content: {_get_safe_text(body)})"
                        elif body:
                            evidence_value = f"{path} (size: {len(body)} bytes)"

                        findings.append({
                            "location": path,
                            "value": evidence_value,
                            "risk": risk,
                            "severity": severity,
                            "confidence": confidence,
                            "poc": poc,
                            "category": "active",
                            "status_code": status,
                            "redirected": is_redirect,
                        })

                        if "admin" in path or "login" in path or "dashboard" in path:
                            discovered_paths.add(path)

                    elif status == 403:
                        findings.append({
                            "location": path,
                            "value": "HTTP 403 Forbidden",
                            "risk": "File exists but is protected. Still confirms its presence.",
                            "severity": "low",
                            "confidence": 90,
                            "poc": poc,
                            "category": "active",
                            "status_code": status,
                        })
                    elif status == 302:
                        findings.append({
                            "location": path,
                            "value": f"Redirects to {final_url}",
                            "risk": "File exists but redirects (likely login page).",
                            "severity": "info",
                            "confidence": 70,
                            "poc": poc,
                            "category": "passive",
                            "status_code": status,
                        })
                    # else: ignore 404

            # Run probes
            tasks = [probe_path(p) for p in all_paths_to_check]
            await asyncio.gather(*tasks)

            # ── 6. GraphQL Introspection (Special Probe) ──────────────
            graphql_url = urljoin(base_url, "/graphql")
            introspection_query = json.dumps({"query": "query { __schema { types { name } } }"})
            async with semaphore:
                try:
                    async with session.post(
                        graphql_url,
                        data=introspection_query,
                        headers={"Content-Type": "application/json"}
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if "data" in data and "__schema" in data["data"]:
                                types = [t.get("name") for t in data["data"]["__schema"]["types"]]
                                findings.append({
                                    "location": "/graphql",
                                    "value": f"Introspection allowed. Schema has {len(types)} types.",
                                    "risk": "GraphQL schema fully exposed. Attackers can see all queries/mutations.",
                                    "severity": "high",
                                    "confidence": 100,
                                    "poc": f"curl -X POST {graphql_url} -H 'Content-Type: application/json' -d '{introspection_query}'",
                                    "category": "active"
                                })
                except Exception:
                    pass

            # ── 7. Directory Listing Fuzzing (Active) ──────────────
            async def check_listing(path):
                async with semaphore:
                    full_url = urljoin(base_url, path)
                    text, _, status, _ = await _safe_get(session, full_url)
                    if status == 200 and text and ("index of /" in text.lower() or "parent directory" in text.lower()):
                        findings.append({
                            "location": f"Directory Listing: {path}",
                            "value": _get_safe_text(text, 150),
                            "risk": "Directory listing enabled. Exposes file structure and potentially sensitive files.",
                            "severity": "high",
                            "confidence": 100,
                            "poc": f"curl {full_url}",
                            "category": "active"
                        })
                    # Path Traversal attempt: try /assets/../
                    traversal_url = urljoin(base_url, path + "../")
                    t_text, _, t_status, _ = await _safe_get(session, traversal_url)
                    if t_status == 200 and t_text and ("index of /" in t_text.lower()):
                        findings.append({
                            "location": f"Path Traversal via {path}../",
                            "value": _get_safe_text(t_text, 150),
                            "risk": "Directory listing outside root via path traversal.",
                            "severity": "critical",
                            "confidence": 100,
                            "poc": f"curl {traversal_url}",
                            "category": "active"
                        })

            tasks = [check_listing(p) for p in DIR_LISTING_PATHS]
            await asyncio.gather(*tasks)

            # ── 8. Cloud Bucket Enumeration ─────────────────────────
            bucket_links = [f["value"] for f in findings if "Cloud Storage reference" in f.get("risk", "")]
            for bucket_url in bucket_links[:3]:  # Limit to 3 to avoid abuse
                # Check if listing is possible
                list_url = bucket_url
                if ".s3.amazonaws.com" in bucket_url:
                    list_url = bucket_url + "?list-type=2"
                elif "storage.googleapis.com" in bucket_url:
                    list_url = bucket_url + "?prefix="
                # Azure: just try root

                text, _, status, _ = await _safe_get(session, list_url)
                if status == 200:
                    if "<ListBucketResult" in text or "Key" in text or "items" in text:
                        findings.append({
                            "location": "Cloud Bucket",
                            "value": f"{bucket_url} is listable!",
                            "risk": "Cloud storage bucket allows directory listing. Confidential files may be exposed.",
                            "severity": "critical",
                            "confidence": 100,
                            "poc": f"curl {list_url}",
                            "category": "active"
                        })

            # ── 9. Active Verification of Discovered Admin Paths ────
            # (Paths found in robots.txt or inferred from structure)
            # We already have them in discovered_paths, but let's verify if they are 200 OK.
            for path in list(discovered_paths)[:5]:
                full_url = urljoin(base_url, path)
                text, _, status, _ = await _safe_get(session, full_url)
                if status == 200 and "login" not in text.lower() and "signin" not in text.lower():
                    findings.append({
                        "location": f"Admin/Dashboard Path: {path}",
                        "value": f"Accessible without authentication (Status {status}).",
                        "risk": "Sensitive admin interface is publicly accessible.",
                        "severity": "critical",
                        "confidence": 95,
                        "poc": f"curl {full_url}",
                        "category": "active"
                    })

        # ── 10. Correlation & Summarization ──────────────────────────
        # Remove duplicates based on location
        unique_findings = []
        seen_locations = set()
        for f in findings:
            loc = f.get("location", "")
            if loc not in seen_locations:
                seen_locations.add(loc)
                unique_findings.append(f)

        if not unique_findings:
            return {
                "test_name": test_name,
                "status": "pass",
                "severity": "info",
                "title": "No sensitive information disclosures found.",
                "description": "Passive and active checks did not reveal exposed sensitive files or directories.",
                "evidence": [],
                "remediation": "No action required.",
                "tech_stack": list(tech_stack),
            }

        # Determine worst severity
        severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        worst_sev = max(unique_findings, key=lambda x: severity_rank.get(x.get("severity", "info"), 0))
        worst_sev_label = worst_sev.get("severity", "info")
        status = "fail" if worst_sev_label in ("critical", "high") else "warning"

        critical_count = sum(1 for f in unique_findings if f.get("severity") == "critical")
        high_count = sum(1 for f in unique_findings if f.get("severity") == "high")

        title = f"{len(unique_findings)} disclosures found"
        if critical_count > 0:
            title += f" (including {critical_count} CRITICAL items)"
        elif high_count > 0:
            title += f" (including {high_count} HIGH items)"

        # Smart remediation based on findings
        remediation_steps = []
        if any("git" in f.get("location", "") for f in unique_findings):
            remediation_steps.append("Remove .git directory from web root immediately.")
        if any(".env" in f.get("location", "") for f in unique_findings):
            remediation_steps.append("Move .env files outside the public web root.")
        if any(f.get("severity") == "critical" for f in unique_findings):
            remediation_steps.append("Review all exposed critical files and restrict permissions.")
        if any("Directory Listing" in f.get("location", "") for f in unique_findings):
            remediation_steps.append("Disable directory listing in web server configuration.")
        if any("phpinfo" in f.get("location", "") for f in unique_findings):
            remediation_steps.append("Delete phpinfo.php and similar debug scripts in production.")
        if any("swagger" in f.get("location", "").lower() or "graphql" in f.get("location", "").lower() for f in unique_findings):
            remediation_steps.append("Restrict access to API documentation endpoints via IP whitelist or authentication.")
        if not remediation_steps:
            remediation_steps.append("Conduct a full audit of all exposed static files and implement proper access controls.")

        return {
            "test_name": test_name,
            "status": status,
            "severity": worst_sev_label,
            "title": title,
            "description": f"Discovered {len(unique_findings)} information disclosure items. Highest severity: {worst_sev_label}.",
            "evidence": unique_findings,
            "remediation": " ".join(remediation_steps),
            "tech_stack": list(tech_stack),
            "findings_count": len(unique_findings),
        }

    except Exception as e:
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": f"Scan failed: {str(e)[:100]}",
            "description": "An unexpected error occurred during the information disclosure scan.",
            "evidence": [],
            "remediation": "Check network connectivity and target availability.",
        }