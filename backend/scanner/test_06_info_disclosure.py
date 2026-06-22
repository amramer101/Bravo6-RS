"""
test_06_info_disclosure.py — Fast Intelligence Gathering (Full Features)

All features from original 400-line version, optimized for speed:
- Header and cookie analysis
- 20+ sensitive paths (Git, Env, Backups, Configs, APIs)
- Dynamic backup filename generation
- GraphQL Introspection
- Path traversal detection
- Cloud bucket enumeration
- Smart severity classification
"""

import asyncio
import re
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

TEST_NAME = "information_disclosure"
USER_AGENT = "Bravo6-Scanner/1.0"
REQUEST_TIMEOUT = 8
MAX_CONCURRENT = 6
GLOBAL_TIMEOUT = 12

# ── Technology detection via cookies ──────────────────────────────────────
TECH_COOKIE_MAP = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java",
    "connect.sid": "Node.js",
    "laravel_session": "Laravel",
    "ASP.NET_SessionId": "ASP.NET",
    "wp-settings-": "WordPress",
}

# ── High-value sensitive paths (top 25) ──────────────────────────────────
PATHS = [
    ".git/HEAD", ".env", ".env.production", ".env.local",
    "backup.zip", "backup.tar.gz", "dump.sql", "db.sql",
    "composer.json", "package.json", "package-lock.json", "yarn.lock",
    "phpinfo.php", "info.php", "test.php", "config.php",
    "settings.py", "web.config", ".htaccess",
    "robots.txt", "sitemap.xml",
    "CHANGELOG.md", "VERSION", "RELEASE",
    "swagger-ui.html", "v3/api-docs", "api-docs",
    ".idea/workspace.xml", ".vscode/settings.json",
]

# ── Backup extensions (domain-aware) ──────────────────────────────────
BACKUP_EXTS = [".zip", ".tar.gz", ".tgz", ".sql", ".bak"]

# ── Directory listing test points ──────────────────────────────────────
DIR_LISTING = ["/assets/", "/static/", "/uploads/", "/files/"]

# ── Cloud Storage hosts ──────────────────────────────────────────────────
BUCKET_HOSTS = [".s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net"]


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = f"https://{url}"
    return url


def _extract_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc.split(":")[0]


def _get_safe_text(text: str, max_len: int = 200) -> str:
    if not text:
        return ""
    return text[:max_len] + ("..." if len(text) > max_len else "")


async def _safe_get(session, url, **kwargs) -> tuple:
    try:
        async with session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, ssl=False, **kwargs) as resp:
            text = await resp.text(errors="replace")
            return text, dict(resp.headers), resp.status, str(resp.url)
    except Exception:
        return None, None, None, None


async def _head_only(session, url) -> tuple:
    try:
        async with session.head(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, ssl=False) as resp:
            return resp.status, dict(resp.headers), str(resp.url)
    except Exception:
        return None, None, None


async def run(url: str) -> dict:
    try:
        target = _normalize_url(url)
        if not target:
            return {"test_name": TEST_NAME, "status": "error", "severity": "info", "evidence": [], "remediation": ""}

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        domain = _extract_domain(target)

        findings = []
        tech_stack = set()
        discovered_paths = set()

        connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT, limit_per_host=5)
        async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}, connector=connector) as session:

            # ── 1. Fetch root & detect technology ──────────────────────────
            root_text, root_headers, root_status, final_root_url = await _safe_get(session, target)

            if root_headers:
                for h in ["Server", "X-Powered-By", "X-Generator", "X-AspNet-Version"]:
                    val = root_headers.get(h)
                    if val:
                        findings.append({
                            "location": f"Header: {h}",
                            "value": val,
                            "risk": "Technology disclosure.",
                            "severity": "low",
                            "confidence": 100,
                            "poc": f"curl -I {target} | grep -i {h}",
                            "category": "passive"
                        })
                        tech_stack.add(val)

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

            # ── 2. Extract links from HTML ──────────────────────────────────
            if root_text:
                soup = BeautifulSoup(root_text, "html.parser")
                all_links = [urljoin(target, a.get("href", "")) for a in soup.find_all("a", href=True)]
                all_scripts = [urljoin(target, s.get("src", "")) for s in soup.find_all("script", src=True)]
                all_styles = [urljoin(target, l.get("href", "")) for l in soup.find_all("link", rel="stylesheet")]

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

            # ── 3. Build dynamic backup names ──────────────────────────────
            backup_names = []
            for ext in BACKUP_EXTS:
                backup_names.append(f"{domain}{ext}")
                backup_names.append(f"{domain}_backup{ext}")
                backup_names.append(f"backup_{domain}{ext}")

            all_paths = set(PATHS + backup_names)

            # ── 4. Parallel path probing ────────────────────────────────────
            semaphore = asyncio.Semaphore(MAX_CONCURRENT)
            probe_tasks = []

            async def probe_path(path):
                async with semaphore:
                    full_url = urljoin(base_url, path)
                    status, _, final_url = await _head_only(session, full_url)
                    if status is None:
                        return
                    fetch_body = False
                    if any(ext in path for ext in [".env", ".git/HEAD", ".sql", "composer.json", "package.json", "web.config", ".map", ".zip", ".tar.gz"]):
                        if status == 200:
                            fetch_body = True
                    body = None
                    if fetch_body:
                        body, _, _, _ = await _safe_get(session, full_url)

                    severity = "info"
                    risk = "File discovered."
                    confidence = 80
                    poc = f"curl {full_url}"

                    if status == 200:
                        if any(k in path for k in [".git", ".env", "dump.sql", "backup.zip", "backup.tar.gz", "composer.json", "web.config"]):
                            severity = "critical"
                            risk = "Extremely sensitive file exposed (source/credentials/database)."
                            confidence = 100
                        elif "api-docs" in path or "swagger" in path:
                            severity = "high"
                            risk = "API documentation exposed."
                            confidence = 95
                        elif "phpinfo" in path or "info.php" in path:
                            severity = "critical"
                            risk = "PHP Info exposed."
                            confidence = 100
                        elif "robots.txt" in path or "sitemap" in path:
                            severity = "low"
                            risk = "May expose hidden paths."
                            confidence = 90
                        elif "CHANGELOG" in path or "VERSION" in path or "RELEASE" in path:
                            severity = "medium"
                            risk = "Exact version disclosure."
                            confidence = 95
                        elif path.endswith(".map"):
                            severity = "high"
                            risk = "Source Map exposed."
                            confidence = 100
                        else:
                            severity = "medium"
                            risk = "Potentially sensitive file accessible."

                        evidence_value = path
                        if body and len(body) < 500:
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
                        })

                        if "admin" in path or "login" in path or "dashboard" in path:
                            discovered_paths.add(path)

                    elif status == 403:
                        findings.append({
                            "location": path,
                            "value": "HTTP 403 Forbidden",
                            "risk": "File exists but protected.",
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
                            "risk": "File exists but redirects.",
                            "severity": "info",
                            "confidence": 70,
                            "poc": poc,
                            "category": "passive",
                            "status_code": status,
                        })

            for p in all_paths:
                probe_tasks.append(probe_path(p))
            try:
                await asyncio.wait_for(asyncio.gather(*probe_tasks, return_exceptions=True), timeout=GLOBAL_TIMEOUT)
            except asyncio.TimeoutError:
                pass  # Partial results are fine

            # ── 5. GraphQL Introspection ────────────────────────────────────
            graphql_url = urljoin(base_url, "/graphql")
            try:
                async with semaphore:
                    async with session.post(
                        graphql_url,
                        json={"query": "query { __schema { types { name } } }"},
                        timeout=REQUEST_TIMEOUT
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if data.get("data", {}).get("__schema"):
                                findings.append({
                                    "location": "/graphql",
                                    "value": "Introspection allowed.",
                                    "risk": "GraphQL schema exposed.",
                                    "severity": "high",
                                    "confidence": 100,
                                    "poc": f"curl -X POST {graphql_url} -H 'Content-Type: application/json' -d '{{\"query\":\"query {{ __schema {{ types {{ name }} }} }}\"}}'",
                                    "category": "active"
                                })
            except:
                pass

            # ── 6. Directory listing ────────────────────────────────────────
            async def check_listing(path):
                async with semaphore:
                    full_url = urljoin(base_url, path)
                    text, _, status, _ = await _safe_get(session, full_url)
                    if status == 200 and text and ("index of /" in text.lower() or "parent directory" in text.lower()):
                        findings.append({
                            "location": f"Directory Listing: {path}",
                            "value": _get_safe_text(text, 150),
                            "risk": "Directory listing enabled.",
                            "severity": "high",
                            "confidence": 100,
                            "poc": f"curl {full_url}",
                            "category": "active"
                        })
                    # Path traversal
                    traversal_url = urljoin(base_url, path + "../")
                    t_text, _, t_status, _ = await _safe_get(session, traversal_url)
                    if t_status == 200 and t_text and ("index of /" in t_text.lower()):
                        findings.append({
                            "location": f"Path Traversal via {path}../",
                            "value": _get_safe_text(t_text, 150),
                            "risk": "Path traversal to root listing.",
                            "severity": "critical",
                            "confidence": 100,
                            "poc": f"curl {traversal_url}",
                            "category": "active"
                        })

            tasks = [check_listing(p) for p in DIR_LISTING]
            await asyncio.gather(*tasks, return_exceptions=True)

            # ── 7. Cloud Bucket enumeration ─────────────────────────────────
            bucket_links = [f["value"] for f in findings if "Cloud Storage" in f.get("risk", "")]
            for bucket_url in bucket_links[:2]:
                list_url = bucket_url
                if ".s3.amazonaws.com" in bucket_url:
                    list_url = bucket_url + "?list-type=2"
                elif "storage.googleapis.com" in bucket_url:
                    list_url = bucket_url + "?prefix="
                text, _, status, _ = await _safe_get(session, list_url)
                if status == 200 and ("ListBucketResult" in text or "Key" in text):
                    findings.append({
                        "location": "Cloud Bucket",
                        "value": f"{bucket_url} is listable!",
                        "risk": "Cloud bucket allows directory listing.",
                        "severity": "critical",
                            "confidence": 100,
                            "poc": f"curl {list_url}",
                            "category": "active"
                        })

        # ── 8. Summarize ──────────────────────────────────────────────────
        unique_findings = []
        seen_locations = set()
        for f in findings:
            loc = f.get("location", "")
            if loc not in seen_locations:
                seen_locations.add(loc)
                unique_findings.append(f)

        if not unique_findings:
            return {
                "test_name": TEST_NAME,
                "status": "pass",
                "severity": "info",
                "title": "No sensitive files found",
                "description": "No exposed sensitive files or directories detected.",
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
            title += f" (including {critical_count} CRITICAL)"
        elif high_count > 0:
            title += f" (including {high_count} HIGH)"

        # Remediation
        remediation_steps = []
        if any("git" in f.get("location", "") for f in unique_findings):
            remediation_steps.append("Remove .git directory from web root.")
        if any(".env" in f.get("location", "") for f in unique_findings):
            remediation_steps.append("Move .env files outside public web root.")
        if any(f.get("severity") == "critical" for f in unique_findings):
            remediation_steps.append("Review all exposed critical files and restrict permissions.")
        if any("Directory Listing" in f.get("location", "") for f in unique_findings):
            remediation_steps.append("Disable directory listing.")
        if any("phpinfo" in f.get("location", "") for f in unique_findings):
            remediation_steps.append("Delete phpinfo.php and similar debug scripts.")
        if any("swagger" in f.get("location", "").lower() or "graphql" in f.get("location", "").lower() for f in unique_findings):
            remediation_steps.append("Restrict access to API documentation endpoints.")
        if not remediation_steps:
            remediation_steps.append("Implement proper access controls on static files.")

        return {
            "test_name": TEST_NAME,
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
            "test_name": TEST_NAME,
            "status": "error",
            "severity": "info",
            "title": f"Scan failed: {str(e)[:100]}",
            "description": "An unexpected error occurred.",
            "evidence": [],
            "remediation": "Check network connectivity and target availability.",
        }