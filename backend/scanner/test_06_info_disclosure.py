"""
test_06_info_disclosure.py — Advanced Info Disclosure (Active Exploit Check)

Upgraded:
- Actively fetches .git/HEAD, .env, robots.txt.
- Confirms if .git is exposed -> CRITICAL (100% confidence) with git clone command.
- Checks for exposed env variables.
- Adds confidence scoring and PoC for every finding.
"""

import asyncio
import re
from urllib.parse import urljoin, urlparse

import aiohttp

USER_AGENT = "Bravo6-Scanner/1.0"
REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=8)
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

INFO_HEADERS = {
    "server": "high",
    "x-powered-by": "high",
    "x-aspnet-version": "medium",
    "x-generator": "medium",
}
COMMENT_FLAG_KEYWORDS = ("todo", "fixme", "password", "secret", "api_key", "debug")
STACK_TRACE_MARKERS = ("traceback", "stack trace", "fatal error", "uncaught exception")
FRAMEWORK_VERSION_MARKERS = ("django", "flask", "express", "laravel", "rails", "asp.net")


def _normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "https://" + url
    return url


async def _safe_get(session, url):
    try:
        async with session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, ssl=False) as resp:
            text = await resp.text(errors="replace")
            return text, dict(resp.headers), resp.status
    except:
        return None, None, None


async def run(url: str) -> dict:
    test_name = "information_disclosure"
    try:
        target = _normalize_url(url)
        parsed = urlparse(target)
        if not parsed.netloc:
            return {"test_name": test_name, "status": "error", "evidence": []}
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
            all_findings = []

            # 1. Root page
            root_text, root_headers, _ = await _safe_get(session, base_url)
            if root_headers:
                # Headers
                for h, sev in INFO_HEADERS.items():
                    val = root_headers.get(h, "")
                    if val:
                        all_findings.append({
                            "location": f"Header: {h}",
                            "value": val,
                            "risk": "Technology/version leaked",
                            "severity": sev,
                            "confidence": 100,
                            "poc": f"curl -I {base_url} | grep -i {h}"
                        })
                # Comments
                if root_text:
                    for match in re.finditer(r"<!--(.*?)-->", root_text, re.DOTALL):
                        comment = match.group(1)
                        if any(kw in comment.lower() for kw in COMMENT_FLAG_KEYWORDS):
                            all_findings.append({
                                "location": "HTML Comment",
                                "value": f"<!--{comment[:100]}...-->",
                                "risk": "Sensitive note/credential in comment",
                                "severity": "medium",
                                "confidence": 90,
                                "poc": "View page source (Ctrl+U) and search for 'TODO' or 'password'."
                            })

            # 2. .git/HEAD (CRITICAL)
            git_url = urljoin(base_url, "/.git/HEAD")
            git_text, _, git_status = await _safe_get(session, git_url)
            if git_status == 200 and git_text and "ref: refs/heads/" in git_text:
                all_findings.append({
                    "location": "/.git/HEAD",
                    "value": git_text.strip(),
                    "risk": "GIT REPOSITORY EXPOSED! Full source code can be downloaded.",
                    "severity": "critical",
                    "confidence": 100,
                    "poc": f"git clone {base_url}/.git (or use tools like GitHack)"
                })

            # 3. .env (CRITICAL)
            env_url = urljoin(base_url, "/.env")
            env_text, _, env_status = await _safe_get(session, env_url)
            if env_status == 200 and env_text:
                if "DB_" in env_text or "PASSWORD" in env_text or "API_KEY" in env_text:
                    all_findings.append({
                        "location": "/.env",
                        "value": env_text[:200] + "...",
                        "risk": "ENVIRONMENT FILE EXPOSED! Contains database credentials, API keys.",
                        "severity": "critical",
                        "confidence": 100,
                        "poc": f"cat {base_url}/.env"
                    })

            # 4. robots.txt & sitemap (info disclosure)
            for path in ["/robots.txt", "/sitemap.xml"]:
                txt, _, st = await _safe_get(session, urljoin(base_url, path))
                if st == 200 and txt:
                    all_findings.append({
                        "location": path,
                        "value": txt[:150],
                        "risk": "Discloses hidden admin paths or site structure.",
                        "severity": "low",
                        "confidence": 100,
                        "poc": f"curl {base_url}{path}"
                    })

            # 5. 404 error details
            error_url = urljoin(base_url, "/bravo6-test-404-xyz")
            err_text, _, err_st = await _safe_get(session, error_url)
            if err_st >= 400 and err_text:
                lowered = err_text.lower()
                if any(m in lowered for m in STACK_TRACE_MARKERS):
                    all_findings.append({
                        "location": "404 Error Page",
                        "value": "Stack trace detected",
                        "risk": "Verbose error page exposes internal paths or framework details.",
                        "severity": "high",
                        "confidence": 90,
                        "poc": f"curl {base_url}/non-existent-page"
                    })

            # 6. Directory listing checks
            for path in ["/images/", "/assets/", "/static/"]:
                dtext, _, dstatus = await _safe_get(session, urljoin(base_url, path))
                if dstatus == 200 and dtext and "index of /" in dtext.lower():
                    all_findings.append({
                        "location": f"Directory Listing ({path})",
                        "value": dtext[:100],
                        "risk": "Directory listing enabled, exposing file structure.",
                        "severity": "high",
                        "confidence": 100,
                        "poc": f"curl {base_url}{path}"
                    })

            # Calculate severity
            if not all_findings:
                return {"test_name": test_name, "status": "pass", "severity": "info", "evidence": [], "remediation": "No action needed."}

            worst_sev = max((f["severity"] for f in all_findings), key=lambda x: _SEVERITY_RANK.get(x, 0))
            status = "fail" if _SEVERITY_RANK.get(worst_sev, 0) >= 3 else "warning"

            return {
                "test_name": test_name,
                "status": status,
                "severity": worst_sev,
                "title": f"{len(all_findings)} Information Disclosure Findings",
                "description": f"Found {len(all_findings)} issues, highest severity: {worst_sev}.",
                "evidence": all_findings,
                "remediation": "Remove .git directory, .env files, disable directory listing, custom error pages.",
                "findings_count": len(all_findings),
            }

    except Exception as e:
        return {"test_name": test_name, "status": "error", "title": f"Error: {e}", "evidence": []}