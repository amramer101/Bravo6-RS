#!/usr/bin/env python3
"""
test_06_info_disclosure.py - Bravo6 Info Disclosure Scanner (v14.0)
=====================================================================
Complete rewrite addressing all issues found in v13.0 results:
  - global requests_made -> per-scan ScanContext
  - one exception could wipe all findings -> each phase isolated
  - 403 noise (46 findings) -> aggregated to a single info finding
  - path budget too small -> min(60s, paths*0.15s) with per-batch waits
  - hardcoded backup years -> dynamic pattern generation
  - robots.txt -> sensitive-path detection, no dual UA probing
  - GraphQL introspection -> explicit Content-Type, GET + POST
  - HTML comments -> noise/interest pattern split
  - tech stack -> single aggregated finding
  - Forbidden findings -> grouped into one aggregate finding

Complies with BRAVO6 UNIFIED PLUGIN CONTRACT - SHARED RULES v2.2:
  - 10-field unified finding schema (+ raw_data)
  - strict severity rules (200/403/404/401/500 handling)
  - mandatory aggregation of repeated patterns
  - scoring v2 (sqrt-dampened, A-F grade)
  - per-phase error isolation
"""
import asyncio
import hashlib
import json
import math
import re
import sys
import time
import traceback
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp

# -- Constants ----------------------------------------------------------------------------
SCANNER_NAME = "test_06_info_disclosure"
USER_AGENT = "Bravo6-InfoDisclosure/14.0"

REQUEST_TIMEOUT_SECONDS = 10
MAX_RESPONSE_SIZE_TEXT = 5 * 1024 * 1024   # 5MB
MAX_RESPONSE_SIZE_JSON = 1 * 1024 * 1024   # 1MB
CONN_POOL_LIMIT_PER_HOST = 50
CACHE_TTL_SECONDS = 300

PATH_SEMAPHORE_SIZE = 20
PATH_BATCH_SIZE = 20
PATH_TIMEOUT_PER_REQUEST = 5
PATH_PROBE_MAX_BUDGET_SECONDS = 60
PATH_PROBE_BUDGET_PER_PATH = 0.15
MIN_PATHS_BEFORE_GIVEUP = 50
CONSECUTIVE_404_THRESHOLD = 20

SEVERITY_WEIGHTS = {"critical": 50, "high": 20, "medium": 5, "low": 1, "info": 0}
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

CWE_MAP = {
    "sensitive_file": "CWE-538",
    "graphql": "CWE-200",
    "robots": "CWE-200",
    "comment": "CWE-615",
    "tech_disclosure": "CWE-200",
}
OWASP_MAP = {
    "sensitive_file": "A01:2021",
    "graphql": "A01:2021",
    "robots": "A05:2021",
    "comment": "A01:2021",
    "tech_disclosure": "A05:2021",
}

# -- Path catalogue -------------------------------------------------------------------------
# Severity/confidence lookup for explicitly named sensitive paths (requirement 11).
STATIC_SENSITIVE_PATHS: Dict[str, Tuple[str, int]] = {
    ".env": ("critical", 90), ".env.local": ("critical", 90), ".env.production": ("critical", 90),
    ".env.staging": ("critical", 85), ".env.bak": ("critical", 85), ".env.old": ("critical", 80),
    ".env.save": ("critical", 80),
    ".git/HEAD": ("high", 85), ".git/config": ("high", 80), ".svn/entries": ("medium", 60),
    "wp-config.php": ("critical", 90), "wp-config.php.bak": ("critical", 85),
    "wp-config.php.save": ("critical", 85), "wp-config.php~": ("critical", 85),
    ".htpasswd": ("critical", 90), ".htaccess": ("medium", 55),
    "phpinfo.php": ("critical", 90), "info.php": ("high", 80), "test.php": ("medium", 55),
    "config.php": ("critical", 85), "adminer.php": ("high", 85),
    ".vscode/settings.json": ("high", 75), ".idea/workspace.xml": ("high", 75),
    "composer.json": ("info", 50), "package.json": ("info", 50),
}

EXPLICIT_SENSITIVE_PATHS = list(STATIC_SENSITIVE_PATHS.keys())

BACKUP_EXTENSIONS = [".sql", ".bak", ".zip", ".tar.gz", ".dump", ".old", ".orig", ".swp", ".tmp"]
BACKUP_STEMS = ["backup", "dump", "db", "data", "config", "settings"]

# -- Tech fingerprinting (kept from prior version, still accurate) --------------------------
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

GRAPHQL_ENDPOINTS = ["/graphql", "/api/graphql", "/graphql/console", "/v1/graphql"]
INTROSPECTION_QUERY = "{__schema{types{name}}}"

SENSITIVE_ROBOTS_PREFIXES = ["/admin", "/wp-admin", "/api", "/internal", "/debug"]

COMMENT_NOISE_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r'copyright', r'license', r'generated by', r'wordpress', r'drupal', r'joomla',
    r'<!doctype', r'<html', r'<head',
]]
COMMENT_INTEREST_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r'\bTODO\b', r'\bFIXME\b', r'\bHACK\b', r'\bXXX\b', r'\bBUG\b',
    r'password', r'secret', r'\bkey\b', r'token', r'\bapi\b', r'internal',
    r'staging', r'\bdev\b', r'admin', r'\broot\b', r'database', r'credentials',
]]


# -- Small helpers --------------------------------------------------------------------------
def _normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/") + "/"


def _get_header(headers: Dict[str, str], name: str) -> Optional[str]:
    for key, val in (headers or {}).items():
        if key.lower() == name.lower():
            return val
    return None


def _domain_part(hostname: str) -> str:
    if not hostname:
        return "site"
    return hostname.split(".")[0]


def _log_debug(msg: str) -> None:
    print(f"[{SCANNER_NAME}] DEBUG: {msg}", file=sys.stderr)


# -- Unified finding schema (10 fields + raw_data) -------------------------------------------
def make_finding(title: str, severity: str, confidence: int, evidence: str,
                  poc: str = "", remediation: str = "", detection_method: str = "pattern_match",
                  cwe: str = "", owasp: str = "", raw_data: Optional[Dict[str, Any]] = None,
                  module: str = SCANNER_NAME) -> Dict[str, Any]:
    return {
        "id": str(uuid.uuid4())[:12],
        "module": module,
        "title": title[:80],
        "severity": severity,
        "confidence": max(0, min(100, int(confidence))),
        "cwe": cwe,
        "owasp": owasp,
        "evidence": (evidence or "")[:500],
        "poc": poc or "Manual verification required.",
        "remediation": remediation or "Review exposure and restrict access if unintended.",
        "detection_method": detection_method,
        "raw_data": raw_data or {},
    }


# -- Per-scan context (fixes global requests_made) -------------------------------------------
@dataclass
class ScanContext:
    target: str
    base_url: str
    hostname: str
    session: aiohttp.ClientSession
    semaphore: asyncio.Semaphore
    requests_made: int = 0
    cache: Dict[str, Tuple[float, Dict[str, Any]]] = field(default_factory=dict)
    cache_hits: int = 0
    cache_misses: int = 0
    errors: List[Dict[str, str]] = field(default_factory=list)
    start_time: float = field(default_factory=time.monotonic)

    def record_error(self, phase: str, exc: Exception) -> None:
        self.errors.append({
            "phase": phase,
            "error": str(exc),
            "type": type(exc).__name__,
            "traceback": traceback.format_exc(limit=3)[-800:],
        })
        _log_debug(f"Phase '{phase}' failed: {exc}")


def _cache_key(url: str, module: str, params: Optional[Dict[str, Any]] = None) -> str:
    params_hash = hashlib.sha256(json.dumps(params or {}, sort_keys=True, default=str).encode()).hexdigest()[:16]
    raw = f"{url}|{module}|{params_hash}"
    return hashlib.sha256(raw.encode()).hexdigest()


async def fetch(ctx: ScanContext, url: str, module: str, method: str = "GET",
                 params: Optional[Dict[str, Any]] = None, json_body: Optional[Dict[str, Any]] = None,
                 headers: Optional[Dict[str, str]] = None, is_json: bool = False,
                 timeout_seconds: float = PATH_TIMEOUT_PER_REQUEST) -> Dict[str, Any]:
    """Cached, size-limited, semaphore-bound HTTP fetch. Never raises."""
    key = _cache_key(url, module, {"method": method, "params": params, "json": json_body})
    now = time.monotonic()
    cached = ctx.cache.get(key)
    if cached and (now - cached[0]) < CACHE_TTL_SECONDS:
        ctx.cache_hits += 1
        return cached[1]
    ctx.cache_misses += 1

    result: Dict[str, Any] = {"status": None, "headers": {}, "body": "", "error": None}
    req_headers = {"User-Agent": USER_AGENT}
    if headers:
        req_headers.update(headers)

    async with ctx.semaphore:
        ctx.requests_made += 1
        try:
            timeout = aiohttp.ClientTimeout(total=timeout_seconds)
            async with ctx.session.request(method, url, params=params, json=json_body,
                                            headers=req_headers, timeout=timeout,
                                            allow_redirects=True) as resp:
                result["status"] = resp.status
                result["headers"] = dict(resp.headers)
                max_size = MAX_RESPONSE_SIZE_JSON if is_json else MAX_RESPONSE_SIZE_TEXT
                raw = await resp.content.read(max_size)
                try:
                    result["body"] = raw.decode(resp.get_encoding() or "utf-8", errors="replace")
                except Exception:
                    result["body"] = raw.decode("utf-8", errors="replace")
        except asyncio.TimeoutError:
            result["error"] = "timeout"
        except (aiohttp.ClientError, ConnectionError, OSError) as e:
            result["error"] = str(e)

    ctx.cache[key] = (now, result)
    return result


# -- Path generation (requirement 5: no hardcoded years) -------------------------------------
def generate_paths(hostname: str) -> List[str]:
    base = _domain_part(hostname)
    stems = list(dict.fromkeys([base] + BACKUP_STEMS))  # dedup, keep order
    paths = set(EXPLICIT_SENSITIVE_PATHS)
    for stem in stems:
        for ext in BACKUP_EXTENSIONS:
            paths.add(f"{stem}{ext}")
    return sorted(paths)


# -- Content verification (requirement 3: distinguish real exposure from noise) --------------
def content_verified_sensitive(path: str, body: str) -> bool:
    if not body:
        return False
    p = path.lower()
    if p in ("phpinfo.php", "info.php"):
        return "phpinfo()" in body.lower() or "php version" in body.lower()
    if p == ".git/head":
        stripped = body.strip()
        return stripped.startswith("ref:") or bool(re.match(r'^[0-9a-f]{40}', stripped))
    if p == ".git/config":
        return "[core]" in body
    if p.startswith(".env"):
        return bool(re.search(r'^[A-Z_]{2,}\s*=', body, re.MULTILINE))
    if "wp-config.php" in p or p == "config.php":
        return ("DB_PASSWORD" in body or "define(" in body
                or bool(re.search(r'\$db|mysqli_connect|PDO\(', body, re.IGNORECASE)))
    if p == ".htpasswd":
        return bool(re.search(r'^[^:\s]+:\$?\w', body, re.MULTILINE))
    if p == "adminer.php":
        return "adminer" in body.lower()
    if p in ("composer.json", "package.json"):
        return '"name"' in body or '"require"' in body
    return len(body) > 20


# -- Phase 1: Technology detection (requirement 9: ONE finding) -------------------------------
async def phase_tech_detection(ctx: ScanContext) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    resp = await fetch(ctx, ctx.base_url, "tech_detection", timeout_seconds=REQUEST_TIMEOUT_SECONDS)
    html = resp.get("body", "") or ""
    headers = resp.get("headers", {}) or {}
    technologies = set()

    for hname, sigmap in HEADER_FINGERPRINTS.items():
        hval = _get_header(headers, hname) or ""
        for needle, tech in sigmap.items():
            if needle.lower() in hval.lower():
                technologies.add(tech)

    set_cookie = _get_header(headers, "Set-Cookie") or ""
    for needle, tech in TECH_COOKIES.items():
        if needle.lower() in set_cookie.lower():
            technologies.add(tech)

    for tech, patterns in HTML_TECH_SIGNATURES.items():
        if any(re.search(pat, html, re.IGNORECASE) for pat in patterns):
            technologies.add(tech)

    wp_match = re.search(r'content=["\']WordPress\s+([\d.]+)["\']', html, re.IGNORECASE)
    if wp_match:
        technologies.discard("WordPress")
        technologies.add(f"WordPress {wp_match.group(1)}")

    tech_list = sorted(technologies)
    if tech_list:
        findings.append(make_finding(
            title="Technology stack identified",
            severity="info", confidence=80,
            evidence=f"Detected: {', '.join(tech_list)}",
            poc=f"curl -sI {ctx.base_url}",
            remediation="Consider suppressing version-revealing headers (Server, X-Powered-By) in production.",
            detection_method="header_html_cookie_fingerprint",
            cwe=CWE_MAP["tech_disclosure"], owasp=OWASP_MAP["tech_disclosure"],
            raw_data={"technologies": tech_list},
        ))

    details = {"status": resp.get("status"), "technologies": tech_list, "html": html, "headers": headers}
    return findings, details


# -- Phase 2: Path probing (requirements 1,3,4,5,10,11,12,13) ---------------------------------
async def phase_path_probing(ctx: ScanContext) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    paths = generate_paths(ctx.hostname)
    total = len(paths)
    budget = min(PATH_PROBE_MAX_BUDGET_SECONDS, total * PATH_PROBE_BUDGET_PER_PATH)

    checked = 0
    consecutive_404 = 0
    high_404_rate = False
    accessible: List[Dict[str, Any]] = []
    forbidden: List[Dict[str, Any]] = []
    unauthorized: List[Dict[str, Any]] = []
    server_errors: List[Dict[str, Any]] = []
    batch_sem = asyncio.Semaphore(PATH_SEMAPHORE_SIZE)
    partial = False
    note = ""
    start = time.monotonic()

    async def probe_one(path: str) -> None:
        nonlocal checked, consecutive_404, high_404_rate
        url = urljoin(ctx.base_url, path)
        async with batch_sem:
            resp = await fetch(ctx, url, "path_probing", timeout_seconds=PATH_TIMEOUT_PER_REQUEST)
        checked += 1
        status = resp.get("status")
        body = resp.get("body", "") or ""

        if status is None or status == 404:
            consecutive_404 += 1
            if consecutive_404 > CONSECUTIVE_404_THRESHOLD:
                high_404_rate = True
            return
        consecutive_404 = 0

        if status == 200:
            verified = content_verified_sensitive(path, body)
            base_sev, base_conf = STATIC_SENSITIVE_PATHS.get(path, ("medium", 55))
            sev = base_sev
            if not verified and sev in ("critical", "high"):
                sev = "medium"
            accessible.append({
                "path": path, "url": url, "severity": sev, "confidence": base_conf,
                "verified": verified, "size": len(body),
            })
        elif status == 403:
            forbidden.append({"path": path, "url": url})
        elif status == 401:
            unauthorized.append({"path": path, "url": url})
        elif status == 500:
            server_errors.append({"path": path, "url": url})
        # any other status: not reported (out of scope for this scanner)

    for i in range(0, total, PATH_BATCH_SIZE):
        batch = paths[i:i + PATH_BATCH_SIZE]
        elapsed = time.monotonic() - start
        remaining = budget - elapsed

        if remaining <= 0 and checked >= MIN_PATHS_BEFORE_GIVEUP:
            partial = True
            note = f"Path probing budget reached; checked {checked}/{total} paths."
            break

        per_batch_timeout = remaining if remaining > 0 else PATH_TIMEOUT_PER_REQUEST * 2
        try:
            await asyncio.wait_for(
                asyncio.gather(*(probe_one(p) for p in batch)),
                timeout=per_batch_timeout,
            )
        except asyncio.TimeoutError:
            if checked >= MIN_PATHS_BEFORE_GIVEUP:
                partial = True
                note = f"Path probing incomplete due to time budget. Checked {checked}/{total} paths."
                break
            # keep going until the floor of 50 paths is met even if over budget

    findings: List[Dict[str, Any]] = []

    # Individually report real, actionable exposures.
    for item in accessible:
        sev = item["severity"]
        conf = item["confidence"] + (10 if item["verified"] else 0)
        findings.append(make_finding(
            title=f"Accessible sensitive file: {item['path']}",
            severity=sev, confidence=conf,
            evidence=(f"HTTP 200, {item['size']} bytes at {item['path']}"
                      + (" (content verified sensitive)" if item["verified"] else " (content not confirmed)")),
            poc=f"curl -s {item['url']}",
            remediation="Remove or restrict access to this file; rotate any exposed credentials immediately.",
            detection_method="path_probe_200",
            cwe=CWE_MAP["sensitive_file"], owasp=OWASP_MAP["sensitive_file"],
            raw_data={"path": item["path"], "url": item["url"], "response_status": 200,
                      "response_size": item["size"], "content_verified": item["verified"]},
        ))

    # Aggregate noise-prone status codes into single findings (requirement 3 & 10).
    def _aggregate(entries: List[Dict[str, Any]], code_label: str, method: str) -> Optional[Dict[str, Any]]:
        if not entries:
            return None
        sample_paths = [e["path"] for e in entries[:10]]
        suffix = ", ..." if len(entries) > 10 else ""
        return make_finding(
            title=f"Multiple sensitive paths return {code_label} ({len(entries)} paths)",
            severity="info", confidence=60 if high_404_rate else 70,
            evidence=f"{len(entries)} paths tested: {', '.join(sample_paths)}{suffix}",
            poc=f"curl -I {entries[0]['url']}",
            remediation=("No action required; paths are protected." if code_label != "HTTP 500" else
                         "Investigate server errors; may indicate fragile input handling."),
            detection_method=method,
            raw_data={"affected_paths": [e["path"] for e in entries], "count": len(entries)},
        )

    for agg in (
        _aggregate(forbidden, "HTTP 403", "path_probe_403_aggregate"),
        _aggregate(unauthorized, "HTTP 401", "path_probe_401_aggregate"),
        _aggregate(server_errors, "HTTP 500", "path_probe_500_aggregate"),
    ):
        if agg:
            findings.append(agg)

    details = {
        "paths_checked": checked, "paths_total": total, "partial": partial, "note": note,
        "accessible_count": len(accessible), "forbidden_count": len(forbidden),
        "unauthorized_count": len(unauthorized), "server_error_count": len(server_errors),
        "high_404_rate": high_404_rate, "budget_seconds": round(budget, 2),
    }
    return findings, details


# -- Phase 3: robots.txt analysis (requirement 6) ---------------------------------------------
async def phase_robots_analysis(ctx: ScanContext) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    url = urljoin(ctx.base_url, "/robots.txt")
    resp = await fetch(ctx, url, "robots_analysis", timeout_seconds=REQUEST_TIMEOUT_SECONDS)

    if resp.get("status") != 200 or not resp.get("body"):
        return findings, {"robots_found": False}

    body = resp["body"]
    disallow = re.findall(r'^\s*Disallow:\s*(\S+)', body, re.IGNORECASE | re.MULTILINE)
    allow = re.findall(r'^\s*Allow:\s*(\S+)', body, re.IGNORECASE | re.MULTILINE)
    all_paths = disallow + allow
    sensitive_hits = [p for p in all_paths if any(p.lower().startswith(pre) for pre in SENSITIVE_ROBOTS_PREFIXES)]

    if sensitive_hits:
        findings.append(make_finding(
            title="robots.txt discloses sensitive paths",
            severity="medium", confidence=65,
            evidence=f"robots.txt references: {', '.join(sensitive_hits[:10])}",
            poc=f"curl -s {url}",
            remediation="Avoid listing sensitive paths in robots.txt; enforce access control server-side instead.",
            detection_method="robots_txt_parse",
            cwe=CWE_MAP["robots"], owasp=OWASP_MAP["robots"],
            raw_data={"sensitive_paths": sensitive_hits, "disallow": disallow, "allow": allow},
        ))
    else:
        findings.append(make_finding(
            title="robots.txt present with only standard paths",
            severity="info", confidence=70,
            evidence=f"{len(all_paths)} path(s) listed; none matched sensitive prefixes.",
            poc=f"curl -s {url}",
            remediation="No action required.",
            detection_method="robots_txt_parse",
            raw_data={"disallow": disallow, "allow": allow},
        ))

    return findings, {"robots_found": True, "paths_count": len(all_paths), "sensitive_count": len(sensitive_hits)}


# -- Phase 4: GraphQL introspection (requirement 7) -------------------------------------------
async def phase_api_probing(ctx: ScanContext) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    tried = []

    for ep in GRAPHQL_ENDPOINTS:
        url = urljoin(ctx.base_url, ep.lstrip("/"))
        get_url = f"{url}?query={INTROSPECTION_QUERY}"
        tried.append(ep)

        get_resp = await fetch(ctx, get_url, "graphql_get", is_json=True,
                                timeout_seconds=REQUEST_TIMEOUT_SECONDS)
        post_resp = await fetch(ctx, url, "graphql_post", method="POST",
                                 json_body={"query": INTROSPECTION_QUERY},
                                 headers={"Content-Type": "application/json"},
                                 is_json=True, timeout_seconds=REQUEST_TIMEOUT_SECONDS)

        for label, resp in (("GET", get_resp), ("POST", post_resp)):
            body = resp.get("body", "") or ""
            if resp.get("status") == 200 and "__schema" in body and '"types"' in body:
                findings.append(make_finding(
                    title=f"GraphQL introspection enabled at {ep}",
                    severity="high", confidence=90,
                    evidence=f"{label} introspection query returned schema data at {ep}",
                    poc=(f"curl -s '{get_url}'" if label == "GET" else
                         f"curl -s -X POST {url} -H 'Content-Type: application/json' "
                         f"-d '{{\"query\":\"{INTROSPECTION_QUERY}\"}}'"),
                    remediation="Disable GraphQL introspection in production deployments.",
                    detection_method="graphql_introspection",
                    cwe=CWE_MAP["graphql"], owasp=OWASP_MAP["graphql"],
                    raw_data={"endpoint": ep, "method": label},
                ))
                break  # one finding per endpoint

    return findings, {"endpoints_tried": tried}


# -- Phase 5: HTML comment analysis (requirement 8) -------------------------------------------
def phase_comment_analysis(html: str, base_url: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not html:
        return findings, {"comments_scanned": 0, "interesting_count": 0}

    comments = re.findall(r"<!--[\s\S]*?-->", html)
    interesting = []
    for c in comments:
        if any(p.search(c) for p in COMMENT_NOISE_PATTERNS):
            continue
        if any(p.search(c) for p in COMMENT_INTEREST_PATTERNS):
            interesting.append(c.strip()[:200])

    if interesting:
        findings.append(make_finding(
            title=f"Sensitive-looking HTML comments found ({len(interesting)})",
            severity="medium", confidence=55,
            evidence="; ".join(interesting[:5]),
            poc=f"curl -s {base_url} | grep -oE '<!--[^>]*-->'",
            remediation="Remove developer comments with internal notes, credentials, or debug markers before deploying.",
            detection_method="html_comment_scan",
            cwe=CWE_MAP["comment"], owasp=OWASP_MAP["comment"],
            raw_data={"comments": interesting, "count": len(interesting)},
        ))

    return findings, {"comments_scanned": len(comments), "interesting_count": len(interesting)}


# -- Aggregation / dedup (shared rules 3 & 7) --------------------------------------------------
def dedup_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    unique = []
    for f in findings:
        key = (f["title"], f["severity"], f["evidence"][:100])
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    return unique


# -- Scoring v2 (shared rule 5) -----------------------------------------------------------------
def compute_score(findings: List[Dict[str, Any]]) -> Tuple[int, int, str]:
    raw_score = sum(SEVERITY_WEIGHTS.get(f["severity"], 0) for f in findings)
    dampened = int(math.sqrt(raw_score) * 5) if raw_score > 0 else 0
    dampened = min(dampened, 100)
    if dampened >= 85:
        grade = "A"
    elif dampened >= 70:
        grade = "B"
    elif dampened >= 50:
        grade = "C"
    elif dampened >= 30:
        grade = "D"
    else:
        grade = "F"
    return raw_score, dampened, grade


# -- Orchestration ------------------------------------------------------------------------------
async def run(target_url: str, min_confidence: int = 0) -> Dict[str, Any]:
    """Run all phases with per-phase error isolation; never returns empty findings
    because of a single phase crash."""
    base_url = _normalize_url(target_url)
    parsed = urlparse(base_url)
    hostname = parsed.hostname or ""

    findings: List[Dict[str, Any]] = []
    phase_details: Dict[str, Any] = {}
    partial_phases: List[str] = []

    try:
        connector = aiohttp.TCPConnector(limit_per_host=CONN_POOL_LIMIT_PER_HOST)
        async with aiohttp.ClientSession(connector=connector) as session:
            ctx = ScanContext(
                target=target_url, base_url=base_url, hostname=hostname,
                session=session, semaphore=asyncio.Semaphore(PATH_SEMAPHORE_SIZE),
            )

            html = ""

            # Phase 1: tech detection
            try:
                f, d = await phase_tech_detection(ctx)
                findings.extend(f)
                phase_details["tech_detection"] = {k: v for k, v in d.items() if k != "html"}
                html = d.get("html", "")
            except Exception as e:
                ctx.record_error("tech_detection", e)

            # Phase 2: path probing
            try:
                f, d = await phase_path_probing(ctx)
                findings.extend(f)
                phase_details["path_probing"] = d
                if d.get("partial"):
                    partial_phases.append("path_probing")
            except Exception as e:
                ctx.record_error("path_probing", e)

            # Phase 3: robots.txt
            try:
                f, d = await phase_robots_analysis(ctx)
                findings.extend(f)
                phase_details["robots_analysis"] = d
            except Exception as e:
                ctx.record_error("robots_analysis", e)

            # Phase 4: GraphQL / API probing
            try:
                f, d = await phase_api_probing(ctx)
                findings.extend(f)
                phase_details["api_probing"] = d
            except Exception as e:
                ctx.record_error("api_probing", e)

            # Phase 5: HTML comment analysis (reuses homepage HTML, no extra request)
            try:
                f, d = phase_comment_analysis(html, base_url)
                findings.extend(f)
                phase_details["comment_analysis"] = d
            except Exception as e:
                ctx.record_error("comment_analysis", e)

            findings = dedup_findings(findings)
            findings = [f for f in findings if f["confidence"] >= min_confidence]
            raw_score, dampened_score, grade = compute_score(findings)

            return {
                "findings": findings,
                "score_raw": raw_score,
                "score_dampened": dampened_score,
                "grade": grade,
                "errors": ctx.errors,
                "details": {
                    **phase_details,
                    "partial_phases": partial_phases,
                    "requests_made": ctx.requests_made,
                    "cache_hits": ctx.cache_hits,
                    "cache_misses": ctx.cache_misses,
                    "duration_ms": int((time.monotonic() - ctx.start_time) * 1000),
                },
            }

    except Exception as e:
        # Catastrophic infra failure (e.g. cannot open session) — only case where
        # findings may legitimately be empty.
        return {
            "findings": [],
            "score_raw": 0,
            "score_dampened": 0,
            "grade": "F",
            "errors": [{"phase": "run", "error": str(e), "type": type(e).__name__,
                        "traceback": traceback.format_exc(limit=3)[-800:]}],
            "details": {"fatal": True},
        }


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2, ensure_ascii=False))