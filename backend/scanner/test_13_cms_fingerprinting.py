"""
test_cms_vibecheck.py

Bravo6 security scanning module.

Detects the CMS/framework powering a target site from its HTML and response
headers, checks a small set of well-known, publicly documented paths for
that CMS to flag common exposures/misconfigurations (e.g. /wp-login.php,
/.env, /administrator/), and runs a heuristic "vibe score" pass over the
page/script content to flag signs of AI-generated ("vibe-coded") front-end
code (debug leftovers, placeholder content, AI-builder fingerprints, etc).

This module only performs passive, read-only HTTP requests to paths that
are part of each framework's normal, public routing. It never attempts to
authenticate, exploit, brute-force, or bypass any access control — it just
checks whether a path is reachable and reports what it finds.

Usage:
    result = await run("example.com")
"""

import asyncio
import re
import time
from urllib.parse import urljoin, urlparse

import aiohttp

USER_AGENT = "Bravo6-Scanner/1.0"
TIMEOUT_SECONDS = 10

# ---------------------------------------------------------------------------
# Signature data
# ---------------------------------------------------------------------------

CMS_SIGNATURES = {
    "WordPress": {
        "patterns": [r"/wp-content/", r"/wp-includes/", r'name="generator" content="WordPress'],
        "check_paths": ["/wp-login.php", "/xmlrpc.php", "/wp-json/"],
        "risks": {
            "/wp-login.php": ("Login page exposed", "info"),
            "/xmlrpc.php": ("XML-RPC enabled — brute force and DDoS risk", "high"),
            "/wp-json/": ("REST API exposed — user enumeration possible", "medium"),
        },
    },
    "Joomla": {
        "patterns": [r"/components/com_", r"/media/jui/", r"Joomla!"],
        "check_paths": ["/administrator/", "/configuration.php"],
        "risks": {
            "/administrator/": ("Admin panel exposed", "medium"),
        },
    },
    "Drupal": {
        "patterns": [r"Drupal\.settings", r"/sites/default/files/", r'name="Generator" content="Drupal'],
        "check_paths": ["/user/login", "/admin/"],
        "risks": {
            "/user/login": ("Default login page exposed", "info"),
        },
    },
    "Laravel": {
        "patterns": [r"laravel_session", r"XSRF-TOKEN", r"Laravel"],
        "check_paths": ["/.env", "/telescope", "/horizon"],
        "risks": {
            "/.env": ("Environment file may be exposed", "critical"),
            "/telescope": ("Laravel Telescope debugger may be exposed", "high"),
        },
    },
    "Django": {
        "patterns": [r"csrfmiddlewaretoken", r"django", r"__django"],
        "check_paths": ["/admin/", "/static/admin/"],
        "risks": {
            "/admin/": ("Django admin panel exposed", "medium"),
        },
    },
    "Next.js": {
        "patterns": [r"__NEXT_DATA__", r"_next/static", r"next/dist"],
        "check_paths": ["/_next/", "/api/"],
        "risks": {},
    },
    "React (Vite/CRA)": {
        "patterns": [r"react-dom", r"__react", r"data-reactroot", r"/assets/index-"],
        "check_paths": [],
        "risks": {},
    },
}

VIBE_SIGNALS = [
    {
        "name": "AI Generator Meta Tag",
        "patterns": [r'content="(v0|lovable|bolt\.new|cursor|replit)'],
        "points": 30,
        "severity": "info",
    },
    {
        "name": "Generic Tailwind Class Structure",
        "patterns": [r'className="(?:flex|grid) (?:flex-col|items-center) (?:justify-center|gap-\d)'],
        "points": 10,
        "severity": "info",
    },
    {
        "name": "Console.log in Production",
        "patterns": [r'console\.log\(["\']'],
        "points": 15,
        "severity": "low",
    },
    {
        "name": "Empty Catch Blocks",
        "patterns": [r'catch\s*\(\s*\w+\s*\)\s*\{\s*\}'],
        "points": 15,
        "severity": "low",
    },
    {
        "name": "TODO/FIXME in Production",
        "patterns": [r'//\s*(?:TODO|FIXME|HACK|XXX)'],
        "points": 10,
        "severity": "info",
    },
    {
        "name": "Placeholder Text",
        "patterns": [r'Lorem ipsum|placeholder text|Your Name Here|email@example'],
        "points": 20,
        "severity": "info",
    },
    {
        "name": "Generic CSS Variable Names",
        "patterns": [r'--primary-color|--secondary-color|--accent-color'],
        "points": 10,
        "severity": "info",
    },
    {
        "name": "AI Comment Patterns",
        "patterns": [r'//\s*(?:Add your|Insert your|Replace with|Update this)'],
        "points": 20,
        "severity": "info",
    },
]

VIBE_LABEL_BANDS = [
    (0, 20, "Likely Human-Written"),
    (21, 40, "Some AI Assistance Detected"),
    (41, 60, "Significant AI Assistance"),
    (61, 80, "Likely AI-Generated"),
    (81, 100, "Almost Certainly Vibe Coded"),
]

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_url(url: str) -> str:
    """Ensure the URL has a scheme; defaults to https://."""
    url = (url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "https://" + url
    return url


def vibe_label(score: int) -> str:
    for low, high, label in VIBE_LABEL_BANDS:
        if low <= score <= high:
            return label
    return "Unknown"


def severity_rank(sev: str) -> int:
    return _SEVERITY_RANK.get(sev, 0)


async def _fetch(session: aiohttp.ClientSession, url: str, allow_redirects: bool = True):
    """GET a URL. Returns (status, text, headers) or (None, None, None) on failure."""
    try:
        async with session.get(
            url,
            allow_redirects=allow_redirects,
            timeout=aiohttp.ClientTimeout(total=TIMEOUT_SECONDS),
        ) as resp:
            try:
                text = await resp.text(errors="ignore")
            except Exception:
                text = ""
            return resp.status, text, dict(resp.headers)
    except (asyncio.TimeoutError, aiohttp.ClientError):
        return None, None, None
    except Exception:
        return None, None, None


def detect_cms(html: str, headers: dict):
    """Match HTML body + headers against CMS_SIGNATURES. Returns CMS name or None."""
    html = html or ""
    header_blob = " ".join(f"{k}: {v}" for k, v in (headers or {}).items())
    haystack = html + " " + header_blob

    for cms_name, cfg in CMS_SIGNATURES.items():
        for pattern in cfg["patterns"]:
            try:
                if re.search(pattern, haystack, re.IGNORECASE):
                    return cms_name
            except re.error:
                continue
    return None


async def check_cms_risks(session: aiohttp.ClientSession, base_url: str, cms_name: str):
    """Probe a CMS's known check_paths and report any that are reachable."""
    findings = []
    cfg = CMS_SIGNATURES.get(cms_name)
    if not cfg:
        return findings

    risk_map = cfg.get("risks", {})

    async def probe(path):
        target = urljoin(base_url, path)
        status, _text, _headers = await _fetch(session, target, allow_redirects=False)
        if status is None or status >= 400:
            return None
        if path in risk_map:
            issue, severity = risk_map[path]
        else:
            issue, severity = (f"{path} reachable", "info")
        return {"path": path, "status_code": status, "issue": issue, "severity": severity}

    results = await asyncio.gather(*(probe(p) for p in cfg.get("check_paths", [])))
    findings = [r for r in results if r is not None]
    return findings


def compute_vibe_score(content: str):
    """Scan page/script content for vibe-coding signals. Returns (score, signal_list)."""
    if not content:
        return 0, []

    score = 0
    signals = []

    for signal in VIBE_SIGNALS:
        occurrences = 0
        matched_value = None
        for pattern in signal["patterns"]:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
            except re.error:
                continue
            occurrences += len(matches)
            if matches and matched_value is None:
                first = matches[0]
                if isinstance(first, str) and first:
                    matched_value = first

        if occurrences > 0:
            score += signal["points"]
            entry = {
                "signal": signal["name"],
                "occurrences": occurrences,
                "severity": signal["severity"],
            }
            if matched_value:
                entry["value"] = matched_value
            signals.append(entry)

    return min(score, 100), signals


def _gather_js_asset_urls(html: str, base_url: str, limit: int = 5):
    """Pull a handful of same-context <script src="..."> URLs to also scan for vibe signals."""
    if not html:
        return []
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    urls = []
    for src in srcs:
        if src.startswith("data:"):
            continue
        urls.append(urljoin(base_url, src))
        if len(urls) >= limit:
            break
    return urls


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def run(url: str) -> dict:
    test_name = "cms_vibe_detection"
    start_time = time.time()

    try:
        base_url = normalize_url(url)
        parsed = urlparse(base_url)
        if not parsed.netloc:
            return {
                "test_name": test_name,
                "status": "error",
                "severity": "info",
                "title": "Invalid URL",
                "description": f"Could not parse a valid host from input: {url!r}.",
                "evidence": "",
                "remediation": "Provide a valid domain or URL, e.g. example.com",
            }

        connector = aiohttp.TCPConnector(ssl=False, limit=10)
        request_headers = {"User-Agent": USER_AGENT}

        async with aiohttp.ClientSession(connector=connector, headers=request_headers) as session:
            status, html, resp_headers = await _fetch(session, base_url)

            if status is None:
                return {
                    "test_name": test_name,
                    "status": "error",
                    "severity": "info",
                    "title": "Site Unreachable",
                    "description": f"Could not connect to {base_url} within {TIMEOUT_SECONDS}s.",
                    "evidence": f"GET {base_url} timed out or failed to connect.",
                    "remediation": "Verify the target is online and accessible, then re-run the scan.",
                }

            # --- Part A: CMS detection + risk path checks ---
            cms = detect_cms(html, resp_headers)
            cms_findings = []
            if cms:
                cms_findings = await check_cms_risks(session, base_url, cms)

            # --- Part B: Vibe score, including a sample of linked JS assets ---
            combined_content = html or ""
            js_urls = _gather_js_asset_urls(html, base_url)
            if js_urls:
                js_texts = await asyncio.gather(
                    *(_fetch(session, js_url) for js_url in js_urls)
                )
                for _status, text, _headers in js_texts:
                    if text:
                        combined_content += "\n" + text

            vibe_score, vibe_signals = compute_vibe_score(combined_content)
            label = vibe_label(vibe_score)

            # --- Aggregate severity/status ---
            finding_severities = [f["severity"] for f in cms_findings]
            overall_severity = max(finding_severities, key=severity_rank) if finding_severities else "info"

            if any(s in ("critical", "high") for s in finding_severities):
                status_result = "fail"
            elif cms_findings or vibe_score >= 41:
                status_result = "warning"
            else:
                status_result = "pass"

            cms_part = f"{cms} Detected" if cms else "No Known CMS Detected"
            title = f"{cms_part} — Vibe Score: {vibe_score}%"

            description_parts = []
            if cms:
                description_parts.append(
                    f"The site was fingerprinted as {cms} based on HTML and response header signatures."
                )
                if cms_findings:
                    description_parts.append(
                        f"{len(cms_findings)} known {cms} path(s) were reachable and may indicate a "
                        f"misconfiguration or unnecessary exposure."
                    )
                else:
                    description_parts.append(
                        f"None of the checked {cms} exposure paths were reachable."
                    )
            else:
                description_parts.append(
                    "No known CMS/framework signature was matched in the page content or response headers."
                )
            description_parts.append(
                f"Vibe analysis score is {vibe_score}/100 ({label}), based on {len(vibe_signals)} "
                f"matched code-quality / AI-tooling signal(s) across the page and {len(js_urls)} linked script(s)."
            )
            description = " ".join(description_parts)

            evidence_lines = []
            if cms:
                evidence_lines.append(f"CMS fingerprint matched: {cms}")
            for f in cms_findings:
                evidence_lines.append(
                    f"  - {f['path']} -> HTTP {f['status_code']}: {f['issue']} [{f['severity']}]"
                )
            for s in vibe_signals:
                val = f" (e.g. '{s['value']}')" if s.get("value") else ""
                evidence_lines.append(
                    f"  - Vibe signal '{s['signal']}': {s['occurrences']} occurrence(s){val}"
                )
            evidence = "\n".join(evidence_lines) if evidence_lines else "No CMS or vibe-coding signals detected."

            remediation_parts = []
            if cms_findings:
                paths = ", ".join(f["path"] for f in cms_findings)
                remediation_parts.append(f"Restrict, disable, or firewall public access to: {paths}.")
            if vibe_score >= 41:
                remediation_parts.append(
                    "Manually review the AI-generated/assisted code for security issues — vibe-coded "
                    "sites statistically show higher rates of missing input validation, leftover debug "
                    "output, and placeholder content shipped to production."
                )
            if not remediation_parts:
                remediation_parts.append("No immediate action required; continue periodic monitoring.")
            remediation = " ".join(remediation_parts)

            return {
                "test_name": test_name,
                "status": status_result,
                "severity": overall_severity,
                "title": title,
                "description": description,
                "evidence": evidence,
                "remediation": remediation,
                # Extended, task-specific detail (in addition to the required schema fields):
                "cms_detected": cms,
                "cms_findings": cms_findings,
                "vibe_score": vibe_score,
                "vibe_label": label,
                "vibe_signals": vibe_signals,
                "scan_duration_seconds": round(time.time() - start_time, 2),
            }

    except Exception as exc:  # noqa: BLE001 - top-level safety net, must never raise
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "Scan Error",
            "description": f"An unexpected error occurred while scanning {url}.",
            "evidence": f"{type(exc).__name__}: {exc}",
            "remediation": "Check the target URL and network connectivity, then retry the scan.",
        }


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(asyncio.run(run(target)), indent=2))