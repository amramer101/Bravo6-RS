"""
test_13_cms_fingerprinting.py

Bravo6 Scout security scanning module — CMS / modern-framework
fingerprinting and security posture analysis.

What it does
------------
1. Fetches the target's homepage and fingerprints the CMS or frontend
   framework powering it using multiple independent signal classes
   (HTML markup / JS globals, response headers, and known public routes).
2. Attempts to extract a version string from generator meta tags, exposed
   changelog/readme files, or framework-specific markers, and flags it as
   "outdated" against a small reference table of recent major versions.
3. Probes a curated set of platform-specific and generic paths (admin
   panels, build output directories, debug endpoints, common
   backup/config/VCS leaks) to flag exposure and misconfiguration.
4. Checks standard security response headers (HSTS, CSP, X-Frame-Options,
   etc.) and looks for directory-listing and known security-plugin
   fingerprints.
5. Rolls all of the above into a single 0-100 "security vibe score" with
   supporting evidence and platform-specific remediation advice.

This module only performs passive, read-only GET requests against paths
that are part of a platform's normal public routing or extremely common,
publicly-documented misconfiguration patterns (e.g. /.env, /.git/HEAD).
It never authenticates, brute-forces, exploits, or attempts to bypass any
access control — it just checks whether something is reachable and reports
what it finds.

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

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_STATUS_RANK = {"pass": 0, "info": 1, "warning": 2, "fail": 3}


def severity_rank(sev: str) -> int:
    return _SEVERITY_RANK.get(sev, 0)


# ---------------------------------------------------------------------------
# Platform signature data
# ---------------------------------------------------------------------------
# Each entry:
#   html              -> regexes tested against page HTML/inline JS
#   headers           -> regexes tested against "Header: value" blob
#   version_patterns  -> regexes with one capture group = version string,
#                        tested against the same HTML/header blob
#   check_paths       -> {path: (issue_description, severity)}
#   plugin_signals    -> regexes indicating a security hardening tool/plugin
#   latest_major      -> rough reference major.minor used only to flag a
#                        clearly stale version; not a live version feed
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
        },
        "plugin_signals": [r"wordfence", r"sucuri", r"ithemes.security", r"wp-rocket", r"all.in.one.wp.security"],
        "latest_major": "6.7",
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
        "plugin_signals": [r"seckit", r"security.kit"],
        "latest_major": "10.3",
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
        "plugin_signals": [r"admintools", r"rsfirewall"],
        "latest_major": "5.1",
    },
    "Shopify": {
        "html": [r"cdn\.shopify\.com", r"Shopify\.theme", r"/checkouts/"],
        "headers": [r"x-shopid", r"x-sorting-hat-podid", r"x-shopify-stage"],
        "version_patterns": [],
        "check_paths": {
            "/admin": ("Merchant admin login route reachable (expected, hosted by Shopify)", "info"),
        },
        "plugin_signals": [],
        "latest_major": None,
    },
    "Wix": {
        "html": [r"wixstatic\.com", r"wix\.com/", r"wixCode"],
        "headers": [r"x-wix-request-id"],
        "version_patterns": [],
        "check_paths": {},
        "plugin_signals": [],
        "latest_major": None,
    },
    "Squarespace": {
        "html": [r"squarespace\.com", r"static1\.squarespace\.com"],
        "headers": [r"server:\s*squarespace"],
        "version_patterns": [],
        "check_paths": {},
        "plugin_signals": [],
        "latest_major": None,
    },
    "HubSpot": {
        "html": [r"hs-scripts\.com", r"hsforms\.net", r"_hsenc"],
        "headers": [r"x-hs-", r"x-hubspot"],
        "version_patterns": [],
        "check_paths": {},
        "plugin_signals": [],
        "latest_major": None,
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
        "plugin_signals": [],
        "latest_major": "2.4",
    },
    "TYPO3": {
        "html": [r"typo3conf", r"TYPO3", r"typo3temp"],
        "headers": [r"x-typo3"],
        "version_patterns": [r"TYPO3\s*([\d]+\.[\d]+)"],
        "check_paths": {
            "/typo3/": ("Backend login reachable", "medium"),
        },
        "plugin_signals": [],
        "latest_major": "13.4",
    },
    "Next.js": {
        "html": [r"__NEXT_DATA__", r"_next/static", r"next/dist"],
        "headers": [r"x-nextjs", r"x-middleware"],
        "version_patterns": [r'"next"\s*:\s*"([\d.]+)"'],
        "check_paths": {
            "/_next/static/": ("Build output directory reachable (expected; confirms framework only)", "info"),
            "/api/": ("API routes base path reachable — verify auth on every handler", "info"),
        },
        "plugin_signals": [],
        "latest_major": None,
    },
    "Nuxt.js": {
        "html": [r"__NUXT__", r"/_nuxt/", r"data-n-head"],
        "headers": [r"x-nuxt"],
        "version_patterns": [r'"nuxt"\s*:\s*"([\d.]+)"'],
        "check_paths": {
            "/_nuxt/": ("Build output directory reachable (expected; confirms framework only)", "info"),
        },
        "plugin_signals": [],
        "latest_major": None,
    },
    "Remix": {
        "html": [r"__remixContext", r"/build/_assets/", r"remix-run"],
        "headers": [],
        "version_patterns": [],
        "check_paths": {},
        "plugin_signals": [],
        "latest_major": None,
    },
    "Gatsby": {
        "html": [r"___gatsby", r"gatsby-image", r"/page-data/"],
        "headers": [],
        "version_patterns": [],
        "check_paths": {
            "/page-data/app-data.json": ("Page-data JSON exposed (normal for Gatsby; verify no sensitive props)", "info"),
        },
        "plugin_signals": [],
        "latest_major": None,
    },
    "VuePress": {
        "html": [r"vuepress", r"__VUEPRESS__"],
        "headers": [],
        "version_patterns": [],
        "check_paths": {},
        "plugin_signals": [],
        "latest_major": None,
    },
    "VitePress": {
        "html": [r"vitepress"],
        "headers": [],
        "version_patterns": [],
        "check_paths": {},
        "plugin_signals": [],
        "latest_major": None,
    },
    "Astro": {
        "html": [r"astro-island", r"data-astro-cid", r"/_astro/"],
        "headers": [],
        "version_patterns": [],
        "check_paths": {
            "/_astro/": ("Build output directory reachable (expected; confirms framework only)", "info"),
        },
        "plugin_signals": [],
        "latest_major": None,
    },
}

# Generic leak/misconfiguration paths checked regardless of detected platform.
GENERIC_EXPOSURE_PATHS = {
    "/.git/HEAD": ("Git repository metadata exposed — can lead to full source disclosure", "critical"),
    "/.env": ("Environment file potentially exposing secrets/credentials", "critical"),
    "/.env.example": ("Example env file exposed — reveals config structure", "low"),
    "/.DS_Store": ("macOS directory metadata file exposed", "low"),
    "/backup.zip": ("Generic backup archive reachable", "high"),
    "/config.php.bak": ("Backup config file reachable", "high"),
    "/.well-known/security.txt": ("security.txt published — good disclosure practice", "info"),
}
_POSITIVE_GENERIC_PATHS = {"/.well-known/security.txt"}

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

DIRECTORY_LISTING_PATTERNS = [r"Index of /", r"<title>Directory Listing", r"Parent Directory</a>"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_url(url: str) -> str:
    """Ensure the URL has a scheme; defaults to https://."""
    url = (url or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url):
        url = "https://" + url
    return url


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


def _safe_search(pattern: str, haystack: str):
    try:
        return re.search(pattern, haystack, re.IGNORECASE)
    except re.error:
        return None


def detect_platform(html: str, headers: dict):
    """
    Score every known platform against HTML + header signals.

    Returns (best_name_or_None, confidence, matched_signal_evidence_list).
    Confidence is "high" (2+ independent signal classes matched), "medium"
    (exactly one signal class matched, possibly multiple patterns within it),
    or "low" (a single weak match) — None if nothing matched at all.
    """
    html = html or ""
    header_blob = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())

    best_name = None
    best_score = 0
    best_evidence = []

    for name, cfg in PLATFORM_SIGNATURES.items():
        html_hits = [p for p in cfg["html"] if _safe_search(p, html)]
        header_hits = [p for p in cfg["headers"] if _safe_search(p, header_blob)]
        if not html_hits and not header_hits:
            continue

        score = len(html_hits) * 2 + len(header_hits) * 2
        evidence = []
        if html_hits:
            evidence.append(f"HTML/JS signature matched for {name} ({len(html_hits)} pattern(s))")
        if header_hits:
            evidence.append(f"Response header signature matched for {name} ({len(header_hits)} pattern(s))")

        if score > best_score:
            best_name, best_score, best_evidence = name, score, evidence

    if best_name is None:
        return None, None, []

    html_classes = 1 if any(_safe_search(p, html) for p in PLATFORM_SIGNATURES[best_name]["html"]) else 0
    header_classes = 1 if any(_safe_search(p, header_blob) for p in PLATFORM_SIGNATURES[best_name]["headers"]) else 0
    classes_matched = html_classes + header_classes

    if classes_matched >= 2:
        confidence = "high"
    elif best_score >= 2:
        confidence = "medium"
    else:
        confidence = "low"

    return best_name, confidence, best_evidence


def extract_version(cms_name: str, html: str, headers: dict):
    """Try to pull a version string out of HTML/header content for a detected platform."""
    if not cms_name:
        return None
    cfg = PLATFORM_SIGNATURES.get(cms_name, {})
    blob = (html or "") + "\n" + "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
    for pattern in cfg.get("version_patterns", []):
        match = _safe_search(pattern, blob)
        if match and match.groups() and match.group(1):
            return match.group(1)
    return None


def _version_tuple(v: str):
    try:
        return tuple(int(p) for p in re.findall(r"\d+", v)[:2])
    except Exception:
        return None


def is_outdated(cms_name: str, version: str):
    """Very rough staleness check against a static reference major.minor — not a live feed."""
    if not cms_name or not version:
        return None
    latest = PLATFORM_SIGNATURES.get(cms_name, {}).get("latest_major")
    if not latest:
        return None
    v_tuple, latest_tuple = _version_tuple(version), _version_tuple(latest)
    if not v_tuple or not latest_tuple:
        return None
    return v_tuple < latest_tuple


async def probe_paths(session: aiohttp.ClientSession, base_url: str, paths: dict):
    """
    Probe a {path: (issue, severity)} map concurrently.
    Returns (findings_list, directory_listing_detected_bool).
    """
    findings = []
    listing_detected = False

    async def probe(path, issue, severity):
        nonlocal listing_detected
        target = urljoin(base_url, path)
        status, text, _headers = await _fetch(session, target, allow_redirects=False)
        if status is None or status >= 400:
            return None
        if text and any(_safe_search(p, text) for p in DIRECTORY_LISTING_PATTERNS):
            listing_detected = True
        return {"path": path, "status_code": status, "issue": issue, "severity": severity}

    tasks = [probe(p, issue, sev) for p, (issue, sev) in paths.items()]
    results = await asyncio.gather(*tasks) if tasks else []
    findings = [r for r in results if r is not None]
    return findings, listing_detected


def check_security_headers(headers: dict):
    """Returns (present_list, missing_list) of the standard hardening headers."""
    headers = headers or {}
    lower_keys = {k.lower() for k in headers.keys()}
    present = [h for h in SECURITY_HEADERS if h.lower() in lower_keys]
    missing = [h for h in SECURITY_HEADERS if h.lower() not in lower_keys]
    return present, missing


def detect_security_plugins(cms_name: str, html: str, headers: dict):
    if not cms_name:
        return []
    cfg = PLATFORM_SIGNATURES.get(cms_name, {})
    blob = (html or "") + "\n" + "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
    return [p for p in cfg.get("plugin_signals", []) if _safe_search(p, blob)]


def compute_vibe_score(exposure_findings, present_headers, missing_headers, listing_detected, plugins_found, security_txt_present):
    """
    0-100 security posture score.
      base 60
      + 5 per present standard security header (max +30)
      + 10 once if a known security-hardening plugin/tool fingerprint matched
      + 5 if security.txt is published
      - severity-weighted penalty per exposure finding (critical/high/medium/low)
      - 15 if directory listing is enabled anywhere probed
    Clamped to [0, 100].
    """
    score = 60
    score += min(len(present_headers), 6) * 5
    if plugins_found:
        score += 10
    if security_txt_present:
        score += 5

    penalty_weights = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
    for f in exposure_findings:
        score -= penalty_weights.get(f["severity"], 0)

    if listing_detected:
        score -= 15

    return max(0, min(100, score))


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
                "evidence": [],
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
                    "evidence": [f"GET {base_url} timed out or failed to connect."],
                    "remediation": "Verify the target is online and accessible, then re-run the scan.",
                }

            # --- 1. Platform fingerprinting ---
            cms_name, confidence, fingerprint_evidence = detect_platform(html, resp_headers)
            version = extract_version(cms_name, html, resp_headers)
            outdated = is_outdated(cms_name, version)

            # --- 2. Path exposure probing (platform-specific + generic) ---
            platform_paths = PLATFORM_SIGNATURES.get(cms_name, {}).get("check_paths", {}) if cms_name else {}
            combined_paths = dict(platform_paths)
            combined_paths.update(GENERIC_EXPOSURE_PATHS)

            all_findings, listing_detected = await probe_paths(session, base_url, combined_paths)

            positive_findings = [f for f in all_findings if f["path"] in _POSITIVE_GENERIC_PATHS]
            exposure_findings = [f for f in all_findings if f["path"] not in _POSITIVE_GENERIC_PATHS]
            security_txt_present = any(f["path"] == "/.well-known/security.txt" for f in positive_findings)

            # --- 3. Security headers + plugin/hardening signals ---
            present_headers, missing_headers = check_security_headers(resp_headers)
            plugins_found = detect_security_plugins(cms_name, html, resp_headers)

            # --- 4. Vibe score ---
            vibe_score = compute_vibe_score(
                exposure_findings, present_headers, missing_headers, listing_detected, plugins_found, security_txt_present
            )

            # --- Aggregate status/severity ---
            finding_severities = [f["severity"] for f in exposure_findings]
            overall_severity = max(finding_severities, key=severity_rank) if finding_severities else "info"

            if any(s in ("critical", "high") for s in finding_severities) or vibe_score < 40:
                status_result = "fail"
            elif exposure_findings or missing_headers or vibe_score < 70:
                status_result = "warning"
            else:
                status_result = "pass"

            cms_part = f"CMS Detection: {cms_name}" if cms_name else "CMS Detection: Unknown/Custom"
            title = f"{cms_part} — Vibe Score: {vibe_score}%"

            # --- Description ---
            desc_parts = []
            if cms_name:
                ver_str = f" version {version}" if version else " (version not publicly exposed)"
                desc_parts.append(
                    f"The site was fingerprinted as {cms_name}{ver_str} with {confidence} confidence, "
                    f"based on HTML/JS markers and response headers."
                )
                if outdated:
                    desc_parts.append(
                        f"The detected version appears older than the current {cms_name} release line — "
                        f"treat as a priority to verify and patch."
                    )
            else:
                desc_parts.append(
                    "No known CMS or framework signature was matched — this looks like a custom-built "
                    "site or the platform actively obscures its fingerprints."
                )
            if exposure_findings:
                desc_parts.append(
                    f"{len(exposure_findings)} reachable path(s) indicate possible exposure or "
                    f"misconfiguration, including {sum(1 for f in exposure_findings if f['severity'] in ('critical','high'))} "
                    f"high/critical finding(s)."
                )
            else:
                desc_parts.append("No sensitive or known-risk paths were found reachable.")
            if missing_headers:
                desc_parts.append(
                    f"{len(missing_headers)} of {len(SECURITY_HEADERS)} recommended security headers are missing."
                )
            if listing_detected:
                desc_parts.append("Directory listing appears to be enabled on at least one probed path.")
            if plugins_found:
                desc_parts.append(f"Evidence of a security-hardening tool/plugin was found ({len(plugins_found)} signal(s)).")
            description = " ".join(desc_parts)

            # --- Evidence (list of strings, per spec) ---
            evidence = []
            evidence.extend(fingerprint_evidence)
            if version:
                evidence.append(f"Version string extracted: {version}" + (" (outdated)" if outdated else ""))
            for f in exposure_findings:
                evidence.append(f"Exposed path: {f['path']} -> HTTP {f['status_code']} ({f['issue']}) [{f['severity']}]")
            if security_txt_present:
                evidence.append("security.txt found at /.well-known/security.txt")
            if listing_detected:
                evidence.append("Directory listing output detected in at least one probed response")
            if present_headers:
                evidence.append(f"Security headers present: {', '.join(present_headers)}")
            if missing_headers:
                evidence.append(f"Security headers missing: {', '.join(missing_headers)}")
            for p in plugins_found:
                evidence.append(f"Security plugin/tool signal matched: {p}")
            if not evidence:
                evidence.append("No fingerprint, exposure, or header signals were collected.")

            # --- Remediation ---
            rem_parts = []
            if exposure_findings:
                crit_high = [f["path"] for f in exposure_findings if f["severity"] in ("critical", "high")]
                if crit_high:
                    rem_parts.append(
                        f"Immediately restrict or remove public access to: {', '.join(crit_high)} — "
                        f"these can expose credentials or source code."
                    )
                other_paths = [f["path"] for f in exposure_findings if f["severity"] not in ("critical", "high")]
                if other_paths:
                    rem_parts.append(f"Review and, where unnecessary, restrict access to: {', '.join(other_paths)}.")
            if missing_headers:
                rem_parts.append(
                    f"Add the missing security headers ({', '.join(missing_headers)}) at the web "
                    f"server, CDN, or framework middleware layer."
                )
            if listing_detected:
                rem_parts.append("Disable directory listing/autoindex on the web server.")
            if outdated and cms_name:
                rem_parts.append(f"Upgrade {cms_name} to the latest stable release to close known CVEs.")
            if cms_name == "WordPress":
                rem_parts.append(
                    "Disable XML-RPC if unused, hide or restrict /wp-json/ user endpoints, and install a "
                    "reputable security plugin (e.g. Wordfence) if not already present."
                )
            elif cms_name == "Magento":
                rem_parts.append("Rename the default admin path and remove the legacy /downloader/ tool if unused.")
            elif cms_name in ("Next.js", "Nuxt.js", "Remix", "Gatsby", "Astro"):
                rem_parts.append(
                    "Keep secrets in environment variables (never bundled client-side), and add auth "
                    "middleware to every API route rather than relying on routing obscurity."
                )
            if not rem_parts:
                rem_parts.append("No immediate action required; continue periodic monitoring.")
            remediation = " ".join(rem_parts)

            exposed_paths = [f["path"] for f in exposure_findings]

            return {
                "test_name": test_name,
                "status": status_result,
                "severity": overall_severity,
                "title": title,
                "description": description,
                "evidence": evidence,
                "remediation": remediation,
                # Extended, task-specific detail (in addition to the required schema fields):
                "cms_type": cms_name or "Unknown",
                "vibe_score": vibe_score,
                "version": (f"{version} (outdated)" if outdated else version) if version else "not detected",
                "exposed_paths": exposed_paths,
                "confidence": confidence or "low",
                "security_headers_present": present_headers,
                "security_headers_missing": missing_headers,
                "directory_listing_detected": listing_detected,
                "scan_duration_seconds": round(time.time() - start_time, 2),
            }

    except Exception as exc:  # noqa: BLE001 - top-level safety net, must never raise
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "Scan Error",
            "description": f"An unexpected error occurred while scanning {url}.",
            "evidence": [f"{type(exc).__name__}: {exc}"],
            "remediation": "Check the target URL and network connectivity, then retry the scan.",
        }


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    print(json.dumps(asyncio.run(run(target)), indent=2))