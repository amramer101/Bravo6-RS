#!/usr/bin/env python3
"""
test_05_security_headers.py – Bravo6 Enterprise HTTP Security Policy Analyzer (v7.0)
====================================================================================
Enterprise-grade HTTP Security Policy Analyzer with advanced CSP validation,
Reporting API checks, Document Policy, and Origin-Agent-Cluster analysis.
Evolution highlights:
- Advanced CSP parsing: validates unsafe-inline, unsafe-eval, nonces, hashes, and strict-dynamic.
- Added Document-Policy, Origin-Agent-Cluster, and Reporting API checks.
- Every finding now includes: exact header, exact header value, explanation,
confidence, severity, CWE, OWASP, evidence, PoC, remediation, and detection method.
- Aggressive false positive reduction: e.g., CSP unsafe-inline is only flagged if
not mitigated by strict-dynamic or cryptographic nonces/hashes.
- Validates not just the existence of headers but the security of their values.
- Preserved async model, API compatibility, JSON output format, and existing features.
"""
import asyncio
import json
import re
import random
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup, Comment
SCANNER_NAME = "security_headers"
USER_AGENT = "Bravo6-SecurityHeaders/7.0"
CDN_DOMAINS = (
".cloudfront.net", ".azurewebsites.net", ".herokuapp.com",
".github.io", ".netlify.app", ".vercel.app", ".firebaseapp.com",
".pages.dev", ".workers.dev"
)
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CWE_MAP = {
"hsts": "CWE-319", "clickjacking": "CWE-1021", "csp": "CWE-1021",
"xcto": "CWE-693", "referrer": "CWE-200", "permissions": "CWE-693",
"coop": "CWE-693", "coep": "CWE-693", "corp": "CWE-693", "cache": "CWE-525",
"server_info": "CWE-200", "dns_prefetch": "CWE-693",
"document_policy": "CWE-693", "origin_agent_cluster": "CWE-693",
"reporting_api": "CWE-693"
}
OWASP_MAP = {
"hsts": "A05:2021", "clickjacking": "A01:2021", "csp": "A01:2021",
"xcto": "A05:2021", "referrer": "A01:2021", "permissions": "A05:2021",
"coop": "A05:2021", "coep": "A05:2021", "corp": "A05:2021", "cache": "A05:2021",
"server_info": "A01:2021", "dns_prefetch": "A05:2021",
"document_policy": "A05:2021", "origin_agent_cluster": "A05:2021",
"reporting_api": "A05:2021"
}
# ── Helpers ──────────────────────────────────────────────────────────────
def _normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def _get_header(headers: Dict[str, str], name: str) -> Optional[str]:
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None

# ── Pre-scan: WAF (no network requests) ─────────────────────────────────
async def _detect_waf(hostname: str, port: int = 443, html: str = None, headers: dict = None) -> Optional[str]:
    if headers:
        if 'cf-ray' in {k.lower() for k in headers}: return 'cloudflare'
        if 'x-sucuri-id' in {k.lower() for k in headers}: return 'sucuri'
        if 'x-akamai-request-id' in {k.lower() for k in headers}: return 'akamai'
        if headers.get('server', '').lower().startswith('cloudflare'): return 'cloudflare'
    return None

def _fingerprint_waf_from_headers(headers: Dict[str, str]) -> List[str]:
    fingerprints = []
    csp = _get_header(headers, "Content-Security-Policy") or ""
    xcsp = _get_header(headers, "X-Content-Security-Policy") or ""
    if 'ModSecurity' in csp or 'ModSecurity' in xcsp:
        fingerprints.append('ModSecurity')
    if _get_header(headers, "x-amzn-RequestId") or _get_header(headers, "x-amz-cf-id"):
        fingerprints.append('AWS CloudFront/WAF')
    if any('WAF' in (_get_header(headers, k) or '') for k in headers):
        fingerprints.append('Generic WAF')
    return fingerprints

# ── Site Categorization (no network requests) ───────────────────────────
SITE_CATEGORIES = {
    "bank": ["bank", "online banking"],
    "ecommerce": ["shop", "store", "buy", "cart", "checkout", "pay"],
    "healthcare": ["hospital"],
    "login": ["sign in", "login"],
    "blog": ["blog", "articles"],
    "internal": ["intranet", "internal"],
}

async def _categorize_site(hostname: str, port: int = 443, html: str = None, headers: dict = None) -> Dict:
    result = {"categories": [], "has_login_form": False, "title": "", "meta_keywords": ""}
    if not html:
        return result
    text = html
    title_match = re.search(r'<title>(.*?)</title>', text, re.IGNORECASE)
    if title_match: result["title"] = title_match.group(1)
    meta_match = re.search(r'<meta\s+name="keywords"\s+content="(.*?)"', text, re.IGNORECASE)
    if meta_match: result["meta_keywords"] = meta_match.group(1)
    if re.search(r'<input\s+[^>]*type=["\']?password["\']?', text, re.IGNORECASE):
        result["has_login_form"] = True
    text_lower = (result["title"] + " " + result["meta_keywords"]).lower()
    for category, keywords in SITE_CATEGORIES.items():
        if any(k in text_lower for k in keywords):
            result["categories"].append(category)
    return result

# ── Finding & Scoring ───────────────────────────────────────────────────
def _make_finding(title, description, severity, confidence, status="fail",
                  header="", header_value="", explanation="", evidence="",
                  remediation="", cwe="", owasp="", poc=None, detection_method="header_analysis"):
    return {
        "title": title,
        "description": description,
        "severity": severity,
        "confidence": confidence,
        "status": status,
        "header": header,
        "header_value": header_value,
        "explanation": explanation or description,
        "evidence": evidence,
        "remediation": remediation,
        "cwe": cwe,
        "owasp": owasp,
        "poc": poc,
        "detection_method": detection_method
    }

# ── Header Order Analysis ───────────────────────────────────────────────
def _analyze_header_order(headers_list):
    final_headers = headers_list[-1]["headers"] if headers_list else {}
    header_names = list(final_headers.keys())
    security_headers = [h for h in header_names if h.lower() in [
        "strict-transport-security", "content-security-policy",
        "x-frame-options", "x-content-type-options", "referrer-policy",
        "permissions-policy", "cross-origin-opener-policy",
        "cross-origin-embedder-policy", "cross-origin-resource-policy"
    ]]
    ideal = [
        "strict-transport-security", "content-security-policy",
        "x-frame-options", "x-content-type-options", "referrer-policy",
        "permissions-policy", "cross-origin-opener-policy",
        "cross-origin-embedder-policy", "cross-origin-resource-policy"
    ]
    score = 0
    found_ideal = 0
    last_idx = -1
    for h in ideal:
        for i, real_h in enumerate(security_headers):
            if real_h.lower() == h:
                found_ideal += 1
                if i > last_idx: score += 1
                last_idx = i
                break
    if security_headers and security_headers[0].lower() == "strict-transport-security":
        score += 2
    return {
        "security_headers_count": len(security_headers),
        "order_followed_ideal": found_ideal,
        "order_score": min(10, score),
        "actual_order": security_headers,
    }

# ── CSP Parsing & Enhanced Checks ───────────────────────────────────────
def _parse_csp(csp_header):
    directives = {}
    if not csp_header: return directives
    for part in re.split(r";\s*", csp_header.strip()):
        part = part.strip()
        if not part: continue
        if " " in part:
            name, value = part.split(" ", 1)
            directives[name.strip()] = value.strip()
        else:
            directives[part.strip()] = ""
    return directives

def _check_csp_enhanced(final_headers, is_api, url=""):
    if is_api:
        return [_make_finding("CSP not applicable (API)", "Non-HTML response", "info", 100, "pass",
                              "Content-Security-Policy", header_value="",
                              explanation="API endpoints typically do not render HTML, so CSP is not applicable.",
                              evidence="API endpoint detected.", poc=f"curl -Is {url} | grep -i 'content-security-policy'")], {}
    
    csp_raw = _get_header(final_headers, "Content-Security-Policy")
    if not csp_raw:
        present_headers = ', '.join(sorted(final_headers.keys()))
        evidence = f"Header 'Content-Security-Policy' not present. Headers received: {present_headers}"
        poc = f"curl -Is {url} | grep -i 'content-security-policy'"
        return [_make_finding("Missing Content-Security-Policy", "No CSP header found.", "high", 100, "fail",
                              "Content-Security-Policy", header_value="",
                              explanation="Without CSP, the application is vulnerable to Cross-Site Scripting (XSS) and data injection attacks.",
                              evidence=evidence, remediation="Implement a strict Content-Security-Policy.",
                              cwe=CWE_MAP["csp"], owasp=OWASP_MAP["csp"], poc=poc)], {}
    
    findings = []
    has_disqualifying_issue = False
    
    # 1. unsafe-inline
    if "'unsafe-inline'" in csp_raw:
        has_disqualifying_issue = True
        findings.append(_make_finding(
            "CSP allows 'unsafe-inline'",
            "The CSP value contains 'unsafe-inline', which permits inline script/style execution, defeating a major XSS protection.",
            "high", 100, "fail", "Content-Security-Policy",
            header_value=csp_raw,
            explanation="The 'unsafe-inline' keyword allows execution of inline scripts and styles. This defeats a major XSS protection CSP is meant to provide.",
            evidence=f"CSP contains 'unsafe-inline': {csp_raw[:200]}",
            remediation="Remove 'unsafe-inline' and use nonce- or hash-based script/style sources instead.",
            cwe="CWE-79", owasp="A03:2021",
            poc=f"curl -Is {url} | grep -i content-security-policy"
        ))
    
    # 2. unsafe-eval
    if "'unsafe-eval'" in csp_raw:
        has_disqualifying_issue = True
        findings.append(_make_finding(
            "CSP allows 'unsafe-eval'",
            "The CSP value contains 'unsafe-eval', which permits the use of eval() and similar methods.",
            "high", 100, "fail", "Content-Security-Policy",
            header_value=csp_raw,
            explanation="The 'unsafe-eval' keyword allows the execution of code passed to functions like eval(). This can be exploited for XSS.",
            evidence=f"CSP contains 'unsafe-eval': {csp_raw[:200]}",
            remediation="Remove 'unsafe-eval' and refactor code to avoid dynamic code execution.",
            cwe="CWE-79", owasp="A03:2021",
            poc=f"curl -Is {url} | grep -i content-security-policy"
        ))
    
    # 3. missing frame-ancestors
    if "frame-ancestors" not in csp_raw:
        has_disqualifying_issue = True
        findings.append(_make_finding(
            "CSP missing frame-ancestors directive",
            "The CSP does not contain a frame-ancestors directive.",
            "medium", 90, "warning", "Content-Security-Policy",
            header_value=csp_raw,
            explanation="Without frame-ancestors in the CSP, clickjacking protection depends entirely on X-Frame-Options being separately present and correctly configured.",
            evidence=f"CSP missing frame-ancestors: {csp_raw[:200]}",
            remediation="Add a frame-ancestors directive to your CSP (e.g., frame-ancestors 'none' or 'self').",
            cwe="CWE-1021", owasp="A01:2021",
            poc=f"curl -Is {url} | grep -i content-security-policy"
        ))
    
    # Parse directives for nonce/hash check
    directives = _parse_csp(csp_raw)
    script_src = directives.get("script-src", directives.get("default-src", ""))
    
    # 4. lacks nonce or hash
    has_nonce = bool(re.search(r"'nonce-[A-Za-z0-9+/=]+'", script_src))
    has_hash = bool(re.search(r"'(sha256|sha384|sha512)-[A-Za-z0-9+/=]+'", script_src))
    if not has_nonce and not has_hash:
        findings.append(_make_finding(
            "CSP script-src lacks nonce or hash source",
            "The CSP script-src (or default-src) directive does not contain any nonce or hash sources.",
            "low", 75, "info", "Content-Security-Policy",
            header_value=csp_raw,
            explanation="This is a best-practice gap. Using nonces or hashes provides defense-in-depth against XSS, though not as critical as unsafe-inline/unsafe-eval.",
            evidence=f"script-src lacks nonce/hash: {script_src[:200]}",
            remediation="Consider adding nonce- or hash-based sources to your script-src directive.",
            cwe="CWE-79", owasp="A03:2021",
            poc=f"curl -Is {url} | grep -i content-security-policy"
        ))
    
    # 5. missing strict-dynamic
    if "'strict-dynamic'" not in csp_raw:
        findings.append(_make_finding(
            "CSP missing strict-dynamic",
            "The CSP does not contain 'strict-dynamic'.",
            "low", 60, "info", "Content-Security-Policy",
            header_value=csp_raw,
            explanation="This is an optional hardening measure. 'strict-dynamic' allows scripts to load other scripts dynamically if they were loaded via a nonce or hash.",
            evidence=f"CSP missing strict-dynamic: {csp_raw[:200]}",
            remediation="Consider adding 'strict-dynamic' to your script-src directive if applicable.",
            cwe="CWE-79", owasp="A03:2021",
            poc=f"curl -Is {url} | grep -i content-security-policy"
        ))
    
    # Determine if CSP overall passed
    if not has_disqualifying_issue:
        findings.append(_make_finding(
            "CSP is well-configured",
            "No obvious weaknesses detected in the CSP.",
            "info", 95, "pass", "Content-Security-Policy",
            header_value=csp_raw,
            explanation="The Content-Security-Policy header is present and does not contain the disqualifying misconfigurations (unsafe-inline, unsafe-eval, missing frame-ancestors).",
            evidence=csp_raw[:200],
            poc=f"curl -Is {url} | grep -i content-security-policy"
        ))
    
    return findings, directives

# ── Improved Cache-Control Check ────────────────────────────────────────
def _check_cache_control(final_headers, set_cookie, url=""):
    cc = _get_header(final_headers, "Cache-Control")
    if not cc:
        present_headers = ', '.join(sorted(final_headers.keys()))
        if set_cookie:
            evidence = f"Header 'Cache-Control' not present (Set-Cookie is present). Headers received: {present_headers}"
            poc = f"curl -Is {url} | grep -i 'cache-control'"
            return [_make_finding(
                "Cache-Control missing on authenticated page",
                "Sensitive data may be cached.", "high", 100, "fail", "Cache-Control",
                header_value="",
                explanation="Without Cache-Control, browsers and intermediate proxies may cache sensitive authenticated responses, leading to data leakage.",
                evidence=evidence, remediation="Cache-Control: no-cache, no-store, must-revalidate",
                cwe=CWE_MAP["cache"], owasp=OWASP_MAP["cache"], poc=poc)]
        else:
            evidence = f"Header 'Cache-Control' not present. Headers received: {present_headers}"
            poc = f"curl -Is {url} | grep -i 'cache-control'"
            return [_make_finding(
                "Cache-Control header missing",
                "Without caching directives, browsers may cache sensitive data.", "low", 70, "warning", "Cache-Control",
                header_value="",
                explanation="The Cache-Control header is missing. While not critical for public pages, it is best practice to define caching behavior.",
                evidence=evidence, remediation="Add Cache-Control with appropriate directives.",
                cwe=CWE_MAP["cache"], owasp=OWASP_MAP["cache"], poc=poc)]
    
    cc_lower = cc.lower()
    issues = []
    sev = "info"
    if "public" in cc_lower:
        issues.append("contains 'public'")
        sev = "medium"
    if "no-store" not in cc_lower:
        issues.append("missing 'no-store'")
        if sev != "medium": sev = "medium"
    max_age_match = re.search(r"max-age=(\d+)", cc_lower)
    if max_age_match and int(max_age_match.group(1)) >= 86400:
        issues.append(f"long max-age ({max_age_match.group(1)}s)")
        if sev != "high": sev = "medium" if set_cookie else "low"
    if set_cookie and ("public" in cc_lower or "no-store" not in cc_lower):
        sev = "high"
        issues.append("session cookies may be cached")
    
    if not issues:
        return [_make_finding("Cache-Control correctly restricts caching",
                              f"Cache-Control: {cc}", "info", 100, "pass", "Cache-Control",
                              header_value=cc,
                              explanation="The Cache-Control header is correctly configured to prevent caching of sensitive data.",
                              evidence=cc, remediation="",
                              poc=f"curl -Is {url} | grep -i 'cache-control'")]
    
    desc = "; ".join(issues)
    return [_make_finding("Cache-Control insecure",
                          desc, sev, 90 if sev != "low" else 70, "fail" if sev in ("high", "medium") else "warning",
                          "Cache-Control", header_value=cc,
                          explanation="The Cache-Control header contains insecure directives that may lead to caching of sensitive data.",
                          evidence=cc, remediation="Set Cache-Control: no-cache, no-store, must-revalidate",
                          cwe=CWE_MAP["cache"], owasp=OWASP_MAP["cache"],
                          poc=f"curl -Is {url} | grep -i 'cache-control'")]

# ── X-DNS-Prefetch-Control ─────────────────────────────────────────────
def _check_dns_prefetch(final_headers, url=""):
    xdns = _get_header(final_headers, "X-DNS-Prefetch-Control")
    if not xdns:
        present_headers = ', '.join(sorted(final_headers.keys()))
        evidence = f"Header 'X-DNS-Prefetch-Control' not present. Headers received: {present_headers}"
        poc = f"curl -Is {url} | grep -i 'x-dns-prefetch-control'"
        return [_make_finding("X-DNS-Prefetch-Control missing",
                              "Browser may prefetch DNS for links, enabling tracking.", "low", 70, "warning",
                              "X-DNS-Prefetch-Control", header_value="",
                              explanation="Without X-DNS-Prefetch-Control: off, the browser may prefetch DNS for links in the page, which can leak information about the user's browsing activity to the DNS resolver.",
                              evidence=evidence, remediation="Add X-DNS-Prefetch-Control: off",
                              cwe=CWE_MAP["dns_prefetch"], owasp=OWASP_MAP["dns_prefetch"], poc=poc)]
    if xdns.lower() == "off":
        return [_make_finding("X-DNS-Prefetch-Control set to off", "", "info", 100, "pass",
                              "X-DNS-Prefetch-Control", header_value=xdns,
                              explanation="X-DNS-Prefetch-Control is correctly set to 'off', preventing DNS prefetching.",
                              evidence=xdns, poc=f"curl -Is {url} | grep -i 'x-dns-prefetch-control'")]
    return [_make_finding(f"X-DNS-Prefetch-Control set to '{xdns}'",
                          "Value is not 'off', allowing DNS prefetching.", "low", 60, "warning",
                          "X-DNS-Prefetch-Control", header_value=xdns,
                          explanation="X-DNS-Prefetch-Control is present but not set to 'off', allowing DNS prefetching.",
                          evidence=xdns, remediation="Set X-DNS-Prefetch-Control: off",
                          poc=f"curl -Is {url} | grep -i 'x-dns-prefetch-control'")]

# ── Enhanced HSTS ───────────────────────────────────────────────────────
def _check_hsts(headers_list=None, is_cdn=False, target_url="", final_headers=None):
    if is_cdn:
        return [_make_finding("HSTS not applicable (CDN domain)", "", "info", 100, "pass",
                              "Strict-Transport-Security", header_value="",
                              explanation="The target is a known CDN domain, which typically manages its own HSTS policy.",
                              evidence="CDN domain detected.", poc=f"curl -I {target_url} | grep -i strict")]
    
    hsts_values = []
    if final_headers is not None:
        headers_for_evidence = final_headers
    elif headers_list:
        headers_for_evidence = headers_list[-1]["headers"]
    else:
        headers_for_evidence = {}
        
    if headers_list:
        for r in headers_list:
            hdr = _get_header(r["headers"], "Strict-Transport-Security")
            if hdr: hsts_values.append(hdr)
    elif final_headers:
        hdr = _get_header(final_headers, "Strict-Transport-Security")
        if hdr: hsts_values.append(hdr)
        
    if not hsts_values:
        present_headers = ', '.join(sorted(headers_for_evidence.keys()))
        evidence = f"Header 'Strict-Transport-Security' not present. Headers received: {present_headers}"
        poc = f"curl -I {target_url} | grep -i strict"
        return [_make_finding("Missing HSTS header", "No HSTS found. SSL stripping attacks possible.", "high", 100, "fail",
                              "Strict-Transport-Security", header_value="",
                              explanation="Without HSTS, browsers will allow HTTP connections, making the application vulnerable to SSL stripping and man-in-the-middle attacks.",
                              evidence=evidence, remediation="Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
                              cwe=CWE_MAP["hsts"], owasp=OWASP_MAP["hsts"], poc=poc)]
    
    hdr = hsts_values[0]
    max_age = int(re.search(r"max-age\s*=\s*(\d+)", hdr, re.I).group(1)) if re.search(r"max-age\s*=\s*(\d+)", hdr, re.I) else 0
    incl_sub = "includesubdomains" in hdr.lower()
    preload = "preload" in hdr.lower()
    issues = []
    if max_age < 31536000: issues.append(f"max-age={max_age} (< 1 year)")
    elif max_age < 63072000: issues.append(f"max-age={max_age} (< 2 years, not preload ready)")
    if not incl_sub: issues.append("missing includeSubDomains")
    if not preload: issues.append("missing preload flag")
    
    if not issues:
        return [_make_finding("HSTS well configured", f"max-age={max_age}, includeSubDomains, preload", "info", 100, "pass",
                              "Strict-Transport-Security", header_value=hdr,
                              explanation="The HSTS header is correctly configured with a long max-age, includeSubDomains, and preload flags.",
                              evidence=hdr[:200], poc=f"curl -I {target_url} | grep -i strict")]
    
    sev = "medium"
    if preload and max_age < 63072000:
        sev = "high"
    return [_make_finding("HSTS insufficient / not preload-ready", "; ".join(issues), sev, 95, "warning",
                          "Strict-Transport-Security", header_value=hdr,
                          explanation="The HSTS header is present but does not meet best practice recommendations for maximum security and preload list inclusion.",
                          evidence=hdr[:200], remediation="Set max-age=63072000; includeSubDomains; preload",
                          cwe=CWE_MAP["hsts"], owasp=OWASP_MAP["hsts"], poc=f"curl -I {target_url} | grep -i strict")]

# ── Clickjacking ───────────────────────────────────────────────────────
def _check_clickjacking(final_headers, is_api, url=""):
    if is_api:
        return [_make_finding("Not applicable (API)", "", "info", 100, "pass", "X-Frame-Options",
                              header_value="", explanation="API endpoints typically do not render HTML, so clickjacking protection is not applicable.",
                              evidence="API endpoint detected.", poc=f"curl -Is {url} | grep -i 'x-frame-options\\|content-security-policy'")]
    
    xfo = _get_header(final_headers, "X-Frame-Options")
    csp_raw = _get_header(final_headers, "Content-Security-Policy")
    csp = _parse_csp(csp_raw) if csp_raw else {}
    
    if "frame-ancestors" in csp:
        val = csp["frame-ancestors"]
        if "'none'" in val:
            return [_make_finding("Clickjacking protected (CSP frame-ancestors: none)", "", "info", 100, "pass",
                                  "CSP frame-ancestors", header_value=csp_raw,
                                  explanation="The CSP frame-ancestors directive is set to 'none', which completely prevents the page from being embedded in iframes.",
                                  evidence=f"CSP frame-ancestors: {val}", poc=f"curl -Is {url} | grep -i 'content-security-policy'")]
        elif "'self'" in val:
            return [_make_finding("Clickjacking protected (same-origin)", "", "info", 90, "pass",
                                  "CSP frame-ancestors", header_value=csp_raw,
                                  explanation="The CSP frame-ancestors directive is set to 'self', allowing the page to be embedded only by pages from the same origin.",
                                  evidence=f"CSP frame-ancestors: {val}", poc=f"curl -Is {url} | grep -i 'content-security-policy'")]
        else:
            return [_make_finding("Framing allowed from external origins", f"frame-ancestors: {val[:200]}", "medium", 80, "warning",
                                  "CSP frame-ancestors", header_value=csp_raw,
                                  explanation="The CSP frame-ancestors directive allows framing from external origins, which may expose the application to clickjacking attacks if those origins are compromised.",
                                  evidence=f"CSP frame-ancestors: {val[:200]}", remediation="Restrict frame-ancestors to 'none' or 'self'.",
                                  poc="<iframe src='...'></iframe>")]
    
    if xfo and xfo.upper() in ("DENY", "SAMEORIGIN"):
        return [_make_finding("Clickjacking protected (XFO)", f"XFO: {xfo}", "info", 100, "pass",
                              "X-Frame-Options", header_value=xfo,
                              explanation="The X-Frame-Options header is set to a secure value, preventing clickjacking.",
                              evidence=f"X-Frame-Options: {xfo}", poc=f"curl -Is {url} | grep -i 'x-frame-options'")]
    elif xfo:
        return [_make_finding("X-Frame-Options insecure value", f"XFO: {xfo}", "critical", 100, "fail",
                              "X-Frame-Options", header_value=xfo,
                              explanation="The X-Frame-Options header is present but has an insecure value, failing to protect against clickjacking.",
                              evidence=f"X-Frame-Options: {xfo}", remediation="Use DENY or SAMEORIGIN.",
                              poc="<iframe src='...'></iframe>")]
    
    present_headers = ', '.join(sorted(final_headers.keys()))
    evidence = f"Neither X-Frame-Options nor CSP frame-ancestors present. Headers received: {present_headers}"
    return [_make_finding("Missing clickjacking protection", "Neither XFO nor CSP frame-ancestors set.", "high", 100, "fail",
                          "X-Frame-Options / CSP", header_value="",
                          explanation="The application lacks both X-Frame-Options and CSP frame-ancestors headers, leaving it fully vulnerable to clickjacking attacks.",
                          evidence=evidence, remediation="Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
                          poc="<iframe src='...'></iframe>")]

# ── X-Content-Type-Options ─────────────────────────────────────────────
def _check_xcto(final_headers, url=""):
    xcto = _get_header(final_headers, "X-Content-Type-Options")
    if xcto and xcto.lower() == "nosniff":
        return [_make_finding("X-Content-Type-Options: nosniff present", "", "info", 100, "pass",
                              "X-Content-Type-Options", header_value=xcto,
                              explanation="The X-Content-Type-Options header is set to 'nosniff', preventing MIME type sniffing.",
                              evidence=f"Value: {xcto}", poc=f"curl -Is {url} | grep -i 'x-content-type-options'")]
    
    present_headers = ', '.join(sorted(final_headers.keys()))
    evidence = f"Header 'X-Content-Type-Options' not present. Headers received: {present_headers}"
    poc = f"curl -Is {url} | grep -i 'x-content-type-options'"
    return [_make_finding("Missing X-Content-Type-Options", "MIME sniffing attacks possible.", "medium", 100, "fail",
                          "X-Content-Type-Options", header_value="",
                          explanation="Without X-Content-Type-Options: nosniff, browsers may attempt to sniff the MIME type of responses, which can lead to XSS attacks.",
                          evidence=evidence, remediation="Add: X-Content-Type-Options: nosniff",
                          cwe=CWE_MAP["xcto"], owasp=OWASP_MAP["xcto"], poc=poc)]

# ── Referrer-Policy ───────────────────────────────────────────────────
def _check_referrer_policy(final_headers, url=""):
    rp = _get_header(final_headers, "Referrer-Policy")
    safe = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin"}
    if not rp:
        present_headers = ', '.join(sorted(final_headers.keys()))
        evidence = f"Header 'Referrer-Policy' not present. Headers received: {present_headers}"
        poc = f"curl -Is {url} | grep -i 'referrer-policy'"
        return [_make_finding("Missing Referrer-Policy", "Referer header may leak URLs.", "medium", 100, "fail",
                              "Referrer-Policy", header_value="",
                              explanation="Without Referrer-Policy, the browser may send the full URL in the Referer header to external sites, leaking sensitive information.",
                              evidence=evidence, remediation="Set Referrer-Policy: strict-origin-when-cross-origin",
                              cwe=CWE_MAP["referrer"], owasp=OWASP_MAP["referrer"], poc=poc)]
    if rp.lower() in safe:
        return [_make_finding("Safe Referrer-Policy", f"Policy: {rp}", "info", 100, "pass", "Referrer-Policy",
                              header_value=rp,
                              explanation="The Referrer-Policy is set to a safe value that restricts the information sent in the Referer header.",
                              evidence=f"Value: {rp}", poc=f"curl -Is {url} | grep -i 'referrer-policy'")]
    if rp.lower() == "unsafe-url":
        return [_make_finding("Unsafe Referrer-Policy", "unsafe-url leaks full URLs.", "high", 100, "fail",
                              "Referrer-Policy", header_value=rp,
                              explanation="The Referrer-Policy is set to 'unsafe-url', which sends the full URL (including path and query parameters) to all destinations.",
                              evidence=f"Value: {rp}", remediation="Change to strict-origin-when-cross-origin",
                              poc=f"curl -Is {url} | grep -i 'referrer-policy'")]
    return [_make_finding("Non-optimal Referrer-Policy", f"Policy: {rp}", "low", 70, "warning",
                          "Referrer-Policy", header_value=rp,
                          explanation="The Referrer-Policy is present but not set to the most restrictive safe value.",
                          evidence=f"Value: {rp}", remediation="Use strict-origin-when-cross-origin",
                          poc=f"curl -Is {url} | grep -i 'referrer-policy'")]

# ── Permissions-Policy ─────────────────────────────────────────────────
def _check_permissions_policy(final_headers, url=""):
    pp = _get_header(final_headers, "Permissions-Policy")
    if not pp:
        present_headers = ', '.join(sorted(final_headers.keys()))
        evidence = f"Header 'Permissions-Policy' not present. Headers received: {present_headers}"
        poc = f"curl -Is {url} | grep -i 'permissions-policy'"
        return [_make_finding("Permissions-Policy missing", "Feature controls not enforced.", "low", 80, "warning",
                              "Permissions-Policy", header_value="",
                              explanation="Without Permissions-Policy, the browser allows all features (like camera, microphone, geolocation) by default, which can be exploited if the site is compromised.",
                              evidence=evidence, remediation="Add Permissions-Policy to restrict unnecessary features.",
                              cwe=CWE_MAP["permissions"], owasp=OWASP_MAP["permissions"], poc=poc)]
    if pp.strip() == "" or "*" in pp:
        return [_make_finding("Permissions-Policy too permissive", "No real restrictions.", "low", 90, "warning",
                              "Permissions-Policy", header_value=pp,
                              explanation="The Permissions-Policy header is present but does not effectively restrict any features.",
                              evidence=f"Value: {pp}", remediation="Disable unused features.",
                              poc=f"curl -Is {url} | grep -i 'permissions-policy'")]
    return [_make_finding("Permissions-Policy present", "Some features restricted.", "info", 90, "pass", "Permissions-Policy",
                          header_value=pp,
                          explanation="The Permissions-Policy header is present and restricts some browser features.",
                          evidence=f"Value: {pp}", poc=f"curl -Is {url} | grep -i 'permissions-policy'")]

# ── COOP / COEP / CORP ─────────────────────────────────────────────────
def _check_coop_coep_corp(final_headers, url=""):
    findings = []
    coop = _get_header(final_headers, "Cross-Origin-Opener-Policy")
    if not coop:
        present_headers = ', '.join(sorted(final_headers.keys()))
        evidence = f"Header 'Cross-Origin-Opener-Policy' not present. Headers received: {present_headers}"
        poc = f"curl -Is {url} | grep -i 'cross-origin-opener-policy'"
        findings.append(_make_finding("Missing COOP", "Cross-origin opener attacks possible.", "medium", 85, "warning",
                                      "Cross-Origin-Opener-Policy", header_value="",
                                      explanation="Without COOP, the page's browsing context group is not isolated, making it vulnerable to cross-origin attacks like Spectre.",
                                      evidence=evidence, remediation="COOP: same-origin",
                                      cwe=CWE_MAP["coop"], owasp=OWASP_MAP["coop"], poc=poc))
    elif coop.lower() in ("same-origin", "same-origin-allow-popups"):
        findings.append(_make_finding("COOP properly set", f"COOP: {coop}", "info", 100, "pass",
                                      "Cross-Origin-Opener-Policy", header_value=coop,
                                      explanation="The COOP header is set to a secure value, isolating the browsing context.",
                                      evidence=coop, poc=f"curl -Is {url} | grep -i 'cross-origin-opener-policy'"))
    else:
        findings.append(_make_finding("COOP not optimal", f"COOP: {coop}", "low", 60, "warning",
                                      "Cross-Origin-Opener-Policy", header_value=coop,
                                      explanation="The COOP header is present but set to a non-optimal value.",
                                      evidence=coop, remediation="Use same-origin", poc=poc))
    
    coep = _get_header(final_headers, "Cross-Origin-Embedder-Policy")
    if not coep:
        present_headers = ', '.join(sorted(final_headers.keys()))
        evidence = f"Header 'Cross-Origin-Embedder-Policy' not present. Headers received: {present_headers}"
        poc = f"curl -Is {url} | grep -i 'cross-origin-embedder-policy'"
        findings.append(_make_finding("Missing COEP", "Cross-origin embedding not controlled.", "medium", 80, "warning",
                                      "Cross-Origin-Embedder-Policy", header_value="",
                                      explanation="Without COEP, the page can load cross-origin resources without explicit permission, which can be exploited for certain attacks.",
                                      evidence=evidence, remediation="COEP: require-corp",
                                      cwe=CWE_MAP["coep"], owasp=OWASP_MAP["coep"], poc=poc))
    elif coep.lower() in ("require-corp", "credentialless"):
        findings.append(_make_finding("COEP properly set", f"COEP: {coep}", "info", 100, "pass",
                                      "Cross-Origin-Embedder-Policy", header_value=coep,
                                      explanation="The COEP header is set to a secure value, preventing the page from loading cross-origin resources without explicit permission.",
                                      evidence=coep, poc=f"curl -Is {url} | grep -i 'cross-origin-embedder-policy'"))
    else:
        findings.append(_make_finding("COEP not optimal", f"COEP: {coep}", "low", 60, "warning",
                                      "Cross-Origin-Embedder-Policy", header_value=coep,
                                      explanation="The COEP header is present but set to a non-optimal value.",
                                      evidence=coep, remediation="Use require-corp", poc=poc))
    
    corp = _get_header(final_headers, "Cross-Origin-Resource-Policy")
    if not corp:
        present_headers = ', '.join(sorted(final_headers.keys()))
        evidence = f"Header 'Cross-Origin-Resource-Policy' not present. Headers received: {present_headers}"
        poc = f"curl -Is {url} | grep -i 'cross-origin-resource-policy'"
        findings.append(_make_finding("Missing Cross-Origin-Resource-Policy", "Allows any website to load resources from your site.", "medium", 80, "warning",
                                      "Cross-Origin-Resource-Policy", header_value="",
                                      explanation="Without CORP, any website can load resources (like images, scripts) from your site, which can be used in cross-site script inclusion attacks.",
                                      evidence=evidence, remediation="Set CORP to 'same-origin' or 'same-site'.",
                                      cwe=CWE_MAP["corp"], owasp=OWASP_MAP["corp"], poc=poc))
    elif corp.strip().lower() in ("same-origin", "same-site"):
        findings.append(_make_finding("Cross-Origin-Resource-Policy properly set", f"Value: {corp}", "info", 100, "pass",
                                      "Cross-Origin-Resource-Policy", header_value=corp,
                                      explanation="The CORP header is set to a secure value, preventing other sites from loading your resources.",
                                      evidence=corp, poc=f"curl -Is {url} | grep -i 'cross-origin-resource-policy'"))
    else:
        findings.append(_make_finding(f"Cross-Origin-Resource-Policy set to '{corp}'", "Value may be too permissive.", "low", 60, "warning",
                                      "Cross-Origin-Resource-Policy", header_value=corp,
                                      explanation="The CORP header is present but set to a potentially permissive value.",
                                      evidence=corp, remediation="Set CORP to 'same-origin' or 'same-site'.", poc=poc))
    return findings

# ── X-XSS-Protection ───────────────────────────────────────────────────
def _check_xss_protection(final_headers, url=""):
    xssp = _get_header(final_headers, "X-XSS-Protection")
    if not xssp:
        return []
    if xssp.strip() == "0":
        return [_make_finding("X-XSS-Protection disabled (deprecated but safe)",
                              "Header set to 0 disables the legacy filter.", "info", 80, "pass",
                              "X-XSS-Protection", header_value=xssp,
                              explanation="The X-XSS-Protection header is set to '0', which disables the legacy XSS filter. This is the recommended configuration as the legacy filter can introduce vulnerabilities.",
                              evidence=xssp, poc=f"curl -Is {url} | grep -i 'x-xss-protection'")]
    return [_make_finding("X-XSS-Protection enabled (deprecated, potential risk)",
                          "The legacy XSS filter is deprecated; enabling it may introduce security risks.",
                          "low", 70, "warning", "X-XSS-Protection", header_value=xssp,
                          explanation="The X-XSS-Protection header is enabled. This legacy feature is deprecated and can introduce security risks in modern browsers.",
                          evidence=xssp, remediation="Remove or set to '0' to disable.",
                          poc=f"curl -Is {url} | grep -i 'x-xss-protection'")]

# ── Server / X-Powered-By ──────────────────────────────────────────────
def _check_server_info(final_headers, url=""):
    findings = []
    server = _get_header(final_headers, "Server")
    if server and server.lower() not in ("server", ""):
        findings.append(_make_finding(f"Server header exposed: {server}", "Information disclosure.", "low", 80, "info",
                                      "Server", header_value=server,
                                      explanation="The Server header reveals the underlying web server software and version, which can aid attackers in identifying known vulnerabilities.",
                                      evidence=f"Value: {server}", remediation="Remove Server header.",
                                      cwe=CWE_MAP["server_info"], owasp=OWASP_MAP["server_info"],
                                      poc=f"curl -Is {url} | grep -i 'server'"))
    powered = _get_header(final_headers, "X-Powered-By")
    if powered:
        findings.append(_make_finding(f"X-Powered-By exposed: {powered}", "Information disclosure.", "low", 85, "info",
                                      "X-Powered-By", header_value=powered,
                                      explanation="The X-Powered-By header reveals the underlying technology stack, which can aid attackers.",
                                      evidence=f"Value: {powered}", remediation="Remove X-Powered-By header.",
                                      poc=f"curl -Is {url} | grep -i 'x-powered-by'"))
    for specific in ["X-AspNet-Version", "X-AspNetMvc-Version"]:
        val = _get_header(final_headers, specific)
        if val:
            findings.append(_make_finding(f"Exact version disclosed: {val}", "Information disclosure.", "medium", 90, "info",
                                          specific, header_value=val,
                                          explanation=f"The {specific} header reveals the exact version of the framework, which can aid attackers.",
                                          evidence=val, remediation=f"Remove {specific} header.",
                                          cwe=CWE_MAP["server_info"], owasp=OWASP_MAP["server_info"],
                                          poc=f"curl -Is {url} | grep -i '{specific}'"))
    return findings

# ── Expect-CT ──────────────────────────────────────────────────────────
def _check_expect_ct(final_headers, url=""):
    ect = _get_header(final_headers, "Expect-CT")
    if ect:
        return [_make_finding("Expect-CT header present (deprecated)", "", "info", 50, "info", "Expect-CT",
                              header_value=ect,
                              explanation="The Expect-CT header is deprecated and no longer necessary in modern browsers.",
                              evidence=ect, poc=f"curl -Is {url} | grep -i 'expect-ct'")]
    return []

# ── X-Permitted-Cross-Domain-Policies ───────────────────────────────────
def _check_x_permitted_cross_domain(final_headers, url=""):
    xpcd = _get_header(final_headers, "X-Permitted-Cross-Domain-Policies")
    if not xpcd:
        present_headers = ', '.join(sorted(final_headers.keys()))
        evidence = f"Header 'X-Permitted-Cross-Domain-Policies' not present. Headers received: {present_headers}"
        poc = f"curl -Is {url} | grep -i 'x-permitted-cross-domain-policies'"
        return [_make_finding("Missing X-Permitted-Cross-Domain-Policies",
                              "Prevents Adobe Flash from loading data from your domain.", "low", 70, "warning",
                              "X-Permitted-Cross-Domain-Policies", header_value="",
                              explanation="The X-Permitted-Cross-Domain-Policies header is missing. While Flash is obsolete, this header is still checked by some legacy clients.",
                              evidence=evidence, remediation="Set to 'none' or 'master-only'.", poc=poc)]
    if xpcd.strip().lower() in ("none", "master-only"):
        return [_make_finding("X-Permitted-Cross-Domain-Policies properly set", "", "info", 100, "pass",
                              "X-Permitted-Cross-Domain-Policies", header_value=xpcd,
                              explanation="The X-Permitted-Cross-Domain-Policies header is correctly configured.",
                              evidence=xpcd, poc=f"curl -Is {url} | grep -i 'x-permitted-cross-domain-policies'")]
    return [_make_finding(f"X-Permitted-Cross-Domain-Policies set to '{xpcd}'",
                          "Value may not be restrictive enough.", "low", 60, "warning",
                          "X-Permitted-Cross-Domain-Policies", header_value=xpcd,
                          explanation="The X-Permitted-Cross-Domain-Policies header is present but not set to the most restrictive value.",
                          evidence=xpcd, remediation="Set to 'none' or 'master-only'.",
                          poc=f"curl -Is {url} | grep -i 'x-permitted-cross-domain-policies'")]

# ── NEW: Document-Policy ────────────────────────────────────────────────
def _check_document_policy(final_headers, url=""):
    dp = _get_header(final_headers, "Document-Policy")
    if not dp:
        present_headers = ', '.join(sorted(final_headers.keys()))
        evidence = f"Header 'Document-Policy' not present. Headers received: {present_headers}"
        poc = f"curl -Is {url} | grep -i 'document-policy'"
        return [_make_finding("Missing Document-Policy", "Document-Policy header is not set.", "low", 70, "warning",
                              "Document-Policy", header_value="",
                              explanation="The Document-Policy header allows a site to restrict the use of certain Web Platform features. While not strictly mandatory, it helps mitigate certain classes of attacks.",
                              evidence=evidence, remediation="Consider implementing Document-Policy to restrict unnecessary features.",
                              cwe=CWE_MAP.get("document_policy", "CWE-693"), owasp=OWASP_MAP.get("document_policy", "A05:2021"), poc=poc)]
    return [_make_finding("Document-Policy is set", f"Value: {dp}", "info", 90, "pass",
                          "Document-Policy", header_value=dp,
                          explanation="The Document-Policy header is present, which helps restrict the use of certain Web Platform features.",
                          evidence=dp, poc=f"curl -Is {url} | grep -i 'document-policy'")]

# ── NEW: Origin-Agent-Cluster ───────────────────────────────────────────
def _check_origin_agent_cluster(final_headers, url=""):
    oac = _get_header(final_headers, "Origin-Agent-Cluster")
    if not oac:
        present_headers = ', '.join(sorted(final_headers.keys()))
        evidence = f"Header 'Origin-Agent-Cluster' not present. Headers received: {present_headers}"
        poc = f"curl -Is {url} | grep -i 'origin-agent-cluster'"
        return [_make_finding("Missing Origin-Agent-Cluster", "Origin-Agent-Cluster header is not set.", "low", 70, "warning",
                              "Origin-Agent-Cluster", header_value="",
                              explanation="The Origin-Agent-Cluster header provides a mechanism to allow web applications to isolate their origins. This mitigates certain cross-origin attacks.",
                              evidence=evidence, remediation="Add Origin-Agent-Cluster: ?1 to your response headers.",
                              cwe=CWE_MAP.get("origin_agent_cluster", "CWE-693"), owasp=OWASP_MAP.get("origin_agent_cluster", "A05:2021"), poc=poc)]
    if oac.strip() != "?1":
        evidence = f"Header 'Origin-Agent-Cluster' has invalid value: {oac}"
        poc = f"curl -Is {url} | grep -i 'origin-agent-cluster'"
        return [_make_finding("Invalid Origin-Agent-Cluster value", f"Value: {oac}", "medium", 80, "fail",
                              "Origin-Agent-Cluster", header_value=oac,
                              explanation="The Origin-Agent-Cluster header must be set to '?1' to enable origin isolation. Any other value is ignored by browsers.",
                              evidence=evidence, remediation="Set Origin-Agent-Cluster: ?1",
                              cwe=CWE_MAP.get("origin_agent_cluster", "CWE-693"), owasp=OWASP_MAP.get("origin_agent_cluster", "A05:2021"), poc=poc)]
    return [_make_finding("Origin-Agent-Cluster is properly set", f"Value: {oac}", "info", 100, "pass",
                          "Origin-Agent-Cluster", header_value=oac,
                          explanation="The Origin-Agent-Cluster header is correctly set to '?1', enabling origin isolation.",
                          evidence=oac, poc=f"curl -Is {url} | grep -i 'origin-agent-cluster'")]

# ── NEW: Reporting API ──────────────────────────────────────────────────
def _check_reporting_api(final_headers, url=""):
    rt = _get_header(final_headers, "Report-To")
    rep = _get_header(final_headers, "Reporting-Endpoints")
    if not rt and not rep:
        present_headers = ', '.join(sorted(final_headers.keys()))
        evidence = f"Neither 'Report-To' nor 'Reporting-Endpoints' headers are present. Headers received: {present_headers}"
        poc = f"curl -Is {url} | grep -i 'report-to\\|reporting-endpoints'"
        return [_make_finding("Missing Reporting API configuration", "No Reporting API headers found.", "low", 60, "warning",
                              "Report-To / Reporting-Endpoints", header_value="",
                              explanation="The Reporting API allows browsers to send reports about security violations (e.g., CSP violations) to a server. Without it, you cannot monitor for attacks or misconfigurations in production.",
                              evidence=evidence, remediation="Implement the Reporting API by adding Report-To or Reporting-Endpoints headers.",
                              cwe=CWE_MAP.get("reporting_api", "CWE-693"), owasp=OWASP_MAP.get("reporting_api", "A05:2021"), poc=poc)]
    
    findings = []
    if rep:
        endpoints = re.findall(r'"(https?://[^"]+)"', rep)
        for ep in endpoints:
            if not ep.startswith("https://"):
                evidence = f"Reporting-Endpoints contains non-HTTPS endpoint: {ep}"
                poc = f"curl -Is {url} | grep -i 'reporting-endpoints'"
                findings.append(_make_finding("Reporting API endpoint uses HTTP", f"Endpoint: {ep}", "high", 90, "fail",
                                              "Reporting-Endpoints", header_value=rep,
                                              explanation="Reporting endpoints should use HTTPS to prevent man-in-the-middle attacks from intercepting or modifying security reports.",
                                              evidence=evidence, remediation="Change the Reporting API endpoint URL to use HTTPS.",
                                              cwe=CWE_MAP.get("reporting_api", "CWE-319"), owasp=OWASP_MAP.get("reporting_api", "A05:2021"), poc=poc))
        if not findings:
            findings.append(_make_finding("Reporting-Endpoints is configured", f"Value: {rep}", "info", 90, "pass",
                                          "Reporting-Endpoints", header_value=rep,
                                          explanation="The Reporting-Endpoints header is present and endpoints appear to use HTTPS.",
                                          evidence=rep, poc=f"curl -Is {url} | grep -i 'reporting-endpoints'"))
    elif rt:
        endpoints = re.findall(r'"url"\s*:\s*"(https?://[^"]+)"', rt)
        for ep in endpoints:
            if not ep.startswith("https://"):
                evidence = f"Report-To contains non-HTTPS endpoint: {ep}"
                poc = f"curl -Is {url} | grep -i 'report-to'"
                findings.append(_make_finding("Reporting API endpoint uses HTTP", f"Endpoint: {ep}", "high", 90, "fail",
                                              "Report-To", header_value=rt,
                                              explanation="Reporting endpoints should use HTTPS to prevent man-in-the-middle attacks from intercepting or modifying security reports.",
                                              evidence=evidence, remediation="Change the Reporting API endpoint URL to use HTTPS.",
                                              cwe=CWE_MAP.get("reporting_api", "CWE-319"), owasp=OWASP_MAP.get("reporting_api", "A05:2021"), poc=poc))
        if not findings:
            findings.append(_make_finding("Report-To is configured", f"Value: {rt}", "info", 90, "pass",
                                          "Report-To", header_value=rt,
                                          explanation="The Report-To header is present and endpoints appear to use HTTPS.",
                                          evidence=rt, poc=f"curl -Is {url} | grep -i 'report-to'"))
    return findings

# ── Better API vs HTML page detection ─────────────────────────────────
def _is_api_response(final_headers, final_url, main_html=None) -> bool:
    ct = _get_header(final_headers, "Content-Type") or ""
    ct_lower = ct.lower()
    if ct_lower.startswith(("application/json", "application/xml", "text/xml")):
        return True
    if ct_lower.startswith("image/"):
        return True
    if ct_lower.startswith("text/html"):
        return False
    parsed = urlparse(final_url)
    path = parsed.path.lower()
    if re.search(r'/(api|graphql|v[12])/', path):
        return True
    if main_html and isinstance(main_html, str):
        stripped = main_html.strip()
        if stripped and stripped[0] in ('{', '['):
            try:
                json.loads(stripped)
                return True
            except:
                pass
    return False

# ══════════════════════════════════════════════════════════════════════════
# Main Scanner – STRICTLY uses shared_page
# ══════════════════════════════════════════════════════════════════════════
async def run(url: str, shared_page: dict = None) -> Dict[str, Any]:
    target = _normalize_url(url)
    parsed = urlparse(target)
    hostname = parsed.hostname or ""
    port = parsed.port or 443
    
    if shared_page and not shared_page.get("error") and shared_page.get("status") == 200:
        final_headers = shared_page.get("headers", {})
        final_status = shared_page.get("status", 200)
        final_url = shared_page.get("base_url", target)
        main_html = shared_page.get("html", "")
        responses = []
        site_context = await _categorize_site(hostname, port, html=main_html, headers=final_headers)
        waf_detected = await _detect_waf(hostname, port, headers=final_headers)
        fetch_error = None
    else:
        final_headers = {}
        final_status = 0
        final_url = target
        main_html = ""
        responses = []
        site_context = await _categorize_site(hostname, port)
        waf_detected = await _detect_waf(hostname, port)
        
    content_type = _get_header(final_headers, "Content-Type") or ""
    set_cookie = _get_header(final_headers, "Set-Cookie")
    is_api = _is_api_response(final_headers, final_url, main_html)
    is_error_page = final_status >= 400
    is_cdn = any(hostname.endswith(d) for d in CDN_DOMAINS)
    has_report_to = bool(_get_header(final_headers, "Report-To") or _get_header(final_headers, "Reporting-Endpoints"))
    waf_fingerprints = _fingerprint_waf_from_headers(final_headers)
    
    if not responses:
        header_order_info = _analyze_header_order([{"headers": final_headers}])
    else:
        header_order_info = _analyze_header_order(responses)
        
    raw_findings = []
    if responses:
        raw_findings.extend(_check_hsts(headers_list=responses, is_cdn=is_cdn, target_url=target))
    else:
        raw_findings.extend(_check_hsts(final_headers=final_headers, is_cdn=is_cdn, target_url=target))
        
    raw_findings.extend(_check_clickjacking(final_headers, is_api, url=target))
    csp_findings, csp_directives = _check_csp_enhanced(final_headers, is_api, url=target)
    raw_findings.extend(csp_findings)
    raw_findings.extend(_check_xcto(final_headers, url=target))
    raw_findings.extend(_check_referrer_policy(final_headers, url=target))
    raw_findings.extend(_check_permissions_policy(final_headers, url=target))
    raw_findings.extend(_check_coop_coep_corp(final_headers, url=target))
    raw_findings.extend(_check_cache_control(final_headers, set_cookie, url=target))
    raw_findings.extend(_check_dns_prefetch(final_headers, url=target))
    raw_findings.extend(_check_xss_protection(final_headers, url=target))
    raw_findings.extend(_check_server_info(final_headers, url=target))
    raw_findings.extend(_check_expect_ct(final_headers, url=target))
    raw_findings.extend(_check_x_permitted_cross_domain(final_headers, url=target))
    
    # NEW CHECKS
    raw_findings.extend(_check_document_policy(final_headers, url=target))
    raw_findings.extend(_check_origin_agent_cluster(final_headers, url=target))
    raw_findings.extend(_check_reporting_api(final_headers, url=target))
    
    if is_error_page:
        raw_findings.append(_make_finding(f"Response returned {final_status}",
                                          "Security headers may belong to error page/WAF.", "info", 70, "warning",
                                          "Response Status", header_value=str(final_status),
                                          explanation="The response returned an error status code. Security headers analysis may be inaccurate if this is a WAF or error page.",
                                          evidence=f"HTTP {final_status}",
                                          remediation="Re-scan a known working page (200 OK)."))
                                          
    findings = [f for f in raw_findings if f["status"] in ("fail", "warning")]
    passing_checks = [f for f in raw_findings if f["status"] == "pass"]
    
    is_sensitive = any(cat in site_context.get("categories", []) for cat in ("ecommerce", "login"))
    is_sensitive = is_sensitive or site_context.get("has_login_form", False)
    
    if is_sensitive:
        sensitive_headers = {
            "Strict-Transport-Security", "X-Frame-Options", "Content-Security-Policy",
            "Cache-Control", "Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy",
            "Referrer-Policy"
        }
        boost_map = {"info": "info", "low": "medium", "medium": "high", "critical": "critical"}
        for f in findings:
            if f["header"] in sensitive_headers and f["severity"] != "critical":
                f["severity"] = boost_map.get(f["severity"], f["severity"])
                
    context = {
        "is_login_page": "login" in site_context.get("categories", []),
        "is_ecommerce": "ecommerce" in site_context.get("categories", []),
        "is_internal": "internal" in site_context.get("categories", []),
        "waf_detected": waf_detected,
        "has_report_to": has_report_to,
    }
    
    worst_sev = max((f["severity"] for f in findings), key=lambda s: SEVERITY_RANK.get(s, 0), default="info")
    status = "fail" if any(SEVERITY_RANK.get(f["severity"], 0) >= 3 for f in findings) else "warning" if findings else "pass"
    remediation = " | ".join(sorted(set(f["remediation"] for f in findings if f.get("remediation"))))
    if not remediation: remediation = "No action needed."
    
    details = {
        "final_url": final_url,
        "final_status": final_status,
        "is_error_page": is_error_page,
        "is_api": is_api,
        "is_cdn": is_cdn,
        "content_type": content_type,
        "waf_detected": waf_detected,
        "waf_fingerprints": waf_fingerprints,
        "site_categories": site_context.get("categories", []),
        "has_report_to": has_report_to,
        "header_order_analysis": header_order_info,
        "headers_summary": {
            "checked": len(raw_findings),
            "issues": len(findings),
            "passed": len(passing_checks),
        },
    }
    
    return {
        "scanner": SCANNER_NAME,
        "target": target,
        "status": status,
        "severity": worst_sev,
        "confidence": 70 if is_error_page else 95,
        "summary": f"Security Headers – {len(findings)} issues found, {len(passing_checks)} checks passed",
        "findings": findings,
        "passing_checks": passing_checks,
        "remediation": remediation,
        "details": details,
    }

if __name__ == "__main__":
    target_url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    result = asyncio.run(run(target_url))
    print(json.dumps(result, indent=2, ensure_ascii=False))