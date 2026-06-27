#!/usr/bin/env python3
"""
test_05_security_headers.py – Bravo6 Ultimate Security Headers Auditor (v6.5 – Pure shared_page)
========================================================================================
Now operates strictly on the shared_page dict from the orchestrator.
All network requests have been removed; the module only analyses pre-fetched data.

Improvements (retained):
- Fixed HSTS logic when using shared_page (checks final HTTPS response correctly).
- _check_xss_protection returns consistent pass/warning findings.
- Enhanced dynamic severity boosting for sensitive sites (login form, ecommerce)
  extends to more headers (Cache‑Control, COOP, COEP, Referrer‑Policy).
- Better API vs HTML page detection (content‑type, URL path heuristics, JSON sniffing).
- Excellent CSP parsing retained.
"""

import asyncio, json, re, random, sys
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup, Comment

SCANNER_NAME = "security_headers"
USER_AGENT = "Bravo6-SecurityHeaders/6.5"

CDN_DOMAINS = (
    ".cloudfront.net", ".azurewebsites.net", ".herokuapp.com",
    ".github.io", ".netlify.app", ".vercel.app", ".firebaseapp.com",
    ".pages.dev", ".workers.dev"
)
SEVERITY_RANK = {"info":0,"low":1,"medium":2,"high":3,"critical":4}

CWE_MAP = {
    "hsts":"CWE-319","clickjacking":"CWE-1021","csp":"CWE-1021",
    "xcto":"CWE-693","referrer":"CWE-200","permissions":"CWE-693",
    "coop":"CWE-693","coep":"CWE-693","corp":"CWE-693","cache":"CWE-525",
    "server_info":"CWE-200","dns_prefetch":"CWE-693"
}
OWASP_MAP = {
    "hsts":"A05:2021","clickjacking":"A01:2021","csp":"A01:2021",
    "xcto":"A05:2021","referrer":"A01:2021","permissions":"A05:2021",
    "coop":"A05:2021","coep":"A05:2021","corp":"A05:2021","cache":"A05:2021",
    "server_info":"A01:2021","dns_prefetch":"A05:2021"
}

# ── Helpers ──────────────────────────────────────────────────────────────
def _normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://","https://")):
        url = "https://"+url
    return url

def _get_header(headers: Dict[str,str], name: str) -> Optional[str]:
    for k,v in headers.items():
        if k.lower()==name.lower(): return v
    return None

# ── Pre‑scan: WAF (no network requests) ─────────────────────────────────
async def _detect_waf(hostname: str, port: int=443,
                      html: str = None, headers: dict = None) -> Optional[str]:
    """
    Pure static detection from headers; no fallback request.
    """
    if headers:
        if 'cf-ray' in {k.lower() for k in headers}: return 'cloudflare'
        if 'x-sucuri-id' in {k.lower() for k in headers}: return 'sucuri'
        if 'x-akamai-request-id' in {k.lower() for k in headers}: return 'akamai'
        if headers.get('server','').lower().startswith('cloudflare'): return 'cloudflare'
    return None

def _fingerprint_waf_from_headers(headers: Dict[str,str]) -> List[str]:
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
    "bank":["bank","بنك","online banking"],
    "ecommerce":["shop","متجر","buy","cart","checkout","pay"],
    "healthcare":["hospital","مستشفى"],
    "login":["sign in","login","تسجيل الدخول"],
    "blog":["blog","مدونة","articles"],
    "internal":["intranet","internal"],
}
async def _categorize_site(hostname: str, port: int=443,
                          html: str = None, headers: dict = None) -> Dict:
    """
    Uses only the supplied HTML; no network requests.
    """
    result = {"categories":[],"has_login_form":False,"title":"","meta_keywords":""}
    if not html:
        return result
    text = html
    title_match = re.search(r'<title>(.*?)</title>',text,re.IGNORECASE)
    if title_match: result["title"] = title_match.group(1)
    meta_match = re.search(r'<meta\s+name="keywords"\s+content="(.*?)"',text,re.IGNORECASE)
    if meta_match: result["meta_keywords"] = meta_match.group(1)
    if re.search(r'<input\s+[^>]*type=["\']?password["\']?',text,re.IGNORECASE):
        result["has_login_form"] = True
    text_lower = (result["title"]+" "+result["meta_keywords"]).lower()
    for category,keywords in SITE_CATEGORIES.items():
        if any(k in text_lower for k in keywords):
            result["categories"].append(category)
    return result

# ── Finding & Scoring ───────────────────────────────────────────────────
def _make_finding(title,description,severity,confidence,status="fail",
                  header="",evidence="",remediation="",cwe="",owasp="",poc=None):
    return {
        "title":title,"description":description,"severity":severity,
        "confidence":confidence,"status":status,"header":header,
        "evidence":evidence,"remediation":remediation,"cwe":cwe,
        "owasp":owasp,"poc":poc
    }

def _apply_scoring(findings: List[Dict], context: Dict, directives: Dict={}) -> Tuple[int,str,List[str]]:
    deductions = {"critical":25,"high":15,"medium":8,"low":3,"info":0}
    score = 100
    total_deduct = 0
    breakdown = []
    for f in findings:
        sev = f.get("severity","info")
        ded = deductions.get(sev,0)
        if ded>0:
            total_deduct += ded
            breakdown.append(f"-{ded} ({sev}): {f['title']}")
    score -= total_deduct
    is_login = context.get("is_login_page",False) or ("login" in context.get("categories",[]))
    is_ecom = context.get("is_ecommerce",False) or ("ecommerce" in context.get("categories",[]))
    is_internal = context.get("is_internal",False) or ("internal" in context.get("categories",[]))
    waf = context.get("waf_detected",False)
    if is_login or is_ecom:
        score = min(100, score+10)
        breakdown.append("+10 (Login/E-commerce context)")
    if is_internal:
        score = max(0, score-15)
        breakdown.append("-15 (Internal IP)")
    if waf:
        score = min(100, score+10)
        breakdown.append("+10 (WAF/CDN detected)")
    if directives:
        if "require-trusted-types-for" in directives:
            score = min(100, score+3)
            breakdown.append("+3 (Trusted Types)")
        if "report-uri" in directives or "report-to" in directives:
            score = min(100, score+2)
            breakdown.append("+2 (CSP reporting)")
    if context.get("has_report_to"):
        score = min(100, score+1)
        breakdown.append("+1 (Report-To header)")
    score = max(0, min(100, score))
    if score>=95: grade="A+"
    elif score>=90: grade="A"
    elif score>=85: grade="A-"
    elif score>=80: grade="B"
    elif score>=70: grade="C"
    elif score>=60: grade="D"
    elif score>=50: grade="E"
    else: grade="F"
    return score, grade, breakdown

# ── Header Order Analysis ───────────────────────────────────────────────
def _analyze_header_order(headers_list):
    final_headers = headers_list[-1]["headers"] if headers_list else {}
    header_names = list(final_headers.keys())
    security_headers = [h for h in header_names if h.lower() in [
        "strict-transport-security","content-security-policy",
        "x-frame-options","x-content-type-options","referrer-policy",
        "permissions-policy","cross-origin-opener-policy",
        "cross-origin-embedder-policy","cross-origin-resource-policy"
    ]]
    ideal = [
        "strict-transport-security","content-security-policy",
        "x-frame-options","x-content-type-options","referrer-policy",
        "permissions-policy","cross-origin-opener-policy",
        "cross-origin-embedder-policy","cross-origin-resource-policy"
    ]
    score=0; found_ideal=0; last_idx=-1
    for h in ideal:
        for i,real_h in enumerate(security_headers):
            if real_h.lower()==h:
                found_ideal+=1
                if i>last_idx: score+=1
                last_idx=i; break
    if security_headers and security_headers[0].lower()=="strict-transport-security":
        score+=2
    return {
        "security_headers_count":len(security_headers),
        "order_followed_ideal":found_ideal,
        "order_score":min(10,score),
        "actual_order":security_headers,
    }

# ── CSP Parsing & Enhanced Checks ───────────────────────────────────────
def _parse_csp(csp_header):
    directives = {}
    if not csp_header: return directives
    for part in re.split(r";\s*",csp_header.strip()):
        part = part.strip()
        if not part: continue
        if " " in part: name,value = part.split(" ",1); directives[name.strip()]=value.strip()
        else: directives[part.strip()]=""
    return directives

def _has_nonce_or_strict_dynamic(directives):
    script_src = directives.get("script-src","")
    return bool(re.search(r"nonce-[a-zA-Z0-9+/=]+",script_src)) or "strict-dynamic" in script_src

def _check_csp_enhanced(final_headers, is_api) -> Tuple[List[Dict], Dict]:
    if is_api:
        return [_make_finding("CSP not applicable (API)","Non‑HTML response","info",100,"pass","Content-Security-Policy")], {}
    csp_raw = _get_header(final_headers,"Content-Security-Policy")
    if not csp_raw:
        return [_make_finding("Missing Content‑Security‑Policy","No CSP header found.","high",100,"fail",
                              "Content-Security-Policy",evidence="Header missing",
                              remediation="Implement a strict CSP.",
                              cwe=CWE_MAP["csp"],owasp=OWASP_MAP["csp"])], {}
    directives = _parse_csp(csp_raw)
    findings = []
    for dir_name in ["default-src","script-src"]:
        val = directives.get(dir_name,"")
        if val=="*" or re.match(r'^\s*\*\s*$',val):
            findings.append(_make_finding(
                f"Dangerous CSP: {dir_name} *",
                f"The directive {dir_name} is set to wildcard, allowing resources from any origin.",
                "critical",100,"fail","Content-Security-Policy",
                evidence=f"{dir_name} {val}",
                remediation=f"Restrict {dir_name} to 'self' or specific origins.",
                cwe=CWE_MAP["csp"],owasp=OWASP_MAP["csp"]))
    if "unsafe-inline" in directives.get("script-src","") and not _has_nonce_or_strict_dynamic(directives):
        findings.append(_make_finding(
            "CSP allows unsafe-inline scripts without nonce/strict-dynamic",
            "This enables inline script execution.","critical",100,"fail",
            "Content-Security-Policy",evidence=f"script-src: {directives.get('script-src','')}",
            remediation="Use nonces or 'strict-dynamic' instead of unsafe-inline.",
            cwe=CWE_MAP["csp"],owasp=OWASP_MAP["csp"]))
    if "unsafe-eval" in directives.get("script-src",""):
        findings.append(_make_finding(
            "CSP allows unsafe-eval","Allows eval() in scripts.","high",90,"fail",
            "Content-Security-Policy",evidence=f"script-src: {directives.get('script-src','')}",
            remediation="Remove 'unsafe-eval' from script-src.",
            cwe=CWE_MAP["csp"],owasp=OWASP_MAP["csp"]))
    if "unsafe-inline" in directives.get("style-src",""):
        findings.append(_make_finding(
            "CSP allows unsafe-inline in style-src","Allows CSS injection.","medium",85,"warning",
            "Content-Security-Policy",evidence=f"style-src: {directives.get('style-src','')}",
            remediation="Use nonces for styles or remove unsafe-inline.",
            cwe=CWE_MAP["csp"],owasp=OWASP_MAP["csp"]))
    for dir_name,msg in [
        ("base-uri","Missing base-uri (allows base injection)"),
        ("form-action","Missing form-action (allows form data to any origin)"),
        ("frame-ancestors","Missing frame-ancestors (clickjacking risk)"),
        ("object-src","Missing object-src (allows plugins)"),
    ]:
        if dir_name not in directives:
            findings.append(_make_finding(
                f"CSP missing {dir_name}",msg,"medium",80,"warning",
                "Content-Security-Policy",evidence="Directive missing",
                remediation=f"Add {dir_name} directive.",
                cwe=CWE_MAP["csp"],owasp=OWASP_MAP["csp"]))
    if not findings:
        findings.append(_make_finding("CSP is well‑configured","No obvious weaknesses detected.","info",90,"pass",
                                      "Content-Security-Policy",evidence=csp_raw[:200]))
    return findings, directives

# ── Improved Cache‑Control Check ────────────────────────────────────────
def _check_cache_control(final_headers, set_cookie):
    cc = _get_header(final_headers,"Cache-Control")
    if not cc:
        if set_cookie:
            return [_make_finding(
                "Cache‑Control missing on authenticated page",
                "Sensitive data may be cached.","high",100,"fail","Cache-Control",
                evidence="Header missing (Set-Cookie present)",
                remediation="Cache-Control: no-cache, no-store, must-revalidate",
                cwe=CWE_MAP["cache"],owasp=OWASP_MAP["cache"])]
        else:
            return [_make_finding(
                "Cache‑Control header missing",
                "Without caching directives, browsers may cache sensitive data.","low",70,"warning","Cache-Control",
                evidence="Header missing",
                remediation="Add Cache-Control with appropriate directives.",
                cwe=CWE_MAP["cache"],owasp=OWASP_MAP["cache"])]
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
        return [_make_finding("Cache‑Control correctly restricts caching",
                              f"Cache-Control: {cc}","info",100,"pass","Cache-Control",
                              evidence=cc,remediation="")]
    desc = "; ".join(issues)
    return [_make_finding("Cache‑Control insecure",
                          desc,sev,90 if sev!="low" else 70,"fail" if sev in ("high","medium") else "warning",
                          "Cache-Control",evidence=cc,
                          remediation="Set Cache-Control: no-cache, no-store, must-revalidate",
                          cwe=CWE_MAP["cache"],owasp=OWASP_MAP["cache"])]

# ── X‑DNS‑Prefetch‑Control ─────────────────────────────────────────────
def _check_dns_prefetch(final_headers):
    xdns = _get_header(final_headers,"X-DNS-Prefetch-Control")
    if not xdns:
        return [_make_finding("X-DNS-Prefetch-Control missing",
                              "Browser may prefetch DNS for links, enabling tracking.","low",70,"warning",
                              "X-DNS-Prefetch-Control",evidence="Header missing",
                              remediation="Add X-DNS-Prefetch-Control: off",
                              cwe=CWE_MAP["dns_prefetch"],owasp=OWASP_MAP["dns_prefetch"])]
    if xdns.lower()=="off":
        return [_make_finding("X-DNS-Prefetch-Control set to off","","info",100,"pass",
                              "X-DNS-Prefetch-Control",evidence=xdns)]
    return [_make_finding(f"X-DNS-Prefetch-Control set to '{xdns}'",
                          "Value is not 'off', allowing DNS prefetching.","low",60,"warning",
                          "X-DNS-Prefetch-Control",evidence=xdns,
                          remediation="Set X-DNS-Prefetch-Control: off")]

# ── Enhanced HSTS (accepts optional final headers dict) ─────────────────
def _check_hsts(headers_list=None, is_cdn=False, target_url="", final_headers=None):
    if is_cdn:
        return [_make_finding("HSTS not applicable (CDN domain)","","info",100,"pass","Strict-Transport-Security",
                              evidence="CDN domain")]
    hsts_values = []
    if headers_list:
        for r in headers_list:
            hdr = _get_header(r["headers"],"Strict-Transport-Security")
            if hdr: hsts_values.append(hdr)
    elif final_headers:
        hdr = _get_header(final_headers, "Strict-Transport-Security")
        if hdr: hsts_values.append(hdr)

    if not hsts_values:
        return [_make_finding("Missing HSTS header","No HSTS found. SSL stripping attacks possible.","high",100,"fail",
                              "Strict-Transport-Security",evidence="Header missing",
                              remediation="Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
                              cwe=CWE_MAP["hsts"],owasp=OWASP_MAP["hsts"],
                              poc=f"curl -I {target_url} | grep -i strict")]
    hdr = hsts_values[0]
    max_age = int(re.search(r"max-age\s*=\s*(\d+)",hdr,re.I).group(1)) if re.search(r"max-age\s*=\s*(\d+)",hdr,re.I) else 0
    incl_sub = "includesubdomains" in hdr.lower()
    preload = "preload" in hdr.lower()
    issues = []
    if max_age < 31536000: issues.append(f"max-age={max_age} (< 1 year)")
    elif max_age < 63072000: issues.append(f"max-age={max_age} (< 2 years, not preload ready)")
    if not incl_sub: issues.append("missing includeSubDomains")
    if not preload: issues.append("missing preload flag")
    if not issues:
        return [_make_finding("HSTS well configured",f"max-age={max_age}, includeSubDomains, preload","info",100,"pass",
                              "Strict-Transport-Security",evidence=hdr[:200])]
    sev = "medium"
    if preload and max_age < 63072000:
        sev = "high"
    return [_make_finding("HSTS insufficient / not preload‑ready","; ".join(issues),sev,95,"warning",
                          "Strict-Transport-Security",evidence=hdr[:200],
                          remediation="Set max-age=63072000; includeSubDomains; preload",
                          cwe=CWE_MAP["hsts"],owasp=OWASP_MAP["hsts"])]

# ── Clickjacking ───────────────────────────────────────────────────────
def _check_clickjacking(final_headers, is_api):
    if is_api:
        return [_make_finding("Not applicable (API)","","info",100,"pass","X-Frame-Options")]
    xfo = _get_header(final_headers,"X-Frame-Options")
    csp_raw = _get_header(final_headers,"Content-Security-Policy")
    csp = _parse_csp(csp_raw) if csp_raw else {}
    if "frame-ancestors" in csp:
        val = csp["frame-ancestors"]
        if "'none'" in val:
            return [_make_finding("Clickjacking protected (CSP frame-ancestors: none)","","info",100,"pass","CSP frame-ancestors")]
        elif "'self'" in val:
            return [_make_finding("Clickjacking protected (same‑origin)","","info",90,"pass","CSP frame-ancestors")]
        else:
            return [_make_finding("Framing allowed from external origins",f"frame-ancestors: {val[:200]}","medium",80,"warning",
                                  "CSP frame-ancestors",remediation="Restrict to 'none' or 'self'.",poc="<iframe src='...'></iframe>")]
    if xfo and xfo.upper() in ("DENY","SAMEORIGIN"):
        return [_make_finding("Clickjacking protected (XFO)",f"XFO: {xfo}","info",100,"pass","X-Frame-Options")]
    elif xfo:
        return [_make_finding("X-Frame-Options insecure value",f"XFO: {xfo}","critical",100,"fail",
                              "X-Frame-Options",remediation="Use DENY or SAMEORIGIN.",poc="<iframe src='...'></iframe>")]
    return [_make_finding("Missing clickjacking protection","Neither XFO nor CSP frame-ancestors set.","critical",100,"fail",
                          "X-Frame-Options / CSP",remediation="Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
                          poc="<iframe src='...'></iframe>")]

# ── X‑Content‑Type‑Options ─────────────────────────────────────────────
def _check_xcto(final_headers):
    xcto = _get_header(final_headers,"X-Content-Type-Options")
    if xcto and xcto.lower()=="nosniff":
        return [_make_finding("X-Content-Type-Options: nosniff present","","info",100,"pass","X-Content-Type-Options")]
    return [_make_finding("Missing X-Content-Type-Options","MIME sniffing attacks possible.","medium",100,"fail",
                          "X-Content-Type-Options",remediation="Add: X-Content-Type-Options: nosniff",
                          cwe=CWE_MAP["xcto"],owasp=OWASP_MAP["xcto"])]

# ── Referrer‑Policy ───────────────────────────────────────────────────
def _check_referrer_policy(final_headers):
    rp = _get_header(final_headers,"Referrer-Policy")
    safe = {"no-referrer","strict-origin","strict-origin-when-cross-origin"}
    if not rp:
        return [_make_finding("Missing Referrer-Policy","Referer header may leak URLs.","medium",100,"fail",
                              "Referrer-Policy",remediation="Set Referrer-Policy: strict-origin-when-cross-origin",
                              cwe=CWE_MAP["referrer"],owasp=OWASP_MAP["referrer"])]
    if rp.lower() in safe:
        return [_make_finding("Safe Referrer-Policy",f"Policy: {rp}","info",100,"pass","Referrer-Policy")]
    if rp.lower()=="unsafe-url":
        return [_make_finding("Unsafe Referrer-Policy","unsafe-url leaks full URLs.","high",100,"fail",
                              "Referrer-Policy",remediation="Change to strict-origin-when-cross-origin")]
    return [_make_finding("Non‑optimal Referrer-Policy",f"Policy: {rp}","low",70,"warning",
                          "Referrer-Policy",remediation="Use strict-origin-when-cross-origin")]

# ── Permissions‑Policy ─────────────────────────────────────────────────
def _check_permissions_policy(final_headers):
    pp = _get_header(final_headers,"Permissions-Policy")
    if not pp:
        return [_make_finding("Permissions-Policy missing","Feature controls not enforced.","low",80,"warning",
                              "Permissions-Policy",remediation="Add Permissions-Policy")]
    if pp.strip()=="" or "*" in pp:
        return [_make_finding("Permissions-Policy too permissive","No real restrictions.","low",90,"warning",
                              "Permissions-Policy",remediation="Disable unused features.")]
    return [_make_finding("Permissions-Policy present","Some features restricted.","info",90,"pass","Permissions-Policy")]

# ── COOP / COEP / CORP ─────────────────────────────────────────────────
def _check_coop_coep_corp(final_headers):
    findings = []
    coop = _get_header(final_headers,"Cross-Origin-Opener-Policy")
    if not coop:
        findings.append(_make_finding("Missing COOP","Cross‑origin opener attacks possible.","medium",85,"warning",
                                      "Cross-Origin-Opener-Policy",evidence="Header missing",
                                      remediation="COOP: same-origin",
                                      cwe=CWE_MAP["coop"],owasp=OWASP_MAP["coop"]))
    elif coop.lower() in ("same-origin","same-origin-allow-popups"):
        findings.append(_make_finding("COOP properly set",f"COOP: {coop}","info",100,"pass",
                                      "Cross-Origin-Opener-Policy",evidence=coop))
    else:
        findings.append(_make_finding("COOP not optimal",f"COOP: {coop}","low",60,"warning",
                                      "Cross-Origin-Opener-Policy",evidence=coop,
                                      remediation="Use same-origin"))
    coep = _get_header(final_headers,"Cross-Origin-Embedder-Policy")
    if not coep:
        findings.append(_make_finding("Missing COEP","Cross‑origin embedding not controlled.","medium",80,"warning",
                                      "Cross-Origin-Embedder-Policy",evidence="Header missing",
                                      remediation="COEP: require-corp",
                                      cwe=CWE_MAP["coep"],owasp=OWASP_MAP["coep"]))
    elif coep.lower() in ("require-corp","credentialless"):
        findings.append(_make_finding("COEP properly set",f"COEP: {coep}","info",100,"pass",
                                      "Cross-Origin-Embedder-Policy",evidence=coep))
    else:
        findings.append(_make_finding("COEP not optimal",f"COEP: {coep}","low",60,"warning",
                                      "Cross-Origin-Embedder-Policy",evidence=coep,
                                      remediation="Use require-corp"))
    corp = _get_header(final_headers,"Cross-Origin-Resource-Policy")
    if not corp:
        findings.append(_make_finding("Missing Cross-Origin-Resource-Policy",
                                      "Allows any website to load resources from your site.","medium",80,"warning",
                                      "Cross-Origin-Resource-Policy",evidence="Header missing",
                                      remediation="Set CORP to 'same-origin' or 'same-site'.",
                                      cwe=CWE_MAP["corp"],owasp=OWASP_MAP["corp"]))
    elif corp.strip().lower() in ("same-origin","same-site"):
        findings.append(_make_finding("Cross-Origin-Resource-Policy properly set",f"Value: {corp}","info",100,"pass",
                                      "Cross-Origin-Resource-Policy",evidence=corp))
    else:
        findings.append(_make_finding(f"Cross-Origin-Resource-Policy set to '{corp}'",
                                      "Value may be too permissive.","low",60,"warning",
                                      "Cross-Origin-Resource-Policy",evidence=corp,
                                      remediation="Set CORP to 'same-origin' or 'same-site'."))
    return findings

# ── X‑XSS‑Protection (now consistent with other checks) ─────────────────
def _check_xss_protection(final_headers):
    xssp = _get_header(final_headers,"X-XSS-Protection")
    if not xssp:
        return []   # deprecated header, missing is acceptable
    if xssp.strip() == "0":
        return [_make_finding("X-XSS-Protection disabled (deprecated but safe)",
                              "Header set to 0 disables the legacy filter.","info",80,"pass",
                              "X-XSS-Protection",evidence=xssp)]
    return [_make_finding("X-XSS-Protection enabled (deprecated, potential risk)",
                          "The legacy XSS filter is deprecated; enabling it may introduce security risks.",
                          "low",70,"warning","X-XSS-Protection",evidence=xssp,
                          remediation="Remove or set to '0' to disable.")]

# ── Server / X‑Powered‑By ──────────────────────────────────────────────
def _check_server_info(final_headers):
    findings = []
    server = _get_header(final_headers,"Server")
    if server and server.lower() not in ("server",""):
        findings.append(_make_finding(f"Server header exposed: {server}","Information disclosure.","low",80,"info",
                                      "Server",remediation="Remove Server header.",
                                      cwe=CWE_MAP["server_info"],owasp=OWASP_MAP["server_info"]))
    powered = _get_header(final_headers,"X-Powered-By")
    if powered:
        findings.append(_make_finding(f"X-Powered-By exposed: {powered}","Information disclosure.","low",85,"info",
                                      "X-Powered-By",remediation="Remove X-Powered-By header."))
    for specific in ["X-AspNet-Version","X-AspNetMvc-Version"]:
        val = _get_header(final_headers,specific)
        if val:
            findings.append(_make_finding(f"Exact version disclosed: {val}","Information disclosure.","medium",90,"info",
                                          specific,evidence=val,remediation=f"Remove {specific} header.",
                                          cwe=CWE_MAP["server_info"],owasp=OWASP_MAP["server_info"]))
    return findings

# ── Expect‑CT ──────────────────────────────────────────────────────────
def _check_expect_ct(final_headers):
    ect = _get_header(final_headers,"Expect-CT")
    if ect:
        return [_make_finding("Expect-CT header present (deprecated)","","info",50,"info","Expect-CT",evidence=ect)]
    return []

# ── X‑Permitted‑Cross‑Domain‑Policies ───────────────────────────────────
def _check_x_permitted_cross_domain(final_headers):
    xpcd = _get_header(final_headers,"X-Permitted-Cross-Domain-Policies")
    if not xpcd:
        return [_make_finding("Missing X-Permitted-Cross-Domain-Policies",
                              "Prevents Adobe Flash from loading data from your domain.","low",70,"warning",
                              "X-Permitted-Cross-Domain-Policies",evidence="Header missing",
                              remediation="Set to 'none' or 'master-only'.")]
    if xpcd.strip().lower() in ("none","master-only"):
        return [_make_finding("X-Permitted-Cross-Domain-Policies properly set","","info",100,"pass",
                              "X-Permitted-Cross-Domain-Policies",evidence=xpcd)]
    return [_make_finding(f"X-Permitted-Cross-Domain-Policies set to '{xpcd}'",
                          "Value may not be restrictive enough.","low",60,"warning",
                          "X-Permitted-Cross-Domain-Policies",evidence=xpcd,
                          remediation="Set to 'none' or 'master-only'.")]

# ── Better API vs HTML page detection ─────────────────────────────────
def _is_api_response(final_headers, final_url, main_html=None) -> bool:
    """Determine if the response is likely an API endpoint rather than an HTML page."""
    ct = _get_header(final_headers, "Content-Type") or ""
    ct_lower = ct.lower()
    # Explicit API content types
    if ct_lower.startswith(("application/json", "application/xml", "text/xml")):
        return True
    # Image, font, etc. – treat as non-HTML (API not, but we still skip HTML checks)
    if ct_lower.startswith("image/"):
        return True
    # If content type is text/html, it's definitely a page
    if ct_lower.startswith("text/html"):
        return False
    # Heuristic: check URL path for common API prefixes
    parsed = urlparse(final_url)
    path = parsed.path.lower()
    if re.search(r'/(api|graphql|v[12])/', path):
        return True
    # If we have the body, try a JSON test (first non‑whitespace char)
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
async def run(url: str, shared_page: dict = None) -> Dict[str,Any]:
    target = _normalize_url(url)
    parsed = urlparse(target)
    hostname = parsed.hostname or ""
    port = parsed.port or 443

    # Use shared_page if available and valid
    if shared_page and not shared_page.get("error") and shared_page.get("status") == 200:
        final_headers = shared_page.get("headers", {})
        final_status = shared_page.get("status", 200)
        final_url = shared_page.get("base_url", target)
        main_html = shared_page.get("html", "")
        responses = []  # No redirect chain
        site_context = await _categorize_site(hostname, port, html=main_html, headers=final_headers)
        waf_detected = await _detect_waf(hostname, port, headers=final_headers)
        fetch_error = None
    else:
        # No valid shared_page – proceed with empty data (NO NETWORK REQUESTS)
        final_headers = {}
        final_status = 0
        final_url = target
        main_html = ""
        responses = []
        site_context = await _categorize_site(hostname, port)
        waf_detected = await _detect_waf(hostname, port)

    # Common analysis from final_headers
    content_type = _get_header(final_headers,"Content-Type") or ""
    set_cookie = _get_header(final_headers,"Set-Cookie")
    is_api = _is_api_response(final_headers, final_url, main_html)
    is_error_page = final_status >= 400
    is_cdn = any(hostname.endswith(d) for d in CDN_DOMAINS)
    has_report_to = bool(_get_header(final_headers,"Report-To") or _get_header(final_headers,"Reporting-Endpoints"))

    waf_fingerprints = _fingerprint_waf_from_headers(final_headers)
    # Header order analysis
    if not responses:
        header_order_info = _analyze_header_order([{"headers": final_headers}])
    else:
        header_order_info = _analyze_header_order(responses)

    findings = []

    # HSTS: pass either the chain (if available) or the final headers
    if responses:
        findings.extend(_check_hsts(headers_list=responses, is_cdn=is_cdn, target_url=target))
    else:
        findings.extend(_check_hsts(final_headers=final_headers, is_cdn=is_cdn, target_url=target))

    findings.extend(_check_clickjacking(final_headers, is_api))
    csp_findings, csp_directives = _check_csp_enhanced(final_headers, is_api)
    findings.extend(csp_findings)
    findings.extend(_check_xcto(final_headers))
    findings.extend(_check_referrer_policy(final_headers))
    findings.extend(_check_permissions_policy(final_headers))
    findings.extend(_check_coop_coep_corp(final_headers))
    findings.extend(_check_cache_control(final_headers, set_cookie))
    findings.extend(_check_dns_prefetch(final_headers))
    findings.extend(_check_xss_protection(final_headers))
    findings.extend(_check_server_info(final_headers))
    findings.extend(_check_expect_ct(final_headers))
    findings.extend(_check_x_permitted_cross_domain(final_headers))

    if is_error_page:
        findings.append(_make_finding(f"Response returned {final_status}",
                                      "Security headers may belong to error page/WAF.","info",70,"warning",
                                      "Response Status",evidence=f"HTTP {final_status}",
                                      remediation="Re‑scan a known working page (200 OK)."))

    # ── Enhanced dynamic severity boosting for sensitive sites ─────────
    is_sensitive = any(cat in site_context.get("categories",[]) for cat in ("ecommerce","login"))
    is_sensitive = is_sensitive or site_context.get("has_login_form", False)

    if is_sensitive:
        sensitive_headers = {
            "Strict-Transport-Security", "X-Frame-Options", "Content-Security-Policy",
            "Cache-Control", "Cross-Origin-Opener-Policy", "Cross-Origin-Embedder-Policy",
            "Referrer-Policy"
        }
        boost_map = {"info":"info", "low":"medium", "medium":"high", "high":"critical", "critical":"critical"}
        for f in findings:
            if f["header"] in sensitive_headers and f["severity"] != "critical":
                f["severity"] = boost_map.get(f["severity"], f["severity"])

    context = {
        "is_login_page": "login" in site_context.get("categories",[]),
        "is_ecommerce": "ecommerce" in site_context.get("categories",[]),
        "is_internal": "internal" in site_context.get("categories",[]),
        "waf_detected": waf_detected,
        "has_report_to": has_report_to,
    }

    score, grade, score_breakdown = _apply_scoring(findings, context, csp_directives)

    worst_sev = max((f["severity"] for f in findings), key=lambda s: SEVERITY_RANK.get(s,0), default="info")
    status = "fail" if any(SEVERITY_RANK.get(f["severity"],0)>=3 for f in findings) else "warning" if findings else "pass"

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
        "site_categories": site_context.get("categories",[]),
        "has_report_to": has_report_to,
        "header_order_analysis": header_order_info,
        "headers_summary": {
            "checked": len(findings),
            "failed": sum(1 for f in findings if f["status"] in ("fail","warning")),
        },
    }

    return {
        "scanner": SCANNER_NAME,
        "target": target,
        "status": status,
        "severity": worst_sev,
        "confidence": 70 if is_error_page else 95,
        "score": score,
        "grade": grade,
        "summary": f"Security Headers – {len(findings)} findings | Score {score}/100 ({grade})",
        "findings": findings,
        "remediation": remediation,
        "details": details,
    }

if __name__ == "__main__":
    target_url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    result = asyncio.run(run(target_url))
    print(json.dumps(result, indent=2, ensure_ascii=False))