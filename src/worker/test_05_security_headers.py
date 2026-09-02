#!/usr/bin/env python3
"""
test_05_security_headers.py – Bravo6 Enterprise HTTP Security Policy Analyzer (v8.5)
====================================================================================
Enterprise-grade HTTP Security Policy Analyzer with advanced CSP validation,
Reporting API checks, Document Policy, and Origin-Agent-Cluster analysis.
Refactored to comply with BRAVO6 UNIFIED PLUGIN CONTRACT — SHARED RULES v8.5.
"""
import re
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

SCANNER_NAME = "security_headers"

CDN_DOMAINS = (
    ".cloudfront.net", ".azurewebsites.net", ".herokuapp.com",
    ".github.io", ".netlify.app", ".vercel.app", ".firebaseapp.com",
    ".pages.dev", ".workers.dev"
)

SITE_CATEGORIES = {
    "bank": ["bank", "online banking", "بنك", "بنوك", "مصرف", "حساب بنكي"],
    "ecommerce": ["shop", "store", "buy", "cart", "checkout", "pay", "تسوق", "متجر", "عربة التسوق", "الدفع", "اشتري", "شراء"],
    "healthcare": ["hospital", "مستشفى", "عيادة", "طبي", "صحة"],
    "login": ["sign in", "login", "password", "تسجيل الدخول", "كلمة المرور", "دخول"],
    "blog": ["blog", "articles", "مدونة", "مقالات"],
    "internal": ["intranet", "internal", "داخلي", "إنترانت"],
}

# ── Helpers ──────────────────────────────────────────────────────────────

def _get_header(headers: Dict[str, str], name: str) -> Optional[str]:
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return None

def _make_finding(title: str, severity: str, confidence: str, cwe: str, owasp: str,
                  location: str, evidence: str, poc: str, remediation: str,
                  detection_method: str, tier: str) -> Dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "cwe": cwe,
        "owasp": owasp,
        "location": location,
        "evidence": evidence,
        "poc": poc,
        "remediation": remediation,
        "detection_method": detection_method,
        "raw_data": {"tier": tier}
    }

async def _categorize_site(html: str, headers: dict) -> Dict:
    result = {"categories": [], "has_login_form": False, "title": "", "meta_keywords": "", "meta_description": ""}
    
    title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
    if title_match: 
        result["title"] = title_match.group(1)
        
    meta_match = re.search(r'<meta\s+name="keywords"\s+content="(.*?)"', html, re.IGNORECASE)
    if meta_match: 
        result["meta_keywords"] = meta_match.group(1)
        
    desc_match = re.search(r'<meta\s+name="description"\s+content="(.*?)"', html, re.IGNORECASE)
    if desc_match:
        result["meta_description"] = desc_match.group(1)
        
    if re.search(r'<input\s+[^>]*type=["\']?password["\']?', html, re.IGNORECASE):
        result["has_login_form"] = True
        
    text_lower = (result["title"] + " " + result["meta_keywords"] + " " + result["meta_description"]).lower()
    for category, keywords in SITE_CATEGORIES.items():
        if any(k in text_lower for k in keywords):
            result["categories"].append(category)
            
    return result

def _parse_csp(csp_header: str) -> Dict[str, str]:
    directives = {}
    if not csp_header:
        return directives
    for part in re.split(r";\s*", csp_header.strip()):
        part = part.strip()
        if not part:
            continue
        if " " in part:
            name, value = part.split(" ", 1)
            directives[name.strip().lower()] = value.strip()
        else:
            directives[part.strip().lower()] = ""
    return directives

# ── Header Checks ────────────────────────────────────────────────────────

def _check_hsts(headers: dict, url: str, is_cdn: bool) -> List[Dict[str, Any]]:
    if is_cdn:
        return []
    
    hdr = _get_header(headers, "Strict-Transport-Security")
    if not hdr:
        return [_make_finding(
            title="HSTS header missing",
            severity="high",
            confidence="verified-live",
            cwe="CWE-319",
            owasp="A05:2021",
            location="Strict-Transport-Security",
            evidence="The 'Strict-Transport-Security' header was not found.",
            poc=f"curl -Is {url} | grep -i 'strict-transport-security'",
            remediation="Add Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
            detection_method="Header Check",
            tier="baseline"
        )]
    
    max_age_match = re.search(r"max-age\s*=\s*(\d+)", hdr, re.I)
    max_age = int(max_age_match.group(1)) if max_age_match else 0
    incl_sub = "includesubdomains" in hdr.lower()
    preload = "preload" in hdr.lower()
    
    issues = []
    if max_age < 31536000:
        issues.append(f"below 1-year threshold (max-age={max_age})")
    elif max_age < 63072000:
        issues.append(f"below 2-year preload threshold (max-age={max_age})")
    if not incl_sub:
        issues.append("missing includeSubDomains")
    if not preload:
        issues.append("missing preload")
        
    if issues:
        title = "HSTS present but missing optimal directives" if len(issues) > 1 else f"HSTS present but {issues[0]}"
        return [_make_finding(
            title=title,
            severity="medium",
            confidence="verified-live",
            cwe="CWE-319",
            owasp="A05:2021",
            location="Strict-Transport-Security",
            evidence=f"Current value: {hdr}",
            poc=f"curl -Is {url} | grep -i 'strict-transport-security'",
            remediation="Set to max-age=63072000; includeSubDomains; preload",
            detection_method="Header Check",
            tier="baseline"
        )]
        
    return []

def _check_csp(headers: dict, url: str, is_api: bool) -> List[Dict[str, Any]]:
    if is_api: return []
    csp_raw = _get_header(headers, "Content-Security-Policy")
    if not csp_raw:
        return [_make_finding(
            title="Missing Content-Security-Policy",
            severity="high",
            confidence="verified-live",
            cwe="CWE-1021",
            owasp="A05:2021",
            location="Content-Security-Policy",
            evidence="Header 'Content-Security-Policy' not present.",
            poc=f"curl -Is {url} | grep -i 'content-security-policy'",
            remediation="Implement a strict Content-Security-Policy.",
            detection_method="CSP Policy Analysis",
            tier="baseline"
        )]
        
    findings = []
    if "'unsafe-inline'" in csp_raw:
        findings.append(_make_finding(
            title="CSP allows 'unsafe-inline'",
            severity="high",
            confidence="verified-live",
            cwe="CWE-79", owasp="A03:2021",
            location="Content-Security-Policy",
            evidence=f"CSP contains 'unsafe-inline': {csp_raw[:200]}",
            poc=f"curl -Is {url} | grep -i 'content-security-policy'",
            remediation="Remove 'unsafe-inline' and use nonce- or hash-based script/style sources instead.",
            detection_method="CSP Policy Analysis", tier="baseline"
        ))
    if "'unsafe-eval'" in csp_raw:
        findings.append(_make_finding(
            title="CSP allows 'unsafe-eval'",
            severity="high",
            confidence="verified-live",
            cwe="CWE-79", owasp="A03:2021",
            location="Content-Security-Policy",
            evidence=f"CSP contains 'unsafe-eval': {csp_raw[:200]}",
            poc=f"curl -Is {url} | grep -i 'content-security-policy'",
            remediation="Remove 'unsafe-eval'.",
            detection_method="CSP Policy Analysis", tier="baseline"
        ))
        
    directives = _parse_csp(csp_raw)
    if "frame-ancestors" not in directives:
        findings.append(_make_finding(
            title="CSP missing frame-ancestors directive",
            severity="medium",
            confidence="verified-live",
            cwe="CWE-1021", owasp="A01:2021",
            location="Content-Security-Policy",
            evidence="No frame-ancestors directive found in CSP.",
            poc=f"curl -Is {url} | grep -i 'content-security-policy'",
            remediation="Add frame-ancestors 'none' or 'self'.",
            detection_method="CSP Policy Analysis", tier="baseline"
        ))
        
    script_src = directives.get("script-src", directives.get("default-src", ""))
    has_nonce = bool(re.search(r"'nonce-[A-Za-z0-9+/=]+'", script_src))
    has_hash = bool(re.search(r"'(sha256|sha384|sha512)-[A-Za-z0-9+/=]+'", script_src))
    if script_src and not has_nonce and not has_hash and "'unsafe-inline'" not in script_src:
        findings.append(_make_finding(
            title="CSP script-src lacks nonce or hash source",
            severity="low",
            confidence="verified-live",
            cwe="CWE-79", owasp="A03:2021",
            location="Content-Security-Policy",
            evidence=f"script-src lacks nonce/hash: {script_src[:100]}",
            poc=f"curl -Is {url} | grep -i 'content-security-policy'",
            remediation="Consider adding nonce- or hash-based sources.",
            detection_method="CSP Policy Analysis", tier="baseline"
        ))
        
    return findings

def _check_clickjacking(headers: dict, url: str, is_api: bool) -> List[Dict[str, Any]]:
    if is_api: return []
    xfo = _get_header(headers, "X-Frame-Options")
    csp_raw = _get_header(headers, "Content-Security-Policy")
    directives = _parse_csp(csp_raw) if csp_raw else {}
    
    if "frame-ancestors" in directives:
        val = directives["frame-ancestors"]
        # An empty value (e.g. "frame-ancestors;") lists zero allowed sources,
        # which blocks all embedding per spec — same effect as 'none'. Without
        # this check the title below would claim framing is allowed from
        # external origins while the evidence shows no origins were listed.
        if not val.strip() or "'none'" in val or "'self'" in val:
            return []
        else:
            return [_make_finding(
                title="Framing allowed from external origins (CSP)",
                severity="medium",
                confidence="verified-live",
                cwe="CWE-1021", owasp="A01:2021",
                location="Content-Security-Policy",
                evidence=f"frame-ancestors: {val[:200]}",
                poc=f"curl -Is {url} | grep -i 'content-security-policy'",
                remediation="Restrict frame-ancestors to 'none' or 'self'.",
                detection_method="Header Check", tier="baseline"
            )]
            
    if xfo:
        if xfo.upper() in ("DENY", "SAMEORIGIN"):
            return []
        else:
            return [_make_finding(
                title="X-Frame-Options insecure value",
                severity="high",
                confidence="verified-live",
                cwe="CWE-1021", owasp="A01:2021",
                location="X-Frame-Options",
                evidence=f"X-Frame-Options: {xfo}",
                poc=f"curl -Is {url} | grep -i 'x-frame-options'",
                remediation="Use DENY or SAMEORIGIN.",
                detection_method="Header Check", tier="baseline"
            )]
            
    return [_make_finding(
        title="Missing clickjacking protection",
        severity="high",
        confidence="verified-live",
        cwe="CWE-1021", owasp="A01:2021",
        location="X-Frame-Options",
        evidence="Neither X-Frame-Options nor CSP frame-ancestors set.",
        poc=f"curl -Is {url} | grep -i 'x-frame-options\\|content-security-policy'",
        remediation="Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.",
        detection_method="Header Check", tier="baseline"
    )]

def _check_cache_control(headers: dict, set_cookie: Optional[str], url: str) -> List[Dict[str, Any]]:
    # NOTE: `set_cookie` only tells us the response carries a Set-Cookie header
    # (a passively observed, real signal). It does NOT tell us the client is
    # "authenticated" — this scanner is strictly passive (a single anonymous
    # GET/HEAD/OPTIONS, no login, no credentials), so it never establishes an
    # authenticated session and cannot claim one exists. Anonymous responses
    # routinely carry cookies too (cart/session IDs, CSRF tokens, consent,
    # WAF/CDN affinity cookies), so findings here must describe what was
    # actually observed — a cookie-bearing response — not an unverifiable
    # authentication state.
    cc = _get_header(headers, "Cache-Control")
    if not cc:
        if set_cookie:
            return [_make_finding(
                title="Cache-Control header missing on cookie-bearing response",
                severity="high",
                confidence="verified-live",
                cwe="CWE-525", owasp="A05:2021",
                location="Cache-Control",
                evidence="Set-Cookie is present but Cache-Control is missing.",
                poc=f"curl -Is {url} | grep -i 'cache-control'",
                remediation="Add Cache-Control: no-store, no-cache, must-revalidate",
                detection_method="Header Check", tier="baseline"
            )]
        else:
            return [_make_finding(
                title="Cache-Control header missing",
                severity="low",
                confidence="informational",
                cwe="CWE-525", owasp="A05:2021",
                location="Cache-Control",
                evidence="Cache-Control is not set on the response.",
                poc=f"curl -Is {url} | grep -i 'cache-control'",
                remediation="Define caching behavior with Cache-Control.",
                detection_method="Header Check", tier="baseline"
            )]

    cc_lower = cc.lower()
    if set_cookie:
        if "public" in cc_lower:
            return [_make_finding(
                title="Cache-Control insecure ('public' on cookie-bearing response)",
                severity="high",
                confidence="verified-live",
                cwe="CWE-525", owasp="A05:2021",
                location="Cache-Control",
                evidence=f"Cache-Control: {cc} (response also sets a cookie via Set-Cookie)",
                poc=f"curl -Is {url} | grep -i 'cache-control\\|set-cookie'",
                remediation="Remove 'public', use 'no-store, no-cache'.",
                detection_method="Header Check", tier="baseline"
            )]
        elif "no-store" not in cc_lower:
            return [_make_finding(
                title="Cache-Control present but missing 'no-store' on cookie-bearing response",
                severity="medium",
                confidence="verified-live",
                cwe="CWE-525", owasp="A05:2021",
                location="Cache-Control",
                evidence=f"Cache-Control: {cc} (response also sets a cookie via Set-Cookie)",
                poc=f"curl -Is {url} | grep -i 'cache-control\\|set-cookie'",
                remediation="Add 'no-store' directive.",
                detection_method="Header Check", tier="baseline"
            )]

    return []

def _check_xcto(headers: dict, url: str) -> List[Dict[str, Any]]:
    xcto = _get_header(headers, "X-Content-Type-Options")
    if not xcto:
        return [_make_finding(
            title="Missing X-Content-Type-Options",
            severity="medium",
            confidence="verified-live",
            cwe="CWE-693", owasp="A05:2021",
            location="X-Content-Type-Options",
            evidence="Header 'X-Content-Type-Options' is missing.",
            poc=f"curl -Is {url} | grep -i 'x-content-type-options'",
            remediation="Add X-Content-Type-Options: nosniff",
            detection_method="Header Check", tier="baseline"
        )]
    if xcto.lower() != "nosniff":
        return [_make_finding(
            title="X-Content-Type-Options insecure value",
            severity="medium",
            confidence="verified-live",
            cwe="CWE-693", owasp="A05:2021",
            location="X-Content-Type-Options",
            evidence=f"Value: {xcto}",
            poc=f"curl -Is {url} | grep -i 'x-content-type-options'",
            remediation="Set to 'nosniff'.",
            detection_method="Header Check", tier="baseline"
        )]
    return []

def _check_referrer(headers: dict, url: str) -> List[Dict[str, Any]]:
    rp = _get_header(headers, "Referrer-Policy")
    if not rp:
        return [_make_finding(
            title="Missing Referrer-Policy",
            severity="medium",
            confidence="verified-live",
            cwe="CWE-200", owasp="A01:2021",
            location="Referrer-Policy",
            evidence="Header 'Referrer-Policy' is missing.",
            poc=f"curl -Is {url} | grep -i 'referrer-policy'",
            remediation="Set Referrer-Policy: strict-origin-when-cross-origin",
            detection_method="Header Check", tier="baseline"
        )]
    safe = {"no-referrer", "strict-origin", "strict-origin-when-cross-origin"}
    if rp.lower() in safe:
        return []
    if rp.lower() == "unsafe-url":
        return [_make_finding(
            title="Unsafe Referrer-Policy",
            severity="high",
            confidence="verified-live",
            cwe="CWE-200", owasp="A01:2021",
            location="Referrer-Policy",
            evidence=f"Value: {rp}",
            poc=f"curl -Is {url} | grep -i 'referrer-policy'",
            remediation="Change to strict-origin-when-cross-origin",
            detection_method="Header Check", tier="baseline"
        )]
    return [_make_finding(
        title="Referrer-Policy present but not optimally restrictive",
        severity="low",
        confidence="verified-live",
        cwe="CWE-200", owasp="A01:2021",
        location="Referrer-Policy",
        evidence=f"Value: {rp}",
        poc=f"curl -Is {url} | grep -i 'referrer-policy'",
        remediation="Use strict-origin-when-cross-origin",
        detection_method="Header Check", tier="baseline"
    )]

def _check_hardening_headers(headers: dict, url: str) -> List[Dict[str, Any]]:
    findings = []
    
    def require_header(name: str, desc: str, expected: Optional[List[str]] = None):
        val = _get_header(headers, name)
        if not val:
            findings.append(_make_finding(
                title=f"Missing {name}",
                severity="low",
                confidence="informational",
                cwe="CWE-693", owasp="A05:2021",
                location=name,
                evidence=f"Header '{name}' is missing.",
                poc=f"curl -Is {url} | grep -i '{name}'",
                remediation=f"Implement {name} to {desc}.",
                detection_method="Header Check", tier="hardening"
            ))
        elif expected and val.lower() not in expected:
            findings.append(_make_finding(
                title=f"{name} present but not optimally restrictive",
                severity="low",
                confidence="verified-live",
                cwe="CWE-693", owasp="A05:2021",
                location=name,
                evidence=f"Value: {val}",
                poc=f"curl -Is {url} | grep -i '{name}'",
                remediation=f"Consider setting {name} to a more restrictive value.",
                detection_method="Header Check", tier="hardening"
            ))

    require_header("Cross-Origin-Opener-Policy", "isolate browsing context", ["same-origin", "same-origin-allow-popups"])
    require_header("Cross-Origin-Embedder-Policy", "control cross-origin embedding", ["require-corp", "credentialless"])
    require_header("Cross-Origin-Resource-Policy", "prevent cross-site resource loading", ["same-origin", "same-site"])
    require_header("Document-Policy", "restrict web platform features")
    require_header("Origin-Agent-Cluster", "enable origin isolation", ["?1"])
    require_header("Permissions-Policy", "restrict browser features")
    
    # X-Permitted-Cross-Domain-Policies
    xpcd = _get_header(headers, "X-Permitted-Cross-Domain-Policies")
    if not xpcd:
        findings.append(_make_finding(
            title="Missing X-Permitted-Cross-Domain-Policies",
            severity="low",
            confidence="informational",
            cwe="CWE-693", owasp="A05:2021",
            location="X-Permitted-Cross-Domain-Policies",
            evidence="Header is missing.",
            poc=f"curl -Is {url} | grep -i 'x-permitted-cross-domain-policies'",
            remediation="Set to 'none' or 'master-only'.",
            detection_method="Header Check", tier="hardening"
        ))
    elif xpcd.strip().lower() not in ("none", "master-only"):
        findings.append(_make_finding(
            title="X-Permitted-Cross-Domain-Policies present but not optimally restrictive",
            severity="low",
            confidence="verified-live",
            cwe="CWE-693", owasp="A05:2021",
            location="X-Permitted-Cross-Domain-Policies",
            evidence=f"Value: {xpcd}",
            poc=f"curl -Is {url} | grep -i 'x-permitted-cross-domain-policies'",
            remediation="Set to 'none' or 'master-only'.",
            detection_method="Header Check", tier="hardening"
        ))
        
    # X-XSS-Protection
    xssp = _get_header(headers, "X-XSS-Protection")
    if xssp and xssp.strip() != "0":
        findings.append(_make_finding(
            title="X-XSS-Protection enabled (deprecated, potential risk)",
            severity="low",
            confidence="verified-live",
            cwe="CWE-693", owasp="A05:2021",
            location="X-XSS-Protection",
            evidence=f"Value: {xssp}",
            poc=f"curl -Is {url} | grep -i 'x-xss-protection'",
            remediation="Remove or set to '0' to disable.",
            detection_method="Header Check", tier="hardening"
        ))

    # Reporting API
    rt = _get_header(headers, "Report-To")
    rep = _get_header(headers, "Reporting-Endpoints")
    if not rt and not rep:
        findings.append(_make_finding(
            title="Missing Reporting API configuration",
            severity="low",
            confidence="informational",
            cwe="CWE-693", owasp="A05:2021",
            location="Report-To",
            evidence="No Reporting API headers found.",
            poc=f"curl -Is {url} | grep -i 'report-to\\|reporting-endpoints'",
            remediation="Implement the Reporting API.",
            detection_method="Header Check", tier="hardening"
        ))
    else:
        for header_name, header_val in [("Report-To", rt), ("Reporting-Endpoints", rep)]:
            if header_val:
                endpoints = re.findall(r'https?://[^"]+', header_val)
                for ep in endpoints:
                    if ep.startswith("http://"):
                        findings.append(_make_finding(
                            title="Reporting API endpoint uses HTTP",
                            severity="medium",
                            confidence="verified-live",
                            cwe="CWE-319", owasp="A05:2021",
                            location=header_name,
                            evidence=f"Endpoint: {ep}",
                            poc=f"curl -Is {url} | grep -i '{header_name}'",
                            remediation="Use HTTPS for reporting endpoints.",
                            detection_method="Header Check", tier="hardening"
                        ))

    return findings

def _check_info_disclosure(headers: dict, url: str) -> List[Dict[str, Any]]:
    findings = []
    server = _get_header(headers, "Server")
    if server and server.lower() not in ("server", ""):
        findings.append(_make_finding(
            title=f"Server header exposed: {server}",
            severity="low",
            confidence="verified-live",
            cwe="CWE-200", owasp="A01:2021",
            location="Server",
            evidence=f"Server: {server}",
            poc=f"curl -Is {url} | grep -i 'server'",
            remediation="Remove Server header.",
            detection_method="Header Check", tier="baseline"
        ))
    powered = _get_header(headers, "X-Powered-By")
    if powered:
        findings.append(_make_finding(
            title=f"X-Powered-By exposed: {powered}",
            severity="low",
            confidence="verified-live",
            cwe="CWE-200", owasp="A01:2021",
            location="X-Powered-By",
            evidence=f"X-Powered-By: {powered}",
            poc=f"curl -Is {url} | grep -i 'x-powered-by'",
            remediation="Remove X-Powered-By header.",
            detection_method="Header Check", tier="baseline"
        ))
    return findings

# ── Main Entry ───────────────────────────────────────────────────────────

async def run(ctx: Any) -> dict:
    url = getattr(ctx, "url", "https://example.com")
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    
    # 1. Mandatory Pre-flight Representativeness Check
    is_rep = getattr(ctx, "page_is_representative", None)
    main_cache = getattr(ctx, "main_page_cache", {})
    final_status = main_cache.get("status", 0)
    html = main_cache.get("html", "")
    headers = main_cache.get("headers", {})
    
    if is_rep is None:
        is_rep = final_status < 400
        if is_rep and any(x in html for x in ["cf-chl", "cf-mitigated", "Just a moment..."]):
            is_rep = False
            
    _m = getattr(ctx, "metrics", None)
    if is_rep and isinstance(_m, dict):
        _m["cache_reads"] = _m.get("cache_reads", 0) + 1

    if not is_rep:
        # Cross-scout consistency fix: test_01/02/03/06 all report a
        # non-representative page via {"fatal_error": ...}, which
        # main_scanner.py excludes from tests_run and adds to errors/
        # errors_count. This scout previously returned a normal findings
        # list (one info-severity "skipped" note) instead -- main_scanner.py
        # then counted it as "complete" and included it in tests_run, which
        # silently inflated tests_run (and correspondingly the "N/7 modules
        # completed" figure in compute_bravo6_score's coverage_note) by one
        # on every WAF-blocked/non-representative scan. Live-confirmed on a
        # 10-site batch: vkuseraudio.net and elcorteingles.es both showed
        # tests_run=3 (test_04 + this scout's fake "complete" + test_07)
        # instead of the honest tests_run=2, understating how little of the
        # scan actually ran. Matching the other four scouts' convention here
        # doesn't change score/grade (the removed finding was severity=info,
        # which always contributes zero to BASE_PENALTY) -- it only fixes
        # the accuracy of tests_run/errors/coverage_note.
        return {"fatal_error": f"Non-representative response (HTTP {final_status}); header analysis skipped."}
        
    # 2. Site Context Categorization
    site_context = await _categorize_site(html, headers)
    content_type = _get_header(headers, "Content-Type") or ""
    is_api = "json" in content_type.lower() or "xml" in content_type.lower() or "/api/" in url.lower()
    is_cdn = any(hostname.endswith(d) for d in CDN_DOMAINS)
    
    # 3. Header Analysis
    all_findings = []
    all_findings.extend(_check_hsts(headers, url, is_cdn))
    all_findings.extend(_check_csp(headers, url, is_api))
    all_findings.extend(_check_clickjacking(headers, url, is_api))
    all_findings.extend(_check_cache_control(headers, _get_header(headers, "Set-Cookie"), url))
    all_findings.extend(_check_xcto(headers, url))
    all_findings.extend(_check_referrer(headers, url))
    all_findings.extend(_check_hardening_headers(headers, url))
    all_findings.extend(_check_info_disclosure(headers, url))
    
    # 4. Context-Aware Severity Boosting
    is_sensitive = any(cat in site_context.get("categories", []) for cat in ("ecommerce", "login"))
    is_sensitive = is_sensitive or site_context.get("has_login_form", False)

    # Scoped narrowly to CSP script-execution-control and HSTS: previously ANY
    # baseline-tier finding (HSTS, CSP, clickjacking, cache-control,
    # X-Content-Type-Options, Referrer-Policy, info-disclosure headers) plus
    # every "missing"-titled hardening-tier finding was escalated one severity
    # tier whenever a password field appeared anywhere on the page -- a proxy
    # signal with no verified relationship to whether the specific flagged gap
    # is actually exploitable in a login-relevant context. On facebook.com
    # this produced a ~60-point score swing purely from boosting Referrer-
    # Policy/frame-ancestors/HSTS-directive findings that have no direct
    # causal link to credential theft. The boost is now limited to: (a) HSTS
    # findings (protocol-downgrade/strip attacks directly expose credentials
    # in transit), and (b) the CSP findings that represent an actual script-
    # execution-control failure (CSP entirely absent, or allowing
    # 'unsafe-inline'/'unsafe-eval') -- NOT CSP directive-completeness gaps
    # like a missing frame-ancestors or missing nonce/hash, which share the
    # same "Content-Security-Policy" location but carry no direct script-
    # injection risk of their own. Every boosted finding records the
    # escalation in its own evidence field instead of hiding it.
    CSP_EXECUTION_CONTROL_TITLES = {
        "Missing Content-Security-Policy",
        "CSP allows 'unsafe-inline'",
        "CSP allows 'unsafe-eval'",
    }

    def _is_boostable(finding: Dict[str, Any]) -> bool:
        loc = finding.get("location")
        if loc == "Strict-Transport-Security":
            return True
        if loc == "Content-Security-Policy" and finding.get("title") in CSP_EXECUTION_CONTROL_TITLES:
            return True
        return False

    if is_sensitive:
        for f in all_findings:
            tier = f.get("raw_data", {}).get("tier", "")
            if tier != "baseline" or not _is_boostable(f):
                continue
            if f["severity"] == "high":
                f["severity"] = "critical"
                f["evidence"] = f.get("evidence", "") + \
                    " [severity escalated from 'high' to 'critical': sensitive-page context (login form or ecommerce/login page detected) affecting CSP/HSTS]"
            elif f["severity"] == "medium":
                f["severity"] = "high"
                f["evidence"] = f.get("evidence", "") + \
                    " [severity escalated from 'medium' to 'high': sensitive-page context (login form or ecommerce/login page detected) affecting CSP/HSTS]"

    return {
        "findings": all_findings,
        "details": {
            "requests_made": 0,
            "site_categories": site_context.get("categories", []),
            "is_sensitive_context": is_sensitive,
            "is_api": is_api,
            "is_cdn": is_cdn
        }
    }

# ────────────────────────────────────────────── Standalone Testing ──────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(description="Bravo6 HTTP Security Policy Analyzer")
    parser.add_argument("url", nargs="?", default="https://example.com", help="Target URL")
    parser.add_argument("--test", action="store_true", help="Run Scout Regression Tests")
    args = parser.parse_args()

    if args.test:
        import unittest

        class TestCacheControlAuthenticationClaim(unittest.TestCase):
            """
            Regression tests for the 'Cache-Control ... on authenticated response'
            bug: this scanner is strictly passive (a single anonymous GET/HEAD/
            OPTIONS, no login, no credentials) and never observes an authenticated
            session, so no finding may claim the response was "authenticated".
            Set-Cookie presence is a real passive signal but only proves the
            response is cookie-bearing, not that the client is authenticated.
            """

            def _titles(self, headers, set_cookie):
                findings = _check_cache_control(headers, set_cookie, "https://shop.example.com")
                return [f["title"] for f in findings]

            def test_anonymous_response_no_cookie_no_finding(self):
                # Plain anonymous homepage GET, no session cookie at all —
                # nothing to flag (matches the real-world bug report scenario
                # minus the cookie).
                headers = {"Cache-Control": "no-cache"}
                self.assertEqual(self._titles(headers, set_cookie=None), [])

            def test_cookie_bearing_response_missing_no_store_worded_correctly(self):
                # Matches the real e-commerce bug report: Cache-Control: no-cache
                # with a cookie present. Must still be flagged, but must not
                # claim an "authenticated" state the scanner cannot verify.
                headers = {"Cache-Control": "no-cache"}
                titles = self._titles(headers, set_cookie="cart_id=abc123; Path=/")
                self.assertEqual(len(titles), 1)
                self.assertNotIn("authenticated", titles[0].lower(),
                                  "Title must not claim an authentication state the scanner never verified.")
                self.assertIn("cookie-bearing response", titles[0])

            def test_cookie_bearing_response_public_worded_correctly(self):
                headers = {"Cache-Control": "public, max-age=3600"}
                titles = self._titles(headers, set_cookie="sessionid=deadbeef; Path=/")
                self.assertEqual(len(titles), 1)
                self.assertNotIn("authenticated", titles[0].lower())
                self.assertIn("cookie-bearing response", titles[0])

            def test_cookie_bearing_response_missing_cache_control_worded_correctly(self):
                titles = self._titles({}, set_cookie="sessionid=deadbeef; Path=/")
                self.assertEqual(len(titles), 1)
                self.assertNotIn("authenticated", titles[0].lower())
                self.assertIn("cookie-bearing response", titles[0])

        class TestClickjackingEmptyFrameAncestors(unittest.TestCase):
            """
            Regression test: an empty frame-ancestors value (e.g.
            "frame-ancestors;") lists zero allowed origins, which blocks all
            framing per spec — the same effect as 'none'. It must not be
            reported as "framing allowed from external origins" since no
            origin is actually listed in the evidence.
            """

            def test_empty_frame_ancestors_is_not_flagged_as_allowing_framing(self):
                headers = {"Content-Security-Policy": "frame-ancestors;"}
                findings = _check_clickjacking(headers, "https://example.com", is_api=False)
                self.assertEqual(findings, [])

        class _BoostCtx:
            """Minimal stand-in for ScannerContext, just enough to drive run()."""
            def __init__(self, url, html, headers):
                self.url = url
                self.page_is_representative = True
                self.main_page_cache = {"status": 200, "html": html, "headers": headers}

        class TestSensitivePageBoostScoping(unittest.IsolatedAsyncioTestCase):
            """
            Regression tests for narrowing the sensitive-page severity boost.
            Previously ANY baseline-tier finding (HSTS, CSP, clickjacking,
            cache-control, X-Content-Type-Options, Referrer-Policy, info-
            disclosure headers) plus every "missing"-titled hardening-tier
            finding was escalated one severity tier whenever a password field
            appeared anywhere on the page. Mirrors the real facebook.com scan:
            a login form on the homepage boosted Missing-Referrer-Policy and
            CSP-missing-frame-ancestors (both medium->high) even though
            neither header has a direct causal link to credential theft,
            contributing a ~60-point score swing. The fix limits boosting to
            CSP/HSTS findings only.
            """

            SENSITIVE_HTML = '<html><body><input type="password" name="pw"></body></html>'

            async def _run_with_headers(self, headers):
                ctx = _BoostCtx("https://example.com", self.SENSITIVE_HTML, headers)
                result = await run(ctx)
                return {f["title"]: f for f in result["findings"]}

            async def test_csp_and_hsts_findings_still_get_boosted(self):
                headers = {
                    "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'",
                    "Strict-Transport-Security": "max-age=15552000; preload",
                }
                findings = await self._run_with_headers(headers)

                unsafe_inline = findings["CSP allows 'unsafe-inline'"]
                self.assertEqual(unsafe_inline["severity"], "critical",
                                  "CSP unsafe-inline must still be boosted (high->critical) on a sensitive page.")
                self.assertIn("severity escalated", unsafe_inline["evidence"])

                hsts = next(f for t, f in findings.items() if t.startswith("HSTS present but"))
                self.assertEqual(hsts["severity"], "high",
                                  "HSTS-directive gap must still be boosted (medium->high) on a sensitive page.")
                self.assertIn("severity escalated", hsts["evidence"])

            async def test_referrer_policy_and_frame_ancestors_are_no_longer_boosted(self):
                headers = {
                    "Content-Security-Policy": "default-src 'self'",  # no frame-ancestors directive
                    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                }
                findings = await self._run_with_headers(headers)

                frame_ancestors = findings["CSP missing frame-ancestors directive"]
                self.assertEqual(
                    frame_ancestors["severity"], "medium",
                    "CSP-missing-frame-ancestors has no direct causal link to credential theft and must stay at source severity."
                )
                self.assertNotIn("severity escalated", frame_ancestors["evidence"])

                referrer = findings["Missing Referrer-Policy"]
                self.assertEqual(
                    referrer["severity"], "medium",
                    "Missing Referrer-Policy has no direct causal link to credential theft and must stay at source severity."
                )
                self.assertNotIn("severity escalated", referrer["evidence"])

            async def test_hardening_tier_findings_are_no_longer_boosted(self):
                headers = {
                    "Content-Security-Policy": "default-src 'self'",
                    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
                }
                findings = await self._run_with_headers(headers)
                coep = findings["Missing Cross-Origin-Embedder-Policy"]
                self.assertEqual(
                    coep["severity"], "low",
                    "Hardening-tier findings must no longer be escalated by the sensitive-page heuristic."
                )

            async def test_non_sensitive_page_never_boosts_anything(self):
                html_no_password = "<html><body>hello</body></html>"
                ctx = _BoostCtx("https://example.com", html_no_password, {
                    "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'",
                })
                result = await run(ctx)
                findings = {f["title"]: f for f in result["findings"]}
                self.assertEqual(findings["CSP allows 'unsafe-inline'"]["severity"], "high")

        class TestNonRepresentativePageReportsFatalError(unittest.IsolatedAsyncioTestCase):
            """Cross-scout consistency regression: a non-representative page
            must report itself via {"fatal_error": ...} like test_01/02/03/06
            do, not a normal findings list -- main_scanner.py only excludes
            fatal_error responses from tests_run and includes them in
            errors/errors_count. Live-confirmed impact: before this fix,
            WAF-blocked scans (vkuseraudio.net, elcorteingles.es) showed an
            inflated tests_run because this scout counted itself as
            "complete" while doing nothing but note the page was skipped."""

            async def test_non_representative_page_returns_fatal_error_not_findings(self):
                ctx = _BoostCtx("https://example.com", "<html>blocked</html>", {})
                ctx.page_is_representative = False
                ctx.main_page_cache["status"] = 403
                result = await run(ctx)
                self.assertIn("fatal_error", result)
                self.assertNotIn("findings", result)
                self.assertIn("403", result["fatal_error"])

        sys.argv = [sys.argv[0]]
        unittest.main()
    else:
        import asyncio
        import aiohttp
        from dataclasses import dataclass, field

        @dataclass
        class DummyContext:
            url: str
            session: Any = None
            config: dict = field(default_factory=dict)
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
                        main_page_cache = {
                            "status": resp.status,
                            "html": html,
                            "headers": dict(resp.headers)
                        }
                except Exception as e:
                    main_page_cache = {"error": str(e), "status": 0, "html": "", "headers": {}}

                ctx = DummyContext(
                    url=args.url,
                    session=session,
                    main_page_cache=main_page_cache
                )
                result = await run(ctx)
                print(json.dumps(result, indent=2, ensure_ascii=False, default=str))

        asyncio.run(_live_scan())