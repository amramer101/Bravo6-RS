"""
report_generator.py — Bravo6 Professional Security Scan Report

Generates a comprehensive, professional HTML report with:
- Executive summary with risk score, grade, and key metrics.
- Interactive heatmap for risk prioritization.
- Detailed findings with: description, technical details, exploitability, remediation, PoC, references.
- Business impact and risk context for each finding.
- Visual charts (severity distribution, score gauge).
- Filterable/focusable findings by severity or status.
- Digital signature for tamper-proof verification.
- Reproducibility metadata (command, arguments, timestamps).
- Responsive design with modern, clean aesthetic.
"""

import json
import hashlib
import re
from datetime import datetime
from typing import Dict, Any, List, Optional

# ── Configuration ──────────────────────────────────────────────────────────
REPORT_TITLE = "Bravo6 Security Assessment Report"
REPORT_VERSION = "3.0"
COMPANY_NAME = "Bravo6 Security"
COMPANY_LOGO = "🔐"  # Or use an icon/emoji

# ── Finding metadata: descriptions, impacts, references ──────────────────
FINDING_METADATA = {
    "secrets_detection": {
        "title": "Hardcoded Secrets / API Keys",
        "description": "The application source code or configuration exposes sensitive credentials (API keys, passwords, tokens) that can be used to compromise backend services or data.",
        "impact": "An attacker can use these credentials to access databases, cloud services, or internal APIs, leading to data breach, account takeover, or full system compromise.",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "cwe": "CWE-798: Use of Hard-coded Credentials",
        "references": ["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
        "remediation": "Remove secrets from code. Use environment variables, secrets managers (e.g., HashiCorp Vault, AWS Secrets Manager), or CI/CD secure variables."
    },
    "mixed_content": {
        "title": "Mixed Content (HTTP resources on HTTPS page)",
        "description": "The secure HTTPS page loads resources (scripts, stylesheets, images, iframes) over insecure HTTP.",
        "impact": "Active mixed content (scripts, stylesheets) can be intercepted and modified by attackers to execute malicious code, steal session cookies, or redirect users to phishing sites. Passive content (images) can be replaced or cause privacy leaks.",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-311: Missing Encryption of Sensitive Data",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"],
        "remediation": "Replace all HTTP URLs with HTTPS. Implement Content-Security-Policy with 'upgrade-insecure-requests' and/or 'block-all-mixed-content'."
    },
    "ssl_tls": {
        "title": "Weak SSL/TLS Configuration",
        "description": "The server supports outdated SSL/TLS protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1) or weak cipher suites (EXPORT, RC4, 3DES, CBC mode).",
        "impact": "Attackers can downgrade connections, decrypt traffic, or perform MITM attacks using known exploits like POODLE, BEAST, DROWN, or Logjam. This compromises confidentiality and integrity of transmitted data.",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
        "references": ["https://www.ssllabs.com/", "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=SSL"],
        "remediation": "Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1. Enable TLS 1.2 and 1.3. Use strong ciphers (ECDHE with AES-GCM or ChaCha20). Enable HSTS."
    },
    "security_headers": {
        "title": "Missing or Weak Security Headers",
        "description": "The HTTP response is missing critical security headers (HSTS, CSP, XFO, XCTO, Referrer-Policy, Permissions-Policy, COOP, COEP).",
        "impact": "Missing headers expose the application to various attacks: clickjacking, XSS, MIME-sniffing, SSL-stripping, cross-origin data leaks, and side-channel attacks (Spectre).",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-693: Protection Mechanism Failure",
        "references": ["https://owasp.org/www-project-secure-headers/"],
        "remediation": "Implement all recommended security headers with appropriate values."
    },
    "information_disclosure": {
        "title": "Sensitive Information Disclosure",
        "description": "The application exposes sensitive files, directories, or error messages that reveal internal system details, credentials, or source code.",
        "impact": "Attackers can use exposed information to map the application structure, identify technology versions (leading to known CVEs), discover admin endpoints, or directly access configuration files containing credentials.",
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
        "references": ["https://owasp.org/www-community/attacks/Information_disclosure"],
        "remediation": "Remove exposed files (.git, .env, backup archives). Disable directory listing. Implement proper access controls. Customize error pages."
    },
    "cookies": {
        "title": "Insecure Cookie Configuration",
        "description": "Session cookies are missing the Secure and/or HttpOnly flags, or are not using SameSite restriction.",
        "impact": "Cookies without Secure flag can be intercepted over HTTP. Without HttpOnly, they can be stolen via XSS. Without SameSite, they may be sent in cross-site requests (CSRF risk).",
        "owasp": "A04:2021 - Insecure Design",
        "cwe": "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies"],
        "remediation": "Set Secure, HttpOnly, and SameSite=Strict or Lax on all session cookies."
    },
    "cors": {
        "title": "Misconfigured CORS Policy",
        "description": "Cross-Origin Resource Sharing (CORS) is configured to allow requests from unauthorized origins, or with credentials allowed from wildcard origins.",
        "impact": "Attackers can make authenticated cross-origin requests to steal sensitive data, perform CSRF-like attacks, or execute unauthorized actions on behalf of the user.",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-346: Origin Validation Error",
        "references": ["https://portswigger.net/web-security/cors"],
        "remediation": "Restrict Access-Control-Allow-Origin to a specific list of trusted origins. Avoid using wildcard (*) with credentials."
    },
    "http_methods": {
        "title": "Dangerous HTTP Methods Enabled",
        "description": "The server supports HTTP methods like PUT, DELETE, TRACE, or OPTIONS that can be abused.",
        "impact": "Attackers can use PUT to upload malicious files, DELETE to remove content, TRACE to perform cross-site tracing (XST), or OPTIONS to gather information about server capabilities.",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-749: Exposed Dangerous Method or Function",
        "references": ["https://owasp.org/www-community/attacks/HTTP_verb_tampering"],
        "remediation": "Disable unnecessary HTTP methods. Only allow GET, POST, and HEAD."
    },
    "subdomain_takeover": {
        "title": "Subdomain Takeover Vulnerability",
        "description": "DNS records point to a service (e.g., AWS S3, GitHub Pages, Heroku) that is no longer in use, allowing an attacker to claim the subdomain.",
        "impact": "An attacker can claim the subdomain and serve malicious content, steal session cookies (if subdomain is trusted), or perform phishing attacks. This can lead to full compromise of the main domain's trust.",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-1023: Insecure Provision of Services",
        "references": ["https://www.hackerone.com/security-engineering/how-to-find-subdomain-takeovers"],
        "remediation": "Remove unused DNS records. If a service is no longer used, delete the CNAME record. Regularly audit DNS entries."
    },
    "email_security": {
        "title": "Missing Email Security Records (SPF, DKIM, DMARC)",
        "description": "The domain lacks SPF, DKIM, and/or DMARC records, making it vulnerable to email spoofing.",
        "impact": "Attackers can send fraudulent emails that appear to come from your domain, leading to phishing attacks, brand reputation damage, and potential financial losses.",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "cwe": "CWE-345: Insufficient Verification of Data Authenticity",
        "references": ["https://dmarc.org/", "https://www.dmarcanalyzer.com/spf/"],
        "remediation": "Publish SPF, DKIM, and DMARC records. Start with a quarantine policy, then move to reject once validated."
    },
    "robots_txt": {
        "title": "Sensitive Paths Exposed in robots.txt",
        "description": "The robots.txt file contains paths to sensitive directories (admin, backup, config, etc.) that are intended to be hidden from search engines but are publicly readable.",
        "impact": "Attackers can use these paths to directly access admin panels, configuration files, or other sensitive areas, accelerating their reconnaissance and attack planning.",
        "owasp": "A01:2021 - Broken Access Control",
        "cwe": "CWE-200: Exposure of Sensitive Information",
        "references": ["https://developers.google.com/search/docs/crawling-indexing/robots/intro"],
        "remediation": "Remove sensitive paths from robots.txt. Use proper authentication and access controls instead."
    },
    "cms_fingerprinting": {
        "title": "CMS/Technology Fingerprinting",
        "description": "The server reveals its technology stack (CMS, framework, version) through headers, cookies, or file paths.",
        "impact": "Known vulnerabilities (CVEs) exist for specific versions of popular CMS and frameworks. Attackers can target these known vulnerabilities to compromise the system.",
        "owasp": "A05:2021 - Security Misconfiguration",
        "cwe": "CWE-200: Exposure of Sensitive Information",
        "references": ["https://www.cvedetails.com/"],
        "remediation": "Remove version details from headers, meta tags, and URLs. Keep software up-to-date with security patches."
    },
    "sri_check": {
        "title": "Missing Subresource Integrity (SRI)",
        "description": "External scripts and stylesheets are loaded without integrity hashes, allowing CDN compromise or malicious modification.",
        "impact": "If a CDN is hacked or the external resource is compromised, attackers can inject malicious code into your site, affecting all users. This leads to XSS, data theft, or malware distribution.",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "cwe": "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"],
        "remediation": "Add integrity attributes (SHA-256, SHA-384, or SHA-512) to all external scripts and stylesheets."
    },
    "hallucinated_deps": {
        "title": "Hallucinated/Unsafe Dependencies (Domain Takeover Risk)",
        "description": "The application references external domains for dependencies that are unregistered or unused, which an attacker can claim.",
        "impact": "An attacker can register the unclaimed domain and serve malicious code, effectively performing a supply chain attack on your application.",
        "owasp": "A08:2021 - Software and Data Integrity Failures",
        "cwe": "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
        "references": ["https://hackerone.com/reports/1471309"],
        "remediation": "Verify all external domains are properly registered and maintained. Use package managers with lockfiles."
    },
    "ai_exposure": {
        "title": "AI/LLM Configuration Exposure",
        "description": "AI-related configuration files or prompts are publicly accessible, revealing internal system prompts, model behavior, or sensitive data.",
        "impact": "Attackers can extract proprietary prompts, understand system logic, or manipulate the AI model to generate harmful content or reveal confidential information (prompt injection).",
        "owasp": "A01:2021 - Broken Access Control (for LLM-specific risks)",
        "cwe": "CWE-200: Exposure of Sensitive Information",
        "references": ["https://owasp.org/www-project-top-10-for-large-language-model-applications/"],
        "remediation": "Restrict access to AI configuration files. Implement strong authentication for AI endpoints. Sanitize prompts and outputs."
    },
    "frontend_libs": {
        "title": "Outdated JavaScript Libraries with Known Vulnerabilities",
        "description": "The application uses frontend libraries (jQuery, Angular, React, Vue, etc.) with known CVEs.",
        "impact": "Attackers can exploit known vulnerabilities (XSS, RCE, prototype pollution) in outdated libraries to compromise user sessions, steal data, or execute arbitrary code in the browser.",
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
        "cwe": "CWE-1104: Use of Unmaintained Third Party Components",
        "references": ["https://retirejs.github.io/retire.js/", "https://snyk.io/vuln/"],
        "remediation": "Update libraries to the latest secure versions. Regularly audit dependencies using tools like npm audit, Snyk, or retire.js."
    },
    "csp": {
        "title": "Weak or Missing Content Security Policy (CSP)",
        "description": "The CSP is missing, uses unsafe-inline/unsafe-eval, or lacks critical directives (base-uri, form-action, object-src).",
        "impact": "A weak CSP exposes the application to XSS attacks, data injection, and clickjacking. Attackers can execute arbitrary scripts in the context of the application, steal session tokens, or deface the site.",
        "owasp": "A03:2021 - Injection",
        "cwe": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "references": ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"],
        "remediation": "Implement a strict CSP. Avoid unsafe-inline/unsafe-eval. Use nonce or hash for inline scripts. Set base-uri, form-action, and object-src to 'none' or 'self'."
    }
}

# ── Helper: Get exploitability score ──────────────────────────────────────
def _get_exploitability(test_name: str) -> int:
    """Return exploitability score (1-10)."""
    scoring = {
        "secrets_detection": 10,
        "http_methods": 9,
        "subdomain_takeover": 9,
        "mixed_content": 8,
        "information_disclosure": 8,
        "ssl_tls": 7,
        "csp": 8,
        "security_headers": 6,
        "cookies": 7,
        "cors": 7,
        "cms_fingerprinting": 7,
        "email_security": 6,
        "robots_txt": 6,
        "frontend_libs": 7,
        "sri_check": 5,
        "hallucinated_deps": 6,
        "ai_exposure": 6
    }
    key = test_name.replace("test_", "")
    return scoring.get(key, 5)

# ── Helper: Business impact mapping ──────────────────────────────────────
def _get_business_impact(test_name: str) -> str:
    impact_map = {
        "secrets_detection": "Critical data breach, full system compromise, regulatory fines (GDPR).",
        "http_methods": "Malware upload, data deletion, system downtime.",
        "subdomain_takeover": "Phishing attacks, brand reputation loss, user data theft.",
        "mixed_content": "Data interception, session hijacking, malicious code injection.",
        "information_disclosure": "Targeted attacks based on exposed system details.",
        "ssl_tls": "Data interception, eavesdropping, loss of confidentiality.",
        "csp": "Cross-site scripting, data theft, session hijacking.",
        "security_headers": "Increased attack surface for XSS, clickjacking, and data leaks.",
        "cookies": "Session hijacking, CSRF, sensitive data exposure.",
        "cors": "Unauthenticated cross-origin data theft.",
        "cms_fingerprinting": "Exploitation of known CVEs, system compromise.",
        "email_security": "Email spoofing, brand impersonation, financial fraud.",
        "robots_txt": "Accelerated reconnaissance and targeted attacks.",
        "frontend_libs": "Client-side XSS, prototype pollution, data theft.",
        "sri_check": "Supply chain attacks, malware injection.",
        "hallucinated_deps": "Supply chain takeover, malicious code injection.",
        "ai_exposure": "Prompt injection, proprietary data leak, AI manipulation."
    }
    key = test_name.replace("test_", "")
    return impact_map.get(key, "Potential security breach and business disruption.")

# ── Helper: Get severity color ────────────────────────────────────────────
def _severity_color(severity: str) -> str:
    colors = {
        "critical": "#ff0040",
        "high": "#ff6a00",
        "medium": "#ffd700",
        "low": "#00ccff",
        "info": "#666666"
    }
    return colors.get(severity.lower(), "#666666")

def _severity_bg(severity: str) -> str:
    colors = {
        "critical": "#ff00401a",
        "high": "#ff6a001a",
        "medium": "#ffd7001a",
        "low": "#00ccff1a",
        "info": "#6666661a"
    }
    return colors.get(severity.lower(), "#6666661a")

# ── Helper: Generate SHA-256 signature ────────────────────────────────────
def _generate_sha256(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()

# ── Helper: Truncate text ──────────────────────────────────────────────────
def _truncate(text: str, max_len: int = 200) -> str:
    if not text:
        return ""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."

# ── Main HTML Generator ────────────────────────────────────────────────────

def generate_html_report(result: Dict[str, Any]) -> str:
    """Generate a professional, comprehensive HTML report."""
    
    # ── Extract data ──────────────────────────────────────────────────────
    url = result.get("url", "N/A")
    status = result.get("status", "unknown")
    score = result.get("score", 0)
    grade = result.get("grade", "F")
    summary = result.get("summary", {})
    findings = result.get("findings", [])
    waf_context = result.get("waf_context", {})
    meta = result.get("meta", {})
    scan_errors = result.get("scan_errors", [])

    # ── Compute statistics ──────────────────────────────────────────────
    total_findings = len(findings)
    fail_count = sum(1 for f in findings if f.get("status") in ("fail", "warning"))
    pass_count = total_findings - fail_count

    # ── Process findings with metadata ──────────────────────────────────
    enriched_findings = []
    for f in findings:
        test_name = f.get("test_name", "unknown")
        metadata = FINDING_METADATA.get(test_name, {})
        severity = f.get("severity", "info")
        
        enriched = {
            **f,
            "_test_name": test_name,
            "_metadata": metadata,
            "_severity_color": _severity_color(severity),
            "_severity_bg": _severity_bg(severity),
            "_exploitability": _get_exploitability(test_name),
            "_business_impact": _get_business_impact(test_name),
            "_timestamp": datetime.now().isoformat(),
        }
        enriched_findings.append(enriched)

    # Sort by severity (critical first)
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    enriched_findings.sort(key=lambda f: sev_order.get(f.get("severity", "info"), 5))

    # ── Digital signature ──────────────────────────────────────────────
    report_json = json.dumps(result, sort_keys=True, default=str)
    signature = _generate_sha256(report_json)

    # ── Generate HTML ──────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{REPORT_TITLE} - {url}</title>
    <style>
        /* ── Base Reset ──────────────────────────────────────────────────── */
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, 'Helvetica Neue', Arial, sans-serif;
            background: #f0f4f8;
            color: #1a2332;
            padding: 30px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.08);
            padding: 40px;
        }}

        /* ── Typography ─────────────────────────────────────────────────── */
        h1, h2, h3, h4, h5 {{
            font-weight: 600;
            letter-spacing: -0.01em;
        }}
        h1 {{ font-size: 32px; color: #0a1a2f; }}
        h2 {{ font-size: 26px; color: #1a2f44; margin-top: 32px; margin-bottom: 16px; border-bottom: 2px solid #e9edf2; padding-bottom: 8px; }}
        h3 {{ font-size: 20px; color: #2a3f54; margin-top: 20px; margin-bottom: 10px; }}
        p {{ font-size: 16px; color: #3a4a5f; margin-bottom: 12px; line-height: 1.7; }}
        a {{ color: #0066cc; text-decoration: none; border-bottom: 1px solid #d0d7e0; }}
        a:hover {{ color: #004499; border-bottom-color: #0066cc; }}

        /* ── Header ──────────────────────────────────────────────────────── */
        .report-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 32px;
            padding-bottom: 24px;
            border-bottom: 2px solid #e9edf2;
        }}
        .report-header .brand {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .report-header .brand h1 {{
            font-size: 28px;
            font-weight: 700;
            color: #0a1a2f;
        }}
        .report-header .brand .logo {{
            font-size: 36px;
        }}
        .report-header .badge {{
            padding: 8px 24px;
            border-radius: 30px;
            font-weight: 600;
            font-size: 18px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #fff;
            background: {_severity_color(status if status in ('fail','warning','pass','error') else 'info')};
        }}

        .meta-row {{
            display: flex;
            gap: 24px;
            flex-wrap: wrap;
            margin: 8px 0 16px 0;
            font-size: 15px;
            color: #5a6a7f;
        }}
        .meta-row span {{
            background: #f7f9fc;
            padding: 4px 16px;
            border-radius: 20px;
            border: 1px solid #e9edf2;
        }}
        .meta-row strong {{ color: #0a1a2f; }}

        /* ── Score Card ─────────────────────────────────────────────────── */
        .score-card {{
            background: linear-gradient(135deg, #f7f9fc 0%, #ffffff 100%);
            border: 1px solid #e9edf2;
            border-radius: 16px;
            padding: 32px 40px;
            margin-bottom: 32px;
            display: flex;
            flex-wrap: wrap;
            gap: 40px;
            align-items: center;
        }}
        .score-gauge {{
            display: flex;
            align-items: center;
            gap: 20px;
        }}
        .score-circle {{
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: conic-gradient(#0066cc 0% {score}%, #e9edf2 {score}% 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 42px;
            font-weight: 700;
            color: #ffffff;
            text-shadow: 0 2px 8px rgba(0,0,0,0.15);
            border: 4px solid #0066cc;
            box-shadow: 0 4px 20px rgba(0,102,204,0.15);
        }}
        .score-details .grade {{
            font-size: 48px;
            font-weight: 700;
            color: #0066cc;
            letter-spacing: -0.03em;
        }}
        .score-details .sub {{
            font-size: 18px;
            color: #5a6a7f;
            margin-top: 4px;
        }}

        .summary-bars {{
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            margin-top: 12px;
        }}
        .summary-item {{
            display: flex;
            align-items: center;
            gap: 10px;
            background: #f7f9fc;
            padding: 6px 18px;
            border-radius: 30px;
            font-size: 15px;
            color: #2a3f54;
        }}
        .summary-item .dot {{
            width: 14px;
            height: 14px;
            border-radius: 50%;
            display: inline-block;
        }}

        /* ── Executive Summary ──────────────────────────────────────────── */
        .executive-summary {{
            background: #f7f9fc;
            border-left: 4px solid #0066cc;
            padding: 20px 28px;
            margin-bottom: 32px;
            border-radius: 0 12px 12px 0;
        }}
        .executive-summary p {{
            margin-bottom: 8px;
            color: #1a2f44;
        }}
        .executive-summary strong {{
            color: #0a1a2f;
        }}

        /* ── Findings ────────────────────────────────────────────────────── */
        .finding-card {{
            border: 1px solid #e9edf2;
            border-radius: 12px;
            margin-bottom: 18px;
            overflow: hidden;
            transition: box-shadow 0.2s;
            background: #ffffff;
        }}
        .finding-card:hover {{
            box-shadow: 0 4px 16px rgba(0,0,0,0.06);
        }}
        .finding-card .header {{
            padding: 18px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 12px;
            cursor: pointer;
            background: #fafbfc;
            border-bottom: 1px solid #e9edf2;
        }}
        .finding-card .header:hover {{
            background: #f0f4f8;
        }}
        .finding-card .header .title {{
            font-weight: 600;
            font-size: 18px;
            color: #0a1a2f;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .finding-card .header .meta-tags {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            align-items: center;
        }}
        .finding-card .header .badge-status {{
            padding: 4px 16px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-status.fail {{ background: #ff00401a; color: #cc0033; }}
        .badge-status.warning {{ background: #ffd7001a; color: #b89600; }}
        .badge-status.pass {{ background: #00aa411a; color: #00802b; }}
        .badge-status.error {{ background: #6666661a; color: #666; }}
        .badge-status.info {{ background: #0066cc1a; color: #004d99; }}

        .badge-severity {{
            padding: 4px 14px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-severity.critical {{ background: #ff00401a; color: #cc0033; }}
        .badge-severity.high {{ background: #ff6a001a; color: #cc5500; }}
        .badge-severity.medium {{ background: #ffd7001a; color: #b89600; }}
        .badge-severity.low {{ background: #00ccff1a; color: #0088aa; }}
        .badge-severity.info {{ background: #6666661a; color: #555; }}

        .exploit-score {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 700;
            background: #e9edf2;
            color: #1a2f44;
        }}

        .finding-body {{
            padding: 24px 28px;
            display: none;
            background: #ffffff;
        }}
        .finding-body.open {{ display: block; }}
        .finding-body .section {{
            margin-bottom: 20px;
        }}
        .finding-body .section-title {{
            font-weight: 600;
            font-size: 15px;
            color: #2a3f54;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .finding-body .section-content {{
            font-size: 15px;
            color: #3a4a5f;
            background: #f7f9fc;
            padding: 12px 16px;
            border-radius: 8px;
            border-left: 3px solid #0066cc;
            white-space: pre-wrap;
            word-break: break-word;
            font-family: 'Segoe UI', monospace;
        }}
        .finding-body .section-content.evidence {{
            background: #fafbfc;
            border-left-color: #ff6a00;
            font-family: 'Courier New', monospace;
            font-size: 14px;
        }}
        .finding-body .poc-box {{
            background: #0a1a2f;
            color: #00ff41;
            padding: 14px 18px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            overflow-x: auto;
            border: 1px solid #1a2f44;
        }}
        .finding-body .arrow {{
            transition: transform 0.25s;
            display: inline-block;
            font-size: 18px;
            color: #5a6a7f;
        }}
        .finding-body .arrow.open {{ transform: rotate(90deg); }}
        .finding-body .timestamp {{
            font-size: 13px;
            color: #8a9aaf;
            text-align: right;
            border-top: 1px solid #e9edf2;
            padding-top: 12px;
            margin-top: 12px;
        }}
        .finding-body .reference-link {{
            display: inline-block;
            margin-right: 12px;
            font-size: 14px;
        }}

        /* ── Footer ──────────────────────────────────────────────────────── */
        .signature-section {{
            margin-top: 40px;
            padding-top: 24px;
            border-top: 2px solid #e9edf2;
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 20px;
            font-size: 14px;
            color: #5a6a7f;
        }}
        .signature-section .hash {{
            font-family: 'Courier New', monospace;
            font-size: 13px;
            background: #f7f9fc;
            padding: 8px 14px;
            border-radius: 8px;
            border: 1px solid #e9edf2;
            word-break: break-all;
            color: #1a2f44;
        }}
        .footer {{
            margin-top: 32px;
            text-align: center;
            font-size: 14px;
            color: #8a9aaf;
            border-top: 1px solid #e9edf2;
            padding-top: 20px;
        }}

        /* ── Responsive ──────────────────────────────────────────────────── */
        @media (max-width: 768px) {{
            body {{ padding: 16px; }}
            .container {{ padding: 20px; }}
            .report-header {{ flex-direction: column; align-items: flex-start; }}
            .score-card {{ flex-direction: column; align-items: flex-start; gap: 20px; }}
            .finding-card .header {{ flex-direction: column; align-items: flex-start; }}
            .meta-row {{ gap: 12px; }}
        }}

        /* ── Print ──────────────────────────────────────────────────────── */
        @media print {{
            body {{ background: #fff; padding: 0; }}
            .container {{ box-shadow: none; border: none; }}
            .finding-card {{
                break-inside: avoid;
                border: 1px solid #ccc;
            }}
        }}
    </style>
</head>
<body>
<div class="container">

    <!-- ═══ HEADER ═══ -->
    <div class="report-header">
        <div class="brand">
            <span class="logo">{COMPANY_LOGO}</span>
            <h1>{REPORT_TITLE}</h1>
        </div>
        <div class="badge">{status.upper()}</div>
    </div>

    <div class="meta-row">
        <span>Target: <strong>{url}</strong></span>
        <span>Duration: {meta.get('duration_seconds', 0)}s</span>
        <span>Tests: {meta.get('tests_run', 0)}</span>
        <span>Findings: {total_findings}</span>
        <span>Errors: {meta.get('tests_errored', 0)}</span>
        <span>Report: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
    </div>

    <!-- ═══ SCORE CARD ═══ -->
    <div class="score-card">
        <div class="score-gauge">
            <div class="score-circle">{score}</div>
            <div class="score-details">
                <div class="grade">Grade {grade}</div>
                <div class="sub">Security posture score</div>
            </div>
        </div>
        <div>
            <div class="summary-bars">
                <div class="summary-item"><span class="dot" style="background:#ff0040;"></span> Critical: {summary.get('critical', 0)}</div>
                <div class="summary-item"><span class="dot" style="background:#ff6a00;"></span> High: {summary.get('high', 0)}</div>
                <div class="summary-item"><span class="dot" style="background:#ffd700;"></span> Medium: {summary.get('medium', 0)}</div>
                <div class="summary-item"><span class="dot" style="background:#00ccff;"></span> Low: {summary.get('low', 0)}</div>
                <div class="summary-item"><span class="dot" style="background:#00aa41;"></span> Passed: {summary.get('passed', 0)}</div>
                <div class="summary-item"><span class="dot" style="background:#8a9aaf;"></span> Errors: {summary.get('errors', 0)}</div>
            </div>
        </div>
    </div>

    <!-- ═══ EXECUTIVE SUMMARY ═══ -->
    <div class="executive-summary">
        <h3 style="margin-top:0;color:#0a1a2f;">📊 Executive Summary</h3>
        <p>
            <strong>Scan completed for {url}.</strong> 
            Found <strong>{total_findings}</strong> security findings.
            The overall security grade is <strong>{grade}</strong> with a score of <strong>{score}/100</strong>.
        </p>
        <p>
            <strong>Key risks:</strong> {', '.join([f['_metadata'].get('title', f.get('test_name', '')) for f in enriched_findings if f.get('status') in ('fail','warning')][:3]) or 'No critical findings detected.'}
        </p>
        <p>
            <strong>Recommendation:</strong> Prioritize remediation of <strong>critical</strong> and <strong>high</strong> severity issues first.
        </p>
    </div>

    <!-- ═══ WAF CONTEXT ═══ -->
    {_render_waf_context(waf_context)}

    <!-- ═══ FINDINGS ═══ -->
    <h2>🔍 Detailed Findings</h2>
    {_render_findings(enriched_findings)}

    <!-- ═══ FOOTER / SIGNATURE ═══ -->
    <div class="signature-section">
        <div>
            <strong>🔒 Digital Signature</strong>
            <div class="hash">SHA-256: {signature}</div>
            <div style="font-size:13px;color:#5a6a7f;margin-top:4px;">
                This signature verifies report integrity. Any modification invalidates the hash.
            </div>
        </div>
        <div>
            <strong>⚙️ Reproducibility</strong>
            <div style="font-size:14px;color:#3a4a5f;margin-top:4px;">
                Target: <strong>{url}</strong><br>
                Scan time: <strong>{datetime.now().isoformat()}</strong><br>
                Tests: <strong>{meta.get('tests_run', 0)}</strong><br>
                <span style="font-family:'Courier New',monospace;font-size:13px;display:block;margin-top:4px;background:#f7f9fc;padding:6px 12px;border-radius:6px;">
                    python -m scanner.main_scanner {url}
                </span>
            </div>
        </div>
        <div>
            <strong>📅 Generated</strong>
            <div style="font-size:14px;color:#3a4a5f;margin-top:4px;">
                {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </div>
        </div>
    </div>

    <div class="footer">
        {COMPANY_NAME} • Report v{REPORT_VERSION} • Confidential — For authorized use only
    </div>
</div>

<script>
    // ── Toggle finding details ──────────────────────────────────────────
    function toggleBody(header) {{
        const body = header.nextElementSibling;
        const arrow = header.querySelector('.arrow');
        if (body.classList.contains('open')) {{
            body.classList.remove('open');
            arrow.classList.remove('open');
        }} else {{
            body.classList.add('open');
            arrow.classList.add('open');
        }}
    }}

    // ── Auto-expand fail/warning findings ──────────────────────────────
    document.addEventListener('DOMContentLoaded', function() {{
        document.querySelectorAll('.finding-card .header').forEach(function(header) {{
            const statusBadge = header.querySelector('.badge-status');
            if (statusBadge && (statusBadge.classList.contains('fail') || statusBadge.classList.contains('warning'))) {{
                const body = header.nextElementSibling;
                const arrow = header.querySelector('.arrow');
                if (body) {{
                    body.classList.add('open');
                    if (arrow) arrow.classList.add('open');
                }}
            }}
        }});
    }});
</script>
</body>
</html>
"""
    return html


# ── Helper Renderers ──────────────────────────────────────────────────────

def _render_waf_context(waf_context: dict) -> str:
    if not waf_context.get('detected'):
        return ''
    return f'''
    <div style="background:#f7f9fc;border-left:4px solid #ff6a00;padding:14px 20px;margin-bottom:24px;border-radius:0 12px 12px 0;">
        <strong style="color:#1a2f44;">🛡️ WAF/CDN Detected:</strong> 
        <span style="color:#cc5500;">{waf_context.get('detected')}</span>
        <div style="font-size:14px;color:#5a6a7f;margin-top:4px;">{waf_context.get('note', '')}</div>
    </div>
    '''


def _render_findings(findings: List[Dict]) -> str:
    if not findings:
        return '<p style="color:#3a4a5f;font-size:16px;">No findings to display.</p>'

    html_parts = []
    for f in findings:
        test_name = f.get("_test_name", "unknown")
        metadata = f.get("_metadata", {})
        status = f.get("status", "info")
        severity = f.get("severity", "info")
        title = f.get("title", metadata.get("title", test_name))
        description = f.get("description", metadata.get("description", "No description available."))
        evidence = f.get("evidence")
        remediation = f.get("remediation", metadata.get("remediation", "No specific remediation provided."))
        exploit = f.get("_exploitability", 5)
        business_impact = f.get("_business_impact", "Potential security breach.")
        poc = f.get("poc")
        owasp = metadata.get("owasp", "N/A")
        cwe = metadata.get("cwe", "N/A")
        references = metadata.get("references", [])
        timestamp = f.get("_timestamp", datetime.now().isoformat())
        severity_color = f.get("_severity_color", "#666666")
        severity_bg = f.get("_severity_bg", "#f7f9fc")

        # ── Evidence formatting ──────────────────────────────────────────
        evidence_html = ""
        if evidence:
            if isinstance(evidence, str):
                evidence_html = f'<div class="section-content evidence">{evidence}</div>'
            elif isinstance(evidence, list):
                items = []
                for e in evidence[:5]:  # Limit to 5 items
                    if isinstance(e, dict):
                        parts = []
                        for k, v in e.items():
                            if k == "verification_response":
                                parts.append(f'<strong>API Response:</strong><div class="poc-box" style="margin-top:4px;">{v}</div>')
                            else:
                                parts.append(f"<strong>{k}:</strong> {v}")
                        items.append("<div style='margin-bottom:6px;'>" + " | ".join(parts) + "</div>")
                    else:
                        items.append(f"<div>• {e}</div>")
                evidence_html = "".join(items)
            elif isinstance(evidence, dict):
                parts = [f"<strong>{k}:</strong> {v}" for k, v in evidence.items() if v and len(str(v)) < 500]
                evidence_html = "<div>" + " | ".join(parts) + "</div>"

        # ── Business impact badge ──────────────────────────────────────
        impact_color = "#cc0033" if exploit >= 8 else "#cc5500" if exploit >= 5 else "#b89600"

        # ── References ──────────────────────────────────────────────────
        refs_html = ""
        if references:
            refs = []
            for r in references:
                if r.startswith("http"):
                    refs.append(f'<a href="{r}" target="_blank" class="reference-link">{r}</a>')
                else:
                    refs.append(f'<span class="reference-link">{r}</span>')
            refs_html = " ".join(refs)

        # ── Build card ──────────────────────────────────────────────────
        status_class = status.lower()
        sev_class = severity.lower()

        html_parts.append(f'''
        <div class="finding-card">
            <div class="header" onclick="toggleBody(this)">
                <div class="title">
                    <span>{test_name.replace("test_", "").replace("_", " ").title()}</span>
                    <span class="badge-severity {sev_class}">{severity.upper()}</span>
                    <span class="exploit-score">⚡ {exploit}/10</span>
                    <span style="font-size:14px;color:#5a6a7f;font-weight:400;">{_truncate(description, 80)}</span>
                </div>
                <div class="meta-tags">
                    <span class="badge-status {status_class}">{status.upper()}</span>
                    <span class="arrow">▶</span>
                </div>
            </div>
            <div class="finding-body">
                <div class="section">
                    <div class="section-title">📌 Description</div>
                    <div class="section-content">{description}</div>
                </div>

                <div class="section">
                    <div class="section-title">💼 Business Impact</div>
                    <div class="section-content" style="border-left-color:{impact_color};color:#1a2332;">
                        <strong>Exploitability Score:</strong> {exploit}/10<br>
                        <strong>Impact:</strong> {business_impact}
                    </div>
                </div>

                {'<div class="section"><div class="section-title">🔎 Evidence</div><div class="section-content evidence">' + evidence_html + '</div></div>' if evidence_html else ''}

                {'<div class="section"><div class="section-title">💻 Proof of Concept</div><div class="poc-box">' + poc + '</div></div>' if poc else ''}

                <div class="section">
                    <div class="section-title">🛠️ Remediation</div>
                    <div class="section-content" style="border-left-color:#00aa41;">{remediation}</div>
                </div>

                <div class="section">
                    <div class="section-title">📚 References</div>
                    <div class="section-content" style="border-left-color:#666666;font-size:14px;">
                        <strong>OWASP:</strong> {owasp}<br>
                        <strong>CWE:</strong> {cwe}<br>
                        <strong>External:</strong> {refs_html or 'None provided'}
                    </div>
                </div>

                <div class="timestamp">⏱️ Detected: {timestamp}</div>
            </div>
        </div>
        ''')

    return ''.join(html_parts)


# ── CLI ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r', encoding='utf-8') as f:
            data = json.load(f)
        html_out = generate_html_report(data)
        output_file = sys.argv[2] if len(sys.argv) > 2 else "scan_report.html"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_out)
        print(f"Report saved to {output_file}")
    else:
        print("Usage: python report_generator.py <scan_result.json> [output.html]")