"""
report_generator.py — Bravo6 Professional HTML Report Generator (No Exploit Scores)

- Removed exploitability scores and business impact sections.
- Clean, professional look with minimal distractions.
- Focus on findings and remediation only.
"""

import json
import hashlib
import re
from datetime import datetime
from typing import Dict, Any, List, Optional

# ── Explanations only (no exploit scores) ────────────────────────────────
EXPLANATIONS = {
    "secrets_detection": "Your website exposes secret keys (like passwords or API tokens) in plain text. An attacker can use these to steal data, hijack services, or compromise your infrastructure.",
    "http_methods": "Your web server accepts dangerous HTTP methods (e.g., DELETE, PUT, TRACE) that can be abused to modify or delete resources, or to bypass security controls.",
    "robots_txt": "The robots.txt file reveals hidden admin panels or sensitive directories. While not a direct vulnerability, it gives attackers a roadmap to high-value targets.",
    "information_disclosure": "Your site leaks internal details such as file paths, server versions, or environment variables. This information helps attackers tailor sophisticated attacks.",
    "subdomain_takeover": "Your DNS records point to services (e.g., S3 buckets, Azure sites) that are no longer in use. An attacker can claim these services and control your subdomains.",
    "cms_vibe_detection": "Your CMS or framework is outdated or misconfigured, which may allow attackers to exploit known vulnerabilities and take over your site.",
    "ssl_tls": "Your HTTPS encryption is weak or misconfigured (e.g., outdated protocols, weak ciphers). Attackers can intercept or decrypt sensitive data transmitted between users and your server.",
    "cors": "Your CORS policy is overly permissive, allowing arbitrary origins to make cross-origin requests. This can lead to data theft or CSRF-like attacks.",
    "email_security": "Your email configuration (SPF, DKIM, DMARC) is missing or weak, allowing spammers to send forged emails that appear to come from your domain, harming your reputation.",
    "cookie_security": "Your session cookies are missing the Secure, HttpOnly, or SameSite flags. This makes them vulnerable to interception via HTTP, XSS, or CSRF attacks.",
    "mixed_content": "Your HTTPS page loads resources (scripts, stylesheets, images) over insecure HTTP. Active mixed content can be intercepted to execute malicious code.",
    "sri_check": "Your site loads external JavaScript libraries without Subresource Integrity (SRI). If the CDN is compromised, attackers can inject malicious code into your page.",
    "hallucinated_deps": "Your site references domains that do not exist. An attacker can register these domains and serve malicious content, leading to supply chain attacks.",
    "AI Configuration Exposure": "Your AI-related configuration files or endpoints are publicly accessible, potentially exposing sensitive prompts, models, or internal logic.",
    "security_headers": "Your site is missing key security headers (e.g., CSP, HSTS, X-Frame-Options). This weakens browser protections against XSS, clickjacking, and other attacks.",
    "js_library_audit": "Your site uses outdated JavaScript libraries with known vulnerabilities (CVEs). Attackers can exploit these to compromise your users.",
}


def _get_explanation(test_name: str) -> str:
    key = test_name.replace("test_", "").replace("_", " ")
    for k, v in EXPLANATIONS.items():
        if k in key.lower():
            return v
    return "This issue may pose a security risk to your website. Review the details below for specific recommendations."


def _get_priority(severity: str) -> str:
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(severity.lower(), 0)
    if sev_rank >= 3:
        return "High"
    if sev_rank >= 2:
        return "Medium"
    if sev_rank >= 1:
        return "Low"
    return "Info"


def _severity_to_risk_level(severity: str) -> str:
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info"
    }.get(severity.lower(), "Info")


def _generate_sha256(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def _combine_security_headers(findings: List[Dict]) -> List[Dict]:
    security_items = [f for f in findings if f.get("test_name") == "security_headers"]
    if not security_items:
        return findings

    other_items = [f for f in findings if f.get("test_name") != "security_headers"]

    has_fail = any(f.get("status") == "fail" for f in security_items)
    has_warning = any(f.get("status") == "warning" for f in security_items)
    overall_status = "fail" if has_fail else "warning" if has_warning else "pass"

    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    max_sev = max(security_items, key=lambda x: severity_order.get(x.get("severity", "info"), 0))
    overall_severity = max_sev.get("severity", "info")

    evidence = []
    for f in security_items:
        evidence.append({
            "header": f.get("header", "Unknown"),
            "status": f.get("status", "unknown"),
            "severity": f.get("severity", "info"),
            "description": f.get("description", ""),
            "poc": f.get("poc", ""),
            "remediation": f.get("remediation", ""),
        })

    combined = {
        "test_name": "security_headers",
        "status": overall_status,
        "severity": overall_severity,
        "title": f"Security Headers ({len(security_items)} issues)",
        "description": f"Found {len(security_items)} security header issues.",
        "evidence": evidence,
        "remediation": " ".join(list(set([f.get("remediation", "") for f in security_items if f.get("remediation")]))),
        "poc": "curl -I https://target.com",
        "_timestamp": datetime.now().isoformat(),
        "_priority": _get_priority(overall_severity),
        "_explanation": _get_explanation("security_headers"),
        "_risk_level": _severity_to_risk_level(overall_severity),
    }

    other_items.append(combined)
    return other_items


def generate_html_report(result: Dict[str, Any]) -> str:
    url = result.get("url", "N/A")
    status = result.get("status", "unknown")
    score = result.get("score", 0)
    grade = result.get("grade", "F")
    summary = result.get("summary", {})
    raw_findings = result.get("findings", [])
    waf_context = result.get("waf_context", {})
    meta = result.get("meta", {})
    scan_errors = result.get("scan_errors", [])

    # ── Combine security headers ───────────────────────────────────────────
    raw_findings = _combine_security_headers(raw_findings)

    # ── Process findings: enrich with metadata ────────────────────────────
    processed_findings = []
    for f in raw_findings:
        if not isinstance(f, dict):
            continue
        test_name = f.get("test_name", "Unnamed")
        severity = f.get("severity", "info")
        status_finding = f.get("status", "unknown")

        if status_finding in ("fail", "warning"):
            explanation = _get_explanation(test_name)
            priority = _get_priority(severity)
            risk_level = _severity_to_risk_level(severity)
        else:
            explanation = "No vulnerability found. This check passed successfully."
            priority = "Info"
            risk_level = "Info"

        if "title" not in f:
            f["title"] = test_name.replace("_", " ").title()
        if "description" not in f:
            f["description"] = "No description provided."
        if "evidence" not in f:
            f["evidence"] = {}
        if "remediation" not in f:
            f["remediation"] = "No specific remediation provided."
        if "poc" not in f:
            f["poc"] = "No PoC available."

        f["_timestamp"] = datetime.now().isoformat()
        f["_priority"] = priority
        f["_explanation"] = explanation
        f["_risk_level"] = risk_level
        processed_findings.append(f)

    # Sort by priority
    priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    sorted_findings = sorted(
        processed_findings,
        key=lambda f: priority_order.get(f.get("_priority", "Info"), 5)
    )

    # ── Replace placeholder PoC for security_headers with actual URL ───
    for f in sorted_findings:
        if f.get("test_name") == "security_headers" and "target.com" in f.get("poc", ""):
            f["poc"] = f"curl -I {url}"
        if "clickjacking" in f.get("title", "").lower() or "frame-ancestors" in f.get("description", "").lower():
            if "target" in f.get("poc", ""):
                f["poc"] = f["poc"].replace("target", url)

    # ── Digital signature ──────────────────────────────────────────────────
    report_json = json.dumps(result, sort_keys=True, default=str)
    signature = _generate_sha256(report_json)

    # ── Prepare data for charts ──────────────────────────────────────────
    severity_counts = {
        "critical": summary.get("critical", 0),
        "high": summary.get("high", 0),
        "medium": summary.get("medium", 0),
        "low": summary.get("low", 0),
        "passed": summary.get("passed", 0),
        "errors": summary.get("errors", 0),
    }

    # ── Heatmap data (without exploit scores) ──────────────────────────────
    heatmap_cells = []
    for f in sorted_findings:
        if f.get("status") in ("fail", "warning"):
            heatmap_cells.append({
                "name": f.get("test_name", "").replace("test_", "").replace("_", " ").title(),
                "risk": f.get("_risk_level", "Info"),
                "priority": f.get("_priority", "Low"),
            })

    # ── Generate HTML ──────────────────────────────────────────────────────
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bravo6 Security Report – {url}</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        /* ── Reset & Base ──────────────────────────────────────────────────── */
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, 'Helvetica Neue', sans-serif;
            font-size: 17px;
            line-height: 1.7;
            background: #0b0d11;
            color: #e8edf3;
            padding: 30px;
            min-height: 100vh;
        }}
        .container {{
            max-width: 1440px;
            margin: 0 auto;
            background: linear-gradient(145deg, #13171e 0%, #1a202a 100%);
            border-radius: 20px;
            box-shadow: 0 30px 80px rgba(0,0,0,0.7);
            padding: 50px 60px;
            border: 1px solid #2a3344;
        }}

        ::-webkit-scrollbar {{ width: 10px; background: #1a202a; }}
        ::-webkit-scrollbar-track {{ background: #1a202a; }}
        ::-webkit-scrollbar-thumb {{ background: #d4a743; border-radius: 8px; }}

        h1, h2, h3, h4, h5 {{
            font-weight: 600;
            letter-spacing: -0.02em;
            color: #ffffff;
        }}
        h1 {{ font-size: 38px; margin-bottom: 8px; }}
        h2 {{ font-size: 30px; margin: 36px 0 16px; color: #e8edf3; border-bottom: 2px solid #2a3344; padding-bottom: 12px; }}
        h3 {{ font-size: 24px; margin: 20px 0 12px; color: #d4a743; }}
        p {{ font-size: 17px; color: #b0b8c6; margin-bottom: 14px; line-height: 1.8; }}
        a {{ color: #d4a743; text-decoration: none; border-bottom: 1px solid transparent; transition: border 0.2s; }}
        a:hover {{ border-bottom-color: #d4a743; }}

        /* ── Header ──────────────────────────────────────────────────────── */
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            padding-bottom: 28px;
            border-bottom: 2px solid #2a3344;
            margin-bottom: 32px;
        }}
        .header-left {{
            display: flex;
            align-items: center;
            gap: 20px;
        }}
        .logo {{
            font-size: 44px;
            font-weight: 800;
            color: #d4a743;
            letter-spacing: -0.04em;
            background: linear-gradient(135deg, #d4a743, #f5d27e);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        .logo-sub {{
            font-size: 14px;
            color: #7a8395;
            letter-spacing: 2px;
            font-weight: 300;
            -webkit-text-fill-color: #7a8395;
        }}
        .header-title h1 {{
            font-size: 32px;
            color: #ffffff;
            margin-bottom: 0;
        }}
        .header-title .sub {{
            color: #7a8395;
            font-size: 16px;
            font-weight: 300;
        }}
        .badge {{
            padding: 12px 32px;
            border-radius: 50px;
            font-weight: 700;
            font-size: 20px;
            letter-spacing: 1px;
            text-transform: uppercase;
            background: #2a3344;
            color: #b0b8c6;
            border: 2px solid #2a3344;
        }}
        .badge.pass {{ background: #1a3a2a; border-color: #2d8f5c; color: #5fcf8a; }}
        .badge.warning {{ background: #3a2f1a; border-color: #b8961a; color: #f5c842; }}
        .badge.fail {{ background: #3a1a1a; border-color: #b82a2a; color: #f55a5a; }}
        .badge.error {{ background: #2a2a2a; border-color: #555; color: #999; }}

        .meta-info {{
            display: flex;
            flex-wrap: wrap;
            gap: 20px 40px;
            margin-top: 16px;
            font-size: 16px;
            color: #7a8395;
        }}
        .meta-info strong {{ color: #e8edf3; }}

        /* ── Score Card ──────────────────────────────────────────────────── */
        .score-card {{
            display: flex;
            flex-wrap: wrap;
            gap: 40px 80px;
            background: rgba(20, 26, 38, 0.6);
            border-radius: 16px;
            padding: 32px 40px;
            margin-bottom: 32px;
            align-items: center;
            border: 1px solid #2a3344;
            backdrop-filter: blur(8px);
        }}
        .score-gauge {{
            display: flex;
            align-items: center;
            gap: 28px;
        }}
        .score-circle {{
            width: 130px;
            height: 130px;
            border-radius: 50%;
            background: conic-gradient(#d4a743 {score}%, #2a3344 {score}%);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 42px;
            font-weight: 800;
            color: #ffffff;
            position: relative;
            box-shadow: 0 0 40px rgba(212, 167, 67, 0.15);
        }}
        .score-circle::after {{
            content: '';
            position: absolute;
            top: 8px;
            left: 8px;
            right: 8px;
            bottom: 8px;
            border-radius: 50%;
            background: #13171e;
            z-index: -1;
        }}
        .score-details .grade {{
            font-size: 56px;
            font-weight: 800;
            color: #d4a743;
            line-height: 1;
            letter-spacing: -0.04em;
        }}
        .score-details .label {{
            font-size: 18px;
            color: #7a8395;
            font-weight: 300;
        }}

        .summary-bars {{
            display: flex;
            flex-wrap: wrap;
            gap: 14px 24px;
            margin-top: 14px;
        }}
        .summary-item {{
            display: inline-flex;
            align-items: center;
            gap: 10px;
            background: rgba(255,255,255,0.04);
            padding: 8px 22px;
            border-radius: 40px;
            font-size: 16px;
            font-weight: 500;
            border: 1px solid #2a3344;
            color: #b0b8c6;
        }}
        .summary-item .dot {{
            width: 14px;
            height: 14px;
            border-radius: 50%;
            display: inline-block;
            flex-shrink: 0;
        }}
        .dot-critical {{ background: #c0392b; }}
        .dot-high {{ background: #e67e22; }}
        .dot-medium {{ background: #f39c12; }}
        .dot-low {{ background: #3498db; }}
        .dot-passed {{ background: #2ecc71; }}
        .dot-errors {{ background: #7f8c8d; }}

        /* ── Dashboard Charts ────────────────────────────────────────────── */
        .dashboard {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin-bottom: 36px;
        }}
        .chart-card {{
            background: rgba(20, 26, 38, 0.5);
            border: 1px solid #2a3344;
            border-radius: 16px;
            padding: 24px 28px;
            backdrop-filter: blur(8px);
        }}
        .chart-card h3 {{
            margin-top: 0;
            font-size: 20px;
            color: #e8edf3;
            margin-bottom: 16px;
        }}
        .chart-container {{
            position: relative;
            height: 220px;
        }}
        @media (max-width: 768px) {{
            .dashboard {{ grid-template-columns: 1fr; }}
        }}

        /* ── WAF Context ─────────────────────────────────────────────────── */
        .waf-note {{
            background: rgba(212, 167, 67, 0.08);
            border-left: 4px solid #d4a743;
            padding: 16px 24px;
            margin-bottom: 28px;
            border-radius: 0 12px 12px 0;
            font-size: 16px;
            color: #b0b8c6;
        }}
        .waf-note strong {{ color: #d4a743; }}

        /* ── Heatmap ────────────────────────────────────────────────────── */
        .heatmap {{
            background: rgba(20, 26, 38, 0.5);
            border: 1px solid #2a3344;
            border-radius: 16px;
            padding: 24px 28px;
            margin-bottom: 32px;
        }}
        .heatmap-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(170px, 1fr));
            gap: 14px;
            margin-top: 16px;
        }}
        .heatmap-cell {{
            background: #1f2838;
            border-radius: 12px;
            padding: 14px 12px;
            text-align: center;
            font-weight: 600;
            font-size: 14px;
            color: #e8edf3;
            transition: transform 0.15s, box-shadow 0.15s;
            border: 1px solid #2a3344;
        }}
        .heatmap-cell:hover {{ transform: scale(1.04); box-shadow: 0 8px 24px rgba(0,0,0,0.4); }}

        /* ── Priority Section ────────────────────────────────────────────── */
        .priority-section {{
            background: rgba(20, 26, 38, 0.5);
            border: 1px solid #2a3344;
            border-radius: 16px;
            padding: 24px 28px;
            margin-bottom: 32px;
        }}
        .priority-list {{
            list-style: none;
            padding: 0;
            margin: 16px 0 0;
        }}
        .priority-list li {{
            display: flex;
            align-items: flex-start;
            gap: 18px;
            padding: 14px 0;
            border-bottom: 1px solid #1f2838;
        }}
        .priority-list li:last-child {{ border-bottom: none; }}
        .priority-badge {{
            font-weight: 700;
            font-size: 13px;
            padding: 4px 18px;
            border-radius: 40px;
            color: #fff;
            background: #2a3344;
            white-space: nowrap;
            flex-shrink: 0;
        }}
        .priority-badge.critical {{ background: #c0392b; }}
        .priority-badge.high {{ background: #d35400; }}
        .priority-badge.medium {{ background: #d4a743; color: #0b0d11; }}
        .priority-badge.low {{ background: #2980b9; }}
        .priority-badge.info {{ background: #3d4a5e; }}

        /* ── Finding Cards ────────────────────────────────────────────────── */
        .finding-card {{
            border: 1px solid #2a3344;
            border-radius: 14px;
            margin-bottom: 18px;
            overflow: hidden;
            background: rgba(20, 26, 38, 0.4);
            transition: box-shadow 0.2s, border-color 0.2s;
        }}
        .finding-card:hover {{ box-shadow: 0 8px 30px rgba(0,0,0,0.5); }}
        .finding-card.pass {{ border-left: 6px solid #2ecc71; }}
        .finding-card.warning {{ border-left: 6px solid #f1c40f; }}
        .finding-card.fail {{ border-left: 6px solid #e74c3c; }}
        .finding-card.error {{ border-left: 6px solid #7f8c8d; }}
        .finding-card.info {{ border-left: 6px solid #3498db; }}

        .finding-header {{
            padding: 18px 26px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(255,255,255,0.02);
            border-bottom: 1px solid #1f2838;
            transition: background 0.15s;
        }}
        .finding-header:hover {{ background: rgba(255,255,255,0.05); }}
        .finding-header .title {{
            font-weight: 600;
            font-size: 20px;
            color: #ffffff;
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }}
        .finding-header .badge-group {{
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            align-items: center;
        }}
        .finding-header .status-badge {{
            padding: 4px 18px;
            border-radius: 40px;
            font-size: 14px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .status-badge.pass {{ background: rgba(46, 204, 113, 0.15); color: #2ecc71; border: 1px solid rgba(46, 204, 113, 0.3); }}
        .status-badge.warning {{ background: rgba(241, 196, 15, 0.15); color: #f1c40f; border: 1px solid rgba(241, 196, 15, 0.3); }}
        .status-badge.fail {{ background: rgba(231, 76, 60, 0.15); color: #e74c3c; border: 1px solid rgba(231, 76, 60, 0.3); }}
        .status-badge.error {{ background: rgba(127, 140, 141, 0.15); color: #95a5a6; border: 1px solid rgba(127, 140, 141, 0.3); }}
        .status-badge.info {{ background: rgba(52, 152, 219, 0.15); color: #3498db; border: 1px solid rgba(52, 152, 219, 0.3); }}

        .severity-tag {{
            padding: 4px 18px;
            border-radius: 40px;
            font-size: 13px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.3px;
        }}
        .severity-tag.critical {{ background: rgba(231, 76, 60, 0.2); color: #e74c3c; border: 1px solid rgba(231, 76, 60, 0.3); }}
        .severity-tag.high {{ background: rgba(230, 126, 34, 0.2); color: #e67e22; border: 1px solid rgba(230, 126, 34, 0.3); }}
        .severity-tag.medium {{ background: rgba(241, 196, 15, 0.2); color: #f1c40f; border: 1px solid rgba(241, 196, 15, 0.3); }}
        .severity-tag.low {{ background: rgba(52, 152, 219, 0.2); color: #3498db; border: 1px solid rgba(52, 152, 219, 0.3); }}
        .severity-tag.info {{ background: rgba(127, 140, 141, 0.2); color: #95a5a6; border: 1px solid rgba(127, 140, 141, 0.3); }}

        .arrow {{
            font-size: 20px;
            color: #7a8395;
            transition: transform 0.3s;
            margin-left: 10px;
        }}
        .arrow.open {{ transform: rotate(90deg); }}

        .finding-body {{
            padding: 24px 28px;
            display: none;
            background: rgba(0,0,0,0.2);
        }}
        .finding-body.open {{ display: block; }}
        .finding-body .section {{
            margin-bottom: 20px;
        }}
        .finding-body .section-title {{
            font-weight: 600;
            font-size: 17px;
            color: #d4a743;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .finding-body .section-content {{
            font-size: 16px;
            color: #b0b8c6;
            background: rgba(0,0,0,0.3);
            padding: 14px 18px;
            border-radius: 10px;
            border-left: 3px solid #d4a743;
            white-space: pre-wrap;
            word-break: break-word;
        }}
        .finding-body .poc {{
            background: #0b0d11;
            color: #5fcf8a;
            padding: 14px 18px;
            border-radius: 10px;
            font-family: 'Courier New', monospace;
            font-size: 15px;
            overflow-x: auto;
            border: 1px solid #1a2a2a;
        }}
        .finding-body .timestamp {{
            font-size: 14px;
            color: #5a6a7f;
            text-align: right;
            border-top: 1px solid #1f2838;
            padding-top: 14px;
            margin-top: 14px;
        }}

        /* ── Print / Export Buttons ──────────────────────────────────────── */
        .toolbar {{
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
            margin-bottom: 28px;
        }}
        .toolbar button {{
            padding: 12px 28px;
            border: 1px solid #2a3344;
            border-radius: 50px;
            background: rgba(255,255,255,0.04);
            color: #e8edf3;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 10px;
        }}
        .toolbar button:hover {{
            background: rgba(212, 167, 67, 0.12);
            border-color: #d4a743;
            color: #d4a743;
        }}

        /* ── Signature & Footer ──────────────────────────────────────────── */
        .signature-section {{
            margin-top: 44px;
            padding-top: 28px;
            border-top: 2px solid #2a3344;
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            gap: 24px;
            font-size: 15px;
            color: #7a8395;
        }}
        .signature-section .hash {{
            font-family: 'Courier New', monospace;
            font-size: 14px;
            color: #b0b8c6;
            background: rgba(0,0,0,0.3);
            padding: 8px 16px;
            border-radius: 8px;
            word-break: break-all;
            border: 1px solid #1f2838;
        }}
        .footer {{
            margin-top: 36px;
            text-align: center;
            font-size: 15px;
            color: #5a6a7f;
            border-top: 1px solid #1f2838;
            padding-top: 24px;
        }}

        /* ── Responsive ────────────────────────────────────────────────────── */
        @media (max-width: 768px) {{
            body {{ padding: 16px; }}
            .container {{ padding: 24px; }}
            .header {{ flex-direction: column; align-items: flex-start; gap: 16px; }}
            .score-card {{ flex-direction: column; align-items: flex-start; gap: 20px; }}
            .finding-header {{ flex-direction: column; align-items: flex-start; gap: 10px; }}
            .heatmap-grid {{ grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); }}
            .signature-section {{ flex-direction: column; }}
            .toolbar {{ justify-content: center; }}
            .header-left {{ flex-wrap: wrap; }}
        }}
        @media print {{
            body {{ background: #fff; color: #000; padding: 10px; }}
            .container {{ box-shadow: none; border: 1px solid #ccc; background: #fff; }}
            .finding-card {{ break-inside: avoid; border-color: #ccc; }}
            .finding-body {{ display: block !important; }}
            .arrow {{ display: none; }}
            .toolbar {{ display: none; }}
            .badge {{ color: #000; border-color: #000; }}
            .badge.fail {{ background: #fee; }}
            .badge.pass {{ background: #efe; }}
            .badge.warning {{ background: #ffe; }}
        }}
    </style>
</head>
<body>
<div class="container">

    <!-- ═══ TOOLBAR ═══ -->
    <div class="toolbar">
        <button onclick="window.print()"><i class="fas fa-print"></i> Print Report</button>
        <button onclick="window.location.href='data:application/json;charset=utf-8,'+encodeURIComponent(JSON.stringify({result}, null, 2))"><i class="fas fa-download"></i> Export JSON</button>
        <button onclick="copyReportLink()"><i class="fas fa-link"></i> Copy Link</button>
    </div>

    <!-- ═══ HEADER ═══ -->
    <div class="header">
        <div class="header-left">
            <div>
                <div class="logo">BRAVO6</div>
                <div class="logo-sub">SECURITY SCANNER</div>
            </div>
            <div class="header-title">
                <h1>Security Assessment Report</h1>
                <div class="sub">Comprehensive vulnerability scan for <strong style="color:#d4a743;">{url}</strong></div>
                <div class="meta-info">
                    <span><i class="far fa-calendar-alt"></i> Scan Date: <strong>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</strong></span>
                    <span><i class="far fa-clock"></i> Duration: <strong>{meta.get('duration_seconds', 0)}s</strong></span>
                    <span><i class="fas fa-tasks"></i> Findings: <strong>{len(sorted_findings)}</strong></span>
                    <span><i class="fas fa-exclamation-triangle"></i> Errors: <strong>{meta.get('tests_errored', 0)}</strong></span>
                </div>
            </div>
        </div>
        <div class="badge {status}">{status.upper()}</div>
    </div>

    <!-- ═══ SCORE CARD ═══ -->
    <div class="score-card">
        <div class="score-gauge">
            <div class="score-circle">{score}</div>
            <div class="score-details">
                <div class="grade">Grade {grade}</div>
                <div class="label">Overall Security Posture</div>
                <div class="summary-bars">
                    <span class="summary-item"><span class="dot dot-critical"></span> Critical: {summary.get('critical', 0)}</span>
                    <span class="summary-item"><span class="dot dot-high"></span> High: {summary.get('high', 0)}</span>
                    <span class="summary-item"><span class="dot dot-medium"></span> Medium: {summary.get('medium', 0)}</span>
                    <span class="summary-item"><span class="dot dot-low"></span> Low: {summary.get('low', 0)}</span>
                    <span class="summary-item"><span class="dot dot-passed"></span> Passed: {summary.get('passed', 0)}</span>
                    <span class="summary-item"><span class="dot dot-errors"></span> Errors: {summary.get('errors', 0)}</span>
                </div>
            </div>
        </div>
    </div>

    <!-- ═══ DASHBOARD / CHARTS ═══ -->
    <div class="dashboard">
        <div class="chart-card">
            <h3><i class="fas fa-chart-pie" style="color:#d4a743;"></i> Severity Distribution</h3>
            <div class="chart-container">
                <canvas id="severityChart"></canvas>
            </div>
        </div>
        <div class="chart-card">
            <h3><i class="fas fa-chart-bar" style="color:#d4a743;"></i> Vulnerability Summary</h3>
            <div class="chart-container">
                <canvas id="summaryChart"></canvas>
            </div>
        </div>
    </div>

    <!-- ═══ WAF CONTEXT ═══ -->
    {_render_waf_context(waf_context)}

    <!-- ═══ HEATMAP ═══ -->
    {_render_heatmap(heatmap_cells)}

    <!-- ═══ PRIORITY RECOMMENDATIONS ═══ -->
    {_render_priorities(sorted_findings)}

    <!-- ═══ DETAILED FINDINGS ═══ -->
    <h2><i class="fas fa-list-check" style="color:#d4a743;"></i> Detailed Findings</h2>
    {_render_findings(sorted_findings, url)}

    <!-- ═══ DIGITAL SIGNATURE ═══ -->
    <div class="signature-section">
        <div>
            <strong><i class="fas fa-shield-alt"></i> Digital Signature</strong>
            <div class="hash">SHA-256: {signature}</div>
            <div style="margin-top:6px;font-size:14px;color:#5a6a7f;">This hash verifies the integrity of this report.</div>
        </div>
        <div>
            <strong><i class="fas fa-code-branch"></i> Reproducibility</strong>
            <div style="font-size:15px;color:#b0b8c6;margin-top:4px;">
                <code style="background:#0b0d11;padding:6px 14px;border-radius:6px;display:inline-block;">python -m scanner.main_scanner {url} --html</code>
            </div>
            <div style="font-size:14px;color:#5a6a7f;margin-top:4px;">Re-run to verify results.</div>
        </div>
        <div>
            <strong><i class="far fa-calendar-check"></i> Report Timestamp</strong>
            <div style="font-size:16px;color:#e8edf3;margin-top:4px;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </div>
    </div>

    <div class="footer">
        <i class="fas fa-crown" style="color:#d4a743;"></i> Bravo6 Security Scanner &bull; Confidential &bull; For authorized use only
    </div>
</div>

<script>
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

    document.addEventListener('DOMContentLoaded', function() {{
        document.querySelectorAll('.finding-card.fail .finding-header, .finding-card.warning .finding-header').forEach(function(header) {{
            const body = header.nextElementSibling;
            const arrow = header.querySelector('.arrow');
            if (body) {{
                body.classList.add('open');
                arrow.classList.add('open');
            }}
        }});
    }});

    document.addEventListener('DOMContentLoaded', function() {{
        const ctx1 = document.getElementById('severityChart').getContext('2d');
        new Chart(ctx1, {{
            type: 'pie',
            data: {{
                labels: ['Critical ({severity_counts['critical']})', 'High ({severity_counts['high']})', 'Medium ({severity_counts['medium']})', 'Low ({severity_counts['low']})', 'Passed ({severity_counts['passed']})', 'Errors ({severity_counts['errors']})'],
                datasets: [{{
                    data: [{severity_counts['critical']}, {severity_counts['high']}, {severity_counts['medium']}, {severity_counts['low']}, {severity_counts['passed']}, {severity_counts['errors']}],
                    backgroundColor: ['#c0392b', '#e67e22', '#f39c12', '#3498db', '#2ecc71', '#7f8c8d'],
                    borderColor: '#1a202a',
                    borderWidth: 2,
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{
                        position: 'right',
                        labels: {{ color: '#b0b8c6', font: {{ size: 13 }} }}
                    }}
                }}
            }}
        }});

        const ctx2 = document.getElementById('summaryChart').getContext('2d');
        new Chart(ctx2, {{
            type: 'bar',
            data: {{
                labels: ['Critical', 'High', 'Medium', 'Low', 'Passed', 'Errors'],
                datasets: [{{
                    label: 'Findings',
                    data: [{severity_counts['critical']}, {severity_counts['high']}, {severity_counts['medium']}, {severity_counts['low']}, {severity_counts['passed']}, {severity_counts['errors']}],
                    backgroundColor: ['#c0392b', '#e67e22', '#f39c12', '#3498db', '#2ecc71', '#7f8c8d'],
                    borderColor: '#1a202a',
                    borderWidth: 2,
                    borderRadius: 8,
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        ticks: {{ color: '#b0b8c6' }},
                        grid: {{ color: '#1f2838' }}
                    }},
                    x: {{
                        ticks: {{ color: '#b0b8c6' }},
                        grid: {{ display: false }}
                    }}
                }}
            }}
        }});
    }});

    function copyReportLink() {{
        const url = window.location.href;
        navigator.clipboard.writeText(url).then(() => {{
            alert('Report link copied to clipboard!');
        }}).catch(() => {{
            prompt('Copy the link manually:', url);
        }});
    }}
</script>
</body>
</html>
'''
    return html


# ── Helper renderers ────────────────────────────────────────────────────────

def _render_waf_context(waf_context: dict) -> str:
    if not waf_context or not waf_context.get('detected'):
        return ''
    return f'''
    <div class="waf-note">
        <strong><i class="fas fa-shield-halved"></i> WAF/CDN Detected:</strong> {waf_context['detected']}
        <span style="display:block;margin-top:4px;font-size:15px;color:#7a8395;">{waf_context.get('note', '')}</span>
    </div>
    '''


def _render_heatmap(cells: List[Dict]) -> str:
    if not cells:
        return '''
        <div class="heatmap">
            <h3><i class="fas fa-fire" style="color:#d4a743;"></i> Risk Heatmap</h3>
            <p style="color:#7a8395;">No vulnerable findings to display.</p>
        </div>
        '''
    color_map = {
        "Critical": "#c0392b",
        "High": "#e67e22",
        "Medium": "#f39c12",
        "Low": "#3498db",
        "Info": "#7f8c8d"
    }
    rows = []
    for cell in cells:
        risk = cell.get("risk", "Info")
        bg = color_map.get(risk, "#7f8c8d")
        rows.append(f'''
            <div class="heatmap-cell" style="background:{bg};border-color:{bg};">
                <span>{cell.get("name", "Unnamed")}</span>
            </div>
        ''')
    return f'''
    <div class="heatmap">
        <h3><i class="fas fa-fire" style="color:#d4a743;"></i> Risk Heatmap</h3>
        <p style="color:#7a8395;margin-bottom:12px;">Each cell represents a vulnerable finding. Higher risk = darker color.</p>
        <div class="heatmap-grid">
            {''.join(rows)}
        </div>
    </div>
    '''


def _render_priorities(findings: List[Dict]) -> str:
    vulnerable = [f for f in findings if f.get("status") in ("fail", "warning") and f.get("_priority") not in ("Info", "Low")]
    if not vulnerable:
        return '''
        <div class="priority-section">
            <h3><i class="fas fa-bullseye" style="color:#d4a743;"></i> Prioritized Recommendations</h3>
            <p style="color:#7a8395;">No high-priority vulnerabilities found.</p>
        </div>
        '''
    critical = [f for f in vulnerable if f.get("_priority") == "Critical"]
    high = [f for f in vulnerable if f.get("_priority") == "High"]
    medium = [f for f in vulnerable if f.get("_priority") == "Medium"]

    rows = []
    for p in ["Critical", "High", "Medium"]:
        items = {"Critical": critical, "High": high, "Medium": medium}.get(p, [])
        for f in items:
            name = f.get("test_name", "").replace("test_", "").replace("_", " ").title()
            sev = f.get("severity", "info").capitalize()
            rows.append(f'''
                <li>
                    <span class="priority-badge {p.lower()}">{p}</span>
                    <span style="color:#b0b8c6;"><strong style="color:#d4a743;">{name}</strong> — {f.get("_explanation", "Review this issue.")}</span>
                    <span style="margin-left:auto;font-size:15px;color:#7a8395;white-space:nowrap;flex-shrink:0;">Severity: {sev}</span>
                </li>
            ''')
    return f'''
    <div class="priority-section">
        <h3><i class="fas fa-bullseye" style="color:#d4a743;"></i> Prioritized Recommendations</h3>
        <p style="color:#7a8395;font-size:17px;margin-bottom:12px;">Fix these in order: Critical → High → Medium</p>
        <ul class="priority-list">
            {''.join(rows)}
        </ul>
    </div>
    '''


def _render_findings(findings: List[Dict], url: str) -> str:
    if not findings:
        return '<p style="color:#7a8395;">No findings to display.</p>'

    html_parts = []
    for f in findings:
        test_name = f.get("test_name", "Unnamed Test")
        status = f.get("status", "unknown")
        severity = f.get("severity", "info")
        title = f.get("title", test_name)
        description = f.get("description", "")
        evidence = f.get("evidence")
        remediation = f.get("remediation", "No specific remediation provided.")
        explanation = f.get("_explanation", "")
        timestamp = f.get("_timestamp", datetime.now().isoformat())

        card_class = "pass"
        if status == "fail":
            card_class = "fail"
        elif status == "warning":
            card_class = "warning"
        elif status == "error":
            card_class = "error"
        elif status == "info":
            card_class = "info"

        poc = f.get("poc", "")
        if "clickjacking" in title.lower() or "frame-ancestors" in description.lower():
            if "target" in poc:
                poc = poc.replace("target", url)
            elif "https://target" in poc:
                poc = poc.replace("https://target", url)
            if not poc or poc == "No PoC available.":
                poc = f'<iframe src="{url}"></iframe>'

        evidence_html = ""
        if evidence is not None:
            if isinstance(evidence, str):
                evidence_html = f'<div class="section-content">{evidence}</div>'
            elif isinstance(evidence, list) and all(isinstance(e, dict) for e in evidence):
                items = []
                for e in evidence[:5]:
                    parts = []
                    for k, v in e.items():
                        if isinstance(v, str) and len(v) > 150:
                            parts.append(f"<strong>{k}:</strong> {v[:150]}...")
                        else:
                            parts.append(f"<strong>{k}:</strong> {v}")
                    items.append("<div style='margin-bottom:10px;'>" + " | ".join(parts) + "</div>")
                evidence_html = "".join(items)
            elif isinstance(evidence, list):
                items = [f"<div>• {item}</div>" for item in evidence[:5]]
                evidence_html = "".join(items)
            else:
                evidence_html = f'<div class="section-content">{str(evidence)}</div>'

        sev_class = severity.lower()
        status_class = status.lower()
        if status_class == "info":
            status_class = "info"

        html_parts.append(f'''
        <div class="finding-card {card_class}">
            <div class="finding-header" onclick="toggleBody(this)">
                <div style="display:flex;align-items:center;gap:14px;flex-wrap:wrap;">
                    <span class="title">{test_name}</span>
                    <span class="severity-tag {sev_class}">{severity.upper()}</span>
                    <span style="font-size:15px;color:#7a8395;">{explanation[:60]}{'...' if len(explanation)>60 else ''}</span>
                </div>
                <div style="display:flex;align-items:center;gap:14px;">
                    <span class="status-badge {status_class}">{status.upper()}</span>
                    <span class="arrow">▶</span>
                </div>
            </div>
            <div class="finding-body">
                <div class="section">
                    <div class="section-title"><i class="fas fa-flag"></i> Summary</div>
                    <div class="section-content">{title}</div>
                </div>
                <div class="section">
                    <div class="section-title"><i class="fas fa-align-left"></i> Description</div>
                    <div class="section-content">{description}</div>
                </div>
                {f'<div class="section"><div class="section-title"><i class="fas fa-search"></i> Evidence</div>{evidence_html}</div>' if evidence_html else ''}
                {f'<div class="section"><div class="section-title"><i class="fas fa-terminal"></i> PoC Command</div><div class="poc">{poc}</div></div>' if poc and poc != "No PoC available." else ''}
                {f'<div class="section"><div class="section-title"><i class="fas fa-wrench"></i> Remediation</div><div class="section-content" style="border-left-color:#2ecc71;">{remediation}</div></div>' if status in ("fail", "warning") else ''}
                <div class="timestamp"><i class="far fa-clock"></i> Detected: {timestamp}</div>
            </div>
        </div>
        ''')

    return ''.join(html_parts)


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