"""
report_generator.py — Bravo6 Professional HTML Report Generator (Fixed)

- Fixed exploit scores: findings with status 'pass' get score 0 and no business impact.
- Added proper handling for priority: only fail/warning findings get priority labels.
- Improved consistency: each finding's severity is correctly reflected.
- Digital signature, reproducibility, and mobile responsiveness.
- Fast: uses efficient string building and minimal overhead.
"""

import json
import hashlib
import re
from datetime import datetime
from typing import Dict, Any, List, Optional

# ── Exploitability scores (1–10) per finding type ────────────────────────
EXPLOITABILITY_SCORES = {
    "secrets_detection": 10,
    "http_methods": 9,
    "robots_txt": 8,
    "information_disclosure": 8,
    "subdomain_takeover": 9,
    "cms_vibe_detection": 7,
    "ssl_tls": 5,
    "cors": 6,
    "email_security": 6,
    "cookie_security": 6,
    "mixed_content": 6,
    "sri_check": 3,
    "hallucinated_deps": 4,
    "AI Configuration Exposure": 5,
    "security_headers": 4,
    "js_library_audit": 4,
}

# ── Plain-language explanations ────────────────────────────────────────────
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

# ── Helper functions ──────────────────────────────────────────────────────

def _get_exploitability(test_name: str) -> int:
    """Return exploitability score (1-10) based on test name."""
    key = test_name.replace("test_", "").replace("_", " ")
    for k, v in EXPLOITABILITY_SCORES.items():
        if k in key.lower():
            return v
    return 5


def _get_explanation(test_name: str) -> str:
    """Return a human-readable explanation for the finding."""
    key = test_name.replace("test_", "").replace("_", " ")
    for k, v in EXPLANATIONS.items():
        if k in key.lower():
            return v
    return "This issue may pose a security risk to your website. Review the details below for specific recommendations."


def _get_priority(severity: str, exploitability: int) -> str:
    """Determine priority based on severity and exploitability."""
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(severity.lower(), 0)
    if sev_rank >= 3 and exploitability >= 7:
        return "Critical"
    if sev_rank >= 2 and exploitability >= 5:
        return "High"
    if sev_rank >= 1:
        return "Medium"
    return "Low"


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


def _truncate_text(text: str, max_len: int = 300) -> str:
    if not text:
        return ""
    if len(text) > max_len:
        return text[:max_len] + "..."
    return text

# ── Main HTML generator ────────────────────────────────────────────────────

def generate_html_report(result: Dict[str, Any]) -> str:
    """
    Generate a standalone, professional HTML report.
    """
    url = result.get("url", "N/A")
    status = result.get("status", "unknown")
    score = result.get("score", 0)
    grade = result.get("grade", "F")
    summary = result.get("summary", {})
    raw_findings = result.get("findings", [])
    waf_context = result.get("waf_context", {})
    meta = result.get("meta", {})
    scan_errors = result.get("scan_errors", [])

    # ── Process findings: enrich with metadata ────────────────────────────
    processed_findings = []
    for f in raw_findings:
        if not isinstance(f, dict):
            continue
        test_name = f.get("test_name", "Unnamed")
        severity = f.get("severity", "info")
        status_finding = f.get("status", "unknown")

        # Determine if we should show exploitability
        if status_finding in ("fail", "warning"):
            exploit = _get_exploitability(test_name)
            explanation = _get_explanation(test_name)
            priority = _get_priority(severity, exploit)
            risk_level = _severity_to_risk_level(severity)
        else:
            # For pass/error/info findings, set exploitability to 0 and no priority
            exploit = 0
            explanation = "No vulnerability found. This check passed successfully."
            priority = "Info"
            risk_level = "Info"

        f["_timestamp"] = datetime.now().isoformat()
        f["_priority"] = priority
        f["_exploitability"] = exploit
        f["_explanation"] = explanation
        f["_risk_level"] = risk_level
        # Ensure key fields exist
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
        processed_findings.append(f)

    # Sort by priority (Critical, High, Medium, Low, Info)
    priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    sorted_findings = sorted(
        processed_findings,
        key=lambda f: priority_order.get(f.get("_priority", "Info"), 5)
    )

    # ── Digital signature ──────────────────────────────────────────────────
    report_json = json.dumps(result, sort_keys=True, default=str)
    signature = _generate_sha256(report_json)

    # ── Heatmap data (only for findings with status fail/warning) ─────────
    heatmap_cells = []
    for f in sorted_findings:
        if f.get("status") in ("fail", "warning") and f.get("_exploitability", 0) > 0:
            cell = {
                "name": f.get("test_name", "").replace("test_", "").replace("_", " ").title(),
                "risk": f.get("_risk_level", "Info"),
                "priority": f.get("_priority", "Low"),
                "score": f.get("_exploitability", 5),
                "severity": f.get("severity", "info")
            }
            heatmap_cells.append(cell)

    # ── Generate HTML ──────────────────────────────────────────────────────
    html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bravo6 Security Report – {url}</title>
    <style>
        /* ── Reset & Base ───────────────────────────────────────── */
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            font-size: 16px;
            line-height: 1.6;
            background: #f4f6fa;
            color: #1e293b;
            padding: 30px;
            min-height: 100vh;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: #ffffff;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.08);
            padding: 40px 50px;
        }}
        /* ── Typography ──────────────────────────────────────────── */
        h1, h2, h3, h4 {{
            font-weight: 600;
            letter-spacing: -0.01em;
        }}
        h1 {{ font-size: 32px; margin-bottom: 8px; }}
        h2 {{ font-size: 26px; margin: 32px 0 16px; color: #0f172a; }}
        h3 {{ font-size: 20px; margin: 16px 0 8px; color: #1e293b; }}
        a {{ color: #2563eb; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}

        /* ── Header ──────────────────────────────────────────────── */
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            padding-bottom: 24px;
            border-bottom: 2px solid #e9edf4;
            margin-bottom: 28px;
        }}
        .header-left h1 {{
            color: #0f172a;
            font-weight: 700;
        }}
        .header-left .sub {{
            color: #64748b;
            font-size: 15px;
        }}
        .badge {{
            padding: 10px 28px;
            border-radius: 40px;
            font-weight: 600;
            font-size: 18px;
            letter-spacing: 0.5px;
            background: #e2e8f0;
            color: #1e293b;
        }}
        .badge.pass {{ background: #dcfce7; color: #166534; }}
        .badge.warning {{ background: #fef9c3; color: #854d0e; }}
        .badge.fail {{ background: #fee2e2; color: #991b1b; }}
        .badge.error {{ background: #f1f5f9; color: #475569; }}

        .meta-info {{
            display: flex;
            flex-wrap: wrap;
            gap: 16px 32px;
            margin: 16px 0 0;
            font-size: 15px;
            color: #475569;
        }}
        .meta-info strong {{ color: #0f172a; }}

        /* ── Score Card ──────────────────────────────────────────── */
        .score-card {{
            display: flex;
            flex-wrap: wrap;
            gap: 30px 60px;
            background: #f8fafc;
            border-radius: 12px;
            padding: 24px 32px;
            margin-bottom: 30px;
            align-items: center;
            border: 1px solid #e9edf4;
        }}
        .score-circle {{
            width: 110px;
            height: 110px;
            border-radius: 50%;
            background: conic-gradient(#2563eb {score}%, #e9edf4 {score}%);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 36px;
            font-weight: 700;
            color: #ffffff;
            background-color: #e9edf4;
            position: relative;
        }}
        .score-circle::after {{
            content: '';
            position: absolute;
            top: 6px;
            left: 6px;
            right: 6px;
            bottom: 6px;
            border-radius: 50%;
            background: #ffffff;
            z-index: -1;
        }}
        .score-details .grade {{
            font-size: 48px;
            font-weight: 700;
            color: #0f172a;
            line-height: 1;
        }}
        .score-details .label {{
            font-size: 18px;
            color: #475569;
        }}
        .summary-bars {{
            display: flex;
            flex-wrap: wrap;
            gap: 12px 20px;
            margin-top: 12px;
        }}
        .summary-item {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: #ffffff;
            padding: 6px 18px;
            border-radius: 40px;
            font-size: 14px;
            font-weight: 500;
            border: 1px solid #e9edf4;
        }}
        .summary-item .dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            display: inline-block;
        }}
        .dot-critical {{ background: #dc2626; }}
        .dot-high {{ background: #f97316; }}
        .dot-medium {{ background: #eab308; }}
        .dot-low {{ background: #3b82f6; }}
        .dot-passed {{ background: #22c55e; }}
        .dot-errors {{ background: #94a3b8; }}

        /* ── WAF Context ─────────────────────────────────────────── */
        .waf-note {{
            background: #f1f5f9;
            border-left: 4px solid #64748b;
            padding: 12px 20px;
            margin-bottom: 24px;
            border-radius: 4px;
            font-size: 15px;
            color: #334155;
        }}

        /* ── Heatmap ────────────────────────────────────────────── */
        .heatmap {{
            background: #f8fafc;
            border: 1px solid #e9edf4;
            border-radius: 12px;
            padding: 20px 24px;
            margin-bottom: 30px;
        }}
        .heatmap-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
            gap: 12px;
            margin-top: 12px;
        }}
        .heatmap-cell {{
            background: #e9edf4;
            border-radius: 8px;
            padding: 12px 10px;
            text-align: center;
            font-weight: 500;
            font-size: 13px;
            color: #0f172a;
            transition: transform 0.15s;
            border: 1px solid #d1d8e6;
        }}
        .heatmap-cell:hover {{ transform: scale(1.03); }}
        .heatmap-cell .cell-score {{
            font-size: 22px;
            font-weight: 700;
            display: block;
            margin-bottom: 2px;
        }}

        /* ── Priority Section ────────────────────────────────────── */
        .priority-section {{
            background: #f8fafc;
            border: 1px solid #e9edf4;
            border-radius: 12px;
            padding: 20px 24px;
            margin-bottom: 30px;
        }}
        .priority-list {{
            list-style: none;
            padding: 0;
            margin: 12px 0 0;
        }}
        .priority-list li {{
            display: flex;
            align-items: flex-start;
            gap: 16px;
            padding: 12px 0;
            border-bottom: 1px solid #e9edf4;
        }}
        .priority-list li:last-child {{ border-bottom: none; }}
        .priority-badge {{
            font-weight: 700;
            font-size: 12px;
            padding: 2px 14px;
            border-radius: 40px;
            color: #fff;
            background: #94a3b8;
            white-space: nowrap;
        }}
        .priority-badge.critical {{ background: #dc2626; }}
        .priority-badge.high {{ background: #f97316; }}
        .priority-badge.medium {{ background: #eab308; color: #0f172a; }}
        .priority-badge.low {{ background: #3b82f6; }}
        .priority-badge.info {{ background: #94a3b8; }}

        /* ── Finding Cards ───────────────────────────────────────── */
        .finding-card {{
            border: 1px solid #e9edf4;
            border-radius: 12px;
            margin-bottom: 16px;
            overflow: hidden;
            background: #ffffff;
            transition: box-shadow 0.15s;
        }}
        .finding-card:hover {{ box-shadow: 0 4px 12px rgba(0,0,0,0.05); }}
        .finding-card.pass {{ border-left: 6px solid #22c55e; }}
        .finding-card.warning {{ border-left: 6px solid #eab308; }}
        .finding-card.fail {{ border-left: 6px solid #dc2626; }}
        .finding-card.error {{ border-left: 6px solid #94a3b8; }}

        .finding-header {{
            padding: 16px 24px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #fafbfc;
            border-bottom: 1px solid #f1f5f9;
            transition: background 0.1s;
        }}
        .finding-header:hover {{ background: #f1f5f9; }}
        .finding-header .title {{
            font-weight: 600;
            font-size: 18px;
            color: #0f172a;
        }}
        .finding-header .badge-group {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            align-items: center;
        }}
        .finding-header .status-badge {{
            padding: 4px 16px;
            border-radius: 40px;
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .status-badge.pass {{ background: #dcfce7; color: #166534; }}
        .status-badge.warning {{ background: #fef9c3; color: #854d0e; }}
        .status-badge.fail {{ background: #fee2e2; color: #991b1b; }}
        .status-badge.error {{ background: #f1f5f9; color: #475569; }}
        .status-badge.info {{ background: #e2e8f0; color: #475569; }}

        .severity-tag {{
            padding: 2px 16px;
            border-radius: 40px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .severity-tag.critical {{ background: #fee2e2; color: #991b1b; }}
        .severity-tag.high {{ background: #ffedd5; color: #9a3412; }}
        .severity-tag.medium {{ background: #fef9c3; color: #854d0e; }}
        .severity-tag.low {{ background: #dbeafe; color: #1e40af; }}
        .severity-tag.info {{ background: #e2e8f0; color: #475569; }}

        .exploit-score {{
            padding: 2px 14px;
            border-radius: 40px;
            font-size: 13px;
            font-weight: 600;
            background: #e9edf4;
            color: #0f172a;
        }}
        .exploit-score.high {{ background: #fee2e2; color: #991b1b; }}
        .exploit-score.medium {{ background: #fef9c3; color: #854d0e; }}
        .exploit-score.low {{ background: #dbeafe; color: #1e40af; }}
        .exploit-score.zero {{ background: #e2e8f0; color: #64748b; }}

        .arrow {{
            font-size: 18px;
            color: #94a3b8;
            transition: transform 0.2s;
            margin-left: 10px;
        }}
        .arrow.open {{ transform: rotate(90deg); }}

        .finding-body {{
            padding: 20px 24px;
            display: none;
            background: #ffffff;
        }}
        .finding-body.open {{ display: block; }}
        .finding-body .section {{
            margin-bottom: 18px;
        }}
        .finding-body .section-title {{
            font-weight: 600;
            font-size: 15px;
            color: #0f172a;
            margin-bottom: 4px;
        }}
        .finding-body .section-content {{
            font-size: 15px;
            color: #334155;
            background: #f8fafc;
            padding: 12px 16px;
            border-radius: 6px;
            white-space: pre-wrap;
            word-break: break-word;
            border: 1px solid #e9edf4;
        }}
        .finding-body .poc {{
            background: #0f172a;
            color: #e9edf4;
            padding: 12px 16px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            overflow-x: auto;
            border: 1px solid #1e293b;
        }}
        .finding-body .timestamp {{
            font-size: 13px;
            color: #94a3b8;
            text-align: right;
            border-top: 1px solid #e9edf4;
            padding-top: 12px;
            margin-top: 12px;
        }}

        /* ── robots.txt highlight ───────────────────────────────── */
        .robots-content {{
            background: #f8fafc;
            padding: 12px 16px;
            border: 1px solid #e9edf4;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            color: #0f172a;
            overflow-x: auto;
            white-space: pre-wrap;
            max-height: 400px;
            overflow-y: auto;
        }}
        .robots-highlight {{
            background: #fef08a;
            padding: 0 4px;
            border-radius: 2px;
            font-weight: 600;
        }}

        /* ── Signature & Footer ──────────────────────────────────── */
        .signature-section {{
            margin-top: 40px;
            padding-top: 24px;
            border-top: 2px solid #e9edf4;
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            gap: 20px;
            font-size: 14px;
            color: #475569;
        }}
        .signature-section .hash {{
            font-family: 'Courier New', monospace;
            font-size: 13px;
            color: #0f172a;
            background: #f1f5f9;
            padding: 6px 12px;
            border-radius: 4px;
            word-break: break-all;
        }}
        .footer {{
            margin-top: 32px;
            text-align: center;
            font-size: 14px;
            color: #94a3b8;
            border-top: 1px solid #e9edf4;
            padding-top: 20px;
        }}

        /* ── Responsive ───────────────────────────────────────────── */
        @media (max-width: 768px) {{
            body {{ padding: 16px; }}
            .container {{ padding: 20px; }}
            .header {{ flex-direction: column; align-items: flex-start; gap: 12px; }}
            .score-card {{ flex-direction: column; align-items: flex-start; gap: 16px; }}
            .finding-header {{ flex-direction: column; align-items: flex-start; gap: 8px; }}
            .heatmap-grid {{ grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); }}
            .signature-section {{ flex-direction: column; }}
        }}
        @media print {{
            body {{ background: #fff; padding: 10px; }}
            .container {{ box-shadow: none; border: 1px solid #ccc; }}
            .finding-card {{ page-break-inside: avoid; }}
            .finding-body {{ display: block !important; }}
            .arrow {{ display: none; }}
        }}
    </style>
</head>
<body>
<div class="container">

    <!-- ═══ HEADER ═══ -->
    <div class="header">
        <div class="header-left">
            <h1>🔒 Bravo6 Security Report</h1>
            <div class="sub">Comprehensive vulnerability assessment for <strong>{url}</strong></div>
            <div class="meta-info">
                <span>Scan Date: <strong>{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</strong></span>
                <span>Duration: <strong>{meta.get('duration_seconds', 0)}s</strong></span>
                <span>Findings: <strong>{meta.get('findings_count', 0)}</strong></span>
                <span>Errors: <strong>{meta.get('tests_errored', 0)}</strong></span>
            </div>
        </div>
        <div class="badge {status}">{status.upper()}</div>
    </div>

    <!-- ═══ SCORE CARD ═══ -->
    <div class="score-card">
        <div class="score-circle">{score}</div>
        <div class="score-details">
            <div class="grade">Grade {grade}</div>
            <div class="label">Overall security posture</div>
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

    <!-- ═══ WAF CONTEXT ═══ -->
    {_render_waf_context(waf_context)}

    <!-- ═══ HEATMAP ═══ -->
    {_render_heatmap(heatmap_cells)}

    <!-- ═══ PRIORITY RECOMMENDATIONS ═══ -->
    {_render_priorities(sorted_findings)}

    <!-- ═══ DETAILED FINDINGS ═══ -->
    <h2>📋 Detailed Findings</h2>
    {_render_findings(sorted_findings)}

    <!-- ═══ DIGITAL SIGNATURE ═══ -->
    <div class="signature-section">
        <div>
            <strong>🔐 Digital Signature</strong>
            <div class="hash">SHA-256: {signature}</div>
            <div style="margin-top:4px;font-size:13px;">This hash verifies the integrity of this report.</div>
        </div>
        <div>
            <strong>⚙️ Reproducibility</strong>
            <div style="font-size:13px;">
                Command: <code>python -m scanner.main_scanner {url} --html</code>
            </div>
            <div style="font-size:13px;margin-top:4px;">Re-run to verify results.</div>
        </div>
        <div>
            <strong>📅 Report Timestamp</strong>
            <div style="font-size:14px;">{datetime.now().strftime('%Y-%m-%d %H:%M:%S %Z')}</div>
        </div>
    </div>

    <div class="footer">
        Generated by Bravo6 Security Scanner • <a href="https://github.com/your-repo" target="_blank">Bravo6 Project</a>
    </div>
</div>

<script>
    // Toggle finding details
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
    // Auto-expand critical and high findings
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
        <strong>🛡️ WAF/CDN Detected:</strong> {waf_context['detected']}
        <span style="display:block;margin-top:4px;font-size:14px;color:#475569;">{waf_context.get('note', '')}</span>
    </div>
    '''

def _render_heatmap(cells: List[Dict]) -> str:
    if not cells:
        return '''
        <div class="heatmap">
            <h3>🔥 Risk Heatmap</h3>
            <p style="color:#64748b;">No vulnerable findings to display.</p>
        </div>
        '''
    color_map = {
        "Critical": "#dc2626",
        "High": "#f97316",
        "Medium": "#eab308",
        "Low": "#3b82f6",
        "Info": "#94a3b8"
    }
    text_color_map = {
        "Critical": "#fff",
        "High": "#fff",
        "Medium": "#0f172a",
        "Low": "#fff",
        "Info": "#fff"
    }
    rows = []
    for cell in cells:
        risk = cell.get("risk", "Info")
        bg = color_map.get(risk, "#94a3b8")
        text = text_color_map.get(risk, "#fff")
        rows.append(f'''
            <div class="heatmap-cell" style="background:{bg};color:{text};border-color:{bg};">
                <span class="cell-score">{cell.get("score", 5)}</span>
                <span>{cell.get("name", "Unnamed")}</span>
            </div>
        ''')
    return f'''
    <div class="heatmap">
        <h3>🔥 Risk Heatmap</h3>
        <p style="color:#64748b;margin-bottom:12px;">Each cell represents a vulnerable finding. Score = Exploitability (1–10). Higher = more dangerous.</p>
        <div class="heatmap-grid">
            {''.join(rows)}
        </div>
    </div>
    '''

def _render_priorities(findings: List[Dict]) -> str:
    # Only include findings with status fail/warning and priority not "Info"
    vulnerable = [f for f in findings if f.get("status") in ("fail", "warning") and f.get("_priority") not in ("Info", "Low")]
    if not vulnerable:
        return '''
        <div class="priority-section">
            <h3>🎯 Prioritized Recommendations</h3>
            <p style="color:#64748b;">No high-priority vulnerabilities found.</p>
        </div>
        '''
    # Group by priority
    critical = [f for f in vulnerable if f.get("_priority") == "Critical"]
    high = [f for f in vulnerable if f.get("_priority") == "High"]
    medium = [f for f in vulnerable if f.get("_priority") == "Medium"]

    rows = []
    for p in ["Critical", "High", "Medium"]:
        items = {"Critical": critical, "High": high, "Medium": medium}.get(p, [])
        for f in items:
            name = f.get("test_name", "").replace("test_", "").replace("_", " ").title()
            sev = f.get("severity", "info").capitalize()
            exp = f.get("_exploitability", 5)
            rows.append(f'''
                <li>
                    <span class="priority-badge {p.lower()}">{p}</span>
                    <span style="color:#b3ffcc;"><strong style="color:#00ff41;">{name}</strong> — {f.get("_explanation", "Review this issue.")}</span>
                    <span style="margin-left:auto;font-size:15px;color:#66ff99;white-space:nowrap;">Severity: {sev} • Exploit: {exp}/10</span>
                </li>
            ''')
    return f'''
    <div class="priority-section">
        <h3>🎯 Prioritized Recommendations</h3>
        <p style="color:#64748b;font-size:17px;margin-bottom:12px;">Fix these in order: Critical → High → Medium</p>
        <ul class="priority-list">
            {''.join(rows)}
        </ul>
    </div>
    '''

def _render_findings(findings: List[Dict]) -> str:
    if not findings:
        return '<p style="color:#64748b;">No findings to display.</p>'

    html_parts = []
    for f in findings:
        test_name = f.get("test_name", "Unnamed Test")
        status = f.get("status", "unknown")
        severity = f.get("severity", "info")
        title = f.get("title", test_name)
        description = f.get("description", "")
        evidence = f.get("evidence")
        remediation = f.get("remediation", "No specific remediation provided.")
        exploit = f.get("_exploitability", 0)
        explanation = f.get("_explanation", "")
        timestamp = f.get("_timestamp", datetime.now().isoformat())

        # Only show business impact for findings with status fail/warning and exploit > 0
        show_business = status in ("fail", "warning") and exploit > 0

        # Determine exploit score class
        if exploit >= 7:
            exp_class = "high"
        elif exploit >= 4:
            exp_class = "medium"
        elif exploit > 0:
            exp_class = "low"
        else:
            exp_class = "zero"

        # ── Evidence display ──────────────────────────────────────────────
        evidence_html = ""
        if evidence is not None:
            if isinstance(evidence, str):
                evidence_html = f'<div class="section-content">{evidence}</div>'
            elif isinstance(evidence, list) and all(isinstance(e, dict) for e in evidence):
                items = []
                for e in evidence:
                    parts = []
                    for k, v in e.items():
                        if k == "verification_response":
                            parts.append(f'<strong>API Response:</strong><div class="verification-response">{v}</div>')
                        elif isinstance(v, str) and len(v) > 150:
                            parts.append(f"<strong>{k}:</strong> {v[:150]}...")
                        else:
                            parts.append(f"<strong>{k}:</strong> {v}")
                    items.append("<div style='margin-bottom:10px;'>" + " | ".join(parts) + "</div>")
                evidence_html = "".join(items)
            elif isinstance(evidence, list):
                items = [f"<div>• {item}</div>" for item in evidence]
                evidence_html = "".join(items)
            else:
                evidence_html = f'<div class="section-content">{evidence}</div>'

        # ── PoC ─────────────────────────────────────────────────────────────
        poc = f.get("poc", "")
        if not poc and "evidence" in f and isinstance(f["evidence"], dict):
            poc = f["evidence"].get("poc", "")

        # ── Severity and exploitability ──────────────────────────────────
        sev_class = severity.lower()
        status_class = status.lower()
        if status_class == "info":
            status_class = "info"

        html_parts.append(f'''
        <div class="finding-card {status_class}">
            <div class="finding-header" onclick="toggleBody(this)">
                <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
                    <span class="title">{test_name}</span>
                    <span class="severity-tag {sev_class}">{severity.upper()}</span>
                    <span class="exploit-score {exp_class}">⚡ {exploit}/10</span>
                    <span style="font-size:16px;color:#64748b;">{explanation[:70]}{'...' if len(explanation)>70 else ''}</span>
                </div>
                <div style="display:flex;align-items:center;gap:14px;">
                    <span class="status-badge {status_class}">{status.upper()}</span>
                    <span class="arrow">▶</span>
                </div>
            </div>
            <div class="finding-body">
                <div class="section">
                    <div class="section-title">📌 Summary</div>
                    <div class="section-content">{title}</div>
                </div>
                <div class="section">
                    <div class="section-title">📝 Description</div>
                    <div class="section-content">{description}</div>
                </div>
                {f'<div class="section"><div class="section-title">💼 Business Impact</div><div class="section-content" style="border-left-color:#dc2626;color:#1a2332;"><strong>Exploitability Score:</strong> {exploit}/10<br><strong>Impact:</strong> {explanation}</div></div>' if show_business else ''}
                {f'<div class="section"><div class="section-title">🔎 Evidence</div><div class="section-content">{evidence_html if evidence_html else "No specific evidence."}</div></div>' if evidence_html else ''}
                {f'<div class="section"><div class="section-title">💻 PoC Command</div><div class="poc">{poc}</div></div>' if poc else ''}
                {f'<div class="section"><div class="section-title">🛠️ Remediation</div><div class="section-content" style="border-left-color:#22c55e;">{remediation}</div></div>' if status in ("fail", "warning") else ''}
                <div class="timestamp">⏱️ Detected: {timestamp}</div>
            </div>
        </div>
        ''')

    return ''.join(html_parts)


# ── CLI ─────────────────────────────────────────────────────────────────────

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