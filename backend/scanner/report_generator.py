"""
report_generator.py — Bravo6 HTML Report Generator (Matrix Edition)

Generates a stunning HTML report with:
- Matrix-inspired dark theme (green on black)
- Digital signature (SHA-256) for tamper-proof verification
- Timestamp per finding (proves when the vulnerability was found)
- Full reproducibility data (parameters, command, checksums)
- robots.txt content with highlighted sensitive paths
- Exploitability scores and prioritized recommendations
"""

import json
import hashlib
import re
from datetime import datetime
from typing import Dict, Any, List, Optional


# ── Exploitability scores (1–10) per finding type ──────────────────────────
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

# ── Plain-language explanations ─────────────────────────────────────────────
EXPLANATIONS = {
    "secrets_detection": "Your website has exposed secret keys (like passwords) that anyone can see. An attacker could use them to steal data or hijack your services.",
    "http_methods": "Your server accepts dangerous commands (like DELETE) that can delete files or upload malicious content. An attacker can easily exploit this.",
    "robots_txt": "A public file intended for search engines reveals hidden admin areas, making it easier for hackers to find and attack them.",
    "information_disclosure": "Your site leaks internal details (e.g., file paths, server versions) that help attackers plan sophisticated attacks.",
    "subdomain_takeover": "Your DNS records point to services that you don't own anymore. An attacker can register those services and control your subdomains.",
    "cms_vibe_detection": "Your CMS or framework is outdated or misconfigured, which may allow hackers to take over your site.",
    "ssl_tls": "Your HTTPS encryption is weak or misconfigured, so attackers could intercept data your users send to you.",
    "cors": "Your server allows other websites to make requests on behalf of your users, potentially stealing their data.",
    "email_security": "Your email setup allows spammers to send fake emails that appear to come from your domain, damaging your reputation.",
    "cookie_security": "Your session cookies are not properly secured, so hackers could steal them and impersonate logged-in users.",
    "mixed_content": "Your secure HTTPS page loads insecure HTTP resources, which can be tampered with by attackers.",
    "sri_check": "Your site loads external JavaScript libraries without verifying their integrity. A hacked CDN could inject malicious code.",
    "hallucinated_deps": "Your site references domains that don't exist. An attacker could register them and control your site.",
    "AI Configuration Exposure": "Your AI-related configuration files are publicly accessible, which may reveal sensitive prompts or internal logic.",
    "security_headers": "Missing security headers weaken your browser's protection against common attacks like XSS or clickjacking.",
    "js_library_audit": "Your site uses outdated JavaScript libraries with known vulnerabilities, which attackers can use to compromise your users.",
}


# ── Helper functions ────────────────────────────────────────────────────────

def _get_exploitability(test_name: str) -> int:
    key = test_name.replace("test_", "")
    return EXPLOITABILITY_SCORES.get(key, 5)


def _get_explanation(test_name: str) -> str:
    key = test_name.replace("test_", "")
    return EXPLANATIONS.get(key, "This issue may pose a security risk to your website.")


def _get_priority(test_name: str, severity: str) -> str:
    score = _get_exploitability(test_name)
    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(severity, 0)
    if severity_rank >= 3 and score >= 7:
        return "Critical"
    if severity_rank >= 2 and score >= 5:
        return "High"
    if severity_rank >= 1:
        return "Medium"
    return "Low"


def _severity_to_risk_level(severity: str) -> str:
    return {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}.get(severity, "Info")


def _generate_sha256(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()


def _highlight_robots_content(content: str, sensitive_paths: list) -> str:
    """Highlight sensitive paths in robots.txt with a glowing green background."""
    if not content or not sensitive_paths:
        return content or ""
    highlighted = content
    for path in sensitive_paths:
        escaped = re.escape(path)
        highlighted = re.sub(
            rf'(?i)({escaped})',
            r'<span style="background:#00ff41;color:#000000;font-weight:bold;padding:0 4px;border-radius:2px;">\1</span>',
            highlighted
        )
    return highlighted


# ── Main HTML generator ─────────────────────────────────────────────────────

def generate_html_report(result: Dict[str, Any]) -> str:
    """
    Generate a standalone HTML report with Matrix theme.
    """
    url = result.get("url", "N/A")
    status = result.get("status", "unknown")
    score = result.get("score", 0)
    grade = result.get("grade", "F")
    summary = result.get("summary", {})
    findings = result.get("findings", [])
    waf_context = result.get("waf_context", {})
    meta = result.get("meta", {})
    scan_errors = result.get("scan_errors", [])

    status_color = {
        "pass": "#00ff41",
        "warning": "#ffd700",
        "fail": "#ff0040",
        "error": "#666666"
    }.get(status, "#00ff41")

    # ── Process findings ───────────────────────────────────────────────────
    for f in findings:
        test_name = f.get("test_name", "Unnamed")
        sev = f.get("severity", "info")
        f["_priority"] = _get_priority(test_name, sev)
        f["_exploitability"] = _get_exploitability(test_name)
        f["_explanation"] = _get_explanation(test_name)
        f["_risk_level"] = _severity_to_risk_level(sev)
        f["_timestamp"] = datetime.now().isoformat()

    priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    sorted_findings = sorted(findings, key=lambda f: priority_order.get(f["_priority"], 5))

    # ── Digital signature ──────────────────────────────────────────────────
    report_json = json.dumps(result, sort_keys=True, default=str)
    signature = _generate_sha256(report_json)

    # ── Heatmap data ───────────────────────────────────────────────────────
    heatmap_cells = []
    for f in sorted_findings:
        if f.get("status") in ("fail", "warning"):
            heatmap_cells.append({
                "name": f.get("test_name", "").replace("test_", "").replace("_", " ").title(),
                "risk": f.get("severity", "info").capitalize(),
                "priority": f["_priority"],
                "score": f["_exploitability"],
            })

    # ── Build HTML ─────────────────────────────────────────────────────────
    html = f'''<!DOCTYPE html>
<html lang="ar" dir="ltr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bravo6 Security Scan Report - {url}</title>
    <style>
        /* ── Base / Matrix Theme ──────────────────────── */
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Times New Roman', Times, serif;
            font-size: 18px;
            background: #0a0a0a;
            color: #00ff41;
            padding: 30px;
            line-height: 1.7;
            min-height: 100vh;
        }}
        .container {{
            max-width: 1440px;
            margin: 0 auto;
            background: rgba(10, 10, 10, 0.95);
            border: 2px solid #00ff41;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 0 60px rgba(0, 255, 65, 0.08);
        }}

        /* ── Scrollbar ────────────────────────────────── */
        ::-webkit-scrollbar {{ width: 8px; background: #0a0a0a; }}
        ::-webkit-scrollbar-track {{ background: #0a0a0a; }}
        ::-webkit-scrollbar-thumb {{ background: #00ff41; border-radius: 4px; }}

        /* ── Typography ───────────────────────────────── */
        h1, h2, h3, h4 {{
            font-family: 'Times New Roman', Times, serif;
            font-weight: 700;
            letter-spacing: 1px;
        }}
        h1 {{ font-size: 36px; }}
        h2 {{ font-size: 30px; margin: 28px 0 16px 0; }}
        h3 {{ font-size: 24px; margin: 16px 0 8px 0; }}
        p {{ font-size: 18px; margin-bottom: 12px; }}

        /* ── Links ────────────────────────────────────── */
        a {{ color: #00ff41; text-decoration: none; border-bottom: 1px dashed #00ff41; }}
        a:hover {{ color: #ffffff; border-bottom: 1px solid #00ff41; }}

        /* ── Header ───────────────────────────────────── */
        .header {{
            border-bottom: 2px solid #00ff41;
            padding-bottom: 24px;
            margin-bottom: 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }}
        .header h1 {{
            font-size: 40px;
            color: #00ff41;
            text-shadow: 0 0 20px rgba(0, 255, 65, 0.3);
            letter-spacing: 4px;
        }}
        .header .badge {{
            font-family: 'Times New Roman', Times, serif;
            background: {status_color};
            color: #0a0a0a;
            padding: 10px 32px;
            border-radius: 0px;
            font-weight: 700;
            font-size: 22px;
            text-transform: uppercase;
            letter-spacing: 2px;
            border: 1px solid {status_color};
            box-shadow: 0 0 30px rgba({status_color}, 0.15);
        }}
        .meta-info {{
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            margin-top: 8px;
            font-size: 17px;
            color: #66ff99;
        }}
        .meta-info span {{
            background: rgba(0, 255, 65, 0.06);
            padding: 4px 16px;
            border: 1px solid rgba(0, 255, 65, 0.15);
            border-radius: 0px;
        }}
        .meta-info strong {{ color: #00ff41; }}

        /* ── Score Card ───────────────────────────────── */
        .score-card {{
            background: rgba(0, 255, 65, 0.03);
            border: 1px solid rgba(0, 255, 65, 0.15);
            padding: 32px;
            margin-bottom: 32px;
            display: flex;
            flex-wrap: wrap;
            gap: 40px;
            align-items: center;
        }}
        .score-circle {{
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: conic-gradient({status_color} {score}%, #1a1a1a {score}%);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
            font-weight: 700;
            color: #0a0a0a;
            border: 2px solid {status_color};
            box-shadow: 0 0 40px rgba({status_color}, 0.10);
        }}
        .score-details {{ flex: 1; }}
        .score-details .grade {{
            font-size: 56px;
            font-weight: 700;
            color: {status_color};
            text-shadow: 0 0 30px rgba({status_color}, 0.15);
        }}
        .score-details .sub {{ font-size: 19px; color: #66ff99; }}
        .summary-bars {{
            display: flex;
            gap: 18px;
            flex-wrap: wrap;
            margin-top: 12px;
        }}
        .summary-item {{
            display: flex;
            align-items: center;
            gap: 10px;
            background: rgba(0, 255, 65, 0.04);
            padding: 8px 20px;
            border: 1px solid rgba(0, 255, 65, 0.08);
            font-size: 16px;
            color: #66ff99;
        }}
        .summary-item .dot {{
            width: 14px;
            height: 14px;
            border-radius: 0px;
            display: inline-block;
        }}

        /* ── Heatmap ──────────────────────────────────── */
        .heatmap {{
            background: rgba(0, 255, 65, 0.03);
            border: 1px solid rgba(0, 255, 65, 0.10);
            padding: 24px 28px;
            margin-bottom: 32px;
        }}
        .heatmap-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 12px;
            margin-top: 16px;
        }}
        .heatmap-cell {{
            padding: 16px 18px;
            border: 1px solid rgba(0, 255, 65, 0.15);
            font-size: 15px;
            font-weight: 600;
            text-align: center;
            color: #0a0a0a;
            transition: all 0.2s;
            background: #1a1a1a;
        }}
        .heatmap-cell:hover {{ transform: scale(1.03); box-shadow: 0 0 30px rgba(0, 255, 65, 0.05); }}
        .heatmap-cell .cell-score {{
            font-size: 22px;
            font-weight: 700;
            display: block;
            margin-bottom: 2px;
        }}
        .heatmap-cell .cell-label {{ font-size: 13px; opacity: 0.8; }}

        /* ── Priority Section ─────────────────────────── */
        .priority-section {{
            background: rgba(0, 255, 65, 0.03);
            border: 1px solid rgba(0, 255, 65, 0.10);
            padding: 24px 28px;
            margin-bottom: 32px;
        }}
        .priority-list {{ list-style: none; padding: 0; margin-top: 12px; }}
        .priority-list li {{
            display: flex;
            align-items: flex-start;
            gap: 18px;
            padding: 14px 18px;
            border-bottom: 1px solid rgba(0, 255, 65, 0.06);
        }}
        .priority-list li:last-child {{ border-bottom: none; }}
        .priority-badge {{
            font-family: 'Times New Roman', Times, serif;
            font-weight: 700;
            font-size: 13px;
            padding: 4px 16px;
            border-radius: 0px;
            color: #0a0a0a;
            white-space: nowrap;
            background: #666;
            border: 1px solid #666;
        }}
        .priority-badge.Critical {{ background: #ff0040; border-color: #ff0040; }}
        .priority-badge.High {{ background: #ff6a00; border-color: #ff6a00; }}
        .priority-badge.Medium {{ background: #ffd700; border-color: #ffd700; color: #0a0a0a; }}
        .priority-badge.Low {{ background: #00ccff; border-color: #00ccff; }}
        .priority-badge.Info {{ background: #666666; border-color: #666666; }}

        /* ── Finding Cards ────────────────────────────── */
        .finding-card {{
            background: rgba(0, 255, 65, 0.02);
            border: 1px solid rgba(0, 255, 65, 0.08);
            margin-bottom: 18px;
            overflow: hidden;
            border-left: 6px solid #333;
        }}
        .finding-card.pass {{ border-left-color: #00ff41; }}
        .finding-card.warning {{ border-left-color: #ffd700; }}
        .finding-card.fail {{ border-left-color: #ff0040; }}
        .finding-card.error {{ border-left-color: #666666; }}

        .finding-header {{
            padding: 20px 26px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(0, 255, 65, 0.02);
            border-bottom: 1px solid rgba(0, 255, 65, 0.05);
            transition: background 0.2s;
        }}
        .finding-header:hover {{ background: rgba(0, 255, 65, 0.05); }}
        .finding-header .title {{
            font-weight: 700;
            font-size: 20px;
            color: #00ff41;
        }}
        .finding-header .status-badge {{
            padding: 4px 20px;
            border: 1px solid;
            font-size: 15px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .status-badge.pass {{ background: rgba(0, 255, 65, 0.10); border-color: #00ff41; color: #00ff41; }}
        .status-badge.warning {{ background: rgba(255, 215, 0, 0.10); border-color: #ffd700; color: #ffd700; }}
        .status-badge.fail {{ background: rgba(255, 0, 64, 0.10); border-color: #ff0040; color: #ff0040; }}
        .status-badge.error {{ background: rgba(102, 102, 102, 0.10); border-color: #666666; color: #666666; }}

        .severity-tag {{
            padding: 2px 16px;
            border: 1px solid;
            font-size: 13px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .severity-tag.critical {{ background: rgba(255, 0, 64, 0.15); border-color: #ff0040; color: #ff0040; }}
        .severity-tag.high {{ background: rgba(255, 106, 0, 0.15); border-color: #ff6a00; color: #ff6a00; }}
        .severity-tag.medium {{ background: rgba(255, 215, 0, 0.15); border-color: #ffd700; color: #ffd700; }}
        .severity-tag.low {{ background: rgba(0, 204, 255, 0.15); border-color: #00ccff; color: #00ccff; }}
        .severity-tag.info {{ background: rgba(102, 102, 102, 0.15); border-color: #666666; color: #666666; }}

        .finding-body {{
            padding: 24px 28px;
            display: none;
            background: rgba(0, 0, 0, 0.4);
        }}
        .finding-body.open {{ display: block; }}
        .finding-body .section {{ margin-bottom: 20px; }}
        .finding-body .section-title {{
            font-weight: 700;
            font-size: 17px;
            color: #66ff99;
            margin-bottom: 6px;
            letter-spacing: 1px;
        }}
        .finding-body .section-content {{
            font-size: 17px;
            color: #b3ffcc;
            background: rgba(0, 0, 0, 0.4);
            padding: 14px 18px;
            border-left: 2px solid rgba(0, 255, 65, 0.15);
            white-space: pre-wrap;
            word-break: break-word;
            font-family: 'Times New Roman', Times, serif;
        }}
        .finding-body .poc {{
            background: #0a0a0a;
            color: #00ff41;
            padding: 14px 18px;
            border: 1px solid rgba(0, 255, 65, 0.15);
            font-family: 'Courier New', monospace;
            font-size: 15px;
            overflow-x: auto;
        }}
        .finding-body .verification-response {{
            background: rgba(0, 0, 0, 0.6);
            color: #66ff99;
            padding: 14px 18px;
            border: 1px solid rgba(0, 255, 65, 0.10);
            font-family: 'Courier New', monospace;
            font-size: 14px;
            overflow-x: auto;
            white-space: pre-wrap;
            max-height: 300px;
            overflow-y: auto;
        }}
        .finding-body .timestamp {{
            font-size: 15px;
            color: #66ff99;
            text-align: right;
            border-top: 1px solid rgba(0, 255, 65, 0.06);
            padding-top: 12px;
            margin-top: 12px;
        }}
        .arrow {{
            transition: transform 0.2s;
            font-size: 22px;
            color: #00ff41;
        }}
        .arrow.open {{ transform: rotate(90deg); }}
        .exploit-score {{
            font-weight: 700;
            padding: 4px 14px;
            border: 1px solid;
            font-size: 15px;
            border-radius: 0px;
        }}
        .exploit-score.high {{ background: rgba(255, 0, 64, 0.15); border-color: #ff0040; color: #ff0040; }}
        .exploit-score.medium {{ background: rgba(255, 215, 0, 0.15); border-color: #ffd700; color: #ffd700; }}
        .exploit-score.low {{ background: rgba(0, 204, 255, 0.15); border-color: #00ccff; color: #00ccff; }}

        /* ── robots.txt display ───────────────────────── */
        .robots-content {{
            background: #0a0a0a;
            padding: 16px 20px;
            border: 1px solid rgba(0, 255, 65, 0.08);
            font-family: 'Courier New', monospace;
            font-size: 15px;
            color: #66ff99;
            overflow-x: auto;
            white-space: pre-wrap;
            max-height: 600px;
            overflow-y: auto;
        }}

        /* ── Signature / Footer ───────────────────────── */
        .signature-section {{
            margin-top: 40px;
            padding-top: 24px;
            border-top: 2px solid rgba(0, 255, 65, 0.10);
            display: flex;
            justify-content: space-between;
            flex-wrap: wrap;
            gap: 20px;
            font-size: 15px;
            color: #66ff99;
        }}
        .signature-section .hash {{
            font-family: 'Courier New', monospace;
            font-size: 14px;
            color: #00ff41;
            word-break: break-all;
            background: rgba(0, 0, 0, 0.4);
            padding: 8px 12px;
            border: 1px solid rgba(0, 255, 65, 0.05);
        }}
        .footer {{
            margin-top: 32px;
            text-align: center;
            font-size: 15px;
            color: #66ff99;
            border-top: 1px solid rgba(0, 255, 65, 0.06);
            padding-top: 20px;
        }}

        /* ── Responsive ────────────────────────────────── */
        @media (max-width: 768px) {{
            body {{ padding: 16px; font-size: 16px; }}
            .container {{ padding: 20px; }}
            .header {{ flex-direction: column; align-items: flex-start; gap: 12px; }}
            .header h1 {{ font-size: 30px; }}
            .score-card {{ flex-direction: column; align-items: flex-start; gap: 20px; }}
            .finding-header {{ flex-wrap: wrap; gap: 10px; }}
            .heatmap-grid {{ grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); }}
            .signature-section {{ flex-direction: column; }}
        }}
        @media print {{
            body {{ background: #ffffff; color: #000000; }}
            .container {{ border: 1px solid #000; box-shadow: none; }}
            .finding-card {{ border: 1px solid #ccc; }}
            .header .badge {{ background: #000; color: #fff; }}
            .score-circle {{ border: 1px solid #000; }}
        }}
    </style>
</head>
<body>
<div class="container">

    <!-- ═══ HEADER ═══ -->
    <div class="header">
        <div>
            <h1>◈ BRAVO6 SECURITY SCAN</h1>
            <div class="meta-info">
                <span>Target: <strong>{url}</strong></span>
                <span>Duration: {meta.get('duration_seconds', 0)}s</span>
                <span>Tests: {meta.get('tests_run', 0)}</span>
                <span>Errors: {meta.get('tests_errored', 0)}</span>
            </div>
        </div>
        <div class="badge">{status.upper()}</div>
    </div>

    <!-- ═══ SCORE CARD ═══ -->
    <div class="score-card">
        <div class="score-circle">{score}</div>
        <div class="score-details">
            <div class="grade">Grade {grade}</div>
            <div class="sub">Security posture based on detected issues</div>
            <div class="summary-bars">
                <div class="summary-item"><span class="dot" style="background:#ff0040;"></span> Critical: {summary.get('critical', 0)}</div>
                <div class="summary-item"><span class="dot" style="background:#ff6a00;"></span> High: {summary.get('high', 0)}</div>
                <div class="summary-item"><span class="dot" style="background:#ffd700;"></span> Medium: {summary.get('medium', 0)}</div>
                <div class="summary-item"><span class="dot" style="background:#00ccff;"></span> Low: {summary.get('low', 0)}</div>
                <div class="summary-item"><span class="dot" style="background:#00ff41;"></span> Passed: {summary.get('passed', 0)}</div>
                <div class="summary-item"><span class="dot" style="background:#666666;"></span> Errors: {summary.get('errors', 0)}</div>
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

    <!-- ═══ DIGITAL SIGNATURE & REPRODUCIBILITY ═══ -->
    <div class="signature-section">
        <div>
            <strong>🔒 Digital Signature</strong>
            <div class="hash">SHA-256: {signature}</div>
            <div style="font-size:14px;color:#66ff99;margin-top:4px;">
                This signature verifies the report's integrity.<br>
                Any modification will invalidate this hash.
            </div>
        </div>
        <div>
            <strong>⚙️ Reproducibility</strong>
            <div style="font-size:14px;color:#66ff99;">
                <div>Target: <strong style="color:#00ff41;">{url}</strong></div>
                <div>Scan Time: <strong style="color:#00ff41;">{datetime.now().isoformat()}</strong></div>
                <div>Tests Run: <strong style="color:#00ff41;">{meta.get('tests_run', 0)}</strong></div>
                <div style="margin-top:4px;font-family:'Courier New',monospace;font-size:13px;">
                    Re-run: <span style="color:#00ff41;">python -m scanner.main_scanner {url}</span>
                </div>
            </div>
        </div>
        <div>
            <strong>📅 Timestamp</strong>
            <div style="font-size:14px;color:#00ff41;">
                {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </div>
            <div style="font-size:13px;color:#66ff99;margin-top:4px;">
                Each finding has its own timestamp below.
            </div>
        </div>
    </div>

    <!-- ═══ FOOTER ═══ -->
    <div class="footer">
        Generated by Bravo6 Scanner • Report date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
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
            body.classList.add('open');
            arrow.classList.add('open');
        }});
    }});
</script>
</body>
</html>
'''
    return html


# ── Helper renderers ────────────────────────────────────────────────────────

def _render_waf_context(waf_context: dict) -> str:
    if not waf_context.get('detected'):
        return ''
    return f'''
    <div style="background:rgba(0,255,65,0.04);border:1px solid rgba(0,255,65,0.08);padding:14px 20px;margin-bottom:32px;font-size:17px;">
        <strong style="color:#00ff41;">🛡️ WAF/CDN detected:</strong> 
        <span style="color:#66ff99;">{waf_context.get('detected')}</span>
        <span style="color:#66ff99;font-size:15px;display:block;margin-top:4px;">{waf_context.get('note', '')}</span>
    </div>
    '''


def _render_heatmap(cells: List[Dict]) -> str:
    if not cells:
        return '''
        <div class="heatmap">
            <h3 style="color:#00ff41;">🔥 Risk Heatmap</h3>
            <p style="color:#66ff99;">No findings to display.</p>
        </div>
        '''

    color_map = {
        "Critical": "#ff0040",
        "High": "#ff6a00",
        "Medium": "#ffd700",
        "Low": "#00ccff",
        "Info": "#666666"
    }

    rows = []
    for cell in cells:
        bg = color_map.get(cell.get("risk", "Info"), "#666666")
        text_color = "#0a0a0a" if cell.get("risk") in ("Critical", "High", "Medium") else "#ffffff"
        rows.append(f'''
            <div class="heatmap-cell" style="background:{bg};color:{text_color};border-color:{bg};">
                <span class="cell-score">{cell.get("score", 5)}</span>
                <span class="cell-label">{cell.get("name", "Unnamed")}</span>
            </div>
        ''')

    return f'''
    <div class="heatmap">
        <h3 style="color:#00ff41;">🔥 Risk Heatmap</h3>
        <p style="color:#66ff99;font-size:17px;margin-bottom:12px;">Each cell shows a finding — darker = higher risk. Score = Exploitability (1–10).</p>
        <div class="heatmap-grid">
            {''.join(rows)}
        </div>
    </div>
    '''


def _render_priorities(findings: List[Dict]) -> str:
    critical = [f for f in findings if f.get("_priority") == "Critical"]
    high = [f for f in findings if f.get("_priority") == "High"]
    medium = [f for f in findings if f.get("_priority") == "Medium"]
    low = [f for f in findings if f.get("_priority") == "Low"]

    if not critical and not high and not medium and not low:
        return '''
        <div class="priority-section">
            <h3 style="color:#00ff41;">🎯 Prioritized Recommendations</h3>
            <p style="color:#66ff99;">No issues found — you're all clear!</p>
        </div>
        '''

    rows = []
    for p in ["Critical", "High", "Medium", "Low"]:
        items = {"Critical": critical, "High": high, "Medium": medium, "Low": low}.get(p, [])
        for f in items:
            name = f.get("test_name", "").replace("test_", "").replace("_", " ").title()
            sev = f.get("severity", "info").capitalize()
            exp = f.get("_exploitability", 5)
            rows.append(f'''
                <li>
                    <span class="priority-badge {p}">{p}</span>
                    <span style="color:#b3ffcc;"><strong style="color:#00ff41;">{name}</strong> — {f.get("_explanation", "Review this issue.")}</span>
                    <span style="margin-left:auto;font-size:15px;color:#66ff99;white-space:nowrap;">Severity: {sev} • Exploit: {exp}/10</span>
                </li>
            ''')

    return f'''
    <div class="priority-section">
        <h3 style="color:#00ff41;">🎯 Prioritized Recommendations</h3>
        <p style="color:#66ff99;font-size:17px;margin-bottom:12px;">Fix these in order: Critical → High → Medium → Low</p>
        <ul class="priority-list">
            {''.join(rows)}
        </ul>
    </div>
    '''


def _render_findings(findings: List[Dict]) -> str:
    if not findings:
        return '<p style="color:#66ff99;">No findings to display.</p>'

    html_parts = []
    for f in findings:
        test_name = f.get("test_name", "Unnamed Test")
        status = f.get("status", "unknown")
        severity = f.get("severity", "info")
        title = f.get("title", test_name)
        description = f.get("description", "")
        evidence = f.get("evidence")
        remediation = f.get("remediation", "No specific remediation provided.")
        exploit = f.get("_exploitability", 5)
        explanation = f.get("_explanation", "")
        timestamp = f.get("_timestamp", datetime.now().isoformat())

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
        poc = ""
        if isinstance(evidence, list):
            for e in evidence:
                if isinstance(e, dict) and "poc" in e:
                    poc = e["poc"]
                    break
                if isinstance(e, str) and "curl" in e:
                    poc = e
                    break
        if not poc and "poc" in f:
            poc = f["poc"]

        # ── robots.txt special handling ──────────────────────────────────
        robots_content = f.get("robots_content")
        sensitive_paths = f.get("sensitive_paths", [])
        if robots_content and sensitive_paths:
            highlighted = _highlight_robots_content(robots_content, sensitive_paths)
            evidence_html = f'''
                <div style="margin-bottom:12px;font-size:17px;color:#66ff99;">
                    <strong>📄 robots.txt Content</strong> 
                    <span style="font-size:14px;color:#66ff99;">(sensitive paths highlighted in green)</span>
                </div>
                <div class="robots-content">{highlighted}</div>
                <div style="margin-top:12px;font-size:15px;color:#66ff99;">
                    <strong>🔎 Detected sensitive paths:</strong> {', '.join([f'<span style="color:#00ff41;font-weight:bold;">{p}</span>' for p in sensitive_paths])}
                </div>
            '''

        # ── Severity and exploitability ──────────────────────────────────
        sev_class = severity.lower()
        status_class = status.lower()
        exploit_class = "high" if exploit >= 7 else "medium" if exploit >= 4 else "low"

        html_parts.append(f'''
        <div class="finding-card {status_class}">
            <div class="finding-header" onclick="toggleBody(this)">
                <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
                    <span class="title">{test_name}</span>
                    <span class="severity-tag {sev_class}">{severity.upper()}</span>
                    <span class="exploit-score {exploit_class}">⚡ {exploit}/10</span>
                    <span style="font-size:16px;color:#66ff99;">{explanation[:70]}{'...' if len(explanation)>70 else ''}</span>
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
                <div class="section">
                    <div class="section-title">🔎 Evidence</div>
                    <div class="section-content">{evidence_html if evidence_html else "No specific evidence."}</div>
                </div>
                {f'<div class="section"><div class="section-title">💻 PoC Command</div><div class="poc">{poc}</div></div>' if poc else ''}
                <div class="section">
                    <div class="section-title">🛠️ Remediation</div>
                    <div class="section-content">{remediation}</div>
                </div>
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