"""
report_generator.py — Bravo6 HTML Report Generator (Legendary Edition)

Generates a stunning HTML report with:
- Exploitability Score (1-10) for each finding
- Heatmap visualization of risk areas
- Prioritized remediation recommendations
- Plain-language explanations for non-technical readers
"""

import json
from datetime import datetime
from typing import Dict, Any, List, Optional


# ── Exploitability scores (1–10) per finding type ──────────────────────────
EXPLOITABILITY_SCORES = {
    # Critical / High impact, trivial to exploit
    "secrets_detection": 10,
    "http_methods": 9,
    "robots_txt": 8,
    "information_disclosure": 8,
    "subdomain_takeover": 9,
    "cms_vibe_detection": 7,
    # Medium impact, requires some effort
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

# ── Plain-language explanations for non-technical readers ──────────────────
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
    """Return exploitability score (1-10) for a test name."""
    # Remove "test_" prefix if present
    key = test_name.replace("test_", "")
    return EXPLOITABILITY_SCORES.get(key, 5)


def _get_explanation(test_name: str) -> str:
    """Return plain-language explanation for a test name."""
    key = test_name.replace("test_", "")
    return EXPLANATIONS.get(key, "This issue may pose a security risk to your website. Review the details below.")


def _get_priority(test_name: str, severity: str) -> str:
    """Return priority level (Critical/High/Medium/Low) based on severity and exploitability."""
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
    """Map severity to risk level for heatmap."""
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info"
    }.get(severity, "Info")


# ── Main HTML generator ─────────────────────────────────────────────────────

def generate_html_report(result: Dict[str, Any]) -> str:
    """
    Generate a standalone, visually stunning HTML report.
    """
    url = result.get("url", "N/A")
    status = result.get("status", "unknown")
    score = result.get("score", 0)
    grade = result.get("grade", "F")
    summary = result.get("summary", {})
    findings = result.get("findings", [])
    waf_context = result.get("waf_context", {})
    meta = result.get("meta", {})

    status_color = {"pass": "#28a745", "warning": "#ffc107", "fail": "#dc3545", "error": "#6c757d"}.get(status, "#6c757d")

    # ── Sort findings by priority ──────────────────────────────────────────
    priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    for f in findings:
        test_name = f.get("test_name", "Unnamed")
        sev = f.get("severity", "info")
        f["_priority"] = _get_priority(test_name, sev)
        f["_exploitability"] = _get_exploitability(test_name)
        f["_explanation"] = _get_explanation(test_name)
        f["_risk_level"] = _severity_to_risk_level(sev)

    sorted_findings = sorted(findings, key=lambda f: priority_order.get(f["_priority"], 5))

    # ── Build heatmap data ──────────────────────────────────────────────────
    heatmap_cells = []
    for f in sorted_findings:
        if f.get("status") in ("fail", "warning"):
            heatmap_cells.append({
                "name": f.get("test_name", "").replace("test_", "").replace("_", " ").title(),
                "risk": f.get("severity", "info").capitalize(),
                "priority": f["_priority"],
                "score": f["_exploitability"],
            })

    # ── HTML ─────────────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="ar" dir="ltr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bravo6 Security Scan Report - {url}</title>
    <style>
        /* ── Base ─────────────────────────────────────── */
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f4f6f9;
            color: #1e2a3a;
            padding: 24px;
            line-height: 1.6;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}

        /* ── Header ───────────────────────────────────── */
        .header {{
            background: linear-gradient(135deg, #0f1a2b, #1e2a3a);
            color: white;
            padding: 30px 40px;
            border-radius: 16px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
        }}
        .header h1 {{ font-size: 28px; font-weight: 300; }}
        .header .badge {{
            background: {status_color};
            padding: 8px 24px;
            border-radius: 50px;
            font-weight: 700;
            font-size: 18px;
            text-transform: uppercase;
        }}
        .meta-info {{
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
            margin-top: 8px;
            font-size: 14px;
            color: #ccc;
        }}
        .meta-info span {{
            background: rgba(255,255,255,0.08);
            padding: 4px 14px;
            border-radius: 20px;
        }}

        /* ── Score Card ───────────────────────────────── */
        .score-card {{
            background: white;
            border-radius: 16px;
            padding: 30px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.04);
            margin-bottom: 30px;
            display: flex;
            flex-wrap: wrap;
            gap: 30px;
            align-items: center;
        }}
        .score-circle {{
            width: 100px;
            height: 100px;
            border-radius: 50%;
            background: conic-gradient({status_color} {score}%, #e9ecef {score}%);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 34px;
            font-weight: 700;
            color: #0f1a2b;
        }}
        .score-details {{ flex: 1; }}
        .score-details .grade {{
            font-size: 48px;
            font-weight: 700;
            color: {status_color};
        }}
        .score-details .sub {{ font-size: 16px; color: #6c757d; }}
        .summary-bars {{
            display: flex;
            gap: 16px;
            flex-wrap: wrap;
            margin-top: 10px;
        }}
        .summary-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            background: #f8f9fa;
            padding: 6px 16px;
            border-radius: 30px;
            font-size: 14px;
        }}
        .summary-item .dot {{ width: 12px; height: 12px; border-radius: 50%; display: inline-block; }}

        /* ── Heatmap ──────────────────────────────────── */
        .heatmap {{
            background: white;
            border-radius: 16px;
            padding: 24px 30px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.04);
            margin-bottom: 30px;
        }}
        .heatmap-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
            gap: 12px;
            margin-top: 16px;
        }}
        .heatmap-cell {{
            padding: 14px 16px;
            border-radius: 12px;
            font-size: 13px;
            font-weight: 600;
            text-align: center;
            color: white;
            transition: transform 0.2s;
        }}
        .heatmap-cell:hover {{ transform: scale(1.02); }}
        .heatmap-cell .cell-score {{
            font-size: 18px;
            font-weight: 700;
            display: block;
            margin-bottom: 2px;
        }}
        .heatmap-cell .cell-label {{ font-size: 11px; opacity: 0.9; }}

        /* ── Priority Recommendations ──────────────────── */
        .priority-section {{
            background: white;
            border-radius: 16px;
            padding: 24px 30px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.04);
            margin-bottom: 30px;
        }}
        .priority-list {{ list-style: none; padding: 0; margin-top: 12px; }}
        .priority-list li {{
            display: flex;
            align-items: flex-start;
            gap: 16px;
            padding: 14px 18px;
            border-bottom: 1px solid #f1f3f5;
        }}
        .priority-list li:last-child {{ border-bottom: none; }}
        .priority-badge {{
            font-weight: 700;
            font-size: 12px;
            padding: 3px 12px;
            border-radius: 30px;
            color: white;
            white-space: nowrap;
            background: #6c757d;
        }}
        .priority-badge.Critical {{ background: #dc3545; }}
        .priority-badge.High {{ background: #fd7e14; }}
        .priority-badge.Medium {{ background: #ffc107; color: #1e2a3a; }}
        .priority-badge.Low {{ background: #17a2b8; }}
        .priority-badge.Info {{ background: #6c757d; }}

        /* ── Finding Cards ────────────────────────────── */
        .finding-card {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.04);
            margin-bottom: 16px;
            overflow: hidden;
            border-left: 5px solid #6c757d;
        }}
        .finding-card.pass {{ border-left-color: #28a745; }}
        .finding-card.warning {{ border-left-color: #ffc107; }}
        .finding-card.fail {{ border-left-color: #dc3545; }}
        .finding-card.error {{ border-left-color: #6c757d; }}

        .finding-header {{
            padding: 18px 24px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #fafbfc;
            border-bottom: 1px solid #eee;
            transition: background 0.2s;
        }}
        .finding-header:hover {{ background: #f1f3f5; }}
        .finding-header .title {{ font-weight: 600; font-size: 16px; }}
        .finding-header .status-badge {{
            padding: 4px 16px;
            border-radius: 50px;
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .status-badge.pass {{ background: #d4edda; color: #155724; }}
        .status-badge.warning {{ background: #fff3cd; color: #856404; }}
        .status-badge.fail {{ background: #f8d7da; color: #721c24; }}
        .status-badge.error {{ background: #e2e3e5; color: #383d41; }}

        .severity-tag {{
            padding: 2px 12px;
            border-radius: 50px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            color: white;
        }}
        .severity-tag.critical {{ background: #dc3545; }}
        .severity-tag.high {{ background: #fd7e14; }}
        .severity-tag.medium {{ background: #ffc107; color: #1e2a3a; }}
        .severity-tag.low {{ background: #17a2b8; }}
        .severity-tag.info {{ background: #6c757d; }}

        .finding-body {{
            padding: 20px 24px;
            display: none;
            background: white;
        }}
        .finding-body.open {{ display: block; }}
        .finding-body .section {{ margin-bottom: 16px; }}
        .finding-body .section-title {{
            font-weight: 600;
            font-size: 14px;
            color: #495057;
            margin-bottom: 4px;
        }}
        .finding-body .section-content {{
            font-size: 14px;
            color: #212529;
            background: #f8f9fa;
            padding: 12px 16px;
            border-radius: 6px;
            white-space: pre-wrap;
            word-break: break-word;
        }}
        .finding-body .poc {{
            background: #0f1a2b;
            color: #f8f9fa;
            padding: 12px 16px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            overflow-x: auto;
        }}
        .arrow {{
            transition: transform 0.2s;
            font-size: 18px;
            color: #6c757d;
        }}
        .arrow.open {{ transform: rotate(90deg); }}
        .exploit-score {{
            font-weight: 700;
            padding: 4px 10px;
            border-radius: 30px;
            font-size: 13px;
        }}
        .exploit-score.high {{ background: #dc3545; color: white; }}
        .exploit-score.medium {{ background: #ffc107; color: #1e2a3a; }}
        .exploit-score.low {{ background: #17a2b8; color: white; }}

        .footer {{
            margin-top: 40px;
            text-align: center;
            font-size: 13px;
            color: #6c757d;
            border-top: 1px solid #dee2e6;
            padding-top: 20px;
        }}
        @media (max-width: 768px) {{
            .header {{ flex-direction: column; align-items: flex-start; gap: 15px; }}
            .score-card {{ flex-direction: column; align-items: flex-start; }}
            .finding-header {{ flex-wrap: wrap; gap: 10px; }}
            .heatmap-grid {{ grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); }}
        }}
    </style>
</head>
<body>
<div class="container">

    <!-- ═══ HEADER ═══ -->
    <div class="header">
        <div>
            <h1>🔍 Bravo6 Security Scan</h1>
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
                <div class="summary-item"><span class="dot" style="background:#dc3545;"></span> Critical: {summary.get('critical', 0)}</div>
                <div class="summary-item"><span class="dot" style="background:#fd7e14;"></span> High: {summary.get('high', 0)}</div>
                <div class="summary-item"><span class="dot" style="background:#ffc107;"></span> Medium: {summary.get('medium', 0)}</div>
                <div class="summary-item"><span class="dot" style="background:#17a2b8;"></span> Low: {summary.get('low', 0)}</div>
                <div class="summary-item"><span class="dot" style="background:#28a745;"></span> Passed: {summary.get('passed', 0)}</div>
                <div class="summary-item"><span class="dot" style="background:#6c757d;"></span> Errors: {summary.get('errors', 0)}</div>
            </div>
        </div>
    </div>

    <!-- ═══ WAF CONTEXT ═══ -->
    {f'<div style="background:#e9ecef;padding:12px 20px;border-radius:12px;margin-bottom:30px;font-size:14px;"><strong>WAF/CDN detected:</strong> {waf_context.get("detected", "None")} {waf_context.get("note", "")}</div>' if waf_context.get('detected') else ''}

    <!-- ═══ HEATMAP ═══ -->
    {_render_heatmap(heatmap_cells)}

    <!-- ═══ PRIORITY RECOMMENDATIONS ═══ -->
    {_render_priorities(sorted_findings)}

    <!-- ═══ DETAILED FINDINGS ═══ -->
    <h2 style="margin-bottom:20px;">📋 Detailed Findings</h2>
    {_render_findings(sorted_findings)}

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
"""
    return html


# ── Helper renderers ────────────────────────────────────────────────────────

def _render_heatmap(cells: List[Dict]) -> str:
    if not cells:
        return '<div class="heatmap"><h3 style="margin-bottom:8px;">🔥 Risk Heatmap</h3><p style="color:#6c757d;">No findings to display.</p></div>'

    color_map = {
        "Critical": "#dc3545",
        "High": "#fd7e14",
        "Medium": "#ffc107",
        "Low": "#17a2b8",
        "Info": "#6c757d"
    }

    rows = []
    for cell in cells:
        bg = color_map.get(cell.get("risk", "Info"), "#6c757d")
        rows.append(f'''
            <div class="heatmap-cell" style="background:{bg};">
                <span class="cell-score">{cell.get("score", 5)}</span>
                <span class="cell-label">{cell.get("name", "Unnamed")}</span>
            </div>
        ''')

    return f'''
    <div class="heatmap">
        <h3 style="margin-bottom:4px;">🔥 Risk Heatmap</h3>
        <p style="font-size:14px;color:#6c757d;margin-bottom:12px;">Each cell shows a finding — darker = higher risk. Score = Exploitability (1–10).</p>
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
        return '<div class="priority-section"><h3>🎯 Prioritized Recommendations</h3><p style="color:#6c757d;">No issues found — you\'re all clear!</p></div>'

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
                    <span><strong>{name}</strong> — {f.get("_explanation", "Review this issue.")}</span>
                    <span style="margin-left:auto;font-size:13px;color:#6c757d;white-space:nowrap;">Severity: {sev} • Exploit: {exp}/10</span>
                </li>
            ''')

    return f'''
    <div class="priority-section">
        <h3 style="margin-bottom:4px;">🎯 Prioritized Recommendations</h3>
        <p style="font-size:14px;color:#6c757d;margin-bottom:12px;">Fix these in order: Critical → High → Medium → Low</p>
        <ul class="priority-list">
            {''.join(rows)}
        </ul>
    </div>
    '''


def _render_findings(findings: List[Dict]) -> str:
    if not findings:
        return '<p style="color:#6c757d;">No findings to display.</p>'

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

        # Evidence display
        evidence_html = ""
        if evidence is not None:
            if isinstance(evidence, str):
                evidence_html = f'<div class="section-content">{evidence}</div>'
            elif isinstance(evidence, list) and all(isinstance(e, dict) for e in evidence):
                items = []
                for e in evidence:
                    parts = []
                    for k, v in e.items():
                        if isinstance(v, str) and len(v) > 100:
                            v = v[:100] + "..."
                        parts.append(f"<strong>{k}:</strong> {v}")
                    items.append("<div style='margin-bottom:8px;'>" + " | ".join(parts) + "</div>")
                evidence_html = "".join(items)
            elif isinstance(evidence, list):
                items = [f"<div>• {item}</div>" for item in evidence]
                evidence_html = "".join(items)
            else:
                evidence_html = f'<div class="section-content">{evidence}</div>'

        # PoC
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

        sev_class = severity.lower()
        status_class = status.lower()

        # Exploitability score badge
        exploit_class = "high" if exploit >= 7 else "medium" if exploit >= 4 else "low"

        html_parts.append(f'''
        <div class="finding-card {status_class}">
            <div class="finding-header" onclick="toggleBody(this)">
                <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">
                    <span class="title">{test_name}</span>
                    <span class="severity-tag {sev_class}">{severity.upper()}</span>
                    <span class="exploit-score {exploit_class}">⚡ {exploit}/10</span>
                    <span style="font-size:12px;color:#6c757d;">{explanation[:60]}{'...' if len(explanation)>60 else ''}</span>
                </div>
                <div style="display:flex;align-items:center;gap:12px;">
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