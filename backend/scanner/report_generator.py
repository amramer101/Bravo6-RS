"""
report_generator.py — Bravo6 HTML Report Generator

Takes a scan result dict (as returned by run_scout) and generates a
standalone, visually appealing HTML report with all findings, evidence,
remediation, and PoC commands.
"""

import json
from typing import Dict, Any, List


def generate_html_report(result: Dict[str, Any]) -> str:
    """
    Generate a self-contained HTML report from the scan result.
    """
    # Extract summary
    url = result.get("url", "N/A")
    status = result.get("status", "unknown")
    score = result.get("score", 0)
    grade = result.get("grade", "F")
    summary = result.get("summary", {})
    findings = result.get("findings", [])
    waf_context = result.get("waf_context", {})
    meta = result.get("meta", {})

    # Colors
    status_color = {
        "pass": "#28a745",
        "warning": "#ffc107",
        "fail": "#dc3545",
        "error": "#6c757d"
    }.get(status, "#6c757d")

    severity_colors = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#17a2b8",
        "info": "#6c757d"
    }

    # Build HTML
    html = f"""<!DOCTYPE html>
<html lang="ar" dir="ltr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bravo6 Security Scan Report - {url}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f4f6f9;
            color: #333;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        /* Header */
        .header {{
            background: linear-gradient(135deg, #1e2a3a, #2c3e50);
            color: white;
            padding: 30px 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
        }}
        .header h1 {{
            font-size: 28px;
            font-weight: 300;
            letter-spacing: 1px;
        }}
        .header .badge {{
            background: {status_color};
            padding: 8px 24px;
            border-radius: 50px;
            font-weight: 600;
            font-size: 18px;
            text-transform: uppercase;
        }}
        .meta-info {{
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            margin-top: 10px;
            font-size: 14px;
            color: #ccc;
        }}
        .meta-info span {{
            background: rgba(255,255,255,0.1);
            padding: 4px 12px;
            border-radius: 20px;
        }}
        /* Score card */
        .score-card {{
            background: white;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
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
            font-size: 32px;
            font-weight: 700;
            color: #1e2a3a;
        }}
        .score-details {{
            flex: 1;
        }}
        .score-details .grade {{
            font-size: 48px;
            font-weight: 700;
            color: {status_color};
        }}
        .score-details .sub {{
            font-size: 16px;
            color: #6c757d;
        }}
        .summary-bars {{
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            margin-top: 10px;
        }}
        .summary-item {{
            display: flex;
            align-items: center;
            gap: 8px;
            background: #f8f9fa;
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 14px;
        }}
        .summary-item .dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            display: inline-block;
        }}
        /* Findings */
        .finding-card {{
            background: white;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            margin-bottom: 15px;
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
        .finding-header:hover {{
            background: #f1f3f5;
        }}
        .finding-header .title {{
            font-weight: 600;
            font-size: 16px;
        }}
        .finding-header .status-badge {{
            padding: 4px 16px;
            border-radius: 50px;
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .finding-header .status-badge.pass {{ background: #d4edda; color: #155724; }}
        .finding-header .status-badge.warning {{ background: #fff3cd; color: #856404; }}
        .finding-header .status-badge.fail {{ background: #f8d7da; color: #721c24; }}
        .finding-header .status-badge.error {{ background: #e2e3e5; color: #383d41; }}
        .finding-header .severity-tag {{
            padding: 2px 12px;
            border-radius: 50px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            background: #6c757d;
            color: white;
        }}
        .finding-header .severity-tag.critical {{ background: #dc3545; }}
        .finding-header .severity-tag.high {{ background: #fd7e14; }}
        .finding-header .severity-tag.medium {{ background: #ffc107; color: #333; }}
        .finding-header .severity-tag.low {{ background: #17a2b8; }}
        .finding-header .severity-tag.info {{ background: #6c757d; }}

        .finding-body {{
            padding: 20px 24px;
            display: none;
            background: white;
        }}
        .finding-body.open {{
            display: block;
        }}
        .finding-body .section {{
            margin-bottom: 16px;
        }}
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
        .finding-body .section-content.code {{
            font-family: 'Courier New', monospace;
            font-size: 13px;
            background: #1e2a3a;
            color: #f8f9fa;
            overflow-x: auto;
        }}
        .finding-body .poc {{
            background: #1e2a3a;
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
        .arrow.open {{
            transform: rotate(90deg);
        }}
        /* Footer */
        .footer {{
            margin-top: 40px;
            text-align: center;
            font-size: 13px;
            color: #6c757d;
            border-top: 1px solid #dee2e6;
            padding-top: 20px;
        }}
        @media (max-width: 768px) {{
            .header {{
                flex-direction: column;
                align-items: flex-start;
                gap: 15px;
            }}
            .score-card {{
                flex-direction: column;
                align-items: flex-start;
            }}
            .finding-header {{
                flex-wrap: wrap;
                gap: 10px;
            }}
        }}
    </style>
</head>
<body>
<div class="container">
    <!-- Header -->
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

    <!-- Score Card -->
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

    <!-- WAF Context -->
    {f'<div style="background: #e9ecef; padding: 12px 20px; border-radius: 8px; margin-bottom: 20px; font-size: 14px;"><strong>WAF/CDN detected:</strong> {waf_context.get("detected", "None")} {waf_context.get("note", "")}</div>' if waf_context.get('detected') else ''}

    <!-- Findings -->
    <h2 style="margin-bottom: 20px;">📋 Detailed Findings</h2>
    """

    # Sort findings: critical/high first, then by status
    def sort_key(f):
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        status_order = {"fail": 0, "warning": 1, "pass": 2, "error": 3}
        return (sev_order.get(f.get("severity", "info"), 5), status_order.get(f.get("status", "pass"), 5))

    sorted_findings = sorted(findings, key=sort_key)

    for idx, finding in enumerate(sorted_findings):
        test_name = finding.get("test_name", "Unnamed Test")
        status = finding.get("status", "unknown")
        severity = finding.get("severity", "info")
        title = finding.get("title", test_name)
        description = finding.get("description", "")
        evidence = finding.get("evidence")
        remediation = finding.get("remediation", "No specific remediation provided.")

        # Build evidence display
        evidence_html = ""
        if evidence is not None:
            if isinstance(evidence, str):
                evidence_html = f'<div class="section-content">{evidence}</div>'
            elif isinstance(evidence, list):
                # If list of dicts, try to format nicely
                if all(isinstance(e, dict) for e in evidence):
                    # For each item, create a small block
                    items = []
                    for e in evidence:
                        parts = []
                        for k, v in e.items():
                            if isinstance(v, str) and len(v) > 100:
                                v = v[:100] + "..."
                            parts.append(f"<strong>{k}:</strong> {v}")
                        items.append("<div style='margin-bottom:8px;'>" + " | ".join(parts) + "</div>")
                    evidence_html = "".join(items)
                else:
                    # list of strings
                    items = [f"<div>• {item}</div>" for item in evidence]
                    evidence_html = "".join(items)
            else:
                evidence_html = f'<div class="section-content">{evidence}</div>'

        # PoC extraction
        poc = ""
        if isinstance(evidence, list):
            # try to find a key named 'poc' or 'poc_command'
            for e in evidence:
                if isinstance(e, dict) and "poc" in e:
                    poc = e["poc"]
                    break
                if isinstance(e, str) and "curl" in e:
                    poc = e
                    break
        # If there is a dedicated PoC field in the finding (some tests have it)
        if not poc and "poc" in finding:
            poc = finding["poc"]

        # Severity class
        sev_class = severity.lower()

        # Status badge class
        status_class = status.lower()

        html += f"""
        <div class="finding-card {status_class}">
            <div class="finding-header" onclick="toggleBody(this)">
                <div>
                    <span class="title">{test_name}</span>
                    <span class="severity-tag {sev_class}">{severity.upper()}</span>
                </div>
                <div>
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
        """

    # Finish
    html += """
    <div class="footer">
        Generated by Bravo6 Scanner • Report date: {now}
    </div>
</div>
<script>
    function toggleBody(header) {
        const body = header.nextElementSibling;
        const arrow = header.querySelector('.arrow');
        if (body.classList.contains('open')) {
            body.classList.remove('open');
            arrow.classList.remove('open');
        } else {
            body.classList.add('open');
            arrow.classList.add('open');
        }
    }
    // Auto-expand findings with critical/high severity
    document.addEventListener('DOMContentLoaded', function() {
        document.querySelectorAll('.finding-card.fail .finding-header').forEach(function(header) {
            // toggle open
            const body = header.nextElementSibling;
            const arrow = header.querySelector('.arrow');
            body.classList.add('open');
            arrow.classList.add('open');
        });
    });
</script>
</body>
</html>
    """.replace("{now}", str(__import__('datetime').datetime.now()))

    return html


if __name__ == "__main__":
    # Example usage: generate report from a JSON file
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