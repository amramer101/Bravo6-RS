#!/usr/bin/env python3
"""
Bravo6 Security Report Generator
--------------------------------
Generates a single, self-contained HTML security report from a Bravo6 scan result dict.
Only one public function: build_html(data: dict) -> str
"""

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

# ── Colour constants ──────────────────────────────────────────────────────────
SEV_COLORS = {
    "critical": "#dc3545",
    "high":     "#fd7e14",
    "medium":   "#ffc107",
    "low":      "#0dcaf0",
    "info":     "#6c757d",
}
PRIO_COLORS = {"P0": "#dc3545", "P1": "#fd7e14", "P2": "#ffc107"}
STATUS_ICON = {"pass": "✅", "fail": "❌", "warning": "⚠️", "info": "ℹ️"}
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# ── Simple helpers ────────────────────────────────────────────────────────────
def _severity_color(sev: str) -> str:
    return SEV_COLORS.get(sev.lower(), "#6c757d")

def _severity_badge(sev: str) -> str:
    color = _severity_color(sev)
    return f'<span class="badge" style="background:{color}">{sev.upper()}</span>'

def _format_datetime(iso_str: str) -> str:
    try:
        dt = datetime.fromisoformat(iso_str)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return iso_str

def _effort(category: str) -> str:
    cat = category.lower() if category else ""
    if "ssl" in cat or "passive" in cat:
        return "Easy"
    if "active" in cat:
        return "Medium"
    return "Hard"

def _impact(sev: str) -> str:
    sev_l = sev.lower() if sev else ""
    impacts = {
        "critical": "Immediate exploitation possible",
        "high": "Significant data exposure",
        "medium": "Limited privilege escalation",
        "low": "Recon enablement / minor risk",
    }
    return impacts.get(sev_l, "—")

def _priority(sev: str) -> Tuple[str, str, str]:
    """Return (label, timeframe, color) based on severity."""
    sev_l = sev.lower() if sev else ""
    mapping = {
        "critical": ("P0", "48h", PRIO_COLORS["P0"]),
        "high":     ("P1", "1 week", PRIO_COLORS["P1"]),
        "medium":   ("P2", "2 weeks", PRIO_COLORS["P2"]),
        "low":      ("P3", "1 month", "#6c757d"),
    }
    return mapping.get(sev_l, ("—", "—", "#6c757d"))

# ── Findings deduplication (highest severity kept) ────────────────────────────
def _deduplicate(findings: List[Dict]) -> List[Dict]:
    best: Dict[str, Dict] = {}
    for f in findings:
        title = (f.get("title") or "").strip().lower()
        if not title:
            continue
        if title in best:
            exist = best[title]
            curr_sev = SEV_RANK.get(f.get("severity","").lower(), 0)
            exist_sev = SEV_RANK.get(exist.get("severity","").lower(), 0)
            if curr_sev > exist_sev or (curr_sev == exist_sev and f.get("confidence",0) > exist.get("confidence",0)):
                best[title] = dict(f)
        else:
            best[title] = dict(f)
    return list(best.values())

# ── SVG gauge ─────────────────────────────────────────────────────────────────
def _gauge_svg(score: int, grade: str) -> str:
    grade_colors = {"A": "#198754", "B": "#6f42c1", "C": "#0d6efd", "D": "#fd7e14", "F": "#dc3545"}
    color = grade_colors.get(grade.upper(), "#6c757d")
    r, cx, cy = 52, 70, 70
    circ = 2 * 3.14159 * r
    filled = circ * score / 100
    return f"""<svg viewBox="0 0 140 140" width="140" height="140" xmlns="http://www.w3.org/2000/svg">
  <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#e9ecef" stroke-width="12"/>
  <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{color}" stroke-width="12"
          stroke-dasharray="{filled:.1f} {circ:.1f}"
          stroke-dashoffset="{circ/4:.1f}"
          stroke-linecap="round"/>
  <text x="{cx}" y="{cy-8}" text-anchor="middle" font-size="26" font-weight="700" fill="{color}" font-family="Segoe UI,sans-serif">{score}</text>
  <text x="{cx}" y="{cy+14}" text-anchor="middle" font-size="13" fill="#6c757d" font-family="Segoe UI,sans-serif">/100</text>
  <text x="{cx}" y="{cy+32}" text-anchor="middle" font-size="16" font-weight="700" fill="{color}" font-family="Segoe UI,sans-serif">Grade {grade}</text>
</svg>"""

# ── TLS Certificate Card ──────────────────────────────────────────────────────
def _tls_card(test_04: Optional[Dict]) -> str:
    if not test_04 or test_04.get("status") == "error":
        return """<div class="card p-3 h-100">
            <h6 class="fw-bold text-muted text-uppercase mb-3" style="font-size:.7rem;letter-spacing:.1em">TLS Certificate</h6>
            <p class="text-muted small">TLS data unavailable</p>
        </div>"""
    details = test_04.get("details", {})
    cert = details.get("certificate", {})
    subject = cert.get("subject", "—")
    issuer = cert.get("issuer", "—")
    expiry_str = cert.get("expiry", "")
    days_left = None
    if expiry_str:
        try:
            expiry = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            days_left = (expiry - now).days
        except Exception:
            pass
    protocols = details.get("protocols", {})
    pfs = details.get("pfs_supported", None)
    key_type = cert.get("key_type", "—")
    key_size = cert.get("key_size", "")
    key_info = f"{key_type} {key_size}bit" if key_size else key_type

    expiry_html = ""
    if days_left is not None:
        if days_left < 0:
            expiry_html = f'<span class="badge bg-danger">EXPIRED</span>'
        elif days_left <= 14:
            expiry_html = f'<span class="badge bg-danger">CRITICAL – EXPIRES SOON ({days_left}d)</span>'
        elif days_left <= 45:
            expiry_html = f'<span class="badge bg-warning text-dark">⚠ {days_left} days remaining</span>'
        else:
            expiry_html = f'<span class="badge bg-success">{days_left} days</span>'

    proto_items = ""
    for proto, supported in protocols.items():
        icon = "✅" if supported else "❌"
        proto_items += f'<li class="list-group-item d-flex justify-content-between py-1"><span>{proto}</span><span>{icon}</span></li>'

    pfs_badge = "✅ Supported" if pfs else "❌ Not supported"

    return f"""<div class="card p-3 h-100">
    <h6 class="fw-bold text-muted text-uppercase mb-3" style="font-size:.7rem;letter-spacing:.1em">TLS Certificate</h6>
    <div class="small">
        <p class="mb-1"><strong>Subject:</strong> {subject}</p>
        <p class="mb-1"><strong>Issuer:</strong> {issuer}</p>
        <p class="mb-1"><strong>Expiry:</strong> {expiry_str} {expiry_html}</p>
        <p class="mb-1"><strong>Protocols:</strong></p>
        <ul class="list-group list-group-flush mb-2">{proto_items}</ul>
        <p class="mb-1"><strong>PFS:</strong> {pfs_badge}</p>
        <p class="mb-1"><strong>Key:</strong> {key_info}</p>
    </div>
</div>"""

# ── Module score bars (progress bars or status badges) ────────────────────────
def _module_bars(tests: Dict) -> str:
    order = [
        ("test_01_secrets", "Secrets"),
        ("test_02_frontend_libs", "Libraries"),
        ("test_04_ssl_tls", "SSL/TLS"),
        ("test_05_security_headers", "Headers"),
        ("test_06_info_disclosure", "Disclosure"),
    ]
    bars = ""
    for key, name in order:
        t = tests.get(key, {})
        if not t:
            continue
        score = t.get("score", None)
        sev = t.get("severity", "info")
        color = SEV_COLORS.get(sev.lower(), "#6c757d")
        # Tests without numeric score show a textual status badge
        if key in ("test_01_secrets", "test_02_frontend_libs") or score is None:
            status = t.get("status", "unknown")
            badge = STATUS_ICON.get(status.lower(), "❓")
            label = status.upper()
            bars += f"""<div class="mb-2">
                <div class="d-flex justify-content-between small mb-1">
                    <span>{name}</span><span class="fw-bold" style="color:{color}">{badge} {label}</span>
                </div>
            </div>"""
        else:
            bars += f"""<div class="mb-2">
                <div class="d-flex justify-content-between small mb-1">
                    <span>{name}</span><span class="fw-bold" style="color:{color}">{score}/100</span>
                </div>
                <div class="progress" style="height:8px">
                    <div class="progress-bar" style="width:{score}%;background:{color}"></div>
                </div>
            </div>"""
    return bars if bars else '<p class="text-muted small">No module scores available</p>'

# ── Test modules summary table ────────────────────────────────────────────────
def _test_summary(key: str, t: Dict) -> str:
    """Format a human-readable summary for the test module table."""
    summary_data = t.get("summary", {})
    if isinstance(summary_data, str):
        return summary_data
    if key == "test_01_secrets":
        resources = summary_data.get("resources_scanned", 0)
        secrets = summary_data.get("total_secrets", 0)
        forbidden = summary_data.get("forbidden_files_count", 0)
        return f"Scanned {resources} resources | {secrets} secrets | {forbidden} forbidden files"
    if key == "test_02_frontend_libs":
        libs = t.get("libraries_detected", 0)
        vuln = t.get("vulnerable_count", 0)
        return f"{libs} libraries detected | {vuln} vulnerable"
    # fallback: summary text or title
    if isinstance(summary_data, dict):
        return ", ".join(f"{k}: {v}" for k, v in summary_data.items())
    return t.get("title", "—")

def _test_rows(tests: Dict) -> str:
    NAME_MAP = {
        "test_01_secrets": "Secrets Detection",
        "test_02_frontend_libs": "Frontend Libraries",
        "test_04_ssl_tls": "SSL / TLS",
        "test_05_security_headers": "Security Headers",
        "test_06_info_disclosure": "Info Disclosure",
    }
    rows = ""
    for key, t in tests.items():
        name = NAME_MAP.get(key, key.replace("_", " ").title())
        status = t.get("status", "?").lower()
        sev = t.get("severity", "?")
        score = t.get("score", "")
        grade = t.get("grade", "")
        summary = _test_summary(key, t)
        icon = STATUS_ICON.get(status, "❓")
        sc = SEV_COLORS.get(sev.lower(), "#6c757d")
        score_txt = f"{score}/100 ({grade})" if score != "" and grade else (str(score) if score != "" else "—")
        rows += f"""<tr>
            <td class="fw-semibold">{name}</td>
            <td>{icon} {status.upper()}</td>
            <td><span class="badge" style="background:{sc}">{sev.upper()}</span></td>
            <td>{score_txt}</td>
            <td class="small text-muted">{summary}</td>
        </tr>"""
    return rows or '<tr><td colspan="5" class="text-muted text-center">No test data</td></tr>'

# ── TLS Details collapsible section ──────────────────────────────────────────
def _tls_details_section(test_04: Optional[Dict]) -> str:
    if not test_04 or test_04.get("status") == "error":
        return ""
    details = test_04.get("details", {})
    breakdown = details.get("score_breakdown", [])
    ciphers = details.get("ciphers", {})
    protocols = details.get("protocols", {})
    ocsp = details.get("ocsp", "—")
    ct = details.get("ct_scts", "—")
    chain_valid = details.get("chain_valid", "—")

    breakdown_rows = ""
    for item in breakdown:
        if isinstance(item, dict):
            description = item.get("description", "")
            points = item.get("points", "")
            breakdown_rows += f'<tr><td>{description}</td><td>{points}</td></tr>'
        else:
            breakdown_rows += f'<tr><td>{item}</td><td></td></tr>'

    cipher_rows = ""
    for cipher, enabled in ciphers.items():
        icon = "✅" if enabled else "❌"
        cipher_rows += f'<tr><td>{cipher}</td><td>{icon}</td></tr>'

    proto_rows = ""
    for proto, supported in protocols.items():
        icon = "✅" if supported else "❌"
        proto_rows += f'<tr><td>{proto}</td><td>{icon}</td></tr>'

    return f"""<div class="card mb-4">
    <div class="card-header">
        <button class="btn btn-link text-decoration-none p-0 w-100 text-start" type="button" data-bs-toggle="collapse" data-bs-target="#tlsDetailsCollapse">
            🔐 TLS Detailed Analysis
        </button>
    </div>
    <div class="collapse" id="tlsDetailsCollapse">
        <div class="card-body">
            <h6>Score Breakdown</h6>
            <table class="table table-sm table-bordered">
                <thead><tr><th>Check</th><th>Points</th></tr></thead>
                <tbody>{breakdown_rows or '<tr><td colspan="2">No breakdown data</td></tr>'}</tbody>
            </table>
            <h6>Cipher Status</h6>
            <table class="table table-sm table-bordered">
                <thead><tr><th>Cipher</th><th>Status</th></tr></thead>
                <tbody>{cipher_rows or '<tr><td colspan="2">No cipher data</td></tr>'}</tbody>
            </table>
            <h6>Protocols</h6>
            <table class="table table-sm table-bordered">
                <thead><tr><th>Protocol</th><th>Status</th></tr></thead>
                <tbody>{proto_rows or '<tr><td colspan="2">No protocol data</td></tr>'}</tbody>
            </table>
            <p><strong>OCSP Stapling:</strong> {ocsp}</p>
            <p><strong>CT SCTs:</strong> {ct}</p>
            <p><strong>Chain Validity:</strong> {chain_valid}</p>
        </div>
    </div>
</div>"""

# ── Tech Stack & Scan Metadata card ──────────────────────────────────────────
def _tech_stack_card(data: Dict) -> str:
    tests = data.get("tests", {})
    test_06 = tests.get("test_06_info_disclosure", {})
    tech_stack = test_06.get("details", {}).get("tech_stack", [])
    tech_items = ", ".join(tech_stack) if tech_stack else "—"

    waf = data.get("waf") or "None detected"
    test_01 = tests.get("test_01_secrets", {})
    scanned_js = test_01.get("summary", {}).get("scanned_urls", [])
    # Filter sensitive paths (simplified: keep only .js files)
    js_list = [url for url in scanned_js if url.endswith(".js")][:10]  # max 10
    js_html = "<br>".join(js_list) if js_list else "None"

    resources = test_01.get("summary", {}).get("resources_scanned", 0)
    dedup_count = data.get("deduplicated_count", 0)

    return f"""<div class="card mb-4">
    <div class="card-header"><strong>🧰 Tech Stack &amp; Scan Metadata</strong></div>
    <div class="card-body">
        <p><strong>Tech Stack Detected:</strong> {tech_items}</p>
        <p><strong>WAF Detected:</strong> {waf}</p>
        <p><strong>Scanned JS Files (sample):</strong><br><code class="small">{js_html}</code></p>
        <p><strong>Resources Scanned:</strong> {resources}</p>
        <p><strong>Deduplicated Findings Count:</strong> {dedup_count}</p>
    </div>
</div>"""

# ── Evidence expandable ──────────────────────────────────────────────────────
def _evidence_html(f: Dict) -> str:
    evidence = f.get("evidence", "")
    if not evidence:
        return "—"
    return f'''<details><summary class="small text-muted" style="cursor:pointer">Show evidence</summary><pre class="p-2 bg-light rounded small mt-1">{evidence}</pre></details>'''

# ── PoC expandable ───────────────────────────────────────────────────────────
def _poc_html(f: Dict) -> str:
    poc = f.get("poc", "")
    if not poc:
        return "—"
    return f'''<details><summary class="small text-danger" style="cursor:pointer">▶ PoC</summary><div class="bg-dark rounded p-2 mt-1"><code class="text-light small">{poc}</code></div></details>'''

# ── Findings table row ───────────────────────────────────────────────────────
def _findings_row(i: int, f: Dict) -> str:
    sev = (f.get("severity") or "info").lower()
    color = _severity_color(sev)
    p_label, timeframe, p_color = _priority(sev)
    impact = _impact(sev)
    effort = _effort(f.get("category", ""))
    evidence = _evidence_html(f)
    poc = _poc_html(f)
    title = f.get("title", "No title")
    desc = f.get("description", "")
    remediation = f.get("remediation", "")
    cwe = f.get("cwe", "")
    owasp = f.get("owasp", "")
    # CWE link
    cwe_html = "—"
    if cwe:
        num = cwe.replace("CWE-", "")
        cwe_html = f'<a href="https://cwe.mitre.org/data/definitions/{num}.html" target="_blank" class="badge bg-secondary text-decoration-none">{cwe}</a>'
    # OWASP link
    owasp_html = "—"
    if owasp:
        owasp_html = f'<a href="https://owasp.org/Top10/" target="_blank" class="badge" style="background:#6610f2;text-decoration:none">{owasp}</a>'
    return f"""<tr data-sev="{sev}">
        <td class="text-muted">{i}</td>
        <td><span class="badge" style="background:{color}">{sev.upper()}</span></td>
        <td>{title}</td>
        <td class="small">{evidence}</td>
        <td>{impact}</td>
        <td>{effort}</td>
        <td><span class="badge" style="background:{p_color}">{p_label}</span> <small class="text-muted">{timeframe}</small></td>
        <td class="small">{remediation[:120]}</td>
        <td>{owasp_html}</td>
        <td>{cwe_html}</td>
        <td>{poc}</td>
    </tr>"""

# ── Main HTML builder ─────────────────────────────────────────────────────────
def build_html(data: Dict[str, Any]) -> str:
    url = data.get("url", "N/A")
    raw_time = data.get("scan_time", datetime.now(timezone.utc).isoformat())
    scan_time = _format_datetime(raw_time)
    duration = data.get("duration_seconds", 0)
    tests_run = data.get("tests_run", 0)
    total_findings = data.get("total_findings", 0)
    waf = data.get("waf") or "None detected"
    errors_count = data.get("errors_count", 0)
    score = data.get("score", 0)
    grade = data.get("grade", "N/A")
    tests_dict = data.get("tests", {})

    # Deduplicate all findings
    raw_findings = data.get("findings", [])
    all_unique = _deduplicate(raw_findings)

    # Separate findings:
    #   - passing_info: status=pass, severity=info  → excluded from table, shown in "Passing Checks"
    #   - hidden_info: severity=info, status!=pass   → hidden by default but available via filter
    #   - actionable: rest (non-info, non-pass)
    passing_info = []      # pass+info
    hidden_info = []       # info, not pass
    actionable = []        # everything else

    for f in all_unique:
        sev = (f.get("severity") or "").lower()
        status = (f.get("status") or "").lower()
        if sev == "info" and status == "pass":
            passing_info.append(f)
        elif sev == "info" and status != "pass":
            hidden_info.append(f)
        else:
            actionable.append(f)

    # Severity counts for actionable only (used in summary)
    summary_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in actionable:
        s = (f.get("severity") or "").lower()
        if s in summary_counts:
            summary_counts[s] += 1
    total_actionable = sum(summary_counts.values())

    # Top 3 risks (critical/high from actionable)
    top_risks = []
    seen = set()
    for f in sorted(actionable, key=lambda x: SEV_RANK.get(x.get("severity","").lower(), 0), reverse=True):
        title = (f.get("title") or "").strip().lower()
        if title and title not in seen:
            seen.add(title)
            top_risks.append(f)
        if len(top_risks) == 3:
            break
    risks_html = ""
    for r in top_risks:
        risks_html += f"<li><strong>{r.get('title','?')}</strong> — {_impact(r.get('severity',''))}</li>"
    if not risks_html:
        risks_html = "<li>No critical/high risks found</li>"

    # Findings table rows (actionable + hidden_info)
    all_table_rows = ""
    idx = 1
    for f in actionable + hidden_info:
        all_table_rows += _findings_row(idx, f)
        idx += 1
    if not all_table_rows:
        all_table_rows = '<tr><td colspan="11" class="text-center text-muted py-3">No findings to display</td></tr>'

    # Passing Checks section: only pass+info, exclude "Technology identified" & aggregation
    pass_items = []
    for f in passing_info:
        title = (f.get("title") or "").strip()
        if title.lower() in ("technology identified", "aggregation finding"):
            continue
        pass_items.append(f)
    pass_html = ""
    if pass_items:
        for p in pass_items:
            title = p.get("title", "?")
            desc = p.get("description", "")
            pass_html += f'<li class="list-group-item d-flex align-items-center gap-2">✅ <span><strong>{title}</strong> — <span class="text-muted small">{desc}</span></span></li>'
    else:
        pass_html = '<li class="list-group-item text-muted">No passing checks recorded</li>'

    # Recommendations tabs: based on priority groupings of actionable findings
    rec_imm, rec_short, rec_long = set(), set(), set()
    for f in actionable:
        rem = f.get("remediation", "")
        if not rem or rem.lower() in ("none", "n/a", ""):
            continue
        p_label, _, _ = _priority(f.get("severity", "").lower())
        if p_label == "P0":
            rec_imm.add(rem)
        elif p_label == "P1":
            rec_short.add(rem)
        else:
            rec_long.add(rem)
    # Deduplicate across buckets: remove lower-priority duplicates
    rec_short -= rec_imm
    rec_long -= rec_imm | rec_short
    rec_imm_html = "".join(f'<li class="list-group-item">{r}</li>' for r in sorted(rec_imm)) or '<li class="list-group-item text-muted">No immediate actions</li>'
    rec_short_html = "".join(f'<li class="list-group-item">{r}</li>' for r in sorted(rec_short)) or '<li class="list-group-item text-muted">No short-term actions</li>'
    rec_long_html = "".join(f'<li class="list-group-item">{r}</li>' for r in sorted(rec_long)) or '<li class="list-group-item text-muted">No long-term actions</li>'

    # Chart data
    sev_labels = ["Critical", "High", "Medium", "Low"]
    sev_data = [summary_counts["critical"], summary_counts["high"], summary_counts["medium"], summary_counts["low"]]
    sev_colors = [SEV_COLORS[c] for c in ["critical", "high", "medium", "low"]]

    # Module scores bars
    bars = _module_bars(tests_dict)

    # TLS card
    test_04 = tests_dict.get("test_04_ssl_tls")
    tls_card = _tls_card(test_04)

    # Test modules summary table
    test_rows = _test_rows(tests_dict)

    # TLS details collapsible
    tls_details = _tls_details_section(test_04)

    # Tech stack & scan metadata
    tech_card = _tech_stack_card(data)

    # Gauge
    gauge = _gauge_svg(score, grade)

    # Build HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bravo6 Security Report — {url}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        :root {{
            --brand-dark: #0f172a;
            --brand-accent: #3b82f6;
        }}
        body {{ background: #f1f5f9; font-family: 'Segoe UI', system-ui, sans-serif; font-size: .9rem; }}
        .bravo-header {{ background: var(--brand-dark); color: #fff; padding: 1.5rem 1rem .75rem; }}
        .bravo-header h1 {{ font-size: 1.4rem; font-weight: 700; letter-spacing: .05em; }}
        .confidential-bar {{ background: #dc3545; color: #fff; font-size: .72rem; letter-spacing: .15em; font-weight: 600; text-align: center; padding: .25rem; }}
        .card {{ border: none; box-shadow: 0 1px 3px rgba(0,0,0,.08); border-radius: .5rem; }}
        .stat-card {{ border-left: 4px solid; }}
        th {{ cursor: pointer; user-select: none; white-space: nowrap; }}
        th:hover {{ background: rgba(0,0,0,.05); }}
        details summary {{ list-style: none; }}
        details summary::-webkit-details-marker {{ display: none; }}
        .table th, .table td {{ vertical-align: middle; }}
        .progress {{ border-radius: 4px; background: #e2e8f0; }}
        @media print {{
            .no-print {{ display: none !important; }}
            .card {{ box-shadow: none !important; border: 1px solid #dee2e6 !important; }}
        }}
    </style>
</head>
<body>

<!-- Confidentiality Banner -->
<div class="confidential-bar">⚠ CONFIDENTIAL — INTERNAL USE ONLY — DO NOT DISTRIBUTE ⚠</div>

<!-- Header -->
<div class="bravo-header">
    <div class="container-fluid">
        <div class="d-flex justify-content-between align-items-start flex-wrap gap-2">
            <div>
                <h1>🛡 Bravo6 Security Report</h1>
                <p class="mb-0 text-light opacity-75">Target: <strong class="text-white">{url}</strong></p>
                <small class="opacity-50">{scan_time} &nbsp;|&nbsp; Duration: {duration}s &nbsp;|&nbsp; Tests: {tests_run}</small>
            </div>
            <button class="btn btn-outline-light btn-sm no-print align-self-center" onclick="window.print()">🖨 Print / Export PDF</button>
        </div>
    </div>
</div>

<div class="container-fluid px-3 px-md-4 py-4">

    <!-- Row 1: Executive Summary + Gauge + Severity Counts -->
    <div class="row g-3 mb-4">

        <!-- Executive Summary -->
        <div class="col-lg-5">
            <div class="card h-100 p-3">
                <h6 class="fw-bold text-uppercase text-muted mb-3" style="font-size:.7rem;letter-spacing:.1em">Executive Summary</h6>
                <p class="mb-1"><strong>Overall Rating:</strong>
                    <span class="badge fs-6" style="background:{_severity_color(grade) if grade in ('A','B','C','D','F') else '#6c757d'}">{grade}</span>
                    <span class="text-muted small"> ({score}/100)</span>
                </p>
                <p class="mb-1"><strong>Actionable findings:</strong> {total_actionable}
                    &nbsp;<span style="color:{SEV_COLORS['critical']}">●</span> {summary_counts['critical']} critical
                    &nbsp;<span style="color:{SEV_COLORS['high']}">●</span> {summary_counts['high']} high
                </p>
                <p class="mb-2"><strong>WAF:</strong> {waf} &nbsp;|&nbsp; <strong>Errors:</strong> {errors_count}</p>
                <hr class="my-2">
                <p class="fw-semibold mb-1">Top Risks:</p>
                <ul class="mb-0 ps-3">{risks_html}</ul>
            </div>
        </div>

        <!-- Score Gauge -->
        <div class="col-lg-2 col-md-4">
            <div class="card h-100 p-3 text-center d-flex flex-column justify-content-center align-items-center">
                <h6 class="fw-bold text-uppercase text-muted mb-2" style="font-size:.7rem;letter-spacing:.1em">Security Score</h6>
                {gauge}
            </div>
        </div>

        <!-- Severity Count Cards -->
        <div class="col-lg-5 col-md-8">
            <div class="row g-2 h-100">
                <div class="col-6"><div class="card stat-card h-100 p-3 text-center" style="border-left-color:{SEV_COLORS['critical']}">
                    <div class="small text-muted mb-1">Critical</div>
                    <div class="fs-2 fw-bold" style="color:{SEV_COLORS['critical']}">{summary_counts['critical']}</div>
                </div></div>
                <div class="col-6"><div class="card stat-card h-100 p-3 text-center" style="border-left-color:{SEV_COLORS['high']}">
                    <div class="small text-muted mb-1">High</div>
                    <div class="fs-2 fw-bold" style="color:{SEV_COLORS['high']}">{summary_counts['high']}</div>
                </div></div>
                <div class="col-6"><div class="card stat-card h-100 p-3 text-center" style="border-left-color:{SEV_COLORS['medium']}">
                    <div class="small text-muted mb-1">Medium</div>
                    <div class="fs-2 fw-bold" style="color:{SEV_COLORS['medium']}">{summary_counts['medium']}</div>
                </div></div>
                <div class="col-6"><div class="card stat-card h-100 p-3 text-center" style="border-left-color:{SEV_COLORS['low']}">
                    <div class="small text-muted mb-1">Low</div>
                    <div class="fs-2 fw-bold" style="color:{SEV_COLORS['low']}">{summary_counts['low']}</div>
                </div></div>
            </div>
        </div>
    </div>

    <!-- Row 2: Charts + Module Scores + TLS Card -->
    <div class="row g-3 mb-4">
        <div class="col-md-4">
            <div class="card p-3 h-100">
                <h6 class="fw-bold text-muted text-uppercase mb-3" style="font-size:.7rem;letter-spacing:.1em">Severity Distribution</h6>
                <canvas id="sevChart" height="220"></canvas>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card p-3 h-100">
                <h6 class="fw-bold text-muted text-uppercase mb-3" style="font-size:.7rem;letter-spacing:.1em">Module Scores</h6>
                {bars}
            </div>
        </div>
        <div class="col-md-4">
            {tls_card}
        </div>
    </div>

    <!-- Findings Table -->
    <div class="card mb-4">
        <div class="card-header d-flex justify-content-between align-items-center flex-wrap gap-2 py-2">
            <strong>🔍 Findings &amp; Priority Matrix</strong>
            <div class="d-flex gap-2 no-print flex-wrap">
                <select class="form-select form-select-sm" id="sevFilter" onchange="filterTable()" style="width:auto">
                    <option value="non-info" selected>Non‑Info (default)</option>
                    <option value="all">All</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                </select>
                <input class="form-control form-control-sm" id="searchBox" placeholder="Search…" oninput="filterTable()" style="width:200px">
                <button class="btn btn-outline-secondary btn-sm" onclick="resetFilters()">Reset</button>
            </div>
        </div>
        <div class="card-body p-0">
            <div class="table-responsive">
                <table class="table table-hover table-sm mb-0" id="findingsTable">
                    <thead class="table-dark">
                        <tr>
                            <th onclick="sortTable(0)">#</th>
                            <th onclick="sortTable(1)">Severity</th>
                            <th onclick="sortTable(2)">Finding</th>
                            <th>Evidence</th>
                            <th>Impact</th>
                            <th>Effort</th>
                            <th onclick="sortTable(6)">Priority</th>
                            <th>Recommendation</th>
                            <th>OWASP</th>
                            <th>CWE</th>
                            <th>PoC</th>
                        </tr>
                    </thead>
                    <tbody>
                        {all_table_rows}
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- TLS Details Section -->
    {tls_details}

    <!-- Tech Stack & Scan Metadata -->
    {tech_card}

    <!-- Recommendations -->
    <div class="card mb-4">
        <div class="card-header"><strong>📋 Consolidated Recommendations</strong></div>
        <div class="card-body">
            <ul class="nav nav-tabs mb-3" role="tablist">
                <li class="nav-item"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#tab-imm" type="button">🔴 Immediate (48h)</button></li>
                <li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#tab-short" type="button">🟠 Short Term (1w)</button></li>
                <li class="nav-item"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#tab-long" type="button">🟡 Medium+ (2w+)</button></li>
            </ul>
            <div class="tab-content">
                <div class="tab-pane fade show active" id="tab-imm"><ul class="list-group list-group-flush">{rec_imm_html}</ul></div>
                <div class="tab-pane fade" id="tab-short"><ul class="list-group list-group-flush">{rec_short_html}</ul></div>
                <div class="tab-pane fade" id="tab-long"><ul class="list-group list-group-flush">{rec_long_html}</ul></div>
            </div>
        </div>
    </div>

    <!-- Passing Checks -->
    <div class="card mb-4">
        <div class="card-header"><strong>✅ Passing Checks</strong></div>
        <ul class="list-group list-group-flush">{pass_html}</ul>
    </div>

    <!-- Test Modules Summary Table -->
    <div class="card mb-4">
        <div class="card-header"><strong>🧪 Test Module Results</strong></div>
        <div class="card-body p-0">
            <div class="table-responsive">
                <table class="table table-sm table-bordered mb-0">
                    <thead class="table-light">
                        <tr><th>Module</th><th>Status</th><th>Severity</th><th>Score</th><th>Summary</th></tr>
                    </thead>
                    <tbody>{test_rows}</tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="text-center text-muted py-3 small">
        Bravo6 Scanner v3.0 &nbsp;|&nbsp; Generated: {scan_time} &nbsp;|&nbsp; 
        <strong class="text-danger">CONFIDENTIAL</strong> — For authorized personnel only
    </footer>

</div><!-- /container -->

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
// ── Charts ──────────────────────────────────────────────────────────────────
const sevCtx = document.getElementById('sevChart');
new Chart(sevCtx, {{
    type: 'doughnut',
    data: {{
        labels: {sev_labels},
        datasets: [{{ data: {sev_data}, backgroundColor: {sev_colors}, borderWidth:2, borderColor:'#fff' }}]
    }},
    options: {{ plugins: {{ legend: {{ position:'bottom', labels:{{ font:{{ size:11 }} }} }} }}, cutout:'65%' }}
}});

// ── Filter & Sort ───────────────────────────────────────────────────────────
function filterTable() {{
    const filter = document.getElementById('sevFilter').value;
    const term = document.getElementById('searchBox').value.toLowerCase();
    document.querySelectorAll('#findingsTable tbody tr').forEach(row => {{
        const sev = row.dataset.sev || '';
        let sevOk = true;
        if (filter === 'non-info') {{
            sevOk = sev !== 'info';
        }} else if (filter === 'info') {{
            sevOk = sev === 'info';
        }} else if (filter !== 'all') {{
            sevOk = sev === filter;
        }}
        const txtOk = !term || row.innerText.toLowerCase().includes(term);
        row.style.display = (sevOk && txtOk) ? '' : 'none';
    }});
}}

function resetFilters() {{
    document.getElementById('sevFilter').value = 'non-info';
    document.getElementById('searchBox').value = '';
    filterTable();
}}

// Initial filtering (hide info rows by default)
filterTable();

let _sortDir = {{}};
function sortTable(col) {{
    const tbody = document.querySelector('#findingsTable tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const dir = (_sortDir[col] = !_sortDir[col]);
    rows.sort((a,b) => {{
        const av = a.cells[col]?.innerText?.trim() || '';
        const bv = b.cells[col]?.innerText?.trim() || '';
        if (col === 0) return dir ? parseInt(av)-parseInt(bv) : parseInt(bv)-parseInt(av);
        return dir ? av.localeCompare(bv) : bv.localeCompare(av);
    }});
    rows.forEach(r => tbody.appendChild(r));
    document.querySelectorAll('#findingsTable thead th').forEach((th,i) => {{
        th.textContent = th.textContent.replace(/ [▲▼]$/,'');
        if (i === col) th.textContent += dir ? ' ▲' : ' ▼';
    }});
}}
</script>
</body>
</html>"""
    return html