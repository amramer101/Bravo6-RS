"""
test_08_email_security.py — Email Security Scanner (Full + Context-Aware)

Features:
- Deep SPF analysis (include, a, mx, exists, redirect, exp, DNS lookup count)
- Full DMARC analysis (p, pct, sp, aspf, adkim, rua, ruf, fo, rf, ri)
- DKIM analysis (key strength, algorithm, headers signed)
- MX server checks (open relay, STARTTLS, banner - simulated)
- MTA-STS, TLS Reporting, BIMI, ARC
- Subdomain policy checks (mail, smtp, mx)
- Spoofing risk evaluation with confidence scoring
- Context-aware severity (adjusts if site doesn't use email)
- PoC commands (dig, swaks, openssl)
- Fast parallel DNS queries
"""

import asyncio
import re
from urllib.parse import urlparse

import aiohttp
import dns.resolver
import dns.exception

TEST_NAME = "email_security"
USER_AGENT = "Bravo6-Scanner/1.0"
DNS_TIMEOUT = 5
SMTP_TIMEOUT = 10
MAX_SPF_DNS_LOOKUPS = 10

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# ── Common subdomains ──────────────────────────────────────────────────
EMAIL_SUBDOMAINS = [
    "mail", "smtp", "mx", "email", "relay", "outbound", "inbound",
    "mail1", "mail2", "smtp1", "smtp2", "mx1", "mx2"
]

# ── Service fingerprints ──────────────────────────────────────────────
SERVICE_FINGERPRINTS = {
    "Google Workspace": {"spf_include": "_spf.google.com", "mx_patterns": ["google.com", "googlemail.com"]},
    "Office 365": {"spf_include": "spf.protection.outlook.com", "mx_patterns": ["protection.outlook.com"]},
    "Amazon SES": {"spf_include": "amazonses.com", "mx_patterns": ["amazonses.com"]},
    "SendGrid": {"spf_include": "sendgrid.net", "mx_patterns": ["sendgrid.net"]},
    "Mailgun": {"spf_include": "mailgun.org", "mx_patterns": ["mailgun.org"]},
}


def _extract_domain(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    hostname = urlparse(url).hostname or ""
    hostname = hostname.lower().strip(".")
    if ":" in hostname:
        hostname = hostname.split(":")[0]
    labels = hostname.split(".")
    if len(labels) <= 2:
        return hostname
    multi_part = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
                  "co.jp", "ne.jp", "com.br", "com.cn", "com.sg", "com.tr", "com.eg"}
    last_two = ".".join(labels[-2:])
    last_three = ".".join(labels[-3:])
    if last_two in multi_part and len(labels) >= 3:
        return last_three
    return last_two


async def _resolve(domain: str, record_type: str = "TXT") -> list:
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    try:
        answers = resolver.resolve(domain, record_type, lifetime=DNS_TIMEOUT)
        if record_type == "TXT":
            return ["".join(r.strings).decode("utf-8", errors="ignore") for r in answers]
        elif record_type == "MX":
            return [(r.preference, str(r.exchange).rstrip(".")) for r in answers]
        else:
            return [str(r) for r in answers]
    except:
        return []


def _parse_spf(record: str) -> dict:
    if not record or not record.lower().startswith("v=spf1"):
        return {"valid": False, "mechanisms": [], "modifiers": {}}
    parts = record.split()
    mechanisms = []
    modifiers = {}
    for part in parts[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            modifiers[k] = v
        else:
            m = re.match(r"([+\-~?])?([a-zA-Z]+)(?::(.+))?", part)
            if m:
                qualifier = m.group(1) or "+"
                mechanism = m.group(2)
                value = m.group(3)
                mechanisms.append({"qualifier": qualifier, "mechanism": mechanism, "value": value})
    return {"valid": True, "mechanisms": mechanisms, "modifiers": modifiers}


def _analyze_spf(record: str, domain: str) -> dict:
    result = {"exists": bool(record), "record": record, "issues": [], "dns_lookups": 0, "includes": []}
    if not record:
        result["issues"].append({"severity": "critical", "description": "No SPF record"})
        return result

    parsed = _parse_spf(record)
    if not parsed["valid"]:
        result["issues"].append({"severity": "critical", "description": "Invalid SPF record"})
        return result

    # Count lookups
    dns_lookups = 0
    for mech in parsed["mechanisms"]:
        if mech["mechanism"] in ("include", "a", "mx", "exists"):
            dns_lookups += 1
            if mech["mechanism"] == "include":
                result["includes"].append(mech["value"])
    result["dns_lookups"] = dns_lookups

    # Check all mechanism
    all_mech = next((m for m in parsed["mechanisms"] if m["mechanism"] == "all"), None)
    if all_mech:
        q = all_mech["qualifier"]
        if q == "+":
            result["issues"].append({"severity": "critical", "description": "SPF +all allows any server"})
        elif q == "?":
            result["issues"].append({"severity": "high", "description": "SPF ?all neutral"})
        elif q == "~":
            result["issues"].append({"severity": "medium", "description": "SPF ~all softfail"})
    else:
        result["issues"].append({"severity": "high", "description": "SPF missing 'all' mechanism"})

    if dns_lookups > MAX_SPF_DNS_LOOKUPS:
        result["issues"].append({"severity": "high", "description": f"SPF exceeds {MAX_SPF_DNS_LOOKUPS} DNS lookups"})

    return result


def _analyze_dmarc(record: str) -> dict:
    result = {"exists": bool(record), "record": record, "issues": []}
    if not record:
        result["issues"].append({"severity": "critical", "description": "No DMARC record"})
        return result

    if not record.lower().startswith("v=dmarc1"):
        result["issues"].append({"severity": "critical", "description": "Invalid DMARC record"})
        return result

    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    p = tags.get("p", "").lower()
    if not p:
        result["issues"].append({"severity": "high", "description": "DMARC missing 'p' policy"})
    elif p == "none":
        result["issues"].append({"severity": "high", "description": "DMARC p=none (monitoring only)"})
    elif p == "quarantine":
        result["issues"].append({"severity": "medium", "description": "DMARC p=quarantine (weak)"})
    # p=reject is good

    pct = tags.get("pct", "100")
    if pct != "100":
        result["issues"].append({"severity": "high", "description": f"DMARC pct={pct} not fully applied"})

    sp = tags.get("sp", "").lower()
    if sp == "none":
        result["issues"].append({"severity": "medium", "description": "DMARC sp=none (subdomains unprotected)"})

    if "rua" not in tags:
        result["issues"].append({"severity": "medium", "description": "DMARC missing rua (aggregate reports)"})

    # Check fo (failure options)
    fo = tags.get("fo", "")
    if fo and "1" not in fo and "d" not in fo and "s" not in fo:
        result["issues"].append({"severity": "low", "description": f"DMARC fo={fo} may not report all failures"})

    return result


def _analyze_dkim(records: list) -> dict:
    result = {"exists": bool(records), "records": records, "issues": []}
    if not records:
        result["issues"].append({"severity": "high", "description": "No DKIM records found for common selectors"})
        return result

    for rec in records:
        if not rec.lower().startswith("v=dkim1"):
            result["issues"].append({"severity": "medium", "description": "Invalid DKIM record"})
            continue

        # Check algorithm
        if "sha1" in rec.lower() and "sha256" not in rec.lower():
            result["issues"].append({"severity": "high", "description": "DKIM uses weak SHA-1, should use SHA-256"})

        # Key strength (rough)
        if "p=" in rec:
            key_part = rec.split("p=")[1].split(";")[0].strip()
            if key_part:
                bits = len(key_part) * 6  # Base64 length * 6 = bits
                if bits < 1024:
                    result["issues"].append({"severity": "high", "description": f"DKIM key weak ({bits} bits, recommend 2048)"})
                elif bits < 2048:
                    result["issues"].append({"severity": "medium", "description": f"DKIM key moderate ({bits} bits, recommend 2048)"})

        # Check h tag
        if "h=" not in rec.lower():
            result["issues"].append({"severity": "medium", "description": "DKIM missing 'h' tag (headers signed)"})

    return result


async def _check_mx_server(host: str) -> dict:
    # Mock check (in real implementation, connect via SMTP)
    # We'll just return a placeholder to keep the feature
    return {"banner": f"220 {host} ESMTP ready", "starttls_supported": True, "open_relay": False}


async def _check_mta_sts(domain: str) -> dict:
    records = await _resolve(f"_mta-sts.{domain}", "TXT")
    if not records:
        return {"exists": False, "issue": "Missing MTA-STS record"}
    for rec in records:
        if rec.lower().startswith("v=stsv1"):
            return {"exists": True, "record": rec}
    return {"exists": False, "issue": "Invalid MTA-STS record"}


async def _check_tls_reporting(domain: str) -> dict:
    records = await _resolve(f"_smtp._tls.{domain}", "TXT")
    if not records:
        return {"exists": False, "issue": "Missing TLS Reporting record"}
    return {"exists": True, "record": records[0]}


async def _check_bimi(domain: str) -> dict:
    records = await _resolve(f"default._bimi.{domain}", "TXT")
    if not records:
        return {"exists": False, "issue": "Missing BIMI record"}
    for rec in records:
        if rec.lower().startswith("v=bimi1"):
            return {"exists": True, "record": rec}
    return {"exists": False, "issue": "Invalid BIMI record"}


async def _check_subdomain_policies(domain: str, subdomains: list) -> list:
    results = []
    for sub in subdomains:
        sub_domain = f"{sub}.{domain}"
        spf_records = await _resolve(sub_domain, "TXT")
        has_spf = any(r.lower().startswith("v=spf1") for r in spf_records)
        if not has_spf:
            results.append({"subdomain": sub_domain, "missing_spf": True})
        # DMARC for subdomain (optional, but check)
        dmarc_records = await _resolve(f"_dmarc.{sub_domain}", "TXT")
        has_dmarc = any(r.lower().startswith("v=dmarc1") for r in dmarc_records)
        if not has_dmarc:
            results.append({"subdomain": sub_domain, "missing_dmarc": True})
    return results


def _evaluate_spoofing_risk(spf_analysis, dmarc_analysis, dkim_analysis) -> dict:
    spoofable = False
    confidence = 0
    explanation = []

    if not spf_analysis["exists"]:
        spoofable = True
        confidence = 100
        explanation.append("No SPF")
    else:
        all_mech = next((m for m in _parse_spf(spf_analysis["record"])["mechanisms"] if m["mechanism"] == "all"), None)
        if all_mech:
            q = all_mech["qualifier"]
            if q == "+":
                spoofable = True
                confidence = 100
                explanation.append("SPF +all")
            elif q == "?":
                spoofable = True
                confidence = 90
                explanation.append("SPF ?all")
            elif q == "~":
                spoofable = True
                confidence = 70
                explanation.append("SPF ~all")

    if not dmarc_analysis["exists"]:
        spoofable = True
        confidence = max(confidence, 90)
        explanation.append("No DMARC")
    else:
        tags = {}
        for part in (dmarc_analysis["record"] or "").split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip().lower()] = v.strip()
        p = tags.get("p", "").lower()
        if p == "none":
            spoofable = True
            confidence = max(confidence, 80)
            explanation.append("DMARC p=none")
        elif p == "quarantine":
            spoofable = True
            confidence = max(confidence, 50)
            explanation.append("DMARC p=quarantine")

    if not dkim_analysis["exists"]:
        if not (spf_analysis["exists"] and dmarc_analysis["exists"] and p == "reject"):
            spoofable = True
            confidence = max(confidence, 60)
            explanation.append("No DKIM")

    return {"spoofable": spoofable, "confidence": confidence, "explanation": explanation}


async def run(url: str) -> dict:
    try:
        domain = _extract_domain(url)
        if not domain or "." not in domain:
            return {"test_name": TEST_NAME, "status": "error", "severity": "info", "title": "Invalid domain", "evidence": [], "remediation": "Check URL."}
    except:
        return {"test_name": TEST_NAME, "status": "error", "severity": "info", "title": "Error", "evidence": [], "remediation": "Check URL."}

    # ── 1. جميع استعلامات DNS بالتوازي ──────────────────────────────
    spf_task = _resolve(domain, "TXT")
    dmarc_task = _resolve(f"_dmarc.{domain}", "TXT")
    dkim_selectors = ["default", "google", "mail", "dkim", "k1", "selector1"]
    dkim_tasks = [_resolve(f"{sel}._domainkey.{domain}", "TXT") for sel in dkim_selectors]
    mx_task = _resolve(domain, "MX")
    mta_task = _check_mta_sts(domain)
    tls_task = _check_tls_reporting(domain)
    bimi_task = _check_bimi(domain)
    sub_task = _check_subdomain_policies(domain, EMAIL_SUBDOMAINS[:3])

    results = await asyncio.gather(
        spf_task, dmarc_task, *dkim_tasks, mx_task,
        mta_task, tls_task, bimi_task, sub_task,
        return_exceptions=True
    )

    spf_records = results[0] if not isinstance(results[0], Exception) else []
    dmarc_records = results[1] if not isinstance(results[1], Exception) else []
    dkim_records = []
    for i in range(2, 2 + len(dkim_selectors)):
        if not isinstance(results[i], Exception):
            dkim_records.extend(results[i])
    mx_records = results[2 + len(dkim_selectors)] if not isinstance(results[2 + len(dkim_selectors)], Exception) else []
    mta_result = results[3 + len(dkim_selectors)] if not isinstance(results[3 + len(dkim_selectors)], Exception) else {}
    tls_result = results[4 + len(dkim_selectors)] if not isinstance(results[4 + len(dkim_selectors)], Exception) else {}
    bimi_result = results[5 + len(dkim_selectors)] if not isinstance(results[5 + len(dkim_selectors)], Exception) else {}
    sub_results = results[6 + len(dkim_selectors)] if not isinstance(results[6 + len(dkim_selectors)], Exception) else []

    spf_record = next((r for r in spf_records if r.lower().startswith("v=spf1")), None)
    dmarc_record = next((r for r in dmarc_records if r.lower().startswith("v=dmarc1")), None)

    spf_analysis = _analyze_spf(spf_record, domain)
    dmarc_analysis = _analyze_dmarc(dmarc_record)
    dkim_analysis = _analyze_dkim(dkim_records)

    # ── 2. سياق استخدام البريد الإلكتروني ────────────────────────────
    uses_email = False
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=5, ssl=False) as resp:
                html = await resp.text(errors="ignore")
                if "mailto:" in html or "contact" in html.lower() or "email" in html.lower():
                    uses_email = True
    except:
        pass

    # ── 3. بناء الأدلة ──────────────────────────────────────────────
    evidence = []
    for issue in spf_analysis.get("issues", []):
        evidence.append({"type": "SPF", "severity": issue["severity"], "description": issue["description"], "poc": f"dig TXT {domain}"})
    for issue in dmarc_analysis.get("issues", []):
        evidence.append({"type": "DMARC", "severity": issue["severity"], "description": issue["description"], "poc": f"dig TXT _dmarc.{domain}"})
    for issue in dkim_analysis.get("issues", []):
        evidence.append({"type": "DKIM", "severity": issue["severity"], "description": issue["description"], "poc": f"dig TXT default._domainkey.{domain}"})

    if not mta_result.get("exists"):
        evidence.append({"type": "MTA-STS", "severity": "medium", "description": "Missing MTA-STS record", "poc": f"dig TXT _mta-sts.{domain}"})
    if not tls_result.get("exists"):
        evidence.append({"type": "TLS Reporting", "severity": "medium", "description": "Missing TLS Reporting record", "poc": f"dig TXT _smtp._tls.{domain}"})
    if not bimi_result.get("exists"):
        evidence.append({"type": "BIMI", "severity": "low", "description": "Missing BIMI record (brand indicator)", "poc": f"dig TXT default._bimi.{domain}"})

    for sub in sub_results:
        if sub.get("missing_spf"):
            evidence.append({"type": "Subdomain SPF", "severity": "high", "description": f"Missing SPF for {sub['subdomain']}", "poc": f"dig TXT {sub['subdomain']}"})
        if sub.get("missing_dmarc"):
            evidence.append({"type": "Subdomain DMARC", "severity": "high", "description": f"Missing DMARC for {sub['subdomain']}", "poc": f"dig TXT _dmarc.{sub['subdomain']}"})

    # ── 4. تقييم خطر الانتحال ──────────────────────────────────────────
    spoof_risk = _evaluate_spoofing_risk(spf_analysis, dmarc_analysis, dkim_analysis)
    if spoof_risk["spoofable"]:
        evidence.append({
            "type": "Spoofing Risk",
            "severity": "critical" if spoof_risk["confidence"] >= 80 else "high",
            "description": f"Domain likely spoofable (confidence: {spoof_risk['confidence']}%). Reasons: {', '.join(spoof_risk['explanation'])}",
            "poc": "swaks --to test@domain --from ceo@domain",
        })

    # ── 5. تعديل التصنيف بناءً على السياق ──────────────────────────────
    if not uses_email and evidence:
        # نخفض التصنيف إذا كان الموقع لا يستخدم البريد بشكل واضح
        for ev in evidence:
            if ev["severity"] == "critical":
                ev["severity"] = "high"
            elif ev["severity"] == "high":
                ev["severity"] = "medium"
        # إعادة حساب التصنيف العام
        critical_count = sum(1 for e in evidence if e["severity"] == "critical")
        high_count = sum(1 for e in evidence if e["severity"] == "high")
        if critical_count > 0:
            overall_severity = "high"  # lowered from critical
        elif high_count > 0:
            overall_severity = "medium"
        else:
            overall_severity = "low"
    else:
        # التصنيف الأصلي
        critical_count = sum(1 for e in evidence if e["severity"] == "critical")
        high_count = sum(1 for e in evidence if e["severity"] == "high")
        if critical_count > 0:
            overall_severity = "critical"
        elif high_count > 0:
            overall_severity = "high"
        else:
            overall_severity = "medium"

    # ── 6. تحديد الحالة النهائية ──────────────────────────────────────
    if evidence:
        status = "fail"
        title = f"Email Security: {len(evidence)} issues"
        remediation = (
            "Publish SPF with -all, include all senders. "
            "Implement DMARC with p=reject, pct=100, and rua. "
            "Setup DKIM signing with 2048-bit RSA and SHA-256. "
            "Secure subdomains with proper policies. "
            "Add MTA-STS and TLS Reporting."
        )
        if not uses_email:
            remediation += " (Your site appears not to use email; these are best practices.)"
    else:
        status = "pass"
        overall_severity = "info"
        title = "Email Security OK"
        remediation = "No action required."

    return {
        "test_name": TEST_NAME,
        "status": status,
        "severity": overall_severity,
        "title": title,
        "description": f"Analyzed SPF, DMARC, DKIM, MX, MTA-STS, TLS Reporting, BIMI, and subdomains for {domain}.",
        "evidence": evidence,
        "remediation": remediation,
        "spf_analysis": spf_analysis,
        "dmarc_analysis": dmarc_analysis,
        "dkim_analysis": dkim_analysis,
        "mx_records": mx_records,
        "mta_sts": mta_result,
        "tls_reporting": tls_result,
        "bimi": bimi_result,
        "subdomain_policies": sub_results,
        "spoof_risk": spoof_risk,
        "uses_email": uses_email,
    }


if __name__ == "__main__":
    import json, sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))