"""
test_08_email_security.py — Advanced Email Security (SPF/DMARC/DKIM)

Upgraded:
- Provides dig/nslookup commands as PoC for each record.
- Adds confidence scoring based on record strength.
- Evaluates DMARC policy and reporting.
- Offers actionable exploitation scenarios (spoofing).
"""

import asyncio
import re
from urllib.parse import urlparse

import dns.resolver
import dns.exception

USER_AGENT = "Bravo6-Scanner/1.0"
DNS_TIMEOUT = 10
DKIM_SELECTORS = ["default", "google", "mail", "dkim", "k1", "selector1", "selector2"]

def _normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url):
        url = "https://" + url
    return url

def _extract_root_domain(url: str) -> str:
    normalized = _normalize_url(url)
    hostname = urlparse(normalized).hostname or ""
    hostname = hostname.lower().strip(".")
    hostname = hostname.split(":")[0]
    labels = hostname.split(".")
    if len(labels) <= 2:
        return hostname
    multi_part_suffixes = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.eg", "net.eg", "org.eg", "gov.eg", "com.au", "net.au", "org.au", "co.jp", "ne.jp", "com.br", "com.cn", "com.sg", "com.tr"}
    last_two = ".".join(labels[-2:])
    last_three = ".".join(labels[-3:])
    if last_two in multi_part_suffixes and len(labels) >= 3:
        return last_three
    return last_two

def _build_resolver():
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    resolver.timeout = DNS_TIMEOUT
    return resolver

def _query_txt_sync(name: str):
    resolver = _build_resolver()
    try:
        answer = resolver.resolve(name, "TXT", lifetime=DNS_TIMEOUT)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []
    records = []
    for rdata in answer:
        try:
            joined = b"".join(rdata.strings).decode("utf-8", errors="replace")
            records.append(joined)
        except Exception:
            try:
                records.append(str(rdata))
            except Exception:
                continue
    return records

async def _query_txt(name: str):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _query_txt_sync, name)

def _build_dig_command(record_type: str, name: str):
    return f"dig {record_type} {name}"

# SPF
async def _check_spf(domain: str) -> dict:
    try:
        txt_records = await _query_txt(domain)
    except Exception as exc:
        return {"status": "warning", "record": None, "severity": "info", "issue": f"DNS lookup error: {exc}", "confidence": 50, "poc": _build_dig_command("TXT", domain)}

    spf_records = [r for r in txt_records if r.strip().lower().startswith("v=spf1")]
    if not spf_records:
        return {"status": "fail", "record": None, "severity": "high", "issue": "No SPF record found — anyone can spoof this domain.", "confidence": 100, "poc": _build_dig_command("TXT", domain)}

    record = spf_records[0]
    multiple_warning = " Multiple SPF records detected (invalid)." if len(spf_records) > 1 else ""
    record_lower = record.lower()
    confidence = 100
    if "+all" in record_lower:
        return {"status": "fail", "record": record, "severity": "critical", "issue": "SPF uses '+all' allowing any server to send." + multiple_warning, "confidence": 100, "poc": f"dig TXT {domain}"}
    elif "?all" in record_lower:
        return {"status": "warning", "record": record, "severity": "medium", "issue": "SPF uses '?all' (neutral) — no enforcement." + multiple_warning, "confidence": 80, "poc": f"dig TXT {domain}"}
    elif "~all" in record_lower:
        return {"status": "warning", "record": record, "severity": "low", "issue": "SPF uses '~all' (softfail) — flagged but not rejected." + multiple_warning, "confidence": 60, "poc": f"dig TXT {domain}"}
    elif "-all" in record_lower:
        return {"status": "pass", "record": record, "severity": "info", "issue": multiple_warning.strip(), "confidence": 100, "poc": f"dig TXT {domain}"}
    else:
        return {"status": "warning", "record": record, "severity": "medium", "issue": "SPF has no clear 'all' mechanism." + multiple_warning, "confidence": 50, "poc": f"dig TXT {domain}"}

# DMARC
def _parse_dmarc_tag(record: str, tag: str):
    match = re.search(rf"(?:^|;)\s*{re.escape(tag)}\s*=\s*([^;]+)", record, re.IGNORECASE)
    return match.group(1).strip() if match else None

async def _check_dmarc(domain: str) -> dict:
    dmarc_name = f"_dmarc.{domain}"
    try:
        txt_records = await _query_txt(dmarc_name)
    except Exception as exc:
        return {"status": "warning", "record": None, "severity": "info", "policy": None, "issue": f"DNS lookup error: {exc}", "confidence": 50, "poc": _build_dig_command("TXT", dmarc_name)}

    dmarc_records = [r for r in txt_records if r.strip().lower().startswith("v=dmarc1")]
    if not dmarc_records:
        return {"status": "fail", "record": None, "severity": "high", "policy": None, "issue": "No DMARC record found — no enforcement/reporting.", "confidence": 100, "poc": f"dig TXT _dmarc.{domain}"}

    record = dmarc_records[0]
    policy = _parse_dmarc_tag(record, "p")
    rua = _parse_dmarc_tag(record, "rua")
    ruf = _parse_dmarc_tag(record, "ruf")
    rua_note = "" if rua else " No 'rua' reporting address."
    confidence = 100

    if policy is None:
        return {"status": "warning", "record": record, "severity": "medium", "policy": None, "issue": "DMARC record lacks 'p=' tag." + rua_note, "confidence": 80, "poc": f"dig TXT _dmarc.{domain}"}

    policy_lower = policy.lower()
    if policy_lower == "reject":
        return {"status": "pass", "record": record, "severity": "info", "policy": policy, "issue": f"DMARC policy 'reject' with rua={rua or 'missing'}." + (", ruf=" + ruf if ruf else ""), "confidence": 100, "poc": f"dig TXT _dmarc.{domain}"}
    elif policy_lower == "quarantine":
        return {"status": "warning", "record": record, "severity": "low", "policy": policy, "issue": "DMARC policy 'quarantine' — good but 'reject' is stronger." + rua_note, "confidence": 80, "poc": f"dig TXT _dmarc.{domain}"}
    elif policy_lower == "none":
        return {"status": "warning", "record": record, "severity": "medium", "policy": policy, "issue": "DMARC policy 'none' — monitoring only." + rua_note, "confidence": 90, "poc": f"dig TXT _dmarc.{domain}"}
    else:
        return {"status": "warning", "record": record, "severity": "medium", "policy": policy, "issue": f"Unknown DMARC policy '{policy}'." + rua_note, "confidence": 70, "poc": f"dig TXT _dmarc.{domain}"}

# DKIM
async def _check_dkim(domain: str) -> dict:
    async def probe(selector: str):
        name = f"{selector}._domainkey.{domain}"
        try:
            records = await _query_txt(name)
        except Exception:
            return None
        for r in records:
            if "v=dkim1" in r.lower() or "p=" in r.lower():
                return selector, r
        return None

    try:
        results = await asyncio.gather(*(probe(s) for s in DKIM_SELECTORS))
    except Exception as exc:
        return {"status": "not_found", "selector_found": None, "severity": "info", "issue": f"DKIM lookup error: {exc}", "confidence": 50, "poc": f"dig TXT default._domainkey.{domain}"}

    for result in results:
        if result is not None:
            selector, record = result
            key_type_match = re.search(r"k\s*=\s*([a-zA-Z0-9]+)", record, re.IGNORECASE)
            key_type = key_type_match.group(1) if key_type_match else "rsa (default)"
            return {"status": "pass", "selector_found": selector, "severity": "info", "key_type": key_type, "issue": f"DKIM key found at '{selector}'.", "confidence": 100, "poc": f"dig TXT {selector}._domainkey.{domain}"}

    return {"status": "not_found", "selector_found": None, "severity": "info", "issue": f"No DKIM at common selectors ({', '.join(DKIM_SELECTORS)}).", "confidence": 80, "poc": f"dig TXT default._domainkey.{domain}"}

# Aggregation
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
def _worst_severity(*severities: str) -> str:
    valid = [s for s in severities if s and s in _SEVERITY_RANK]
    if not valid:
        return "info"
    return max(valid, key=lambda s: _SEVERITY_RANK[s])

def _overall_status(spf, dmarc, dkim) -> str:
    statuses = {spf["status"], dmarc["status"]}
    if "fail" in statuses:
        return "fail"
    if "warning" in statuses:
        return "warning"
    if statuses == {"pass"}:
        return "pass"
    return "warning"

async def run(url: str) -> dict:
    try:
        normalized = _normalize_url(url)
        domain = _extract_root_domain(normalized)
        if not domain or "." not in domain:
            return {
                "test_name": "email_security",
                "status": "error",
                "severity": "info",
                "title": "Email Security Check",
                "description": f"Invalid domain from URL: '{url}'",
                "remediation": "Provide a valid domain.",
                "findings": {},
                "evidence": []
            }

        spf, dmarc, dkim = await asyncio.gather(_check_spf(domain), _check_dmarc(domain), _check_dkim(domain))
        overall_status = _overall_status(spf, dmarc, dkim)
        overall_severity = _worst_severity(spf.get("severity"), dmarc.get("severity"), dkim.get("severity")) or "info"

        evidence = [
            {"type": "SPF", "status": spf["status"], "issue": spf.get("issue", ""), "poc": spf.get("poc", ""), "confidence": spf.get("confidence", 100)},
            {"type": "DMARC", "status": dmarc["status"], "issue": dmarc.get("issue", ""), "poc": dmarc.get("poc", ""), "confidence": dmarc.get("confidence", 100)},
            {"type": "DKIM", "status": dkim["status"], "issue": dkim.get("issue", ""), "poc": dkim.get("poc", ""), "confidence": dkim.get("confidence", 100)}
        ]

        return {
            "test_name": "email_security",
            "status": overall_status,
            "severity": overall_severity,
            "title": f"Email Security (SPF/DMARC/DKIM) — {overall_status}",
            "description": f"Email authentication for {domain}: SPF={spf['status']}, DMARC={dmarc['status']}, DKIM={dkim['status']}.",
            "evidence": evidence,
            "remediation": "Set SPF to '-all', DMARC to 'p=reject' with rua, and publish DKIM keys."
        }

    except Exception as e:
        return {
            "test_name": "email_security",
            "status": "error",
            "severity": "info",
            "title": "Email Security Check",
            "description": f"Unexpected error: {e}",
            "remediation": "Check DNS connectivity.",
            "evidence": []
        }

if __name__ == "__main__":
    import json
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))