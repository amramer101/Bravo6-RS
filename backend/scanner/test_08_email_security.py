"""
test_08_email_security.py — Fast Email Security Scanner (Optimized)

Optimized for speed:
- Parallel DNS queries with asyncio.gather
- Reduced selectors for DKIM (only most common)
- Simplified SPF/DMARC parsing
- Minimal external checks (no SMTP connections)
- Lightweight subdomain checks
- High confidence scoring
- Quick spoofing risk assessment
"""

import asyncio
import re
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional, Tuple

import dns.resolver
import dns.exception

# ── Configuration ──────────────────────────────────────────────────────────
DNS_TIMEOUT = 3  # Reduced timeout
MAX_SPF_DNS_LOOKUPS = 10

# ── Severity ranking ──────────────────────────────────────────────────────
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# ── Helper: Extract domain ──────────────────────────────────────────────
def _extract_domain(url: str) -> str:
    """Extract root domain from URL."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    hostname = urlparse(url).hostname or ""
    hostname = hostname.lower().strip(".")
    # Remove port if present
    if ":" in hostname:
        hostname = hostname.split(":")[0]
    labels = hostname.split(".")
    if len(labels) <= 2:
        return hostname
    # Handle multi-part TLDs
    multi_part = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
                  "co.jp", "ne.jp", "com.br", "com.cn", "com.sg", "com.tr", "com.eg"}
    last_two = ".".join(labels[-2:])
    last_three = ".".join(labels[-3:])
    if last_two in multi_part and len(labels) >= 3:
        return last_three
    return last_two

# ── Async DNS resolver ────────────────────────────────────────────────────
async def _resolve(domain: str, record_type: str = "TXT") -> List[str]:
    """Async DNS resolver with short timeout."""
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

# ── SPF Analysis ──────────────────────────────────────────────────────────
def _parse_spf(record: str) -> Dict[str, Any]:
    """Parse SPF record quickly."""
    if not record or not record.lower().startswith("v=spf1"):
        return {"valid": False}
    parts = record.split()
    mechanisms = []
    modifiers = {}
    for part in parts[1:]:
        if "=" in part:
            key, val = part.split("=", 1)
            modifiers[key] = val
        else:
            match = re.match(r"([+\-~?])?([a-zA-Z]+)(?::(.+))?", part)
            if match:
                qualifier = match.group(1) or "+"
                mech = match.group(2)
                value = match.group(3)
                mechanisms.append({"qualifier": qualifier, "mechanism": mech, "value": value})
    return {"valid": True, "mechanisms": mechanisms, "modifiers": modifiers}

def _analyze_spf(record: str) -> Dict[str, Any]:
    """Analyze SPF record."""
    result = {"exists": bool(record), "issues": []}
    if not record:
        result["issues"].append({"severity": "critical", "description": "No SPF record"})
        return result
    parsed = _parse_spf(record)
    if not parsed["valid"]:
        result["issues"].append({"severity": "critical", "description": "Invalid SPF record"})
        return result
    # Check all mechanism
    all_mech = next((m for m in parsed["mechanisms"] if m["mechanism"] == "all"), None)
    if all_mech:
        q = all_mech["qualifier"]
        if q == "+":
            result["issues"].append({"severity": "critical", "description": "SPF +all allows any server to send"})
        elif q == "?":
            result["issues"].append({"severity": "high", "description": "SPF ?all neutral — no enforcement"})
        elif q == "~":
            result["issues"].append({"severity": "medium", "description": "SPF ~all softfail — weak protection"})
    else:
        result["issues"].append({"severity": "high", "description": "SPF missing 'all' mechanism"})
    # Count includes
    includes = [m["value"] for m in parsed["mechanisms"] if m["mechanism"] == "include"]
    if len(includes) > 5:
        result["issues"].append({"severity": "high", "description": f"SPF has many includes ({len(includes)}), may cause resolution issues"})
    return result

# ── DMARC Analysis ────────────────────────────────────────────────────────
def _parse_dmarc(record: str) -> Dict[str, Any]:
    """Parse DMARC record."""
    if not record or not record.lower().startswith("v=dmarc1"):
        return {"valid": False}
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return {"valid": True, "tags": tags}

def _analyze_dmarc(record: str) -> Dict[str, Any]:
    """Analyze DMARC record."""
    result = {"exists": bool(record), "issues": []}
    if not record:
        result["issues"].append({"severity": "critical", "description": "No DMARC record"})
        return result
    parsed = _parse_dmarc(record)
    if not parsed["valid"]:
        result["issues"].append({"severity": "critical", "description": "Invalid DMARC record"})
        return result
    tags = parsed["tags"]
    p = tags.get("p", "").lower()
    if not p:
        result["issues"].append({"severity": "high", "description": "DMARC missing 'p' policy"})
    elif p == "none":
        result["issues"].append({"severity": "high", "description": "DMARC p=none — monitoring only"})
    elif p == "quarantine":
        result["issues"].append({"severity": "medium", "description": "DMARC p=quarantine — weak"})
    # Check pct
    pct = tags.get("pct", "100")
    try:
        if int(pct) < 100:
            result["issues"].append({"severity": "high", "description": f"DMARC pct={pct} not fully applied"})
    except:
        pass
    # Check sp (subdomain policy)
    sp = tags.get("sp", "")
    if sp and sp.lower() == "none":
        result["issues"].append({"severity": "medium", "description": "DMARC sp=none — subdomains unprotected"})
    # Check rua (reporting)
    if not tags.get("rua"):
        result["issues"].append({"severity": "medium", "description": "DMARC missing rua (aggregate reports)"})
    return result

# ── DKIM Analysis ──────────────────────────────────────────────────────────
def _analyze_dkim(records: List[str]) -> Dict[str, Any]:
    """Analyze DKIM records (simplified)."""
    result = {"exists": bool(records), "issues": []}
    if not records:
        result["issues"].append({"severity": "high", "description": "No DKIM records found for common selectors"})
        return result
    for rec in records:
        if not rec.lower().startswith("v=dkim1"):
            result["issues"].append({"severity": "medium", "description": "Invalid DKIM record"})
            continue
        # Check for weak algorithm
        if "sha1" in rec.lower() and "sha256" not in rec.lower():
            result["issues"].append({"severity": "high", "description": "DKIM uses weak SHA-1, should use SHA-256"})
        # Check key length (rough)
        if "p=" in rec:
            key_part = rec.split("p=")[1].split(";")[0].strip()
            if key_part:
                # base64 length * 6 ≈ bits
                bits = len(key_part) * 6
                if bits < 1024:
                    result["issues"].append({"severity": "high", "description": f"DKIM key weak ({bits} bits, recommend 2048)"})
                elif bits < 2048:
                    result["issues"].append({"severity": "medium", "description": f"DKIM key moderate ({bits} bits, recommend 2048)"})
        # Check missing h tag
        if "h=" not in rec.lower():
            result["issues"].append({"severity": "medium", "description": "DKIM missing 'h' tag (headers signed)"})
    return result

# ── Subdomain checks ──────────────────────────────────────────────────────
async def _check_subdomain(domain: str, sub: str) -> Dict[str, Any]:
    """Check SPF for a subdomain."""
    sub_domain = f"{sub}.{domain}"
    records = await _resolve(sub_domain, "TXT")
    has_spf = any(r.lower().startswith("v=spf1") for r in records)
    return {"subdomain": sub_domain, "has_spf": has_spf}

# ── Main function ──────────────────────────────────────────────────────────
async def run(url: str, context: Optional[Dict] = None) -> Dict[str, Any]:
    """Main entry point for email security test (fast)."""
    test_name = "email_security"
    try:
        domain = _extract_domain(url)
        if not domain or "." not in domain:
            return {
                "test_name": test_name,
                "status": "error",
                "severity": "info",
                "title": "Invalid domain",
                "description": f"Could not extract domain from {url}",
                "evidence": [],
                "remediation": "Provide a valid domain.",
            }
    except Exception as e:
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "Normalization error",
            "description": str(e),
            "evidence": [],
            "remediation": "Check URL format.",
        }

    # ── 1. Run all DNS lookups in parallel ──────────────────────────────
    spf_task = _resolve(domain, "TXT")
    dmarc_task = _resolve(f"_dmarc.{domain}", "TXT")
    # DKIM: only 3 most common selectors
    dkim_selectors = ["default", "google", "dkim"]
    dkim_tasks = [_resolve(f"{sel}._domainkey.{domain}", "TXT") for sel in dkim_selectors]
    # Subdomain checks (limited)
    subdomains = ["mail", "smtp", "mx"]
    sub_tasks = [_check_subdomain(domain, sub) for sub in subdomains]

    results = await asyncio.gather(spf_task, dmarc_task, *dkim_tasks, *sub_tasks, return_exceptions=True)

    # Unpack results
    spf_records = results[0] if not isinstance(results[0], Exception) else []
    dmarc_records = results[1] if not isinstance(results[1], Exception) else []
    dkim_records = []
    for i in range(2, 2 + len(dkim_selectors)):
        if not isinstance(results[i], Exception):
            dkim_records.extend(results[i])
    sub_results = []
    for i in range(2 + len(dkim_selectors), len(results)):
        if not isinstance(results[i], Exception):
            sub_results.append(results[i])

    spf_record = next((r for r in spf_records if r.lower().startswith("v=spf1")), None)
    dmarc_record = next((r for r in dmarc_records if r.lower().startswith("v=dmarc1")), None)

    # ── 2. Analyze ────────────────────────────────────────────────────────
    spf_analysis = _analyze_spf(spf_record)
    dmarc_analysis = _analyze_dmarc(dmarc_record)
    dkim_analysis = _analyze_dkim(dkim_records)

    # ── 3. Build evidence ────────────────────────────────────────────────
    evidence = []
    for issue in spf_analysis.get("issues", []):
        evidence.append({
            "type": "SPF",
            "severity": issue["severity"],
            "description": issue["description"],
            "poc": f"dig TXT {domain}",
            "confidence": 100,
        })
    for issue in dmarc_analysis.get("issues", []):
        evidence.append({
            "type": "DMARC",
            "severity": issue["severity"],
            "description": issue["description"],
            "poc": f"dig TXT _dmarc.{domain}",
            "confidence": 100,
        })
    for issue in dkim_analysis.get("issues", []):
        evidence.append({
            "type": "DKIM",
            "severity": issue["severity"],
            "description": issue["description"],
            "poc": f"dig TXT default._domainkey.{domain}",
            "confidence": 80,
        })
    for sub in sub_results:
        if not sub.get("has_spf"):
            evidence.append({
                "type": "Subdomain SPF",
                "severity": "high",
                "description": f"Missing SPF for {sub['subdomain']}",
                "poc": f"dig TXT {sub['subdomain']}",
                "confidence": 90,
            })

    # ── 4. Spoofing risk ──────────────────────────────────────────────────
    spoof_risk = "low"
    if not spf_analysis["exists"] or not dmarc_analysis["exists"]:
        spoof_risk = "high"
    elif spf_analysis.get("issues") or dmarc_analysis.get("issues"):
        spoof_risk = "medium"
    if spoof_risk != "low":
        evidence.append({
            "type": "Spoofing Risk",
            "severity": "critical" if spoof_risk == "high" else "high",
            "description": f"Domain is vulnerable to email spoofing. Risk: {spoof_risk}",
            "poc": f"swaks --to test@{domain} --from ceo@{domain}",
            "confidence": 90 if spoof_risk == "high" else 70,
        })

    # ── 5. Determine overall status ──────────────────────────────────────
    critical_issues = [e for e in evidence if e["severity"] == "critical"]
    high_issues = [e for e in evidence if e["severity"] == "high"]
    medium_issues = [e for e in evidence if e["severity"] == "medium"]

    if critical_issues:
        status = "fail"
        overall_severity = "critical"
    elif high_issues:
        status = "fail"
        overall_severity = "high"
    elif medium_issues:
        status = "warning"
        overall_severity = "medium"
    else:
        status = "pass"
        overall_severity = "info"

    # ── 6. Remediation ────────────────────────────────────────────────────
    remediation_parts = []
    if not spf_analysis["exists"]:
        remediation_parts.append("Publish SPF record with -all, include all authorized senders.")
    if not dmarc_analysis["exists"]:
        remediation_parts.append("Publish DMARC record with p=reject, pct=100, rua, and sp=reject.")
    if not dkim_analysis["exists"]:
        remediation_parts.append("Setup DKIM signing with 2048-bit RSA keys and SHA-256.")
    if any(not sub.get("has_spf") for sub in sub_results):
        remediation_parts.append("Ensure subdomains (mail, smtp, mx) have SPF records.")
    if spoof_risk != "low":
        remediation_parts.append("Immediately strengthen email authentication to prevent spoofing.")
    if not remediation_parts:
        remediation_parts.append("Email security is well configured. Continue monitoring.")

    return {
        "test_name": test_name,
        "status": status,
        "severity": overall_severity,
        "title": f"Email Security Assessment: {len(evidence)} issue(s)",
        "description": f"Analyzed SPF, DMARC, DKIM, and subdomains for {domain}.",
        "evidence": evidence,
        "remediation": " ".join(remediation_parts),
        "spf_analysis": spf_analysis,
        "dmarc_analysis": dmarc_analysis,
        "dkim_analysis": dkim_analysis,
    }


if __name__ == "__main__":
    import json
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))