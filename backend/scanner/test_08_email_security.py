"""
Bravo6 Security Scanner
Module: test_email_security.py

Checks DNS-based email authentication mechanisms (SPF, DMARC, DKIM) to
assess a domain's exposure to spoofing/phishing via forged "From" headers.

All DNS work happens in dnspython's synchronous resolver, pushed onto the
asyncio default executor so it doesn't block the event loop.
"""

import asyncio
import re
from urllib.parse import urlparse

import dns.resolver
import dns.exception

USER_AGENT = "Bravo6-Scanner/1.0"
DNS_TIMEOUT = 10  # seconds, per query
DKIM_SELECTORS = ["default", "google", "mail", "dkim", "k1", "selector1", "selector2"]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    """Ensure the input has a scheme so urlparse behaves correctly."""
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url):
        url = "https://" + url
    return url


def _extract_root_domain(url: str) -> str:
    """
    Extract the root (registrable-ish) domain from a URL.

    Example: "https://blog.example.com/page" -> "example.com"

    Note: this uses a simple "last two labels" heuristic, except for a small
    set of known multi-part public suffixes (co.uk, com.eg, etc.) where the
    last three labels are kept. It is not a full Public Suffix List
    implementation, but covers the overwhelming majority of real-world
    domains correctly.
    """
    normalized = _normalize_url(url)
    hostname = urlparse(normalized).hostname or ""
    hostname = hostname.lower().strip(".")

    # Strip port if present (defensive, hostname from urlparse shouldn't have it)
    hostname = hostname.split(":")[0]

    labels = hostname.split(".")
    if len(labels) <= 2:
        return hostname

    multi_part_suffixes = {
        "co.uk", "org.uk", "ac.uk", "gov.uk",
        "com.eg", "net.eg", "org.eg", "gov.eg",
        "com.au", "net.au", "org.au",
        "co.jp", "ne.jp",
        "com.br", "com.cn", "com.sg", "com.tr",
    }

    last_two = ".".join(labels[-2:])
    last_three = ".".join(labels[-3:])

    if last_two in multi_part_suffixes and len(labels) >= 3:
        return last_three

    return last_two


def _build_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    resolver.timeout = DNS_TIMEOUT
    return resolver


def _query_txt_sync(name: str):
    """
    Synchronous TXT lookup, run in executor. Returns a list of decoded
    TXT strings, or an empty list if the name has no records / doesn't
    exist / times out.
    """
    resolver = _build_resolver()
    try:
        answer = resolver.resolve(name, "TXT", lifetime=DNS_TIMEOUT)
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []
    except Exception:
        return []

    records = []
    for rdata in answer:
        try:
            # TXT records can be split into multiple quoted strings;
            # dnspython exposes them as a list of bytes in rdata.strings
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


# --------------------------------------------------------------------------
# SPF
# --------------------------------------------------------------------------

async def _check_spf(domain: str) -> dict:
    try:
        txt_records = await _query_txt(domain)
    except Exception as exc:
        return {
            "status": "warning",
            "record": None,
            "severity": "info",
            "issue": f"DNS lookup error: {exc}",
        }

    spf_records = [r for r in txt_records if r.strip().lower().startswith("v=spf1")]

    if not spf_records:
        return {
            "status": "fail",
            "record": None,
            "severity": "high",
            "issue": "No SPF record found — anyone can send email as this domain.",
        }

    # If multiple SPF records exist, that is itself a misconfiguration
    # (RFC 7208 says exactly one should be present), but for severity
    # grading we evaluate the first and note the issue.
    record = spf_records[0]
    multiple_warning = ""
    if len(spf_records) > 1:
        multiple_warning = " Multiple SPF records detected, which is invalid per RFC 7208 and may cause mail validation failures."

    record_lower = record.lower()

    if "+all" in record_lower:
        return {
            "status": "fail",
            "record": record,
            "severity": "critical",
            "issue": "SPF uses '+all', which allows ANY server to send mail as this domain." + multiple_warning,
        }
    elif "?all" in record_lower:
        return {
            "status": "warning",
            "record": record,
            "severity": "medium",
            "issue": "SPF uses '?all' (neutral) — provides no real enforcement." + multiple_warning,
        }
    elif "~all" in record_lower:
        return {
            "status": "warning",
            "record": record,
            "severity": "low",
            "issue": "SPF uses '~all' (softfail) — spoofed mail is flagged but not rejected." + multiple_warning,
        }
    elif "-all" in record_lower:
        return {
            "status": "pass",
            "record": record,
            "severity": "info",
            "issue": "SPF correctly uses '-all' (hardfail)." + multiple_warning if multiple_warning else "",
        }
    else:
        return {
            "status": "warning",
            "record": record,
            "severity": "medium",
            "issue": "SPF record found but has no recognizable 'all' mechanism qualifier." + multiple_warning,
        }


# --------------------------------------------------------------------------
# DMARC
# --------------------------------------------------------------------------

def _parse_dmarc_tag(record: str, tag: str):
    """Extract a tag value (e.g. 'p', 'rua') from a DMARC TXT record."""
    match = re.search(rf"(?:^|;)\s*{re.escape(tag)}\s*=\s*([^;]+)", record, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None


async def _check_dmarc(domain: str) -> dict:
    dmarc_name = f"_dmarc.{domain}"
    try:
        txt_records = await _query_txt(dmarc_name)
    except Exception as exc:
        return {
            "status": "warning",
            "record": None,
            "severity": "info",
            "policy": None,
            "issue": f"DNS lookup error: {exc}",
        }

    dmarc_records = [r for r in txt_records if r.strip().lower().startswith("v=dmarc1")]

    if not dmarc_records:
        return {
            "status": "fail",
            "record": None,
            "severity": "high",
            "policy": None,
            "issue": "No DMARC record found — spoofed mail has no enforcement or reporting policy.",
        }

    record = dmarc_records[0]
    policy = _parse_dmarc_tag(record, "p")
    rua = _parse_dmarc_tag(record, "rua")
    rua_note = "" if rua else " No 'rua=' reporting address configured."

    if policy is None:
        return {
            "status": "warning",
            "record": record,
            "severity": "medium",
            "policy": None,
            "issue": "DMARC record found but no 'p=' policy tag could be parsed." + rua_note,
        }

    policy = policy.lower()

    if policy == "reject":
        return {
            "status": "pass",
            "record": record,
            "severity": "info",
            "policy": policy,
            "issue": rua_note.strip() if rua_note else "",
        }
    elif policy == "quarantine":
        return {
            "status": "warning",
            "record": record,
            "severity": "low",
            "policy": policy,
            "issue": "DMARC policy is 'quarantine' — good, but 'reject' is stronger." + rua_note,
        }
    elif policy == "none":
        return {
            "status": "warning",
            "record": record,
            "severity": "medium",
            "policy": policy,
            "issue": "DMARC policy is 'none' — monitoring only, no enforcement against spoofed mail." + rua_note,
        }
    else:
        return {
            "status": "warning",
            "record": record,
            "severity": "medium",
            "policy": policy,
            "issue": f"DMARC policy '{policy}' is not a recognized value." + rua_note,
        }


# --------------------------------------------------------------------------
# DKIM
# --------------------------------------------------------------------------

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
        return {
            "status": "not_found",
            "selector_found": None,
            "severity": "info",
            "issue": f"DNS lookup error during DKIM probing: {exc}",
        }

    for result in results:
        if result is not None:
            selector, record = result
            key_type_match = re.search(r"k\s*=\s*([a-zA-Z0-9]+)", record, re.IGNORECASE)
            key_type = key_type_match.group(1) if key_type_match else "rsa (default)"
            return {
                "status": "pass",
                "selector_found": selector,
                "severity": "info",
                "key_type": key_type,
                "issue": f"DKIM key found at selector '{selector}'.",
            }

    return {
        "status": "not_found",
        "selector_found": None,
        "severity": "info",
        "issue": (
            "No DKIM record found at common selectors "
            f"({', '.join(DKIM_SELECTORS)}). DKIM may still exist under a "
            "custom selector not checked here."
        ),
    }


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------

_SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _worst_severity(*severities: str) -> str:
    valid = [s for s in severities if s in _SEVERITY_RANK]
    if not valid:
        return "info"
    return max(valid, key=lambda s: _SEVERITY_RANK[s])


def _overall_status(spf: dict, dmarc: dict, dkim: dict) -> str:
    statuses = {spf["status"], dmarc["status"]}
    if "fail" in statuses:
        return "fail"
    if "warning" in statuses:
        return "warning"
    # dkim "not_found" alone (with spf/dmarc passing) shouldn't fail the run,
    # since DKIM may exist under an unchecked selector.
    if statuses == {"pass"}:
        return "pass"
    return "warning"


def _build_description(domain: str, spf: dict, dmarc: dict, dkim: dict) -> str:
    parts = [f"Email authentication posture for {domain}:"]
    parts.append(f"SPF: {spf['status']}" + (f" ({spf['issue']})" if spf.get("issue") else "."))
    parts.append(f"DMARC: {dmarc['status']}" + (f" ({dmarc['issue']})" if dmarc.get("issue") else "."))
    if dkim["status"] == "pass":
        parts.append(f"DKIM: found at selector '{dkim['selector_found']}'.")
    else:
        parts.append("DKIM: not found at common selectors (informational only).")
    return " ".join(parts)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

async def run(url: str) -> dict:
    """
    Check SPF, DMARC, and DKIM DNS records for the domain extracted from
    `url`, to assess exposure to email spoofing.
    """
    try:
        normalized = _normalize_url(url)
        domain = _extract_root_domain(normalized)

        if not domain or "." not in domain:
            return {
                "test_name": "email_security",
                "status": "error",
                "overall_severity": "info",
                "findings": {},
                "title": "Email Security (SPF/DMARC/DKIM) Check",
                "description": f"Could not extract a valid domain from input: '{url}'.",
                "remediation": "Provide a valid domain or URL and re-run the scan.",
            }

        # Run all three checks concurrently — they're independent DNS lookups.
        spf_result, dmarc_result, dkim_result = await asyncio.gather(
            _check_spf(domain),
            _check_dmarc(domain),
            _check_dkim(domain),
        )

        overall_status = _overall_status(spf_result, dmarc_result, dkim_result)
        overall_severity = _worst_severity(
            spf_result["severity"], dmarc_result["severity"], dkim_result["severity"]
        )

        return {
            "test_name": "email_security",
            "status": overall_status,
            "overall_severity": overall_severity,
            "findings": {
                "spf": spf_result,
                "dmarc": dmarc_result,
                "dkim": dkim_result,
            },
            "title": "Email Security (SPF/DMARC/DKIM) Check",
            "description": _build_description(domain, spf_result, dmarc_result, dkim_result),
            "remediation": (
                "Add an SPF record ending in '-all' to explicitly fail "
                "unauthorized senders. Publish a DMARC record at "
                "_dmarc.<domain> with 'p=reject' and an 'rua=' reporting "
                "address. Configure DKIM signing on all outbound mail "
                "servers and publish the corresponding public key under a "
                "known selector."
            ),
        }

    except Exception as exc:
        return {
            "test_name": "email_security",
            "status": "error",
            "overall_severity": "info",
            "findings": {},
            "title": "Email Security (SPF/DMARC/DKIM) Check",
            "description": f"Unexpected error while scanning '{url}': {exc}",
            "remediation": "Re-run the scan; if the error persists, check DNS connectivity and the target domain.",
        }


# --------------------------------------------------------------------------
# Manual test harness
# --------------------------------------------------------------------------

if __name__ == "__main__":
    import json

    async def _main():
        test_targets = [
            "https://google.com",
            "https://github.com",
            "example.com",
            "https://blog.cloudflare.com/some-post",
        ]
        for target in test_targets:
            print(f"\n=== {target} ===")
            result = await run(target)
            print(json.dumps(result, indent=2))

    asyncio.run(_main())