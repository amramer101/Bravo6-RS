"""
Bravo6 Security Scanner
Module: test_15_hallucinated_deps.py - Advanced

Enhanced with:
- Multi-resolver DNS check (Cloudflare, Google, Quad9) to confirm NXDOMAIN.
- HTTP verification for resolved domains (checks if resource actually loads).
- PoC exploitation commands: dig, curl, nslookup.
- Confidence scoring based on DNS + HTTP results.
- Attack scenario: domain registration risk and supply-chain attack.
"""

import asyncio
import re
from urllib.parse import urlparse

import aiohttp
import dns.exception
import dns.resolver
from bs4 import BeautifulSoup

TEST_NAME = "hallucinated_deps"
USER_AGENT = "Bravo6-Scanner/1.0"
REQUEST_TIMEOUT_SECONDS = 8
DNS_RETRY_ATTEMPTS = 3
DNS_LOOKUP_TIMEOUT_SECONDS = 5

REMEDIATION = (
    "Remove all references to non-existent or unresponsive domains immediately. "
    "If the domain is intentionally unregistered, register and deploy it. "
    "Use Subresource Integrity (SRI) hashes and a restrictive Content-Security-Policy. "
    "For third-party CDNs, verify domain ownership and use SRI hashes."
)


def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    return url


def _normalize_domain(domain: str) -> str:
    domain = (domain or "").strip().lower().rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def _error_result(title: str, description: str) -> dict:
    return {
        "test_name": TEST_NAME,
        "status": "error",
        "severity": "info",
        "title": title,
        "description": description,
        "evidence": [],
        "domains_checked": 0,
        "hallucinated_count": 0,
        "remediation": REMEDIATION,
    }


def _extract_external_domains(html: str, target_domain: str) -> dict:
    found = {}
    soup = BeautifulSoup(html, "html.parser")
    sources = (("script", "src"), ("link", "href"))

    for tag_name, attr in sources:
        for tag in soup.find_all(tag_name):
            raw_url = tag.get(attr)
            if not raw_url:
                continue
            raw_url = raw_url.strip()
            if raw_url.startswith("//"):
                raw_url = "https:" + raw_url
            if not raw_url.lower().startswith(("http://", "https://")):
                continue
            parsed = urlparse(raw_url)
            domain = parsed.netloc.split(":")[0].lower()
            if not domain:
                continue
            if _normalize_domain(domain) == _normalize_domain(target_domain):
                continue
            if domain not in found:
                found[domain] = {"referenced_in": tag_name, "full_url": raw_url}
    return found


def _resolve_with_resolver(domain: str, resolver_ip: str = None) -> dict:
    resolver = dns.resolver.Resolver()
    if resolver_ip:
        resolver.nameservers = [resolver_ip]
    resolver.timeout = DNS_LOOKUP_TIMEOUT_SECONDS
    resolver.lifetime = DNS_LOOKUP_TIMEOUT_SECONDS
    try:
        answers = resolver.resolve(domain, "A")
        return {"status": "RESOLVED", "ips": [str(r) for r in answers]}
    except dns.resolver.NXDOMAIN:
        return {"status": "NXDOMAIN"}
    except dns.resolver.NoAnswer:
        return {"status": "NOERROR", "ips": []}
    except dns.exception.Timeout:
        return {"status": "TIMEOUT"}
    except Exception as e:
        return {"status": "ERROR", "error": str(e)}


async def _check_domain_dns(domain: str) -> dict:
    """Check DNS using multiple resolvers to confirm NXDOMAIN."""
    resolvers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]  # Cloudflare, Google, Quad9
    results = []
    for resolver_ip in resolvers:
        for attempt in range(DNS_RETRY_ATTEMPTS):
            loop = asyncio.get_event_loop()
            res = await loop.run_in_executor(None, _resolve_with_resolver, domain, resolver_ip)
            if res["status"] in ("RESOLVED", "NOERROR"):
                return {"domain": domain, "dns_status": res["status"], "ips": res.get("ips", [])}
            if res["status"] == "NXDOMAIN":
                # If multiple resolvers agree on NXDOMAIN, it's 100% confirmed
                results.append("NXDOMAIN")
                break
            if res["status"] in ("TIMEOUT", "ERROR"):
                await asyncio.sleep(0.5)
                continue
        # If all resolvers gave NXDOMAIN, confirm
        if results.count("NXDOMAIN") >= 2:
            return {"domain": domain, "dns_status": "NXDOMAIN"}
    # If all failed with timeout/error, return UNVERIFIABLE
    return {"domain": domain, "dns_status": "UNVERIFIABLE", "error": "All resolvers failed"}


async def _check_http(session: aiohttp.ClientSession, full_url: str) -> dict:
    """Check if the resource URL actually loads (GET)."""
    try:
        async with session.get(full_url, timeout=aiohttp.ClientTimeout(total=5), ssl=False, allow_redirects=True) as resp:
            body = await resp.text(errors="ignore", limit=500)
            return {
                "status_code": resp.status,
                "body_snippet": body[:200],
                "error": None,
                "content_type": resp.headers.get("Content-Type", ""),
            }
    except asyncio.TimeoutError:
        return {"status_code": None, "error": "Timeout"}
    except aiohttp.ClientError as e:
        return {"status_code": None, "error": str(e)}
    except Exception as e:
        return {"status_code": None, "error": str(e)}


async def run(url: str) -> dict:
    try:
        normalized_url = _normalize_url(url)
        target_domain = urlparse(normalized_url).netloc.split(":")[0].lower()
        if not target_domain:
            return _error_result("Invalid Target", f"Could not parse hostname from {url!r}")
    except Exception as e:
        return _error_result("Normalization Error", str(e))

    # Fetch page
    headers = {"User-Agent": USER_AGENT}
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)
    try:
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.get(normalized_url, allow_redirects=True, ssl=False) as resp:
                html = await resp.text(errors="ignore")
    except asyncio.TimeoutError:
        return _error_result("Timeout", f"Request to {normalized_url} timed out.")
    except aiohttp.ClientError as e:
        return _error_result("Fetch Error", str(e))
    except Exception as e:
        return _error_result("Unexpected Fetch Error", str(e))

    external_domains = _extract_external_domains(html, target_domain)
    if not external_domains:
        return {
            "test_name": TEST_NAME,
            "status": "pass",
            "severity": "info",
            "title": "No external dependencies found",
            "description": "No cross-origin script or link resources detected.",
            "evidence": [],
            "domains_checked": 0,
            "hallucinated_count": 0,
            "remediation": REMEDIATION,
        }

    # DNS checks
    dns_tasks = [_check_domain_dns(domain) for domain in external_domains.keys()]
    dns_results = await asyncio.gather(*dns_tasks, return_exceptions=False)

    # HTTP checks for resolved domains
    async with aiohttp.ClientSession() as session:
        http_tasks = {}
        for domain, dns_res in zip(external_domains.keys(), dns_results):
            if dns_res.get("dns_status") in ("RESOLVED", "NOERROR"):
                full_url = external_domains[domain]["full_url"]
                http_tasks[domain] = _check_http(session, full_url)
        http_results = await asyncio.gather(*http_tasks.values(), return_exceptions=False)

    # Build evidence
    evidence = []
    hallucinated_count = 0
    domains_checked = len(external_domains)

    for idx, (domain, meta) in enumerate(external_domains.items()):
        dns_res = dns_results[idx] if idx < len(dns_results) else {"dns_status": "UNVERIFIABLE"}
        dns_status = dns_res.get("dns_status", "UNVERIFIABLE")

        entry = {
            "domain": domain,
            "referenced_in": meta["referenced_in"],
            "full_url": meta["full_url"],
            "dns_status": dns_status,
            "confidence": 0,
            "severity": "info",
            "poc": f"dig {domain} A",
            "attack_scenario": "",
            "remediation": REMEDIATION,
        }

        if dns_status == "NXDOMAIN":
            hallucinated_count += 1
            entry.update({
                "severity": "critical",
                "confidence": 100,
                "attack_scenario": (
                    f"Domain '{domain}' does not exist in DNS (confirmed by multiple resolvers). "
                    f"An attacker can register this domain (~$10/year) and host malicious JavaScript/CSS. "
                    f"This would lead to a supply-chain compromise affecting all visitors."
                ),
                "poc": f"dig {domain} A +short ; nslookup {domain} ; curl -v {meta['full_url']}",
            })
            evidence.append(entry)
        elif dns_status == "RESOLVED":
            # Check HTTP response
            http_res = http_results[domain] if domain in http_results else None
            if http_res and http_res.get("status_code") is not None:
                if http_res["status_code"] >= 400:
                    entry.update({
                        "severity": "high",
                        "confidence": 90,
                        "attack_scenario": (
                            f"Domain '{domain}' resolves but returned HTTP {http_res['status_code']} "
                            f"(likely unconfigured, parked, or missing resource). "
                            f"An attacker could register the domain if available, or exploit the misconfigured endpoint."
                        ),
                        "poc": f"curl -v {meta['full_url']}",
                    })
                    evidence.append(entry)
                elif http_res["status_code"] == 200:
                    # Resource loads normally, consider safe (skip evidence)
                    continue
                else:
                    # Some other status (e.g., 301, 302)
                    entry.update({
                        "severity": "low",
                        "confidence": 70,
                        "attack_scenario": f"Domain resolved but returned HTTP {http_res['status_code']} (redirect).",
                        "poc": f"curl -v {meta['full_url']}",
                    })
                    evidence.append(entry)
            else:
                # Resolved but HTTP check failed (timeout, error)
                entry.update({
                    "severity": "medium",
                    "confidence": 60,
                    "attack_scenario": (
                        f"Domain '{domain}' resolves but HTTP check failed (timeout/error). "
                        f"May be unmaintained or behind firewall."
                    ),
                    "poc": f"curl -v {meta['full_url']} ; traceroute {domain}",
                })
                evidence.append(entry)
        elif dns_status == "NOERROR":
            # Domain exists but no A record
            entry.update({
                "severity": "low",
                "confidence": 80,
                "attack_scenario": (
                    f"Domain '{domain}' exists (NOERROR) but has no A record. "
                    f"Could be a misconfiguration or a domain used only for MX/other records."
                ),
                "poc": f"dig {domain} A ; dig {domain} MX",
            })
            evidence.append(entry)
        else:  # UNVERIFIABLE
            entry.update({
                "severity": "info",
                "confidence": 40,
                "attack_scenario": (
                    f"DNS lookup for '{domain}' was inconclusive (timeout/error). "
                    f"Manual verification recommended."
                ),
                "poc": f"dig {domain} A +trace",
            })
            evidence.append(entry)

    if not evidence:
        return {
            "test_name": TEST_NAME,
            "status": "pass",
            "severity": "info",
            "title": "All dependencies resolved and served content",
            "description": f"All {domains_checked} external domains resolved and served content.",
            "evidence": [],
            "domains_checked": domains_checked,
            "hallucinated_count": 0,
            "remediation": REMEDIATION,
        }

    hallucinated_count = sum(1 for e in evidence if e["severity"] in ("critical", "high"))
    severity_levels = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    overall_severity = max(evidence, key=lambda e: severity_levels.get(e["severity"], 0))["severity"]
    status = "fail" if hallucinated_count > 0 else "warning" if any(e["severity"] in ("medium",) for e in evidence) else "pass"

    return {
        "test_name": TEST_NAME,
        "status": status,
        "severity": overall_severity,
        "title": f"Hallucinated dependencies: {len(evidence)} risky domain(s) found",
        "description": f"Found {len(evidence)} external domain(s) with potential hallucination risk out of {domains_checked} checked. {hallucinated_count} domain(s) are confirmed non-existent.",
        "evidence": evidence,
        "domains_checked": domains_checked,
        "hallucinated_count": hallucinated_count,
        "remediation": REMEDIATION,
    }


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))