"""
Bravo6 Security Scanner
Module: test_15_hallucinated_deps.py

Detects "hallucinated dependency" / slopsquatting risk: external
<script src> and <link href> references that point at domains which
do not actually exist in DNS. This commonly happens with AI-generated
or copy-pasted front-end code that invents plausible-looking CDN
hostnames. If such a domain is later registered by an attacker, every
visitor to the page will execute attacker-controlled JS/CSS.

Requirements:
    pip install aiohttp dnspython beautifulsoup4

Usage:
    result = await run("example.com")
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
REQUEST_TIMEOUT_SECONDS = 10
DNS_RETRY_ATTEMPTS = 3
DNS_RETRY_DELAY_SECONDS = 2
DNS_LOOKUP_TIMEOUT_SECONDS = 5

REMEDIATION = (
    "Remove or replace all script/stylesheet references to non-existent "
    "domains immediately. Verify all CDN URLs are reachable before "
    "deploying. Consider using Subresource Integrity (SRI) hashes and a "
    "Content-Security-Policy to restrict allowed script/style sources, "
    "and pin third-party dependencies to domains your organization "
    "controls or trusts."
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


def _error_result(title: str, description: str, severity: str = "info") -> dict:
    return {
        "test_name": TEST_NAME,
        "status": "error",
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": [],
        "domains_checked": 0,
        "hallucinated_count": 0,
        "remediation": REMEDIATION,
    }


def _extract_external_domains(html: str, target_domain: str) -> dict:
    """
    Parses HTML and returns a dict of {domain: {"referenced_in": ..., "full_url": ...}}
    for every unique cross-origin domain found in <script src> or <link href>.
    """
    found = {}
    soup = BeautifulSoup(html, "html.parser")

    sources = (
        ("script", "src"),
        ("link", "href"),
    )

    for tag_name, attr in sources:
        for tag in soup.find_all(tag_name):
            raw_url = tag.get(attr)
            if not raw_url:
                continue
            raw_url = raw_url.strip()

            # protocol-relative URLs (//cdn.example.com/x.js)
            if raw_url.startswith("//"):
                raw_url = "https:" + raw_url

            if not raw_url.lower().startswith(("http://", "https://")):
                continue  # relative/local path, not an external dependency

            parsed = urlparse(raw_url)
            domain = parsed.netloc.split(":")[0].lower()
            if not domain:
                continue

            if _normalize_domain(domain) == _normalize_domain(target_domain):
                continue  # same-origin, not relevant

            if domain not in found:
                found[domain] = {"referenced_in": tag_name, "full_url": raw_url}

    return found


def _resolve_a_record_blocking(domain: str):
    """Blocking DNS A-record lookup, intended to be run in an executor."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_LOOKUP_TIMEOUT_SECONDS
    resolver.lifetime = DNS_LOOKUP_TIMEOUT_SECONDS
    answers = resolver.resolve(domain, "A")
    return [str(r) for r in answers]


async def _check_domain_dns(domain: str) -> dict:
    """
    Resolves a domain's A record. Retries up to DNS_RETRY_ATTEMPTS times
    (with a delay) specifically on NXDOMAIN before declaring it
    non-existent. Other errors (timeouts, no nameservers, etc.) are
    reported as unverifiable without the NXDOMAIN retry loop.
    """
    loop = asyncio.get_event_loop()

    for attempt in range(1, DNS_RETRY_ATTEMPTS + 1):
        try:
            ips = await loop.run_in_executor(None, _resolve_a_record_blocking, domain)
            return {"domain": domain, "dns_status": "RESOLVED", "ips": ips}
        except dns.resolver.NXDOMAIN:
            if attempt < DNS_RETRY_ATTEMPTS:
                await asyncio.sleep(DNS_RETRY_DELAY_SECONDS)
                continue
            return {"domain": domain, "dns_status": "NXDOMAIN"}
        except dns.resolver.NoAnswer:
            # Domain exists but has no A record — treat as unverifiable,
            # not as proof of non-existence.
            return {"domain": domain, "dns_status": "UNVERIFIABLE", "error": "NoAnswer"}
        except (dns.exception.Timeout, asyncio.TimeoutError):
            return {"domain": domain, "dns_status": "UNVERIFIABLE", "error": "Timeout"}
        except dns.exception.DNSException as e:
            return {"domain": domain, "dns_status": "UNVERIFIABLE", "error": str(e)}
        except Exception as e:  # noqa: BLE001 - never let DNS errors crash the scan
            return {"domain": domain, "dns_status": "UNVERIFIABLE", "error": str(e)}

    # Should not be reached, but keep a safe fallback.
    return {"domain": domain, "dns_status": "UNVERIFIABLE", "error": "unknown"}


async def run(url: str) -> dict:
    try:
        normalized_url = _normalize_url(url)
        target_domain = urlparse(normalized_url).netloc.split(":")[0].lower()
        if not target_domain:
            return _error_result(
                "Invalid Target URL",
                f"Could not parse a valid hostname from input: {url!r}",
            )
    except Exception as e:  # noqa: BLE001
        return _error_result("Input Normalization Failed", f"Error normalizing target URL: {e}")

    # --- Step 1: fetch target HTML ---
    headers = {"User-Agent": USER_AGENT}
    timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT_SECONDS)

    try:
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.get(normalized_url, allow_redirects=True, ssl=False) as resp:
                html = await resp.text(errors="ignore")
    except asyncio.TimeoutError:
        return _error_result(
            "Target Unreachable (Timeout)",
            f"Request to {normalized_url} did not complete within "
            f"{REQUEST_TIMEOUT_SECONDS} seconds.",
        )
    except aiohttp.ClientError as e:
        return _error_result(
            "Target Unreachable",
            f"Failed to fetch {normalized_url}: {e}",
        )
    except Exception as e:  # noqa: BLE001
        return _error_result(
            "Unexpected Fetch Error",
            f"Unexpected error fetching {normalized_url}: {e}",
        )

    # --- Step 2: extract external domains ---
    try:
        external_domains = _extract_external_domains(html, target_domain)
    except Exception as e:  # noqa: BLE001
        return _error_result(
            "HTML Parsing Failed",
            f"Failed to parse HTML from {normalized_url}: {e}",
        )

    if not external_domains:
        return {
            "test_name": TEST_NAME,
            "status": "pass",
            "severity": "info",
            "title": "No External Script/Stylesheet Dependencies Found",
            "description": (
                "No cross-origin <script src> or <link href> references were "
                "found on the page, so there is no hallucinated-dependency "
                "risk to evaluate."
            ),
            "evidence": [],
            "domains_checked": 0,
            "hallucinated_count": 0,
            "remediation": REMEDIATION,
        }

    # --- Step 3: DNS lookups (concurrent) ---
    try:
        dns_results = await asyncio.gather(
            *[_check_domain_dns(domain) for domain in external_domains.keys()],
            return_exceptions=True,
        )
    except Exception as e:  # noqa: BLE001
        return _error_result(
            "DNS Resolution Phase Failed",
            f"Unexpected error during DNS resolution: {e}",
        )

    # --- Step 4: build evidence ---
    evidence = []
    hallucinated_count = 0
    unverifiable_count = 0

    for domain, dns_result in zip(external_domains.keys(), dns_results):
        meta = external_domains[domain]

        if isinstance(dns_result, Exception):
            dns_status = "UNVERIFIABLE"
        else:
            dns_status = dns_result.get("dns_status", "UNVERIFIABLE")

        if dns_status == "NXDOMAIN":
            hallucinated_count += 1
            evidence.append({
                "domain": domain,
                "referenced_in": meta["referenced_in"],
                "full_url": meta["full_url"],
                "dns_status": "NXDOMAIN",
                "severity": "critical",
                "attack_scenario": (
                    f"Domain '{domain}' does not exist in DNS. If an attacker "
                    f"registers this domain (~$10/yr) and hosts malicious "
                    f"JavaScript/CSS, all visitors to this site will execute "
                    f"attacker-controlled code (Supply Chain Attack)."
                ),
            })
        elif dns_status == "UNVERIFIABLE":
            unverifiable_count += 1
            evidence.append({
                "domain": domain,
                "referenced_in": meta["referenced_in"],
                "full_url": meta["full_url"],
                "dns_status": "UNVERIFIABLE",
                "severity": "low",
                "attack_scenario": (
                    "DNS lookup could not be completed reliably (timeout or "
                    "resolver error). Manual verification of this domain is "
                    "recommended."
                ),
            })
        # RESOLVED -> safe, no evidence entry needed.

    domains_checked = len(external_domains)

    if hallucinated_count > 0:
        status = "fail"
        severity = "critical"
        title = f"Hallucinated External Dependencies Detected ({hallucinated_count})"
        description = (
            f"{hallucinated_count} of {domains_checked} cross-origin "
            f"script/stylesheet domain(s) referenced on {normalized_url} "
            f"do not resolve in DNS after {DNS_RETRY_ATTEMPTS} retries. "
            "These likely originate from AI-generated, copy-pasted, or "
            "typo'd code, and represent a critical supply-chain risk if an "
            "attacker registers the missing domain(s)."
        )
    elif unverifiable_count > 0:
        status = "warning"
        severity = "low"
        title = f"DNS Verification Inconclusive for {unverifiable_count} Domain(s)"
        description = (
            f"All {domains_checked} cross-origin domain(s) were checked; "
            f"{unverifiable_count} could not be conclusively resolved due to "
            "DNS timeouts or resolver errors. None were confirmed as "
            "non-existent (NXDOMAIN)."
        )
    else:
        status = "pass"
        severity = "info"
        title = "No Hallucinated External Dependencies Found"
        description = (
            f"All {domains_checked} cross-origin script/stylesheet domain(s) "
            f"referenced on {normalized_url} resolved successfully in DNS."
        )

    return {
        "test_name": TEST_NAME,
        "status": status,
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "domains_checked": domains_checked,
        "hallucinated_count": hallucinated_count,
        "remediation": REMEDIATION,
    }


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    output = asyncio.run(run(target))
    print(json.dumps(output, indent=2))