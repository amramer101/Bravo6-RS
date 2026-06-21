"""
test_subdomain_takeover.py
Bravo6 Security Scanner - Subdomain Takeover Detection Module
"""

import asyncio
import re
from urllib.parse import urlparse

import aiohttp
import dns.resolver
import dns.exception

SUBDOMAINS = [
    "www", "mail", "blog", "dev", "staging", "api", "cdn", "static",
    "assets", "media", "help", "support", "docs", "app", "dashboard"
]

TAKEOVER_FINGERPRINTS = {
    "amazonaws.com": {
        "error_pattern": r"NoSuchBucket|The specified bucket does not exist",
        "service": "AWS S3",
        "severity": "critical"
    },
    "github.io": {
        "error_pattern": r"There isn't a GitHub Pages site here",
        "service": "GitHub Pages",
        "severity": "critical"
    },
    "herokuapp.com": {
        "error_pattern": r"No such app|There is no app configured at that hostname",
        "service": "Heroku",
        "severity": "critical"
    },
    "azurewebsites.net": {
        "error_pattern": r"404 Web Site not found",
        "service": "Azure Web Apps",
        "severity": "critical"
    },
    "netlify.app": {
        "error_pattern": r"Not Found - Request ID",
        "service": "Netlify",
        "severity": "high"
    },
    "readthedocs.io": {
        "error_pattern": r"unknown to Read the Docs",
        "service": "ReadTheDocs",
        "severity": "medium"
    }
}

REQUEST_TIMEOUT = 10
USER_AGENT = "Bravo6-Scanner/1.0"
DNS_TIMEOUT = 5


def _normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = f"https://{url}"
    return url


def _extract_root_domain(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path
    host = host.split(":")[0].split("/")[0]
    return host.lstrip("www.") if host.startswith("www.") else host


def _resolve_cname_sync(hostname: str):
    """Sync DNS CNAME lookup, run in a thread via asyncio.to_thread."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    resolver.timeout = DNS_TIMEOUT
    try:
        answers = resolver.resolve(hostname, "CNAME")
        target = str(answers[0].target).rstrip(".")
        return {"status": "resolved", "cname": target}
    except dns.resolver.NXDOMAIN:
        return {"status": "nxdomain", "cname": None}
    except dns.resolver.NoAnswer:
        return {"status": "no_cname", "cname": None}
    except dns.exception.Timeout:
        return {"status": "timeout", "cname": None}
    except Exception as e:
        return {"status": "error", "cname": None, "error": str(e)}


def _resolve_a_sync(hostname: str):
    """Check if a hostname resolves at all (A/AAAA), used to detect dangling targets."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    resolver.timeout = DNS_TIMEOUT
    try:
        resolver.resolve(hostname, "A")
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except Exception:
        # Ambiguous (timeout/no answer) — don't claim dangling on uncertain data
        return None


def _match_fingerprint(cname: str):
    if not cname:
        return None
    cname_lower = cname.lower()
    for provider_suffix, fingerprint in TAKEOVER_FINGERPRINTS.items():
        if cname_lower.endswith(provider_suffix):
            return provider_suffix, fingerprint
    return None


async def _check_http_body(session: aiohttp.ClientSession, subdomain: str, error_pattern: str):
    """Fetch the subdomain over HTTP(S) and check the body against the fingerprint pattern."""
    for scheme in ("https", "http"):
        try:
            async with session.get(
                f"{scheme}://{subdomain}",
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
                ssl=False,
                allow_redirects=True
            ) as resp:
                body = await resp.text(errors="ignore")
                if re.search(error_pattern, body, re.IGNORECASE):
                    return {"reachable": True, "matched": True, "status_code": resp.status}
                return {"reachable": True, "matched": False, "status_code": resp.status}
        except asyncio.TimeoutError:
            continue
        except aiohttp.ClientConnectorError:
            continue
        except Exception:
            continue
    return {"reachable": False, "matched": False, "status_code": None}


async def _check_subdomain(session: aiohttp.ClientSession, sub: str, root_domain: str):
    """Run the full CNAME -> fingerprint -> HTTP verification pipeline for one subdomain."""
    fqdn = f"{sub}.{root_domain}"

    cname_result = await asyncio.to_thread(_resolve_cname_sync, fqdn)

    if cname_result["status"] != "resolved":
        return None  # no CNAME, not relevant to this check

    cname = cname_result["cname"]
    match = _match_fingerprint(cname)
    if not match:
        return None  # CNAME doesn't point at a known cloud provider

    provider_suffix, fingerprint = match

    # Case A: the CNAME target itself doesn't resolve at all (NXDOMAIN) —
    # strong, low-false-positive signal of a dangling/claimable resource.
    target_resolves = await asyncio.to_thread(_resolve_a_sync, cname)

    if target_resolves is False:
        return {
            "subdomain": fqdn,
            "cname": cname,
            "service": fingerprint["service"],
            "vulnerable": True,
            "severity": fingerprint["severity"],
            "detection_method": "dns_nxdomain",
            "http_checked": False
        }

    # Case B: target resolves, but may still be an unclaimed resource serving
    # a provider-specific "not found" error page. Verify via HTTP body match.
    http_result = await _check_http_body(session, fqdn, fingerprint["error_pattern"])

    if http_result["matched"]:
        return {
            "subdomain": fqdn,
            "cname": cname,
            "service": fingerprint["service"],
            "vulnerable": True,
            "severity": fingerprint["severity"],
            "detection_method": "http_fingerprint",
            "http_checked": True,
            "status_code": http_result["status_code"]
        }

    # CNAME points to a known provider but no takeover signal found —
    # still worth surfacing as informational evidence, marked not vulnerable.
    return {
        "subdomain": fqdn,
        "cname": cname,
        "service": fingerprint["service"],
        "vulnerable": False,
        "severity": "info",
        "detection_method": "http_fingerprint" if http_result["reachable"] else "unreachable",
        "http_checked": http_result["reachable"]
    }


async def run(url: str) -> dict:
    """
    Bravo6 module entrypoint.
    Checks the target domain and common subdomains for dangling CNAME
    records pointing at unclaimed cloud resources (subdomain takeover).
    """
    test_name = "subdomain_takeover"
    remediation = (
        "Remove DNS records pointing to unclaimed cloud resources. "
        "Claim the resource or delete the CNAME record."
    )

    try:
        normalized_url = _normalize_url(url)
        root_domain = _extract_root_domain(normalized_url)

        if not root_domain or "." not in root_domain:
            return {
                "test_name": test_name,
                "status": "error",
                "severity": "info",
                "title": "Subdomain Takeover Check - Invalid Input",
                "description": f"Could not extract a valid root domain from input: '{url}'",
                "evidence": [],
                "subdomains_checked": 0,
                "vulnerable_count": 0,
                "remediation": remediation
            }

        headers = {"User-Agent": USER_AGENT}
        connector = aiohttp.TCPConnector(limit=10, ssl=False)
        timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)

        async with aiohttp.ClientSession(
            headers=headers, connector=connector, timeout=timeout
        ) as session:
            tasks = [
                _check_subdomain(session, sub, root_domain)
                for sub in SUBDOMAINS
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        evidence = []
        for r in results:
            if isinstance(r, Exception) or r is None:
                continue
            evidence.append(r)

        vulnerable_findings = [e for e in evidence if e.get("vulnerable")]
        vulnerable_count = len(vulnerable_findings)

        if vulnerable_count > 0:
            highest_severity = "critical" if any(
                e["severity"] == "critical" for e in vulnerable_findings
            ) else "high"
            return {
                "test_name": test_name,
                "status": "fail",
                "severity": highest_severity,
                "title": f"Subdomain Takeover Vulnerability Detected ({vulnerable_count} found)",
                "description": (
                    f"Scanned {len(SUBDOMAINS)} common subdomains for {root_domain}. "
                    f"Found {vulnerable_count} subdomain(s) with CNAME records pointing "
                    f"to cloud resources that appear unclaimed, making them vulnerable "
                    f"to takeover."
                ),
                "evidence": evidence,
                "subdomains_checked": len(SUBDOMAINS),
                "vulnerable_count": vulnerable_count,
                "remediation": remediation
            }

        if evidence:
            return {
                "test_name": test_name,
                "status": "pass",
                "severity": "info",
                "title": "No Subdomain Takeover Vulnerabilities Found",
                "description": (
                    f"Scanned {len(SUBDOMAINS)} common subdomains for {root_domain}. "
                    f"{len(evidence)} subdomain(s) had CNAMEs pointing to known cloud "
                    f"providers, but all resolved to claimed/active resources."
                ),
                "evidence": evidence,
                "subdomains_checked": len(SUBDOMAINS),
                "vulnerable_count": 0,
                "remediation": "No action required. Continue monitoring DNS records when decommissioning services."
            }

        return {
            "test_name": test_name,
            "status": "pass",
            "severity": "info",
            "title": "No Subdomain Takeover Vulnerabilities Found",
            "description": (
                f"Scanned {len(SUBDOMAINS)} common subdomains for {root_domain}. "
                f"No CNAME records pointing to known cloud providers were found."
            ),
            "evidence": [],
            "subdomains_checked": len(SUBDOMAINS),
            "vulnerable_count": 0,
            "remediation": "No action required."
        }

    except Exception as e:
        return {
            "test_name": "subdomain_takeover",
            "status": "error",
            "severity": "info",
            "title": "Subdomain Takeover Check - Scan Error",
            "description": f"An unexpected error occurred while scanning: {str(e)}",
            "evidence": [],
            "subdomains_checked": 0,
            "vulnerable_count": 0,
            "remediation": "Re-run the scan. If the error persists, check network connectivity and DNS resolver configuration."
        }


if __name__ == "__main__":
    import json

    async def _test():
        result = await run("example.com")
        print(json.dumps(result, indent=2))

    asyncio.run(_test())