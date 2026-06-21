"""
test_09_subdomain_takeover.py — Advanced Subdomain Takeover Scanner (Active Verification)

Upgraded:
- Expanded fingerprints with more cloud providers.
- Provides dig commands as PoC for each finding.
- Adds confidence scoring based on CNAME resolution and HTTP response.
- Distinguishes between confirmed vulnerable (NXDOMAIN + error page) and informational.
"""

import asyncio
import re
from urllib.parse import urlparse

import aiohttp
import dns.resolver
import dns.exception

SUBDOMAINS = [
    "www", "mail", "blog", "dev", "staging", "api", "cdn", "static",
    "assets", "media", "help", "support", "docs", "app", "dashboard",
    "admin", "test", "beta", "stage", "demo"
]

TAKEOVER_FINGERPRINTS = {
    "amazonaws.com": {
        "error_pattern": r"NoSuchBucket|The specified bucket does not exist|AccessDenied",
        "service": "AWS S3",
        "severity": "critical"
    },
    "github.io": {
        "error_pattern": r"There isn't a GitHub Pages site here|Repository not found",
        "service": "GitHub Pages",
        "severity": "critical"
    },
    "herokuapp.com": {
        "error_pattern": r"No such app|There is no app configured at that hostname",
        "service": "Heroku",
        "severity": "critical"
    },
    "azurewebsites.net": {
        "error_pattern": r"404 Web Site not found|The resource you are looking for has been removed",
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
    },
    "s3.amazonaws.com": {
        "error_pattern": r"NoSuchBucket|The specified bucket does not exist",
        "service": "AWS S3",
        "severity": "critical"
    },
    "cloudfront.net": {
        "error_pattern": r"<Error>|AccessDenied",
        "service": "AWS CloudFront",
        "severity": "high"
    },
    "azureedge.net": {
        "error_pattern": r"404 Not Found",
        "service": "Azure CDN",
        "severity": "high"
    },
    "cloudflare.com": {
        "error_pattern": r"Error 1001|DNS resolution error",
        "service": "Cloudflare Workers",
        "severity": "high"
    },
    "firebaseio.com": {
        "error_pattern": r"Firebase: No such app|Project not found",
        "service": "Firebase",
        "severity": "critical"
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
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    resolver.timeout = DNS_TIMEOUT
    try:
        resolver.resolve(hostname, "A")
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except Exception:
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
    fqdn = f"{sub}.{root_domain}"

    cname_result = await asyncio.to_thread(_resolve_cname_sync, fqdn)

    if cname_result["status"] != "resolved":
        return None

    cname = cname_result["cname"]
    match = _match_fingerprint(cname)
    if not match:
        return None

    provider_suffix, fingerprint = match

    target_resolves = await asyncio.to_thread(_resolve_a_sync, cname)

    if target_resolves is False:
        return {
            "subdomain": fqdn,
            "cname": cname,
            "service": fingerprint["service"],
            "vulnerable": True,
            "severity": fingerprint["severity"],
            "confidence": 100,
            "detection_method": "dns_nxdomain",
            "poc": f"dig {fqdn} CNAME",
            "issue": f"CNAME points to {cname} which does not resolve (NXDOMAIN)."
        }

    http_result = await _check_http_body(session, fqdn, fingerprint["error_pattern"])

    if http_result["matched"]:
        return {
            "subdomain": fqdn,
            "cname": cname,
            "service": fingerprint["service"],
            "vulnerable": True,
            "severity": fingerprint["severity"],
            "confidence": 100,
            "detection_method": "http_fingerprint",
            "status_code": http_result["status_code"],
            "poc": f"curl -v https://{fqdn}",
            "issue": f"CNAME points to {cname} which returns a {http_result['status_code']} error page matching the provider's takeover fingerprint."
        }

    # Not vulnerable, but informational
    return {
        "subdomain": fqdn,
        "cname": cname,
        "service": fingerprint["service"],
        "vulnerable": False,
        "severity": "info",
        "confidence": 80 if http_result["reachable"] else 60,
        "detection_method": "http_fingerprint",
        "poc": f"curl -v https://{fqdn}",
        "issue": "CNAME points to a claimed resource (no takeover fingerprint)."
    }


async def run(url: str) -> dict:
    test_name = "subdomain_takeover"
    remediation = (
        "Remove DNS CNAME records pointing to unclaimed cloud resources. "
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
                "title": "Invalid Input",
                "description": f"Could not extract a valid root domain from '{url}'",
                "evidence": [],
                "subdomains_checked": 0,
                "vulnerable_count": 0,
                "remediation": remediation
            }

        async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
            tasks = [_check_subdomain(session, sub, root_domain) for sub in SUBDOMAINS]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        evidence = [r for r in results if isinstance(r, dict) and r is not None]
        vulnerable = [e for e in evidence if e.get("vulnerable")]

        if vulnerable:
            severity = "critical" if any(e["severity"] == "critical" for e in vulnerable) else "high"
            return {
                "test_name": test_name,
                "status": "fail",
                "severity": severity,
                "title": f"Subdomain Takeover Vulnerabilities ({len(vulnerable)} found)",
                "description": f"Found {len(vulnerable)} subdomain(s) with dangling CNAME records pointing to unclaimed cloud resources.",
                "evidence": evidence,
                "subdomains_checked": len(SUBDOMAINS),
                "vulnerable_count": len(vulnerable),
                "remediation": remediation
            }

        return {
            "test_name": test_name,
            "status": "pass",
            "severity": "info",
            "title": "No Subdomain Takeover Vulnerabilities",
            "description": f"Scanned {len(SUBDOMAINS)} subdomains of {root_domain}. No dangling CNAME records found.",
            "evidence": evidence,
            "subdomains_checked": len(SUBDOMAINS),
            "vulnerable_count": 0,
            "remediation": "No action required."
        }

    except Exception as e:
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "Scan Error",
            "description": f"Unexpected error: {e}",
            "evidence": [],
            "subdomains_checked": 0,
            "vulnerable_count": 0,
            "remediation": remediation
        }


if __name__ == "__main__":
    import json
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))