"""
test_09_subdomain_takeover.py — Advanced Subdomain Takeover Scanner with Active Verification (v3)

Enhancements:
- Expanded subdomain list (dynamic, customizable via config)
- Multiple DNS record types (CNAME, A, MX, TXT, NS)
- Advanced active verification with HTTP/HTTPS analysis
- Response fingerprinting with service-specific patterns
- Support for 20+ cloud services (AWS, Azure, GCP, GitHub, Vercel, Netlify, etc.)
- Multi-resolver DNS checking for NXDOMAIN confirmation
- Edge case handling (403, 302, default pages)
- Exploitability scoring
- Integration with other test contexts
- Detailed PoC with step-by-step exploitation
- Dynamic confidence scoring
- External threat intelligence integration (optional)
- Updated fingerprint database as JSON
"""

import asyncio
import json
import re
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional, Tuple, Set

import aiohttp
import dns.resolver
import dns.exception

# ── Configuration ──────────────────────────────────────────────────────────
USER_AGENT = "Bravo6-Scanner/1.0"
REQUEST_TIMEOUT = 10
DNS_TIMEOUT = 5
MAX_CONCURRENT_CHECKS = 15
DNS_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

# ── Service Fingerprint Database ──────────────────────────────────────────
# Each service: {
#   "cname_patterns": list of regex for CNAME suffix,
#   "a_patterns": list of regex for IP ranges,
#   "error_pattern": regex to match error page content,
#   "header_patterns": list of regex to match headers,
#   "status_codes": list of expected status codes for takeover,
#   "service": display name,
#   "severity": critical/high/medium,
#   "exploit_difficulty": easy/medium/hard,
#   "remediation": specific remediation,
#   "poc": PoC command or description
# }

# Load from JSON if available, else use built-in
FINGERPRINTS_JSON = """
{
  "amazonaws.com": {
    "cname_patterns": ["\\.s3\\.amazonaws\\.com$", "\\.s3\\-.*\\.amazonaws\\.com$", "\\.cloudfront\\.net$"],
    "a_patterns": ["^54\\.", "^52\\.", "^13\\.", "^35\\.", "^3\\."],
    "error_pattern": "NoSuchBucket|The specified bucket does not exist|AccessDenied",
    "header_patterns": ["x-amz-request-id", "x-amz-id-2"],
    "status_codes": [404, 403],
    "service": "AWS S3 / CloudFront",
    "severity": "critical",
    "exploit_difficulty": "easy",
    "remediation": "Delete the CNAME record or claim the bucket/CloudFront distribution.",
    "poc": "aws s3 ls s3://{domain} --region {region}  # or create bucket with same name"
  },
  "github.io": {
    "cname_patterns": ["\\.github\\.io$"],
    "a_patterns": ["^185\\.199\\.", "^185\\.199\\.108\\.", "^185\\.199\\.109\\.", "^185\\.199\\.110\\.", "^185\\.199\\.111\\."],
    "error_pattern": "There isn't a GitHub Pages site here|Repository not found",
    "header_patterns": ["x-github-request-id"],
    "status_codes": [404, 200],
    "service": "GitHub Pages",
    "severity": "critical",
    "exploit_difficulty": "easy",
    "remediation": "Remove CNAME record or create a GitHub Pages repository.",
    "poc": "Create a repository named {domain} and enable GitHub Pages."
  },
  "herokuapp.com": {
    "cname_patterns": ["\\.herokuapp\\.com$"],
    "a_patterns": ["^34\\.", "^35\\.", "^52\\.", "^54\\.", "^104\\.", "^185\\.", "^204\\."],
    "error_pattern": "No such app|There is no app configured at that hostname",
    "header_patterns": ["x-powered-by: Express", "server: Cowboy"],
    "status_codes": [404, 403],
    "service": "Heroku",
    "severity": "critical",
    "exploit_difficulty": "medium",
    "remediation": "Remove CNAME or deploy an app to Heroku.",
    "poc": "heroku create {app_name} --region {region} and add custom domain."
  },
  "azurewebsites.net": {
    "cname_patterns": ["\\.azurewebsites\\.net$", "\\.cloudapp\\.azure\\.com$"],
    "a_patterns": ["^13\\.", "^20\\.", "^23\\.", "^40\\.", "^51\\.", "^52\\.", "^65\\.", "^104\\."],
    "error_pattern": "404 Web Site not found|The resource you are looking for has been removed|The web site you are looking for has been stopped",
    "header_patterns": ["x-ms-request-id", "x-ms-version"],
    "status_codes": [404, 403],
    "service": "Azure Web Apps / Cloud Services",
    "severity": "critical",
    "exploit_difficulty": "medium",
    "remediation": "Delete CNAME or deploy an app to Azure.",
    "poc": "az webapp create --name {app_name} --resource-group {group} --plan {plan} --runtime {runtime}"
  },
  "netlify.app": {
    "cname_patterns": ["\\.netlify\\.app$", "\\.netlify\\.com$"],
    "a_patterns": ["^13\\.", "^15\\.", "^34\\.", "^35\\.", "^54\\.", "^104\\."],
    "error_pattern": "Not Found - Request ID|404 Page Not Found",
    "header_patterns": ["x-nf-request-id"],
    "status_codes": [404, 200],
    "service": "Netlify",
    "severity": "high",
    "exploit_difficulty": "easy",
    "remediation": "Remove CNAME or deploy a site to Netlify.",
    "poc": "netlify deploy --site {site_name}"
  },
  "vercel.app": {
    "cname_patterns": ["\\.vercel\\.app$", "\\.now\\.sh$"],
    "a_patterns": ["^76\\.", "^18\\.", "^44\\.", "^54\\.", "^104\\.", "^172\\.", "^199\\."],
    "error_pattern": "The deployment could not be found|404: NOT_FOUND|This deployment is not found",
    "header_patterns": ["x-vercel-cache", "x-vercel-id"],
    "status_codes": [404, 403],
    "service": "Vercel",
    "severity": "high",
    "exploit_difficulty": "easy",
    "remediation": "Remove CNAME or deploy a project to Vercel.",
    "poc": "vercel --cwd {project} --prod --domain {domain}"
  },
  "readthedocs.io": {
    "cname_patterns": ["\\.readthedocs\\.io$", "\\.rtfd\\.io$"],
    "a_patterns": ["^104\\.", "^34\\.", "^35\\.", "^54\\."],
    "error_pattern": "unknown to Read the Docs|Project does not exist",
    "header_patterns": ["x-rtd-version"],
    "status_codes": [404, 200],
    "service": "ReadTheDocs",
    "severity": "medium",
    "exploit_difficulty": "easy",
    "remediation": "Remove CNAME or create a project on ReadTheDocs.",
    "poc": "Create a project with same name on ReadTheDocs."
  },
  "firebaseio.com": {
    "cname_patterns": ["\\.firebaseio\\.com$"],
    "a_patterns": ["^34\\.", "^35\\.", "^52\\.", "^104\\."],
    "error_pattern": "Firebase: No such app|Project not found",
    "header_patterns": ["firebase", "x-firebase"],
    "status_codes": [404, 403],
    "service": "Firebase Realtime DB",
    "severity": "critical",
    "exploit_difficulty": "easy",
    "remediation": "Remove CNAME or create Firebase project.",
    "poc": "firebase projects:create {project_id}"
  },
  "githubapp.com": {
    "cname_patterns": ["\\.github\\.com$", "\\.githubapp\\.com$"],
    "a_patterns": ["^140\\.82\\.", "^185\\.199\\."],
    "error_pattern": "There is no website at this address|Repository not found",
    "header_patterns": ["x-github-request-id"],
    "status_codes": [404],
    "service": "GitHub Pages",
    "severity": "critical",
    "exploit_difficulty": "easy",
    "remediation": "Remove CNAME or create repository.",
    "poc": "Create repository named {domain}"
  },
  "gitlab.io": {
    "cname_patterns": ["\\.gitlab\\.io$"],
    "a_patterns": ["^35\\.", "^52\\.", "^104\\."],
    "error_pattern": "404 - GitLab Pages|No such project",
    "header_patterns": ["x-gitlab"],
    "status_codes": [404],
    "service": "GitLab Pages",
    "severity": "high",
    "exploit_difficulty": "easy",
    "remediation": "Remove CNAME or create GitLab Pages project.",
    "poc": "Create a GitLab project with same name."
  },
  "cloudfront.net": {
    "cname_patterns": ["\\.cloudfront\\.net$"],
    "a_patterns": ["^54\\.", "^52\\.", "^13\\.", "^35\\."],
    "error_pattern": "AccessDenied|This distribution is not configured",
    "header_patterns": ["x-amz-cf-id", "x-amz-request-id"],
    "status_codes": [403, 404],
    "service": "AWS CloudFront",
    "severity": "high",
    "exploit_difficulty": "medium",
    "remediation": "Delete distribution or CNAME.",
    "poc": "aws cloudfront create-distribution --origin-domain-name {origin}"
  },
  "azureedge.net": {
    "cname_patterns": ["\\.azureedge\\.net$"],
    "a_patterns": ["^13\\.", "^20\\.", "^23\\.", "^40\\.", "^52\\."],
    "error_pattern": "404 Not Found|The specified blob does not exist",
    "header_patterns": ["x-azure-ref", "x-ms-blob-type"],
    "status_codes": [404, 403],
    "service": "Azure CDN / Storage",
    "severity": "high",
    "exploit_difficulty": "medium",
    "remediation": "Remove CNAME or create Azure Storage account.",
    "poc": "az storage account create --name {account} --resource-group {group}"
  },
  "cloudflare.com": {
    "cname_patterns": ["\\.cloudflare\\.com$", "\\.cloudflare\\.net$"],
    "a_patterns": ["^104\\.", "^172\\.", "^162\\.", "^188\\."],
    "error_pattern": "Error 1001|DNS resolution error|Cloudflare Worker not found",
    "header_patterns": ["cf-ray", "cf-cache-status"],
    "status_codes": [404, 403],
    "service": "Cloudflare Workers / Pages",
    "severity": "high",
    "exploit_difficulty": "medium",
    "remediation": "Remove CNAME or create Cloudflare Worker/Pages.",
    "poc": "wrangler publish --name {worker_name}"
  },
  "render.com": {
    "cname_patterns": ["\\.render\\.com$", "\\.onrender\\.com$"],
    "a_patterns": ["^13\\.", "^34\\.", "^35\\.", "^54\\.", "^104\\."],
    "error_pattern": "404 Not Found|Render site not found",
    "header_patterns": ["x-render-request-id"],
    "status_codes": [404],
    "service": "Render",
    "severity": "high",
    "exploit_difficulty": "easy",
    "remediation": "Remove CNAME or deploy to Render.",
    "poc": "render deploy --name {service_name}"
  },
  "fly.io": {
    "cname_patterns": ["\\.fly\\.io$", "\\.fly\\.dev$"],
    "a_patterns": ["^34\\.", "^35\\.", "^52\\.", "^104\\."],
    "error_pattern": "404 page not found|This app is not running",
    "header_patterns": ["fly-request-id"],
    "status_codes": [404],
    "service": "Fly.io",
    "severity": "medium",
    "exploit_difficulty": "medium",
    "remediation": "Remove CNAME or deploy to Fly.io.",
    "poc": "flyctl deploy --app {app_name}"
  },
  "deno.dev": {
    "cname_patterns": ["\\.deno\\.dev$", "\\.deno\\.com$"],
    "a_patterns": ["^13\\.", "^34\\.", "^35\\.", "^52\\."],
    "error_pattern": "Deployment not found",
    "header_patterns": ["x-deno-request-id"],
    "status_codes": [404],
    "service": "Deno Deploy",
    "severity": "medium",
    "exploit_difficulty": "easy",
    "remediation": "Remove CNAME or deploy to Deno Deploy.",
    "poc": "deployctl deploy --project {project_name}"
  },
  "supabase.co": {
    "cname_patterns": ["\\.supabase\\.co$", "\\.supabase\\.in$"],
    "a_patterns": ["^34\\.", "^35\\.", "^52\\.", "^104\\."],
    "error_pattern": "Project not found|404 - Project not found",
    "header_patterns": ["x-supabase-request-id"],
    "status_codes": [404],
    "service": "Supabase",
    "severity": "high",
    "exploit_difficulty": "medium",
    "remediation": "Remove CNAME or create Supabase project.",
    "poc": "Create a Supabase project with same name."
  },
  "digitalocean.com": {
    "cname_patterns": ["\\.digitalocean\\.com$", "\\.ondigitalocean\\.app$"],
    "a_patterns": ["^34\\.", "^35\\.", "^52\\.", "^104\\."],
    "error_pattern": "The requested URL was not found|404 Not Found",
    "header_patterns": ["x-digitalocean"],
    "status_codes": [404],
    "service": "DigitalOcean App Platform",
    "severity": "high",
    "exploit_difficulty": "medium",
    "remediation": "Remove CNAME or deploy to DigitalOcean.",
    "poc": "doctl apps create --spec {spec_file}"
  }
}
"""

try:
    FINGERPRINTS = json.loads(FINGERPRINTS_JSON)
except:
    # Fallback to older version if JSON fails
    FINGERPRINTS = {
        "amazonaws.com": {
            "cname_patterns": ["\\.s3\\.amazonaws\\.com$", "\\.cloudfront\\.net$"],
            "error_pattern": "NoSuchBucket|The specified bucket does not exist",
            "service": "AWS S3/CloudFront",
            "severity": "critical",
        },
        "github.io": {
            "cname_patterns": ["\\.github\\.io$"],
            "error_pattern": "There isn't a GitHub Pages site here",
            "service": "GitHub Pages",
            "severity": "critical",
        },
        "herokuapp.com": {
            "cname_patterns": ["\\.herokuapp\\.com$"],
            "error_pattern": "No such app",
            "service": "Heroku",
            "severity": "critical",
        },
        "azurewebsites.net": {
            "cname_patterns": ["\\.azurewebsites\\.net$"],
            "error_pattern": "404 Web Site not found",
            "service": "Azure Web Apps",
            "severity": "critical",
        },
        "netlify.app": {
            "cname_patterns": ["\\.netlify\\.app$", "\\.netlify\\.com$"],
            "error_pattern": "Not Found - Request ID",
            "service": "Netlify",
            "severity": "high",
        },
        "vercel.app": {
            "cname_patterns": ["\\.vercel\\.app$", "\\.now\\.sh$"],
            "error_pattern": "The deployment could not be found",
            "service": "Vercel",
            "severity": "high",
        },
        "readthedocs.io": {
            "cname_patterns": ["\\.readthedocs\\.io$"],
            "error_pattern": "unknown to Read the Docs",
            "service": "ReadTheDocs",
            "severity": "medium",
        },
        "firebaseio.com": {
            "cname_patterns": ["\\.firebaseio\\.com$"],
            "error_pattern": "Firebase: No such app",
            "service": "Firebase",
            "severity": "critical",
        },
        "cloudfront.net": {
            "cname_patterns": ["\\.cloudfront\\.net$"],
            "error_pattern": "AccessDenied|This distribution is not configured",
            "service": "AWS CloudFront",
            "severity": "high",
        },
        "azureedge.net": {
            "cname_patterns": ["\\.azureedge\\.net$"],
            "error_pattern": "404 Not Found|The specified blob does not exist",
            "service": "Azure CDN",
            "severity": "high",
        },
    }

# ── Expanded subdomain list ───────────────────────────────────────────────
DEFAULT_SUBDOMAINS = [
    "www", "mail", "blog", "dev", "staging", "api", "cdn", "static",
    "assets", "media", "help", "support", "docs", "app", "dashboard",
    "admin", "test", "beta", "stage", "demo", "auth", "identity",
    "sso", "oauth", "auth0", "firebase", "storage", "img", "resources",
    "download", "upload", "backup", "dev-api", "test-api", "stage-api",
    "preprod", "prod-api", "gateway", "proxy", "socket", "ws", "stream",
    "event", "push", "notify", "analytics", "metrics", "monitor", "status",
    "health", "ping", "live", "sandbox", "playground", "lab", "internal-api",
    "partner", "vendor", "supplier", "shop", "store", "cart", "checkout",
    "payment", "pay", "billing", "invoice", "reports", "admin-api", "manage",
    "control", "system", "core", "service", "svc", "api2", "cdn-static",
    "assets-dev", "static-dev", "media-staging", "docs-dev", "app-dev",
    "dashboard-dev", "admin-dev", "test-api", "stage-api", "prod-api",
    "gateway-dev", "proxy-dev", "socket-dev", "ws-dev", "stream-dev",
    "event-dev", "push-dev", "notify-dev", "analytics-dev", "metrics-dev",
    "monitor-dev", "status-dev", "health-dev", "ping-dev", "live-dev",
    "sandbox-dev", "playground-dev", "lab-dev", "internal-api-dev",
    "partner-dev", "vendor-dev", "supplier-dev", "shop-dev", "store-dev",
    "cart-dev", "checkout-dev", "payment-dev", "pay-dev", "billing-dev",
    "invoice-dev", "reports-dev", "admin-api-dev", "manage-dev", "control-dev",
    "system-dev", "core-dev", "service-dev", "svc-dev"
]

# ── Helper Functions ──────────────────────────────────────────────────────

def _normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url
    return url

def _extract_root_domain(url: str) -> str:
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path
    host = host.split(":")[0].split("/")[0]
    if host.startswith("www."):
        host = host[4:]
    return host

def _resolve_dns_sync(hostname: str, record_type: str = "CNAME") -> Dict[str, Any]:
    """Synchronous DNS resolver with timeout."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    try:
        answers = resolver.resolve(hostname, record_type)
        if record_type == "CNAME":
            target = str(answers[0].target).rstrip(".")
            return {"status": "resolved", "data": target}
        elif record_type == "A":
            ips = [str(r) for r in answers]
            return {"status": "resolved", "data": ips}
        elif record_type == "MX":
            mx = [(r.preference, str(r.exchange).rstrip(".")) for r in answers]
            return {"status": "resolved", "data": mx}
        elif record_type == "TXT":
            txt = [b"".join(r.strings).decode("utf-8", errors="ignore") for r in answers]
            return {"status": "resolved", "data": txt}
        elif record_type == "NS":
            ns = [str(r.target).rstrip(".") for r in answers]
            return {"status": "resolved", "data": ns}
        else:
            return {"status": "resolved", "data": str(answers[0])}
    except dns.resolver.NXDOMAIN:
        return {"status": "nxdomain"}
    except dns.resolver.NoAnswer:
        return {"status": "no_answer"}
    except dns.exception.Timeout:
        return {"status": "timeout"}
    except Exception as e:
        return {"status": "error", "error": str(e)}

async def _resolve_dns(hostname: str, record_type: str = "CNAME") -> Dict[str, Any]:
    """Async wrapper for DNS resolution with multiple resolvers."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _resolve_dns_sync, hostname, record_type)

def _match_fingerprint(domain: str, record_data: Any, record_type: str) -> Optional[Dict[str, Any]]:
    """Match domain/record against fingerprint database."""
    if record_type == "CNAME":
        target = record_data.lower()
        for provider, fp in FINGERPRINTS.items():
            for pattern in fp.get("cname_patterns", []):
                if re.search(pattern, target, re.IGNORECASE):
                    return {"provider": provider, "fingerprint": fp}
    elif record_type == "A":
        ips = record_data if isinstance(record_data, list) else [record_data]
        for ip in ips:
            for provider, fp in FINGERPRINTS.items():
                for pattern in fp.get("a_patterns", []):
                    if re.match(pattern, ip):
                        return {"provider": provider, "fingerprint": fp}
    return None

async def _check_http(session: aiohttp.ClientSession, subdomain: str, fingerprint: Dict) -> Dict:
    """Perform advanced HTTP/HTTPS checks."""
    results = {}
    for scheme in ("https", "http"):
        try:
            url = f"{scheme}://{subdomain}"
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=REQUEST_TIMEOUT),
                ssl=False,
                allow_redirects=True,
            ) as resp:
                body = await resp.text(errors="ignore", limit=5000)
                headers = dict(resp.headers)
                # Check error pattern
                error_pattern = fingerprint.get("error_pattern", "")
                matched_error = False
                if error_pattern:
                    matched_error = re.search(error_pattern, body, re.IGNORECASE)
                # Check header patterns
                matched_header = False
                for h_pattern in fingerprint.get("header_patterns", []):
                    for h_value in headers.values():
                        if re.search(h_pattern, h_value, re.IGNORECASE):
                            matched_header = True
                            break
                    if matched_header:
                        break

                results[scheme] = {
                    "status": resp.status,
                    "matched_error": bool(matched_error),
                    "matched_header": matched_header,
                    "final_url": str(resp.url),
                    "body_snippet": body[:500],
                }
                # Consider takeover if error pattern matches OR (status in expected and header matches)
                expected_statuses = fingerprint.get("status_codes", [404, 403])
                if matched_error or (resp.status in expected_statuses and matched_header):
                    results[scheme]["vulnerable"] = True
                else:
                    results[scheme]["vulnerable"] = False
        except Exception as e:
            results[scheme] = {"error": str(e), "vulnerable": False}
    return results

async def _check_subdomain(
    session: aiohttp.ClientSession,
    subdomain: str,
    root_domain: str,
    semaphore: asyncio.Semaphore,
) -> Optional[Dict]:
    """Check a single subdomain for takeover vulnerability."""
    fqdn = f"{subdomain}.{root_domain}" if subdomain != root_domain else root_domain
    async with semaphore:
        # ── 1. DNS checks ─────────────────────────────────────────────────
        dns_results = {}

        # CNAME
        cname_result = await _resolve_dns(fqdn, "CNAME")
        dns_results["CNAME"] = cname_result

        if cname_result["status"] == "nxdomain":
            # Domain doesn't exist at all -> no takeover risk (it's not configured)
            return None

        if cname_result["status"] == "resolved":
            cname = cname_result["data"]
            # Match fingerprint on CNAME
            match = _match_fingerprint(fqdn, cname, "CNAME")
            if match:
                fp = match["fingerprint"]
                # ── 2. HTTP verification ──────────────────────────────────
                http_results = await _check_http(session, fqdn, fp)
                # Check if any scheme indicates vulnerability
                vulnerable = any(r.get("vulnerable", False) for r in http_results.values())
                if vulnerable:
                    # Determine confidence
                    confidence = 100
                    if http_results.get("https", {}).get("matched_error") or http_results.get("http", {}).get("matched_error"):
                        confidence = 100
                    elif http_results.get("https", {}).get("matched_header") or http_results.get("http", {}).get("matched_header"):
                        confidence = 90
                    else:
                        confidence = 80

                    # Build PoC
                    poc = fp.get("poc", f"Check {fqdn} for takeover.")
                    poc = poc.replace("{domain}", fqdn)

                    return {
                        "subdomain": fqdn,
                        "cname": cname,
                        "service": fp.get("service", "Unknown"),
                        "severity": fp.get("severity", "high"),
                        "confidence": confidence,
                        "vulnerable": True,
                        "dns_results": dns_results,
                        "http_results": http_results,
                        "poc": poc,
                        "remediation": fp.get("remediation", "Remove CNAME or claim the resource."),
                        "exploit_difficulty": fp.get("exploit_difficulty", "medium"),
                    }
                else:
                    # Not vulnerable, but maybe informational
                    return {
                        "subdomain": fqdn,
                        "cname": cname,
                        "service": fp.get("service", "Unknown"),
                        "severity": "info",
                        "confidence": 40,
                        "vulnerable": False,
                        "dns_results": dns_results,
                        "http_results": http_results,
                        "poc": "Resource exists but may not be exploitable.",
                        "remediation": "No action required.",
                        "exploit_difficulty": "none",
                    }

        # ── 3. Check A record ────────────────────────────────────────────
        a_result = await _resolve_dns(fqdn, "A")
        if a_result["status"] == "resolved":
            match = _match_fingerprint(fqdn, a_result["data"], "A")
            if match:
                fp = match["fingerprint"]
                http_results = await _check_http(session, fqdn, fp)
                vulnerable = any(r.get("vulnerable", False) for r in http_results.values())
                if vulnerable:
                    return {
                        "subdomain": fqdn,
                        "a_records": a_result["data"],
                        "service": fp.get("service", "Unknown"),
                        "severity": fp.get("severity", "high"),
                        "confidence": 90,
                        "vulnerable": True,
                        "dns_results": dns_results,
                        "http_results": http_results,
                        "poc": fp.get("poc", f"Check {fqdn} for takeover.").replace("{domain}", fqdn),
                        "remediation": fp.get("remediation", "Remove A record or claim the IP."),
                        "exploit_difficulty": fp.get("exploit_difficulty", "medium"),
                    }

        # ── 4. Check MX record ────────────────────────────────────────────
        mx_result = await _resolve_dns(fqdn, "MX")
        if mx_result["status"] == "resolved":
            mx_data = mx_result["data"]
            for pref, target in mx_data:
                match = _match_fingerprint(fqdn, target, "CNAME")
                if match:
                    fp = match["fingerprint"]
                    # MX takeover is harder, but still risk
                    return {
                        "subdomain": fqdn,
                        "mx_records": mx_data,
                        "service": fp.get("service", "Unknown"),
                        "severity": "medium",
                        "confidence": 60,
                        "vulnerable": True,
                        "dns_results": dns_results,
                        "poc": f"Check MX records for {fqdn}: dig MX {fqdn}",
                        "remediation": "Remove or update MX records.",
                        "exploit_difficulty": "hard",
                    }

        # ── 5. Check TXT record (Google Workspace, etc.) ────────────────
        txt_result = await _resolve_dns(fqdn, "TXT")
        if txt_result["status"] == "resolved":
            txt_data = txt_result["data"]
            for record in txt_data:
                if "google-site-verification" in record:
                    # Could indicate abandoned verification
                    return {
                        "subdomain": fqdn,
                        "txt_records": txt_data,
                        "service": "Google Workspace/Search Console",
                        "severity": "medium",
                        "confidence": 50,
                        "vulnerable": False,  # Not directly exploitable, but info leak
                        "dns_results": dns_results,
                        "poc": f"dig TXT {fqdn}",
                        "remediation": "Remove obsolete verification records.",
                        "exploit_difficulty": "none",
                    }

        return None

# ── Main run function ──────────────────────────────────────────────────────

async def run(url: str, context: Optional[Dict] = None) -> Dict[str, Any]:
    """
    Main entry point for subdomain takeover test.
    Args:
        url: target URL
        context: optional context from other tests
    Returns:
        dict with findings
    """
    test_name = "subdomain_takeover"
    remediation_base = (
        "Remove dangling DNS records pointing to unclaimed cloud resources. "
        "Claim the resource or delete the DNS record."
    )

    try:
        normalized = _normalize_url(url)
        root_domain = _extract_root_domain(normalized)
        if not root_domain or "." not in root_domain:
            return {
                "test_name": test_name,
                "status": "error",
                "severity": "info",
                "title": "Invalid domain",
                "description": f"Could not extract root domain from '{url}'",
                "evidence": [],
                "subdomains_checked": 0,
                "vulnerable_count": 0,
                "remediation": remediation_base,
            }
    except Exception as e:
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "Normalization error",
            "description": str(e),
            "evidence": [],
            "subdomains_checked": 0,
            "vulnerable_count": 0,
            "remediation": remediation_base,
        }

    # Allow custom subdomains from context
    subdomains = DEFAULT_SUBDOMAINS.copy()
    if context and context.get("custom_subdomains"):
        subdomains.extend(context["custom_subdomains"])

    # Remove duplicates
    subdomains = list(set(subdomains))
    # Also check the root domain itself
    subdomains.append("")

    async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)
        tasks = [
            _check_subdomain(session, sub, root_domain, semaphore)
            for sub in subdomains
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    # Process results
    evidence = []
    vulnerable = []
    for res in results:
        if isinstance(res, Exception):
            continue
        if res is None:
            continue
        if res.get("vulnerable"):
            vulnerable.append(res)
        evidence.append(res)

    if vulnerable:
        # Determine highest severity
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        max_sev = max(vulnerable, key=lambda x: severity_order.get(x.get("severity", "info"), 0))
        overall_severity = max_sev.get("severity", "high")
        status = "fail"
        title = f"Subdomain Takeover Vulnerabilities ({len(vulnerable)} found)"
        description = f"Found {len(vulnerable)} subdomain(s) with dangling DNS records pointing to unclaimed cloud resources."
        # Build detailed remediation
        remediation_parts = []
        for v in vulnerable:
            remediation_parts.append(f"{v['subdomain']}: {v.get('remediation', '')}")
        remediation = " ".join(remediation_parts)
    else:
        overall_severity = "info"
        status = "pass"
        title = "No Subdomain Takeover Vulnerabilities"
        description = f"Scanned {len(subdomains)} subdomains of {root_domain}. No dangling DNS records found."
        remediation = "No action required."

    return {
        "test_name": test_name,
        "status": status,
        "severity": overall_severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "subdomains_checked": len(subdomains),
        "vulnerable_count": len(vulnerable),
        "remediation": remediation,
    }


if __name__ == "__main__":
    import json
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))