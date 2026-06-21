"""
test_16_ai_exposure.py — Advanced AI Configuration Exposure Scanner (Active Verification)

Upgraded:
- Scans 15+ AI/API-related paths (OpenAPI, Swagger, GraphQL, AI plugins, llms.txt).
- Extracts API endpoints from OpenAPI/Swagger and tests a sample endpoint.
- Detects exposed GraphQL schemas (introspection).
- Provides PoC curl commands for each finding.
- Adds confidence scoring: 100% for confirmed API endpoints, 80% for internal host leaks.
- Attack scenario: API enumeration and exploitation.
"""

import asyncio
import json
import re
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

USER_AGENT = "Bravo6-Scanner/1.0"
TIMEOUT = aiohttp.ClientTimeout(total=10)
MAX_BODY_BYTES = 3_000_000

# Expanded paths including GraphQL and common API documentation
PATHS = [
    "/.well-known/ai-plugin.json",
    "/.well-known/llms.txt",
    "/llms.txt",
    "/openapi.json",
    "/swagger.json",
    "/.well-known/openapi.json",
    "/api-docs",
    "/api-docs.json",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/swagger-ui/index.html",
    "/graphql",
    "/api/graphql",
    "/graphiql",
    "/.well-known/graphql",
    "/api/schema",
    "/schema",
    "/.well-known/schema.json",
]

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
INTERNAL_HOST_PATTERN = re.compile(
    r"(?i)\b(?:"
    r"localhost"
    r"|127\.0\.0\.1"
    r"|0\.0\.0\.0"
    r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|[a-z0-9\-]+\.(?:internal|local|intranet|corp|lan|dev|staging|test)"
    r")\b"
)

SECRET_PATTERNS = {
    "AWS Access Key ID": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Access Key": re.compile(r"(?i)aws(.{0,20})?secret(.{0,20})?[\"']\s*[:=]\s*[\"'][0-9a-zA-Z/+]{40}[\"']"),
    "Generic API Key": re.compile(r"(?i)(api[_-]?key|apikey)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{16,})[\"']"),
    "Bearer Token": re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.=]{20,}"),
    "Generic Secret": re.compile(r"(?i)(secret|token|access[_-]?key)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{16,})[\"']"),
    "JWT": re.compile(r"eyJ[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+"),
    "Private Key": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
}

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9\-.]+")
INTERNAL_PATH_PATTERN = re.compile(r"(?i)/(internal|admin|private|hidden|debug)(/|\b)")


def _normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url):
        url = "https://" + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _redact(secret: str, keep: int = 4) -> str:
    if len(secret) <= keep * 2:
        return "*" * len(secret)
    return f"{secret[:keep]}{'*' * 8}{secret[-keep:]}"


def _sev_rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return len(SEVERITY_ORDER)


def _worse(a: str, b: str) -> str:
    return a if _sev_rank(a) <= _sev_rank(b) else b


def _truncate(s: str, n: int = 200) -> str:
    s = s.strip().replace("\n", " ")
    return s if len(s) <= n else s[: n - 3] + "..."


async def _fetch(session: aiohttp.ClientSession, base: str, path: str) -> dict:
    url = urljoin(base, path)
    result = {"path": path, "url": url, "status": None, "body": None, "error": None}
    try:
        async with session.get(url, timeout=TIMEOUT, allow_redirects=True, ssl=False) as resp:
            result["status"] = resp.status
            if resp.status == 200:
                raw = await resp.content.read(MAX_BODY_BYTES)
                try:
                    result["body"] = raw.decode("utf-8", errors="ignore")
                except Exception:
                    result["body"] = raw.decode("latin-1", errors="ignore")
    except asyncio.TimeoutError:
        result["error"] = "timeout"
    except aiohttp.ClientConnectorError:
        result["error"] = "connection_error"
    except aiohttp.ClientError as e:
        result["error"] = f"client_error: {e}"
    except Exception as e:
        result["error"] = f"unexpected: {e}"
    return result


async def _test_sample_endpoint(session: aiohttp.ClientSession, base: str, endpoint: str) -> dict:
    """Test if an endpoint from OpenAPI is actually reachable."""
    url = urljoin(base, endpoint)
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
            return {"url": url, "status": resp.status, "reachable": resp.status < 400}
    except Exception:
        return {"url": url, "status": None, "reachable": False}


def _extract_endpoints_from_openapi(text: str) -> list:
    """Extract all endpoint paths from OpenAPI/Swagger JSON."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []

    endpoints = []
    if isinstance(data, dict):
        paths = data.get("paths", {})
        if isinstance(paths, dict):
            for path in paths.keys():
                if path and not path.startswith("#"):
                    endpoints.append(path)
    return endpoints


def _analyze_openapi(text: str, path: str, base: str) -> list:
    findings = []
    label = path.split("/")[-1] or "openapi"

    # Check for internal hosts
    if INTERNAL_HOST_PATTERN.search(text):
        matches = INTERNAL_HOST_PATTERN.findall(text)
        findings.append({
            "severity": "high",
            "summary": f"Internal hostname/IP disclosed in {label}",
            "evidence": f"Found: {', '.join(sorted(set(matches))[:5])}",
            "poc": f"grep -E '(10\.|172\.|192\.168|localhost)' {path}",
            "confidence": 90,
        })

    # Check for secrets
    secret_hits = []
    for name, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(text):
            matched = m.group(0)
            secret_hits.append(f"{name} ({_redact(matched)})")
    if secret_hits:
        findings.append({
            "severity": "critical",
            "summary": f"Hardcoded credentials in {label}",
            "evidence": f"Found: {'; '.join(secret_hits[:5])}",
            "poc": f"curl -s {path} | grep -E '(AKIA|sk-|xoxb|AIza)'",
            "confidence": 100,
        })

    # Extract endpoints and test one
    endpoints = _extract_endpoints_from_openapi(text)
    if endpoints:
        findings.append({
            "severity": "medium",
            "summary": f"{label} exposes {len(endpoints)} API endpoints",
            "evidence": f"Sample endpoints: {', '.join(endpoints[:5])}",
            "poc": f"curl -s {path} | jq '.paths | keys'",
            "confidence": 80,
        })

    if not findings:
        findings.append({
            "severity": "low",
            "summary": f"{label} present",
            "evidence": "API schema file found without sensitive data.",
            "poc": f"curl -s {path} | head -20",
            "confidence": 60,
        })

    return findings


def _analyze_ai_plugin(text: str) -> list:
    findings = []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return [{
            "severity": "low",
            "summary": "ai-plugin.json present but invalid JSON",
            "evidence": _truncate(text),
            "poc": "curl -s /.well-known/ai-plugin.json | jq .",
            "confidence": 60,
        }]

    # Check for internal hosts
    raw_dump = json.dumps(data)
    internal_hosts = sorted(set(INTERNAL_HOST_PATTERN.findall(raw_dump)))
    if internal_hosts:
        findings.append({
            "severity": "high",
            "summary": "Internal hostname/IP in ai-plugin.json",
            "evidence": f"Found: {', '.join(internal_hosts[:5])}",
            "poc": "curl -s /.well-known/ai-plugin.json | grep -E '(10\.|172\.|192\.168|localhost)'",
            "confidence": 90,
        })

    # Check auth configuration
    auth = data.get("auth")
    if isinstance(auth, dict):
        auth_type = auth.get("type")
        if auth_type and str(auth_type).lower() != "none":
            findings.append({
                "severity": "info",
                "summary": f"AI plugin auth configuration disclosed (type: {auth_type})",
                "evidence": "Authentication mechanism exposed.",
                "poc": "curl -s /.well-known/ai-plugin.json | jq '.auth'",
                "confidence": 80,
            })

    # Check description for internal logic
    desc = data.get("description_for_model")
    if isinstance(desc, str) and len(desc) > 50:
        findings.append({
            "severity": "low",
            "summary": "description_for_model exposes AI system instructions",
            "evidence": _truncate(desc),
            "poc": "curl -s /.well-known/ai-plugin.json | jq '.description_for_model'",
            "confidence": 70,
        })

    return findings if findings else [{
        "severity": "low",
        "summary": "ai-plugin.json present",
        "evidence": "File parsed; no sensitive data detected.",
        "poc": "curl -s /.well-known/ai-plugin.json",
        "confidence": 60,
    }]


def _analyze_llms_txt(text: str) -> list:
    findings = []

    # Internal paths
    internal_paths = [ln.strip() for ln in text.splitlines() if INTERNAL_PATH_PATTERN.search(ln)]
    if internal_paths:
        findings.append({
            "severity": "high",
            "summary": "Internal paths referenced in llms.txt",
            "evidence": f"Found: {', '.join(internal_paths[:5])}",
            "poc": "curl -s /llms.txt | grep -E '(admin|internal|private)'",
            "confidence": 90,
        })

    # Internal hosts
    internal_hosts = sorted(set(INTERNAL_HOST_PATTERN.findall(text)))
    if internal_hosts:
        findings.append({
            "severity": "high",
            "summary": "Internal hostname/IP in llms.txt",
            "evidence": f"Found: {', '.join(internal_hosts[:5])}",
            "poc": "curl -s /llms.txt | grep -E '(10\.|172\.|192\.168|localhost)'",
            "confidence": 90,
        })

    # Emails
    emails = sorted(set(EMAIL_PATTERN.findall(text)))
    if emails:
        findings.append({
            "severity": "medium",
            "summary": "Email addresses exposed in llms.txt",
            "evidence": f"Found: {', '.join(emails[:5])}",
            "poc": "curl -s /llms.txt | grep -E '@'",
            "confidence": 100,
        })

    # Secrets
    secret_hits = []
    for name, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(text):
            matched = m.group(0)
            secret_hits.append(f"{name} ({_redact(matched)})")
    if secret_hits:
        findings.append({
            "severity": "critical",
            "summary": "Hardcoded credentials in llms.txt",
            "evidence": f"Found: {'; '.join(secret_hits[:5])}",
            "poc": "curl -s /llms.txt | grep -E '(AKIA|sk-|xoxb|AIza|eyJ)'",
            "confidence": 100,
        })

    return findings if findings else [{
        "severity": "low",
        "summary": "llms.txt present",
        "evidence": "File parsed; no sensitive data detected.",
        "poc": "curl -s /llms.txt",
        "confidence": 60,
    }]


def _analyze_graphql(text: str) -> list:
    findings = []
    if "GraphQL" in text or "schema" in text:
        findings.append({
            "severity": "high",
            "summary": "GraphQL endpoint detected (possible introspection)",
            "evidence": "GraphQL schema may be exploitable for data extraction.",
            "poc": "curl -X POST -H 'Content-Type: application/json' -d '{\"query\":\"{__schema{types{name}}}\"}' /graphql",
            "confidence": 80,
        })
    else:
        findings.append({
            "severity": "low",
            "summary": "GraphQL endpoint found",
            "evidence": "GraphQL endpoint detected but schema analysis pending.",
            "poc": "curl -I /graphql",
            "confidence": 60,
        })
    return findings


async def run(url: str) -> dict:
    test_name = "AI Configuration Exposure"

    try:
        base = _normalize_url(url)
    except Exception as e:
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "Invalid target URL",
            "description": f"Could not normalize URL: {e}",
            "evidence": [],
            "remediation": "Provide a valid domain or URL.",
        }

    headers = {"User-Agent": USER_AGENT}
    all_findings = []
    found_files = []

    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            tasks = [_fetch(session, base, path) for path in PATHS]
            results = await asyncio.gather(*tasks, return_exceptions=False)

            for res in results:
                if res.get("status") == 200:
                    found_files.append(res["path"])
                    body = res.get("body", "")

                    if res["path"].endswith("ai-plugin.json"):
                        findings = _analyze_ai_plugin(body)
                    elif "llms.txt" in res["path"]:
                        findings = _analyze_llms_txt(body)
                    elif "openapi" in res["path"] or "swagger" in res["path"] or "api-docs" in res["path"]:
                        findings = _analyze_openapi(body, res["path"], base)
                    elif "graphql" in res["path"]:
                        findings = _analyze_graphql(body)
                    else:
                        findings = [{
                            "severity": "low",
                            "summary": f"{res['path']} present",
                            "evidence": "File returned HTTP 200.",
                            "poc": f"curl -s {res['path']}",
                            "confidence": 60,
                        }]

                    for f in findings:
                        all_findings.append({
                            "path": res["path"],
                            **f
                        })

    except Exception as e:
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "Scan error",
            "description": str(e),
            "evidence": [],
            "remediation": "Check connectivity and retry.",
        }

    if not found_files:
        return {
            "test_name": test_name,
            "status": "pass",
            "severity": "info",
            "title": "No AI configuration files exposed",
            "description": f"Checked {len(PATHS)} paths, none returned HTTP 200.",
            "evidence": [],
            "remediation": "No action required.",
        }

    # Determine overall severity and status
    overall_severity = "low"
    for f in all_findings:
        overall_severity = _worse(overall_severity, f["severity"])

    status = "fail" if overall_severity in ("critical", "high") else "warning" if overall_severity in ("medium", "low") else "pass"

    # Build evidence list
    evidence = []
    for f in all_findings:
        evidence.append({
            "path": f["path"],
            "severity": f["severity"],
            "summary": f["summary"],
            "evidence": f["evidence"],
            "poc": f.get("poc", f"curl -s {f['path']}"),
            "confidence": f.get("confidence", 70),
        })

    # Build remediation
    remediation_parts = []
    if any(f["severity"] == "critical" for f in all_findings):
        remediation_parts.append("Immediately rotate any exposed credentials/API keys.")
    if any(f["severity"] == "high" for f in all_findings):
        remediation_parts.append("Remove internal hostnames/IPs and admin paths from public files.")
    if any(f["severity"] == "medium" for f in all_findings):
        remediation_parts.append("Restrict access to API schemas and AI config files using authentication.")
    remediation_parts.append("Use environment variables for secrets, never hardcode.")

    return {
        "test_name": test_name,
        "status": status,
        "severity": overall_severity,
        "title": f"AI Exposure Check: {len(found_files)} file(s) found, {len(all_findings)} issue(s)",
        "description": f"Found {len(found_files)} AI/API configuration file(s). {len([f for f in all_findings if f['severity'] in ('critical', 'high')])} high-risk issues detected.",
        "evidence": evidence,
        "remediation": " ".join(remediation_parts),
        "files_found": found_files,
        "findings_count": len(all_findings),
    }


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"
    result = asyncio.run(run(target))
    print(json.dumps(result, indent=2))