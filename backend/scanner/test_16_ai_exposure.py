"""
test_16_ai_exposure.py

Bravo6 Security Scanner Module
-------------------------------
Detects exposed AI configuration / metadata files that may leak internal
architecture details, system-prompt-like instructions, staff contact info,
internal network/hostname details, or hardcoded credentials.

This is a PASSIVE check: it only issues GET requests against well-known,
static file paths that are commonly published by sites running AI plugins
or API gateways. It never probes functional/conversational endpoints
(e.g. /api/chat, /api/generate) and never sends any payload.

Paths checked:
    /.well-known/ai-plugin.json
    /llms.txt
    /.well-known/llms.txt
    /openapi.json
    /swagger.json
    /.well-known/openapi.json
"""

import asyncio
import json
import re
from urllib.parse import urljoin, urlparse

import aiohttp

USER_AGENT = "Bravo6-Scanner/1.0"
TIMEOUT = aiohttp.ClientTimeout(total=10)
MAX_BODY_BYTES = 2_000_000  # don't try to parse absurdly large responses

PATHS = [
    "/.well-known/ai-plugin.json",
    "/llms.txt",
    "/.well-known/llms.txt",
    "/openapi.json",
    "/swagger.json",
    "/.well-known/openapi.json",
]

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# Mirrors the credential-detection patterns used by test_01_secrets, kept
# local here so this module has no cross-module import dependency.
SECRET_PATTERNS = {
    "AWS Access Key ID": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Access Key": re.compile(
        r"(?i)aws(.{0,20})?secret(.{0,20})?[\"']\s*[:=]\s*[\"'][0-9a-zA-Z/+]{40}[\"']"
    ),
    "Generic API Key": re.compile(
        r"(?i)(api[_-]?key|apikey)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{16,})[\"']"
    ),
    "Bearer Token": re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.=]{20,}"),
    "Generic Secret/Token": re.compile(
        r"(?i)(secret|token|access[_-]?key)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{16,})[\"']"
    ),
    "JWT": re.compile(r"eyJ[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+"),
    "Private Key Block": re.compile(
        r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
    ),
    "Slack Token": re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
}

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9\-.]+")

INTERNAL_PATH_PATTERN = re.compile(r"(?i)/(internal|admin)(/|\b)")

INTERNAL_HOST_PATTERN = re.compile(
    r"(?i)\b(?:"
    r"localhost"
    r"|127\.0\.0\.1"
    r"|0\.0\.0\.0"
    r"|10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|[a-z0-9\-]+\.(?:internal|local|intranet|corp|lan)"
    r")\b"
)

SYSTEM_LOGIC_PATTERN = re.compile(
    r"(?i)(do not (reveal|disclose|mention)|never tell the user|system prompt|"
    r"internal logic|you are an? (ai|assistant) (that|who)|ignore (previous|"
    r"prior) instructions|confidential|internal use only|backend (logic|"
    r"architecture)|do not output)"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url):
        url = "https://" + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _redact(secret: str, keep: int = 4) -> str:
    """Redact a matched secret for safe evidence reporting."""
    secret = secret.strip()
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


def _truncate(s: str, n: int = 160) -> str:
    s = s.strip().replace("\n", " ")
    return s if len(s) <= n else s[: n - 3] + "..."


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

async def _fetch(session: aiohttp.ClientSession, base: str, path: str) -> dict:
    url = urljoin(base, path)
    result = {"path": path, "url": url, "status": None, "body": None, "error": None}
    try:
        async with session.get(
            url, timeout=TIMEOUT, allow_redirects=True, ssl=False
        ) as resp:
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
        result["error"] = f"unexpected_error: {e}"
    return result


# ---------------------------------------------------------------------------
# Analyzers — each returns a list of finding dicts:
#   {"severity": str, "summary": str, "evidence": str}
# ---------------------------------------------------------------------------

def _analyze_ai_plugin(text: str) -> list:
    findings = []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        findings.append(
            {
                "severity": "low",
                "summary": "ai-plugin.json present but not valid JSON",
                "evidence": _truncate(text),
            }
        )
        return findings

    if not isinstance(data, dict):
        findings.append(
            {
                "severity": "low",
                "summary": "ai-plugin.json present (unexpected JSON structure)",
                "evidence": _truncate(text),
            }
        )
        return findings

    # auth field
    auth = data.get("auth")
    if isinstance(auth, dict):
        auth_type = auth.get("type")
        if auth_type and str(auth_type).lower() != "none":
            findings.append(
                {
                    "severity": "info",
                    "summary": "AI plugin auth configuration disclosed",
                    "evidence": f"auth.type = {auth_type!r}",
                }
            )

    # internal hostnames/IPs anywhere in the document (covers api.url, etc.)
    raw_dump = json.dumps(data)
    internal_hosts = sorted(set(INTERNAL_HOST_PATTERN.findall(raw_dump)))
    if internal_hosts:
        findings.append(
            {
                "severity": "high",
                "summary": "Internal hostname/IP referenced inside ai-plugin.json",
                "evidence": "Found: " + ", ".join(internal_hosts[:5]),
            }
        )

    # description_for_model — system-prompt-style internal logic
    desc = data.get("description_for_model")
    if isinstance(desc, str) and SYSTEM_LOGIC_PATTERN.search(desc):
        match = SYSTEM_LOGIC_PATTERN.search(desc)
        findings.append(
            {
                "severity": "medium",
                "summary": "description_for_model exposes internal/system-prompt-like instructions",
                "evidence": f"Matched phrase near: \"{_truncate(desc[max(0, match.start()-20):match.end()+40])}\"",
            }
        )

    if not findings:
        findings.append(
            {
                "severity": "low",
                "summary": "ai-plugin.json present, no sensitive fields detected",
                "evidence": "File parsed successfully; no internal hosts, "
                "auth, or system-prompt indicators found.",
            }
        )

    return findings


def _analyze_llms_txt(text: str) -> list:
    findings = []

    # internal paths
    internal_lines = [
        ln.strip() for ln in text.splitlines() if INTERNAL_PATH_PATTERN.search(ln)
    ]
    if internal_lines:
        findings.append(
            {
                "severity": "high",
                "summary": "Internal paths referenced in llms.txt",
                "evidence": " | ".join(_truncate(ln, 100) for ln in internal_lines[:5]),
            }
        )

    # emails
    emails = sorted(set(EMAIL_PATTERN.findall(text)))
    if emails:
        findings.append(
            {
                "severity": "medium",
                "summary": "Staff/contact email address(es) exposed in llms.txt",
                "evidence": "Found: " + ", ".join(emails[:5]),
            }
        )

    # secrets / API keys
    secret_hits = []
    for label, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(text):
            matched = m.group(0)
            secret_hits.append(f"{label} ({_redact(matched)})")
    if secret_hits:
        findings.append(
            {
                "severity": "critical",
                "summary": "Hardcoded credential(s)/API key(s) exposed in llms.txt",
                "evidence": "Found: " + "; ".join(secret_hits[:5]),
            }
        )

    if not findings:
        findings.append(
            {
                "severity": "low",
                "summary": "llms.txt present, no sensitive content detected",
                "evidence": "File parsed; no internal paths, emails, or "
                "credentials found.",
            }
        )

    return findings


def _analyze_openapi(text: str, label: str) -> list:
    findings = [
        {
            "severity": "medium",
            "summary": f"{label} publicly exposed",
            "evidence": "API schema publicly exposed — reveals all endpoints, "
            "parameters, and data models to attackers.",
        }
    ]

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return findings

    if not isinstance(data, dict):
        return findings

    internal_servers = []

    # OpenAPI 3.x: servers: [{ "url": "..." }, ...]
    servers = data.get("servers")
    if isinstance(servers, list):
        for s in servers:
            if isinstance(s, dict):
                url_val = str(s.get("url", ""))
            else:
                url_val = str(s)
            if INTERNAL_HOST_PATTERN.search(url_val):
                internal_servers.append(url_val)

    # Swagger 2.0: "host": "internal.example.local"
    host_val = data.get("host")
    if isinstance(host_val, str) and INTERNAL_HOST_PATTERN.search(host_val):
        internal_servers.append(host_val)

    if internal_servers:
        findings.append(
            {
                "severity": "high",
                "summary": f"Internal server URL(s) disclosed in {label}",
                "evidence": "Found: " + ", ".join(sorted(set(internal_servers))[:5]),
            }
        )

    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def run(url: str) -> dict:
    test_name = "AI Configuration File Exposure"

    try:
        base = _normalize_url(url)
    except Exception as e:
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "Invalid target URL",
            "description": "The provided URL/domain could not be normalized.",
            "evidence": f"Input: {url!r} | Error: {e}",
            "remediation": "Provide a valid domain or URL (e.g. example.com).",
        }

    headers = {"User-Agent": USER_AGENT}

    try:
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(headers=headers, connector=connector) as session:
            tasks = [_fetch(session, base, path) for path in PATHS]
            results = await asyncio.gather(*tasks, return_exceptions=False)
    except Exception as e:
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "Scan could not be completed",
            "description": "An unexpected error occurred while setting up "
            "HTTP requests to the target.",
            "evidence": f"Error: {e}",
            "remediation": "Verify the target is reachable and retry the scan.",
        }

    found_files = []        # entries that returned HTTP 200
    not_found = []          # entries that returned a non-200 status
    transport_errors = []   # entries that raised a connection/timeout error
    all_findings = []       # (path, finding_dict) across all found files

    for res in results:
        path = res["path"]
        if res["error"]:
            transport_errors.append((path, res["error"]))
            continue
        if res["status"] != 200:
            not_found.append((path, res["status"]))
            continue

        found_files.append((path, res["url"]))
        body = res["body"] or ""

        if path.endswith("ai-plugin.json"):
            findings = _analyze_ai_plugin(body)
        elif path.endswith("llms.txt"):
            findings = _analyze_llms_txt(body)
        elif path.endswith("openapi.json"):
            findings = _analyze_openapi(body, "openapi.json")
        elif path.endswith("swagger.json"):
            findings = _analyze_openapi(body, "swagger.json")
        else:
            findings = [
                {
                    "severity": "low",
                    "summary": f"{path} present",
                    "evidence": "File returned HTTP 200.",
                }
            ]

        for f in findings:
            all_findings.append((path, f))

    # -----------------------------------------------------------------
    # If every single request failed at the transport level, this is a
    # scan error, not a finding about the target's posture.
    # -----------------------------------------------------------------
    if not found_files and not not_found and transport_errors:
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "Unable to reach target for AI exposure checks",
            "description": "All requests to candidate AI configuration "
            "paths failed at the network/transport layer.",
            "evidence": "; ".join(f"{p} -> {e}" for p, e in transport_errors),
            "remediation": "Confirm the target host is online and reachable, "
            "then re-run the scan.",
        }

    # -----------------------------------------------------------------
    # Nothing exposed at all.
    # -----------------------------------------------------------------
    if not found_files:
        evidence_lines = [f"{p} -> HTTP {s}" for p, s in not_found]
        evidence_lines += [f"{p} -> {e}" for p, e in transport_errors]
        return {
            "test_name": test_name,
            "status": "pass",
            "severity": "info",
            "title": "No AI configuration files exposed",
            "description": "None of the checked AI plugin/metadata/API "
            "schema paths returned HTTP 200. No exposure detected.",
            "evidence": "Checked paths: " + "; ".join(evidence_lines) if evidence_lines
            else f"Checked {len(PATHS)} paths, none returned HTTP 200.",
            "remediation": "No action required. If any of these files are "
            "intentionally published in the future, ensure they do not "
            "contain internal hostnames, credentials, or system-prompt-like "
            "content.",
        }

    # -----------------------------------------------------------------
    # Files were found — determine overall severity from worst finding.
    # -----------------------------------------------------------------
    overall_severity = "low"
    for _, f in all_findings:
        overall_severity = _worse(overall_severity, f["severity"])

    if overall_severity in ("critical", "high"):
        status = "fail"
    elif overall_severity == "medium":
        status = "warning"
    elif overall_severity in ("low", "info"):
        status = "warning" if overall_severity == "low" else "pass"
    else:
        status = "warning"

    # Build evidence string: which files were found + what was flagged inside.
    evidence_parts = []
    found_summary = ", ".join(f"{p} (HTTP 200)" for p, _ in found_files)
    evidence_parts.append(f"Files found: {found_summary}")

    for path, f in all_findings:
        evidence_parts.append(
            f"[{f['severity'].upper()}] {path}: {f['summary']} — {f['evidence']}"
        )

    if not_found:
        evidence_parts.append(
            "Not found: " + ", ".join(f"{p} (HTTP {s})" for p, s in not_found)
        )
    if transport_errors:
        evidence_parts.append(
            "Errors: " + ", ".join(f"{p} ({e})" for p, e in transport_errors)
        )

    evidence = "\n".join(evidence_parts)

    # Title/description reflect the worst category found.
    has_secrets = any(f["severity"] == "critical" for _, f in all_findings)
    has_internal = any(
        f["severity"] == "high" for _, f in all_findings
    )
    has_schema_medium = any(
        f["severity"] == "medium" for _, f in all_findings
    )

    if has_secrets:
        title = "Exposed AI configuration file contains hardcoded credentials"
        description = (
            "One or more AI configuration files (e.g. llms.txt) are "
            "publicly accessible and contain what appears to be live "
            "credentials, API keys, or tokens. This represents an "
            "immediate, exploitable exposure."
        )
        remediation = (
            "Immediately rotate any exposed credentials/API keys. Remove "
            "secrets from publicly served files, move them to a secrets "
            "manager or environment variables, and restrict access to "
            "AI configuration/metadata files via authentication or .well-known "
            "scoping where appropriate."
        )
    elif has_internal:
        title = "Exposed AI configuration file reveals internal infrastructure"
        description = (
            "One or more publicly accessible AI configuration/metadata "
            "files reference internal hostnames, IP addresses, or internal-"
            "only paths (e.g. /internal/, /admin/). This can help an "
            "attacker map internal network/application architecture."
        )
        remediation = (
            "Remove internal hostnames, IP addresses, and internal-only "
            "path references from any publicly served AI configuration "
            "files. Serve a sanitized, external-only version, and restrict "
            "or remove the file if it is not required to be public."
        )
    elif has_schema_medium:
        title = "API schema or AI configuration file publicly exposed"
        description = (
            "A publicly accessible API schema (openapi.json/swagger.json) "
            "or AI plugin/metadata file was found. This reveals API "
            "structure, endpoints, parameters, or model integration "
            "details to anyone who requests it."
        )
        remediation = (
            "Restrict access to API schema and AI configuration files to "
            "authenticated/internal consumers where possible, or ensure "
            "published schemas intentionally expose only what is meant to "
            "be public. Review descriptions and fields for unintended "
            "internal detail before publishing."
        )
    else:
        title = "AI configuration file(s) present, no sensitive data detected"
        description = (
            "AI configuration/metadata files were found on the target, "
            "but no internal hostnames, credentials, or system-prompt-"
            "like content were detected within them."
        )
        remediation = (
            "No immediate action required. Periodically re-review these "
            "files, as their content can change and may later expose "
            "sensitive details."
        )

    return {
        "test_name": test_name,
        "status": status,
        "severity": overall_severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
    }


# ---------------------------------------------------------------------------
# Manual/local test harness
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"

    async def _main():
        result = await run(target)
        print(json.dumps(result, indent=2))

    asyncio.run(_main())