"""
test_04_ssl_tls.py — Advanced SSL/TLS Scanner (with OpenSSL PoC & HSTS)

Upgraded:
- Checks for HSTS header to provide full context.
- Generates ready-to-use openssl s_client commands for each weak protocol.
- Confirms weak protocol support via active probing.
- Provides actionable evidence for auditors.
"""

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import aiohttp
from cryptography import x509
from cryptography.x509.oid import NameOID

CONNECT_TIMEOUT = 10
DEFAULT_HTTPS_PORT = 443

NULL_CIPHER_MARKERS = ("NULL",)
RC4_MARKERS = ("RC4",)
DES_MARKERS = ("3DES", "DES-CBC", "-DES-")
SHA1_MARKERS = ("-SHA", "SHA1")


def _normalize_target(url: str) -> tuple[str, int]:
    raw = url.strip()
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Invalid hostname: {url}")
    port = parsed.port or DEFAULT_HTTPS_PORT
    return hostname, port


def _make_result(status, severity, title, description, evidence, remediation):
    return {
        "test_name": "ssl_tls",
        "status": status,
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
    }


def _parse_dn(name):
    if not name:
        return ""
    return ", ".join(f"{a.oid._name}={a.value}" for a in name)


def _get_san(cert):
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except:
        return []


def _hostname_matches(hostname, cert):
    san_names = _get_san(cert)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    candidates = san_names or ([cn[0].value] if cn else [])
    host = hostname.lower()
    for c in candidates:
        c = c.lower()
        if c == host:
            return True
        if c.startswith("*.") and host.endswith(c[1:]) and host.count(".") == c.count("."):
            return True
    return False


def _check_self_signed(cert):
    return _parse_dn(cert.issuer) == _parse_dn(cert.subject)


def _classify_cipher(name):
    upper = name.upper()
    if any(m in upper for m in NULL_CIPHER_MARKERS):
        return "NULL cipher (no encryption)", "critical"
    if any(m in upper for m in RC4_MARKERS):
        return "RC4 (broken)", "critical"
    if any(m in upper for m in DES_MARKERS):
        return "DES/3DES (weak)", "high"
    if any(m in upper for m in SHA1_MARKERS) and "SHA256" not in upper and "SHA384" not in upper:
        return "SHA1 MAC (weak)", "medium"
    return None, None


async def _fetch_hsts(hostname, session):
    """Check for HSTS header."""
    try:
        async with session.get(f"https://{hostname}", ssl=False, timeout=aiohttp.ClientTimeout(total=5)) as resp:
            return resp.headers.get("Strict-Transport-Security")
    except:
        return None


async def run(url: str) -> dict:
    try:
        hostname, port = _normalize_target(url)
    except Exception as e:
        return _make_result("error", "info", "Invalid Target", str(e), {}, "Check URL.")

    loop = asyncio.get_event_loop()

    async def _bounded(fn, *args):
        return await asyncio.wait_for(loop.run_in_executor(None, fn, *args), timeout=CONNECT_TIMEOUT)

    # --- 1. Fetch HSTS (parallel with TLS scan ideally, but we do it first) ---
    hsts_value = None
    async with aiohttp.ClientSession() as session:
        hsts_value = await _fetch_hsts(hostname, session)

    # --- 2. Main TLS Scan ---
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
                if not der:
                    raise ValueError("No cert")
                cert = x509.load_der_x509_certificate(der)
                negotiated_version = tls_sock.version()
                negotiated_cipher = tls_sock.cipher()
    except Exception as e:
        return _make_result("error", "info", "TLS Handshake Failed", str(e), {}, "Check firewall/port.")

    # --- 3. Analysis ---
    now = datetime.now(timezone.utc)
    days_until = (cert.not_valid_after_utc - now).days

    issues = []
    evidence = {
        "hostname": hostname,
        "port": port,
        "cert_expiry": cert.not_valid_after_utc.strftime("%Y-%m-%d"),
        "days_until_expiry": days_until,
        "issuer": _parse_dn(cert.issuer),
        "subject": _parse_dn(cert.subject),
        "san": _get_san(cert),
        "hostname_match": _hostname_matches(hostname, cert),
        "self_signed": _check_self_signed(cert),
        "negotiated_version": negotiated_version,
        "negotiated_cipher": negotiated_cipher[0] if negotiated_cipher else None,
        "hsts": hsts_value,
        "weak_protocols": {},
        "poc_commands": []
    }

    # Expiry
    if days_until < 0:
        issues.append(("fail", "critical", "Certificate expired"))
    elif days_until < 30:
        issues.append(("fail", "high", f"Expires in {days_until} days"))
    elif days_until < 90:
        issues.append(("warning", "medium", f"Expires in {days_until} days"))

    # Hostname / Self-signed
    if not evidence["hostname_match"]:
        issues.append(("fail", "critical", "Hostname mismatch"))
    if evidence["self_signed"]:
        issues.append(("fail", "high", "Self-signed certificate"))

    # Cipher check
    cipher_name = evidence["negotiated_cipher"]
    if cipher_name:
        label, sev = _classify_cipher(cipher_name)
        if label:
            issues.append((sev, sev, f"Weak cipher: {label} ({cipher_name})"))

    # Protocol probing (SSLv3, TLS 1.0, 1.1)
    probe_map = {
        "SSLv3": ssl.TLSVersion.SSLv3,
        "TLSv1.0": ssl.TLSVersion.TLSv1,
        "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    }
    for label, ver in probe_map.items():
        try:
            supported = await _bounded(_probe_protocol, hostname, port, ver)
            evidence["weak_protocols"][label] = supported
            if supported:
                issues.append(("fail", "critical" if "SSLv3" in label else "high", f"{label} is supported"))
                evidence["poc_commands"].append(f"openssl s_client -connect {hostname}:{port} -{label.lower().replace('.', '')}")
        except:
            evidence["weak_protocols"][label] = "timeout/error"

    # Determine worst issue
    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    worst_sev = "info"
    worst_title = "TLS configuration is secure"
    for status, sev, title in issues:
        if severity_rank.get(sev, 0) > severity_rank.get(worst_sev, 0):
            worst_sev = sev
            worst_title = title

    status = "fail" if worst_sev in ("critical", "high") else "warning" if worst_sev in ("medium", "low") else "pass"

    remediation = []
    if days_until < 30:
        remediation.append("Renew the certificate immediately.")
    if not evidence["hostname_match"]:
        remediation.append("Issue a certificate with correct SAN/CN.")
    if evidence["self_signed"]:
        remediation.append("Replace self-signed with trusted CA cert.")
    if any(evidence["weak_protocols"].get(p, False) for p in ["SSLv3", "TLSv1.0", "TLSv1.1"]):
        remediation.append("Disable SSLv3, TLS 1.0, TLS 1.1; require TLS 1.2+.")
    if not hsts_value:
        remediation.append("Add Strict-Transport-Security (HSTS) header with long max-age.")
    if not remediation:
        remediation.append("No immediate action required, but consider enabling HSTS.")

    return _make_result(
        status=status,
        severity=worst_sev,
        title=worst_title,
        description=f"SSL/TLS scan of {hostname} found {len(issues)} issue(s).",
        evidence=evidence,
        remediation=" ".join(remediation)
    )


def _probe_protocol(hostname, port, version):
    """Blocking probe for a specific TLS version."""
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = version
        context.maximum_version = version
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return True
    except:
        return False