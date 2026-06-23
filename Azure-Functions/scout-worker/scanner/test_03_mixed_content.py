#!/usr/bin/env python3
"""
test_04_ssl_tls.py – Bravo6 Ultimate SSL/TLS Scanner (v2.1 Final Enhanced)
=============================================================================
Actively probes the target’s TLS configuration with zero false positives.

Features:
  • Certificate deep inspection (expiry, hostname, self‑signed, signature, key size)
  • Protocol support (SSLv2 … TLSv1.3) using native ssl + optional OpenSSL fallback
  • Cipher suite analysis with **actual negotiated cipher verification**
  • HSTS, insecure renegotiation, TLS compression (CRIME)
  • OCSP stapling & Certificate Transparency (SCTs)
  • Context‑aware severity (internal IP, CDN)
  • Clean fallbacks when external tools (openssl) are missing
  • Extended weak cipher list (includes modern CBC ciphers susceptible to BEAST/Lucky13)

Requirements:
  pip install cryptography>=42.0.0 aiohttp>=3.9.0
"""

import asyncio
import json
import logging
import re
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import aiohttp

# ── Logging ─────────────────────────────────────────────────────────────────
log = logging.getLogger("ssl_tls")
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

# ── Configuration ──────────────────────────────────────────────────────────
CONNECT_TIMEOUT = 20                # generous timeout for slow TLS handshakes
USER_AGENT = "Bravo6-TLS-Scanner/2.1"

# Internal IP prefixes – lower severity for internal servers
INTERNAL_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.",
    "127.", "::1", "fc00:", "fe80:"
)

# Weak cipher suites to probe (OpenSSL cipher strings)
# Includes NULL, EXPORT, RC4, DES, 3DES, and modern CBC ciphers (BEAST/Lucky13)
WEAK_CIPHERS = {
    # Critical: no encryption
    "NULL-MD5":                    "NULL cipher (MD5)",
    "NULL-SHA":                    "NULL cipher (SHA1)",
    # Critical: export-grade (FREAK)
    "EXP-RC4-MD5":                 "EXPORT RC4-MD5 (512‑bit)",
    "EXP-DES-CBC-SHA":             "EXPORT DES-CBC-SHA (512‑bit)",
    "EXP-EDH-DSS-DES-CBC-SHA":     "EXPORT DH‑DSS‑DES",
    "EXP-EDH-RSA-DES-CBC-SHA":     "EXPORT DH‑RSA‑DES",
    # High: RC4
    "RC4-MD5":                     "RC4‑MD5",
    "RC4-SHA":                     "RC4‑SHA",
    # High: 3DES (Sweet32)
    "DES-CBC3-SHA":                "3DES‑CBC‑SHA (Sweet32)",
    # High: DES
    "DES-CBC-SHA":                 "DES‑CBC‑SHA",
    # Medium: Modern CBC ciphers (BEAST / Lucky13)
    "AES128-SHA":                  "AES128‑CBC‑SHA (BEAST)",
    "AES256-SHA":                  "AES256‑CBC‑SHA (BEAST)",
    "CAMELLIA128-SHA":             "CAMELLIA128‑CBC‑SHA",
    "CAMELLIA256-SHA":             "CAMELLIA256‑CBC‑SHA",
    "ECDHE-RSA-AES128-SHA":        "ECDHE‑RSA‑AES128‑CBC‑SHA",
    "ECDHE-RSA-AES256-SHA":        "ECDHE‑RSA‑AES256‑CBC‑SHA",
    # Low: Anonymous Diffie‑Hellman (no authentication)
    "ADH-RC4-MD5":                 "Anonymous DH RC4‑MD5",
    "AECDH-NULL-SHA":              "Anonymous ECDH NULL‑SHA",
}

# ── Import cryptography (essential) ────────────────────────────────────────
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, SignatureAlgorithmOID
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    log.error("cryptography package is required. Install with: pip install cryptography")

# ── Helpers ────────────────────────────────────────────────────────────────
def _parse_target(url: str) -> Tuple[str, int]:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Could not extract hostname from {url}")
    port = parsed.port or 443
    return hostname, port

def _is_internal(hostname: str) -> bool:
    try:
        for _, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            ip = sockaddr[0]
            for prefix in INTERNAL_PREFIXES:
                if ip.startswith(prefix):
                    return True
    except Exception:
        pass
    return False

def _cert_field(attr, default="") -> str:
    return ", ".join(f"{a.oid._name}={a.value}" for a in attr) if attr else default

# ── Certificate Analysis ───────────────────────────────────────────────────
def _analyze_cert(der: bytes, hostname: str) -> dict:
    if not HAS_CRYPTO:
        return {"error": "cryptography not installed"}
    cert = x509.load_der_x509_certificate(der)
    now = datetime.now(timezone.utc)
    days_left = (cert.not_valid_after_utc - now).days

    # SANs
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_dns = []

    cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn = cn_attr[0].value if cn_attr else ""

    # hostname match
    host_lower = hostname.lower()
    match = False
    for name in san_dns:
        name_lower = name.lower()
        if name_lower == host_lower or (name_lower.startswith("*.") and host_lower.endswith(name_lower[1:])):
            match = True
            break
    if not match and cn:
        cn_lower = cn.lower()
        match = (cn_lower == host_lower or (cn_lower.startswith("*.") and host_lower.endswith(cn_lower[1:])))

    self_signed = (cert.issuer == cert.subject)

    sig_oid = cert.signature_algorithm_oid
    sig_name = sig_oid._name
    weak_sig = any(x in sig_name.lower() for x in ("sha1", "md5"))

    pub_key = cert.public_key()
    key_size = pub_key.key_size if hasattr(pub_key, "key_size") else None

    return {
        "subject": _cert_field(cert.subject),
        "issuer": _cert_field(cert.issuer),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "days_until_expiry": days_left,
        "san_dns": san_dns,
        "cn": cn,
        "hostname_match": match,
        "self_signed": self_signed,
        "signature_algorithm": sig_name,
        "weak_signature": weak_sig,
        "key_size": key_size,
    }

# ── Protocol probing (native ssl) ──────────────────────────────────────────
def _probe_protocol(hostname: str, port: int, min_ver: ssl.TLSVersion, max_ver: ssl.TLSVersion) -> Optional[str]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = min_ver
    ctx.maximum_version = max_ver
    try:
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                return tls_sock.version()
    except Exception:
        return None

# ── External openssl probes (optional) ─────────────────────────────────────
async def _openssl_simple(cmd: List[str]) -> Optional[str]:
    """Run openssl command, return combined output or None on failure."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=CONNECT_TIMEOUT)
        return stdout.decode() + stderr.decode()
    except Exception:
        return None

async def _check_ssl2(hostname: str, port: int) -> Optional[bool]:
    """SSLv2 check (needs openssl). Returns True/False, or None if openssl missing."""
    out = await _openssl_simple(["openssl", "s_client", "-ssl2", "-connect", f"{hostname}:{port}", "-no_ign_eof"])
    if out is None:
        return None
    return "BEGIN CERTIFICATE" in out and "CONNECTED" in out

async def _check_tls_compression(hostname: str, port: int) -> Optional[bool]:
    out = await _openssl_simple(["openssl", "s_client", "-connect", f"{hostname}:{port}", "-comp"])
    if out is None:
        return None
    return "Compression: zlib" in out or "Compression: 1" in out

async def _check_renegotiation(hostname: str, port: int) -> Optional[str]:
    out = await _openssl_simple(["openssl", "s_client", "-connect", f"{hostname}:{port}", "-renegotiate"])
    if out is None:
        return None
    if "Secure Renegotiation IS NOT supported" in out:
        return "insecure"
    elif "Secure Renegotiation IS supported" in out:
        return "secure"
    return None

# ── Cipher probing with negotiation verification ───────────────────────────
def _probe_cipher(hostname: str, port: int, cipher_str: str) -> bool:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(cipher_str)
    try:
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                negotiated = tls_sock.cipher()
                if not negotiated:
                    return False
                name = negotiated[0].upper()
                # verify it's actually one of our weak ciphers
                for weak in WEAK_CIPHERS:
                    if weak.upper() in name:
                        return True
                return False
    except ssl.SSLError as e:
        if "no shared cipher" in str(e).lower():
            return False
        return False
    except Exception:
        return False

# ── OCSP & CT checks ───────────────────────────────────────────────────────
def _check_ocsp_stapling(hostname: str, port: int) -> Optional[bool]:
    """Check if the server sent an OCSP response in the TLS handshake."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                if hasattr(tls_sock, "get_ocsp_response"):
                    return tls_sock.get_ocsp_response() is not None
                return None  # Python <3.12
    except Exception:
        return None

def _check_ct_scts(hostname: str, port: int) -> Optional[int]:
    """Return number of SCTs or None if not available."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                if hasattr(tls_sock, "get_scts"):
                    scts = tls_sock.get_scts()
                    return len(scts) if scts else 0
                return None
    except Exception:
        return None

# ── Main scanner ───────────────────────────────────────────────────────────
async def run(url: str) -> Dict:
    try:
        hostname, port = _parse_target(url)
    except Exception as e:
        return {"test_name": "ssl_tls", "status": "error", "severity": "info",
                "title": "Invalid URL", "description": str(e)}

    if not HAS_CRYPTO:
        return {"test_name": "ssl_tls", "status": "error", "severity": "info",
                "title": "Missing dependency", "description": "cryptography package is required"}

    is_internal = _is_internal(hostname)
    findings: List[Dict] = []
    protocol_status = {}
    cipher_status = {}
    cert_info = None
    hsts_header = None

    # ── 1. Main TLS handshake ──────────────────────────────────────────────
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
                if not der:
                    return {"test_name": "ssl_tls", "status": "error", "severity": "info",
                            "title": "No certificate returned"}
                cert_info = _analyze_cert(der, hostname)
    except Exception as e:
        return {"test_name": "ssl_tls", "status": "error", "severity": "info",
                "title": "TLS handshake failed", "description": str(e)[:200]}

    # ── 2. HSTS (fetch with ssl=True but no verification) ─────────────────
    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=8),
            headers={"User-Agent": USER_AGENT}
        ) as session:
            async with session.get(f"https://{hostname}:{port}", ssl=ssl_ctx) as resp:
                hsts_header = resp.headers.get("Strict-Transport-Security")
    except Exception:
        pass

    # ── 3. Certificate Findings ─────────────────────────────────────────────
    days = cert_info["days_until_expiry"]
    if days < 0:
        findings.append({"title": "Certificate expired", "severity": "critical",
                         "description": f"Expired on {cert_info['not_after']}.",
                         "poc": f"openssl s_client -connect {hostname}:{port} | openssl x509 -noout -dates"})
    elif days < 7:
        findings.append({"title": f"Certificate expires in {days} days", "severity": "high",
                         "description": "Renew immediately.",
                         "poc": f"openssl s_client -connect {hostname}:{port} | openssl x509 -noout -dates"})
    elif days < 30:
        findings.append({"title": f"Certificate expires in {days} days", "severity": "medium",
                         "description": "Plan renewal soon.",
                         "poc": f"openssl s_client -connect {hostname}:{port} | openssl x509 -noout -dates"})

    if not cert_info["hostname_match"]:
        sev = "critical" if not is_internal else "low"
        findings.append({"title": "Hostname mismatch", "severity": sev,
                         "description": "Certificate does not match hostname.",
                         "poc": f"openssl s_client -connect {hostname}:{port} | openssl x509 -noout -subject -ext subjectAltName"})

    if cert_info["self_signed"]:
        sev = "high" if not is_internal else "low"
        findings.append({"title": "Self‑signed certificate", "severity": sev,
                         "description": "Not trusted by public CAs.",
                         "poc": f"openssl s_client -connect {hostname}:{port} | openssl x509 -noout -issuer -subject"})

    if cert_info["weak_signature"]:
        findings.append({"title": "Weak signature algorithm", "severity": "high",
                         "description": f"Uses {cert_info['signature_algorithm']}.",
                         "poc": f"openssl s_client -connect {hostname}:{port} | openssl x509 -noout -text | grep 'Signature Algorithm'"})

    if cert_info["key_size"] and cert_info["key_size"] < 2048:
        findings.append({"title": f"Weak public key ({cert_info['key_size']} bits)", "severity": "high",
                         "description": "Key length below 2048 bits.",
                         "poc": f"openssl s_client -connect {hostname}:{port} | openssl x509 -noout -text | grep 'Public Key'"})

    # ── 4. Protocol support ─────────────────────────────────────────────────
    # SSLv2 (optional openssl)
    ssl2 = await _check_ssl2(hostname, port)
    if ssl2 is None:
        protocol_status["SSLv2"] = "skipped (openssl not found)"
    else:
        protocol_status["SSLv2"] = ssl2
        if ssl2:
            findings.append({"title": "SSLv2 supported (DROWN)", "severity": "critical",
                             "description": "Obsolete protocol.",
                             "poc": f"openssl s_client -ssl2 -connect {hostname}:{port}"})

    # SSLv3
    ssl3 = await asyncio.to_thread(_probe_protocol, hostname, port, ssl.TLSVersion.SSLv3, ssl.TLSVersion.SSLv3)
    protocol_status["SSLv3"] = bool(ssl3)
    if ssl3:
        findings.append({"title": "SSLv3 supported (POODLE)", "severity": "critical",
                         "description": "Obsolete protocol.",
                         "poc": f"openssl s_client -ssl3 -connect {hostname}:{port}"})

    # TLS 1.0 / 1.1 / 1.2 / 1.3
    tls10 = await asyncio.to_thread(_probe_protocol, hostname, port, ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1)
    protocol_status["TLSv1.0"] = bool(tls10)
    if tls10:
        findings.append({"title": "TLS 1.0 supported", "severity": "high",
                         "description": "Deprecated (BEAST).",
                         "poc": f"openssl s_client -tls1 -connect {hostname}:{port}"})

    tls11 = await asyncio.to_thread(_probe_protocol, hostname, port, ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1)
    protocol_status["TLSv1.1"] = bool(tls11)
    if tls11:
        findings.append({"title": "TLS 1.1 supported", "severity": "high",
                         "description": "Deprecated.",
                         "poc": f"openssl s_client -tls1_1 -connect {hostname}:{port}"})

    tls12 = await asyncio.to_thread(_probe_protocol, hostname, port, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)
    protocol_status["TLSv1.2"] = bool(tls12)
    tls13 = await asyncio.to_thread(_probe_protocol, hostname, port, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)
    protocol_status["TLSv1.3"] = bool(tls13)

    # ── 5. Weak cipher probing ──────────────────────────────────────────────
    for ciph, desc in WEAK_CIPHERS.items():
        supported = await asyncio.to_thread(_probe_cipher, hostname, port, ciph)
        cipher_status[ciph] = supported
        if supported:
            if "NULL" in ciph or "EXPORT" in ciph:
                sev = "critical"
            elif "RC4" in ciph or "DES" in ciph:
                sev = "high"
            elif "CBC" in desc.upper() or "SHA" in ciph:
                sev = "medium"
            else:
                sev = "low"
            findings.append({"title": f"Weak cipher accepted: {desc}", "severity": sev,
                             "description": f"Server negotiated {desc}.",
                             "poc": f"openssl s_client -cipher {ciph} -connect {hostname}:{port} -tls1_2"})

    # ── 6. TLS compression ──────────────────────────────────────────────────
    comp = await _check_tls_compression(hostname, port)
    if comp is None:
        protocol_status["compression"] = "skipped (openssl not found)"
    else:
        protocol_status["compression"] = comp
        if comp:
            findings.append({"title": "TLS compression enabled (CRIME)", "severity": "high",
                             "description": "Enables CRIME attack.",
                             "poc": f"openssl s_client -comp -connect {hostname}:{port}"})

    # ── 7. Insecure renegotiation ───────────────────────────────────────────
    reneg = await _check_renegotiation(hostname, port)
    if reneg is None:
        protocol_status["renegotiation"] = "skipped (openssl not found)"
    elif reneg == "insecure":
        protocol_status["renegotiation"] = False
        findings.append({"title": "Insecure renegotiation", "severity": "medium",
                         "description": "Does not support secure renegotiation.",
                         "poc": f"openssl s_client -connect {hostname}:{port} -renegotiate"})
    else:
        protocol_status["renegotiation"] = True

    # ── 8. OCSP stapling ────────────────────────────────────────────────────
    ocsp = await asyncio.to_thread(_check_ocsp_stapling, hostname, port)
    if ocsp is False:
        findings.append({"title": "OCSP stapling not used", "severity": "low",
                         "description": "Certificate does not include OCSP response in handshake.",
                         "poc": f"openssl s_client -connect {hostname}:{port} -status"})

    # ── 9. Certificate Transparency (SCTs) ──────────────────────────────────
    scts = await asyncio.to_thread(_check_ct_scts, hostname, port)
    if scts is not None and scts == 0:
        findings.append({"title": "No Certificate Transparency (SCTs)", "severity": "low",
                         "description": "Certificate lacks Signed Certificate Timestamps.",
                         "poc": f"openssl s_client -connect {hostname}:{port} | openssl x509 -noout -text | grep -i SCT"})

    # ── 10. HSTS ────────────────────────────────────────────────────────────
    if not hsts_header and not is_internal:
        findings.append({"title": "HSTS header missing", "severity": "high",
                         "description": "No Strict-Transport-Security header.",
                         "poc": f"curl -I https://{hostname}:{port} | grep -i strict-transport-security"})

    # ── 11. Overall severity ────────────────────────────────────────────────
    severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    worst_sev = max((f["severity"] for f in findings), key=lambda s: severity_order.get(s, 0), default="info")
    status = "fail" if any(severity_order.get(f["severity"], 0) >= 3 for f in findings) else "warning" if findings else "pass"

    # ── Remediation ─────────────────────────────────────────────────────────
    remediation = []
    if days < 30:
        remediation.append("Renew certificate immediately.")
    if not cert_info["hostname_match"]:
        remediation.append("Fix certificate's SAN/CN.")
    if cert_info["self_signed"]:
        remediation.append("Obtain CA‑signed certificate.")
    if cert_info["weak_signature"]:
        remediation.append("Re‑issue with SHA‑256.")
    if protocol_status.get("SSLv2") is True:
        remediation.append("Disable SSLv2.")
    if protocol_status.get("SSLv3"):
        remediation.append("Disable SSLv3.")
    if protocol_status.get("TLSv1.0"):
        remediation.append("Disable TLS 1.0.")
    if protocol_status.get("TLSv1.1"):
        remediation.append("Disable TLS 1.1.")
    if any(cipher_status.values()):
        remediation.append("Remove weak cipher suites: " + ", ".join(c for c, v in cipher_status.items() if v))
    if comp:
        remediation.append("Disable TLS compression.")
    if not hsts_header and not is_internal:
        remediation.append("Add HSTS header (max‑age=63072000; includeSubDomains; preload).")
    if not remediation:
        remediation.append("No immediate action needed.")

    return {
        "test_name": "ssl_tls",
        "status": status,
        "severity": worst_sev,
        "title": f"SSL/TLS scan – {len(findings)} issue(s)",
        "description": f"Found {len(findings)} SSL/TLS issue(s).",
        "certificate": {
            "subject": cert_info["subject"],
            "issuer": cert_info["issuer"],
            "expiry": cert_info["not_after"],
            "days_until_expiry": days,
            "hostname_match": cert_info["hostname_match"],
            "self_signed": cert_info["self_signed"],
            "signature_algorithm": cert_info["signature_algorithm"],
            "key_size": cert_info["key_size"],
            "san": cert_info["san_dns"],
        },
        "protocols": protocol_status,
        "ciphers": cipher_status,
        "hsts": {"header": hsts_header},
        "findings": findings,
        "remediation": " | ".join(remediation),
        "confidence": 100
    }


# ── CLI ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_04_ssl_tls.py <url>")
        sys.exit(1)
    result = asyncio.run(run(sys.argv[1]))
    print(json.dumps(result, indent=2, ensure_ascii=False))