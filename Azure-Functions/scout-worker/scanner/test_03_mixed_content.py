#!/usr/bin/env python3
"""
test_03_mixed_content.py – Bravo6 Mixed Content & SSL/TLS Hybrid Scanner (v3.1)
================================================================================
Fully patched with:
  • EC key strength equivalence (no more false “weak key” for ECDSA 384)
  • Smart CBC severity (low on modern sites, medium otherwise)
  • Informational note when openssl is missing (SSLv2)
  • Security header checks: X-Content-Type-Options, Referrer-Policy
  • Mixed content severity: forms/scripts → high
  • All set_ciphers() inside try/except → zero crashes
"""

import asyncio
import json
import re
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

# ── Silence deprecation warnings ────────────────────────────────────────
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# ── Configuration ──────────────────────────────────────────────────────────
CONNECT_TIMEOUT = 15
USER_AGENT = "Bravo6-MixedContent/3.1"
INTERNAL_PREFIXES = ("10.", "172.16.", "192.168.", "127.", "::1", "fc00:", "fe80:")

# Weak ciphers to test (OpenSSL names)
WEAK_CIPHERS = {
    "NULL-MD5": "NULL cipher (MD5)",
    "NULL-SHA": "NULL cipher (SHA1)",
    "EXP-RC4-MD5": "EXPORT RC4-MD5",
    "EXP-DES-CBC-SHA": "EXPORT DES-CBC-SHA",
    "RC4-MD5": "RC4-MD5",
    "RC4-SHA": "RC4-SHA",
    "DES-CBC3-SHA": "3DES-CBC-SHA (Sweet32)",
    "DES-CBC-SHA": "DES-CBC-SHA",
    "AES128-SHA": "AES128-CBC-SHA (BEAST)",
    "AES256-SHA": "AES256-CBC-SHA (BEAST)",
    "ECDHE-RSA-AES128-SHA": "ECDHE-RSA-AES128-CBC-SHA",
    "ECDHE-RSA-AES256-SHA": "ECDHE-RSA-AES256-CBC-SHA",
}

# ── Helpers ────────────────────────────────────────────────────────────────
def _parse_target(url: str) -> Tuple[str, int]:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    hostname = parsed.hostname
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

# ── Certificate analysis (cryptography) ───────────────────────────────────
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives.asymmetric import ec
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

def _analyze_cert(der: bytes, hostname: str) -> dict:
    if not HAS_CRYPTO:
        return {"error": "cryptography library missing"}
    cert = x509.load_der_x509_certificate(der)
    now = datetime.now(timezone.utc)
    days_left = (cert.not_valid_after_utc - now).days

    san_dns = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns = san_ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        pass

    cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn = cn_attr[0].value if cn_attr else ""
    host_lower = hostname.lower()
    match = any(name.lower() == host_lower or (name.startswith("*.") and host_lower.endswith(name[1:].lower())) for name in san_dns)
    if not match and cn:
        match = cn.lower() == host_lower or (cn.startswith("*.") and host_lower.endswith(cn[1:].lower()))
    self_signed = (cert.issuer == cert.subject)
    sig_oid = cert.signature_algorithm_oid._name
    weak_sig = any(x in sig_oid.lower() for x in ("sha1", "md5"))

    pub_key = cert.public_key()
    key_size = pub_key.key_size if hasattr(pub_key, "key_size") else None

    # Convert EC key size to equivalent RSA strength
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        curve = pub_key.curve.name
        if "384" in curve:
            key_size = 3072
        elif "256" in curve:
            key_size = 2048
        elif "521" in curve:
            key_size = 15360
        # else keep original (unlikely)

    return {
        "subject": ", ".join(f"{a.oid._name}={a.value}" for a in cert.subject),
        "issuer": ", ".join(f"{a.oid._name}={a.value}" for a in cert.issuer),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "days_until_expiry": days_left,
        "san": san_dns,
        "cn": cn,
        "hostname_match": match,
        "self_signed": self_signed,
        "signature_algorithm": sig_oid,
        "weak_signature": weak_sig,
        "key_size": key_size,
    }

# ── Protocol probes (native ssl) ───────────────────────────────────────────
def _probe_protocol(hostname: str, port: int, min_ver, max_ver) -> Optional[str]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = min_ver
    ctx.maximum_version = max_ver
    try:
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                return tls.version()
    except Exception:
        return None

# ── Cipher probe (safe) ────────────────────────────────────────────────────
def _probe_cipher(hostname: str, port: int, cipher_str: str) -> bool:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_ciphers(cipher_str)
    except ssl.SSLError:
        return False
    try:
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                neg = tls_sock.cipher()
                if not neg:
                    return False
                name = neg[0].upper()
                for weak in WEAK_CIPHERS:
                    if weak.upper() in name:
                        return True
                return False
    except Exception:
        return False

# ── External openssl helpers (optional) ────────────────────────────────────
async def _openssl_cmd(cmd: List[str]) -> Optional[str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout=10)
        return out.decode() + err.decode()
    except Exception:
        return None

async def _check_ssl2(host, port):
    out = await _openssl_cmd(["openssl", "s_client", "-ssl2", "-connect", f"{host}:{port}"])
    if out is None:
        return None   # openssl missing
    return "BEGIN CERTIFICATE" in out

async def _check_compression(host, port):
    out = await _openssl_cmd(["openssl", "s_client", "-connect", f"{host}:{port}", "-comp"])
    return "Compression: zlib" in out if out else None

async def _check_renegotiation(host, port):
    out = await _openssl_cmd(["openssl", "s_client", "-connect", f"{host}:{port}", "-renegotiate"])
    if out is None:
        return None
    return "Secure Renegotiation IS NOT supported" not in out

# ── OCSP & CT checks ──────────────────────────────────────────────────────
def _check_ocsp_stapling(hostname, port):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                return getattr(tls, "get_ocsp_response", lambda: None)() is not None
    except Exception:
        return None

def _check_ct_scts(hostname, port):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                scts = getattr(tls, "get_scts", lambda: [])()
                return len(scts)
    except Exception:
        return None

# ── Mixed content scan with severity ───────────────────────────────────────
async def _scan_mixed_content(html: str, base_url: str) -> List[dict]:
    findings = []
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all(["img", "script", "link", "iframe", "video", "audio", "source", "form"]):
        if tag.name == "form":
            src = tag.get("action")
        else:
            src = tag.get("src") or tag.get("href")
        if not src:
            continue
        full = urljoin(base_url, src)
        if full.startswith("http://"):
            # Determine severity based on tag
            if tag.name in ("form", "script"):
                sev = "high"
            elif tag.name in ("iframe", "video", "audio"):
                sev = "medium"
            else:
                sev = "low"
            findings.append({
                "type": "mixed_content",
                "tag": tag.name,
                "url": full,
                "severity": sev,
                "risk": f"Loaded over HTTP on HTTPS page ({tag.name})."
            })
    return findings

# ── Main scanner ───────────────────────────────────────────────────────────
async def run(url: str) -> Dict:
    try:
        hostname, port = _parse_target(url)
    except Exception as e:
        return {"test_name": "mixed_content", "status": "error", "title": "Invalid URL", "description": str(e)}

    if not HAS_CRYPTO:
        return {"test_name": "mixed_content", "status": "error", "title": "Missing cryptography package"}

    is_internal = _is_internal(hostname)
    findings = []
    cert_info = None
    hsts_header = None
    x_content_type_options = None
    referrer_policy = None
    mixed_findings = []
    tls13_supported = False

    # 1. Fetch page over HTTPS and collect headers
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=15),
            headers={"User-Agent": USER_AGENT}
        ) as session:
            async with session.get(f"https://{hostname}:{port}", ssl=True) as resp:
                html = await resp.text(errors="replace")
                hsts_header = resp.headers.get("Strict-Transport-Security")
                x_content_type_options = resp.headers.get("X-Content-Type-Options")
                referrer_policy = resp.headers.get("Referrer-Policy")
                # Mixed content check
                mixed_findings = await _scan_mixed_content(html, f"https://{hostname}:{port}")
                findings.extend(mixed_findings)
    except Exception as e:
        findings.append({"type": "fetch_error", "description": str(e)})

    # 2. SSL/TLS handshake & certificate
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
                if der:
                    cert_info = _analyze_cert(der, hostname)
    except Exception as e:
        findings.append({"type": "tls_error", "description": str(e)})

    # Certificate issues
    if cert_info:
        days = cert_info["days_until_expiry"]
        if days < 0:
            findings.append({"title": "Certificate expired", "severity": "critical", "days": days})
        elif days < 30:
            sev = "high" if days < 7 else "medium"
            findings.append({"title": f"Certificate expires in {days} days", "severity": sev, "days": days})
        if not cert_info["hostname_match"]:
            findings.append({"title": "Hostname mismatch", "severity": "critical" if not is_internal else "low"})
        if cert_info["self_signed"]:
            findings.append({"title": "Self‑signed certificate", "severity": "high" if not is_internal else "low"})
        if cert_info["weak_signature"]:
            findings.append({"title": "Weak signature", "severity": "high", "algorithm": cert_info["signature_algorithm"]})
        # Key size now uses equivalent RSA bits, so this threshold is correct
        if cert_info["key_size"] and cert_info["key_size"] < 2048:
            findings.append({"title": f"Weak public key ({cert_info['key_size']} bits)", "severity": "high"})

    # 3. Protocol checks
    protocol_status = {}
    ssl2 = await _check_ssl2(hostname, port)
    if ssl2 is None:
        protocol_status["SSLv2"] = "skipped (openssl not found)"
        findings.append({"title": "SSLv2 check skipped (openssl not installed)", "severity": "info"})
    elif ssl2:
        protocol_status["SSLv2"] = True
        findings.append({"title": "SSLv2 supported (DROWN)", "severity": "critical"})
    else:
        protocol_status["SSLv2"] = False

    ssl3 = await asyncio.to_thread(_probe_protocol, hostname, port, ssl.TLSVersion.SSLv3, ssl.TLSVersion.SSLv3)
    protocol_status["SSLv3"] = bool(ssl3)
    if ssl3:
        findings.append({"title": "SSLv3 supported (POODLE)", "severity": "critical"})

    tls10 = await asyncio.to_thread(_probe_protocol, hostname, port, ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1)
    protocol_status["TLSv1.0"] = bool(tls10)
    if tls10:
        findings.append({"title": "TLS 1.0 supported", "severity": "high"})

    tls11 = await asyncio.to_thread(_probe_protocol, hostname, port, ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1)
    protocol_status["TLSv1.1"] = bool(tls11)
    if tls11:
        findings.append({"title": "TLS 1.1 supported", "severity": "high"})

    # Check TLS 1.3 (used for modern site detection)
    tls13 = await asyncio.to_thread(_probe_protocol, hostname, port, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)
    tls13_supported = bool(tls13)
    protocol_status["TLSv1.3"] = tls13_supported

    # 4. Weak cipher probing
    cipher_status = {}
    for ciph, desc in WEAK_CIPHERS.items():
        ok = await asyncio.to_thread(_probe_cipher, hostname, port, ciph)
        cipher_status[ciph] = ok
        if ok:
            if "NULL" in ciph or "EXPORT" in ciph:
                sev = "critical"
            elif "RC4" in ciph or "DES" in ciph or "3DES" in ciph:
                sev = "high"
            elif "CBC" in desc.upper() or "SHA" in ciph:
                # Smart severity: on modern sites (TLS 1.3 + HSTS), reduce to low
                if tls13_supported and hsts_header:
                    sev = "low"
                else:
                    sev = "medium"
            else:
                sev = "low"
            findings.append({"title": f"Weak cipher accepted: {desc}", "severity": sev, "cipher": ciph})

    # 5. TLS compression, renegotiation
    comp = await _check_compression(hostname, port)
    if comp is None:
        findings.append({"title": "TLS compression check skipped (openssl not installed)", "severity": "info"})
    elif comp:
        findings.append({"title": "TLS compression enabled (CRIME)", "severity": "high"})

    reneg = await _check_renegotiation(hostname, port)
    if reneg is None:
        findings.append({"title": "Renegotiation check skipped (openssl not installed)", "severity": "info"})
    elif reneg is False:
        findings.append({"title": "Insecure renegotiation", "severity": "medium"})

    # 6. OCSP & CT
    ocsp = await asyncio.to_thread(_check_ocsp_stapling, hostname, port)
    if ocsp is False:
        findings.append({"title": "OCSP stapling not used", "severity": "low"})
    scts = await asyncio.to_thread(_check_ct_scts, hostname, port)
    if scts is not None and scts == 0:
        findings.append({"title": "No Certificate Transparency (SCTs)", "severity": "low"})

    # 7. HSTS
    if not hsts_header and not is_internal:
        findings.append({"title": "HSTS missing", "severity": "high"})

    # 8. Additional security headers
    if not x_content_type_options:
        findings.append({"title": "X-Content-Type-Options missing", "severity": "low"})
    if not referrer_policy:
        findings.append({"title": "Referrer-Policy missing", "severity": "low"})

    # Summary
    criticals = sum(1 for f in findings if f.get("severity") == "critical")
    highs = sum(1 for f in findings if f.get("severity") == "high")
    mediums = sum(1 for f in findings if f.get("severity") == "medium")

    sev = "critical" if criticals else "high" if highs else "medium" if mediums else "info"
    status = "fail" if criticals or highs else "warning" if findings else "pass"

    return {
        "test_name": "mixed_content_ssl",
        "status": status,
        "severity": sev,
        "title": f"Mixed Content & SSL/TLS – {len(findings)} issues",
        "mixed_content_count": len(mixed_findings),
        "ssl_tls_issues": len(findings) - len(mixed_findings),
        "certificate": cert_info,
        "protocols": protocol_status,
        "ciphers": {c: v for c, v in cipher_status.items() if v},
        "hsts": bool(hsts_header),
        "x_content_type_options": bool(x_content_type_options),
        "referrer_policy": bool(referrer_policy),
        "findings": findings,
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_03_mixed_content.py <url>")
        sys.exit(1)
    result = asyncio.run(run(sys.argv[1]))
    print(json.dumps(result, indent=2, ensure_ascii=False))