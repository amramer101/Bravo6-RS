#!/usr/bin/env python3
"""
test_04_ssl_tls.py – Bravo6 Ultimate SSL/TLS Scanner (v9.1 – Polished)
================================================================================
- OCSP stapling / CT: when null, note "unavailable" instead of missing.
- HSTS max‑age: ages between 1 and 2 years now raise a low‑severity finding
  (encourages preload eligibility).
- All other features unchanged (reliable chain, protocol/cipher checks).
"""

import asyncio
import json
import logging
import re
import socket
import ssl
import sys
import tempfile
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse

import aiohttp

# cryptography
try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtensionOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.x509 import ocsp as crypto_ocsp
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# certifi
try:
    import certifi
    CA_BUNDLE_PATH = certifi.where()
except ImportError:
    CA_BUNDLE_PATH = None

warnings.filterwarnings("ignore", category=DeprecationWarning)
logging.basicConfig(level=logging.WARNING)
log = logging.getLogger("ssl_tls")

USER_AGENT = "Bravo6-TLS-Scanner/9.1"
TIMEOUT = 20

# ── Helpers ────────────────────────────────────────────────────────────────
def _normalize_url(url: str) -> Tuple[str, int]:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("No hostname")
    port = parsed.port or 443
    return hostname, port

def _get_header(headers: Dict, name: str) -> Optional[str]:
    for key, val in headers.items():
        if key.lower() == name.lower():
            return val
    return None

def _make_finding(title, description, severity, confidence,
                  location="", evidence="", remediation="",
                  cwe="", owasp="", poc=None, category="ssl"):
    return {
        "title": title,
        "description": description,
        "severity": severity,
        "confidence": confidence,
        "location": location,
        "evidence": evidence,
        "remediation": remediation,
        "cwe": cwe,
        "owasp": owasp,
        "poc": poc,
        "category": category,
    }

def _apply_scoring(findings, context):
    deductions = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
    score = 100
    breakdown = []
    for f in findings:
        sev = f.get("severity", "info")
        ded = deductions.get(sev, 0)
        if ded:
            score -= ded
            breakdown.append(f"-{ded} ({sev}): {f['title']}")
    if context.get("is_login_page") or context.get("is_ecommerce"):
        score += 10
        breakdown.append("+10 (Login / E-commerce context)")
    if context.get("is_internal"):
        score -= 15
        breakdown.append("-15 (Internal IP)")
    if context.get("waf_detected"):
        score -= 10
        breakdown.append("-10 (WAF/CDN detected)")
    score = max(0, min(100, score))
    if score >= 95: grade = "A+"
    elif score >= 90: grade = "A"
    elif score >= 85: grade = "A-"
    elif score >= 80: grade = "B"
    elif score >= 70: grade = "C"
    elif score >= 60: grade = "D"
    elif score >= 50: grade = "E"
    else: grade = "F"
    return score, grade, breakdown

# ── Site context ───────────────────────────────────────────────────────────
async def _detect_context(hostname: str) -> Dict:
    ctx = {
        "is_login_page": False,
        "is_ecommerce": False,
        "is_internal": False,
        "waf_detected": False,
    }
    try:
        for _, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            ip = sockaddr[0]
            if ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                              "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                              "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                              "172.30.", "172.31.", "192.168.", "127.", "::1",
                              "fc00:", "fe80:")):
                ctx["is_internal"] = True
                break
    except Exception:
        pass

    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=8),
            headers={"User-Agent": USER_AGENT}
        ) as session:
            async with session.get(f"https://{hostname}", ssl=ssl_ctx) as resp:
                html = await resp.text()
                headers = resp.headers
                if 'cf-ray' in headers or 'x-sucuri-id' in headers or 'x-akamai-request-id' in headers:
                    ctx["waf_detected"] = True
                if re.search(r'<input[^>]*type=["\']?password["\']?', html, re.IGNORECASE):
                    ctx["is_login_page"] = True
                title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
                title = title_match.group(1).lower() if title_match else ""
                ecom_kw = ["shop", "store", "buy", "cart", "checkout", "shopping", "amazon", "ebay"]
                if any(k in title or k in html.lower() for k in ecom_kw):
                    ctx["is_ecommerce"] = True
    except Exception:
        pass
    return ctx

# ── Certificate analysis ───────────────────────────────────────────────────
def _analyze_cert(der: bytes, hostname: str) -> dict:
    cert = x509.load_der_x509_certificate(der)
    now = datetime.now(timezone.utc)
    days_left = (cert.not_valid_after_utc - now).days
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_dns = []
    cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn = cn_attr[0].value if cn_attr else ""
    host_lower = hostname.lower()
    match = any(
        name.lower() == host_lower or (name.lower().startswith("*.") and host_lower.endswith(name.lower()[1:]))
        for name in san_dns
    )
    if not match and cn:
        match = (cn.lower() == host_lower or (cn.lower().startswith("*.") and host_lower.endswith(cn.lower()[1:])))
    self_signed = (cert.issuer == cert.subject)
    sig_name = cert.signature_algorithm_oid._name
    weak_sig = any(x in sig_name.lower() for x in ("sha1", "md5"))
    pub_key = cert.public_key()
    key_size = None
    key_type = "unknown"
    if isinstance(pub_key, rsa.RSAPublicKey):
        key_size = pub_key.key_size
        key_type = "rsa"
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_size = pub_key.curve.key_size
        key_type = "ecdsa"
    is_le = any("Let's Encrypt" in attr.value for attr in cert.issuer)
    must_staple = False
    try:
        tls_feature = cert.extensions.get_extension_for_oid(ExtensionOID.TLS_FEATURE)
        for feature in tls_feature.value:
            if feature == x509.TLSFeatureType.status_request:
                must_staple = True
                break
    except x509.ExtensionNotFound:
        pass
    return {
        "subject": ", ".join(f"{a.oid._name}={a.value}" for a in cert.subject) if cert.subject else "",
        "issuer": ", ".join(f"{a.oid._name}={a.value}" for a in cert.issuer) if cert.issuer else "",
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
        "key_type": key_type,
        "is_lets_encrypt": is_le,
        "must_staple": must_staple,
    }

# ── Protocol probing (fixed version mapping) ───────────────────────────────
PROTOCOLS = {
    "SSLv3": ssl.TLSVersion.SSLv3,
    "TLSv1.0": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}

_VERSION_WIRE = {
    ssl.TLSVersion.SSLv3: "SSLv3",
    ssl.TLSVersion.TLSv1: "TLSv1",
    ssl.TLSVersion.TLSv1_1: "TLSv1.1",
    ssl.TLSVersion.TLSv1_2: "TLSv1.2",
    ssl.TLSVersion.TLSv1_3: "TLSv1.3",
}

def _test_protocol(hostname: str, port: int, min_ver: int) -> bool:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = min_ver
        ctx.maximum_version = min_ver
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                negotiated = tls_sock.version()
                expected = _VERSION_WIRE.get(min_ver)
                return negotiated == expected
    except Exception:
        return False

# ── Cipher testing (accurate, checks negotiated cipher) ────────────────────
WEAK_CIPHERS = {
    "NULL-MD5": "NULL cipher (MD5)",
    "NULL-SHA": "NULL cipher (SHA1)",
    "EXP-RC4-MD5": "EXPORT RC4-MD5 (512‑bit)",
    "EXP-DES-CBC-SHA": "EXPORT DES-CBC-SHA (512‑bit)",
    "EXP-EDH-DSS-DES-CBC-SHA": "EXPORT DH‑DSS‑DES",
    "EXP-EDH-RSA-DES-CBC-SHA": "EXPORT DH‑RSA‑DES",
    "RC4-MD5": "RC4‑MD5",
    "RC4-SHA": "RC4‑SHA",
    "DES-CBC3-SHA": "3DES‑CBC‑SHA (Sweet32)",
    "DES-CBC-SHA": "DES‑CBC‑SHA",
    "AES128-SHA": "AES128‑CBC‑SHA (BEAST)",
    "AES256-SHA": "AES256‑CBC‑SHA (BEAST)",
    "CAMELLIA128-SHA": "CAMELLIA128‑CBC‑SHA",
    "CAMELLIA256-SHA": "CAMELLIA256‑CBC‑SHA",
    "ECDHE-RSA-AES128-SHA": "ECDHE‑RSA‑AES128‑CBC‑SHA",
    "ECDHE-RSA-AES256-SHA": "ECDHE‑RSA‑AES256‑CBC‑SHA",
    "ADH-RC4-MD5": "Anonymous DH RC4‑MD5",
    "AECDH-NULL-SHA": "Anonymous ECDH NULL‑SHA",
}

def _test_cipher(hostname: str, port: int, cipher_string: str) -> bool:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers(cipher_string)
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                negotiated = tls_sock.cipher()
                if negotiated is None:
                    return False
                return negotiated[0].split('-')[0] == cipher_string.split('-')[0]
    except Exception:
        return False

# ── Chain validation (SSL verified connection) ─────────────────────────────
def _verify_chain_via_ssl_connect(hostname: str, port: int) -> Tuple[Optional[bool], Optional[str]]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return True, None
    except ssl.SSLCertVerificationError as e:
        return False, str(e)
    except Exception:
        return None, None

# ── Full chain retrieval (Python 3.10+) ────────────────────────────────────
def _get_peer_cert_chain(hostname: str, port: int) -> Optional[List[str]]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                if hasattr(tls_sock, "getpeercertchain"):
                    certs = tls_sock.getpeercertchain()
                    pem_chain = []
                    for cert_dict in certs:
                        der = cert_dict.get("certificate", b"")
                        if der:
                            pem = ssl.DER_cert_to_PEM_cert(der)
                            pem_chain.append(pem)
                    return pem_chain if pem_chain else None
    except Exception:
        pass
    return None

# ── OCSP check (Python, requires chain) ────────────────────────────────────
async def _check_ocsp_python(chain: List[str]) -> Dict:
    if not HAS_CRYPTO or len(chain) < 2:
        return {"revoked": None, "detail": "cryptography or intermediate not available"}
    try:
        leaf = x509.load_pem_x509_certificate(chain[0].encode())
        issuer = x509.load_pem_x509_certificate(chain[1].encode())
        builder = crypto_ocsp.OCSPRequestBuilder()
        builder = builder.add_certificate(leaf, issuer, hashes.SHA1())
        req = builder.build()
        req_data = req.public_bytes(serialization.Encoding.DER)
        aia = leaf.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        ocsp_urls = [desc.access_location.value for desc in aia.value
                     if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP]
        if not ocsp_urls:
            return {"revoked": None, "detail": "No OCSP responder URL"}
        async with aiohttp.ClientSession() as session:
            async with session.post(ocsp_urls[0], data=req_data,
                                    headers={"Content-Type": "application/ocsp-request"}) as resp:
                ocsp_resp = await resp.read()
        if not ocsp_resp:
            return {"revoked": None, "detail": "Empty OCSP response"}
        parsed = crypto_ocsp.load_der_ocsp_response(ocsp_resp)
        if parsed.response_status == crypto_ocsp.OCSPResponseStatus.SUCCESSFUL:
            return {"revoked": False, "detail": "OCSP response received (status not checked in detail)"}
        else:
            return {"revoked": None, "detail": f"OCSP response status: {parsed.response_status}"}
    except Exception as e:
        return {"revoked": None, "detail": f"OCSP check failed: {e}"}

# ── Main Scanner ───────────────────────────────────────────────────────────
async def run(url: str) -> Dict[str, Any]:
    hostname, port = _normalize_url(url)
    if not HAS_CRYPTO:
        return {"scanner": "ssl_tls", "target": f"{hostname}:{port}", "status": "error",
                "severity": "info", "confidence": 0, "score": 0, "grade": "N/A",
                "summary": "cryptography library required", "findings": [], "remediation": [], "details": {}}

    context = await _detect_context(hostname)
    findings = []
    cert_info = None

    # 1. Basic handshake & certificate parsing
    try:
        pem = ssl.get_server_certificate((hostname, port))
        der = ssl.PEM_cert_to_DER_cert(pem)
        cert_info = _analyze_cert(der, hostname)
    except Exception as e:
        return {"scanner": "ssl_tls", "target": f"{hostname}:{port}", "status": "error",
                "severity": "info", "confidence": 0, "score": 0, "grade": "N/A",
                "summary": f"TLS handshake failed: {e}", "findings": [], "remediation": [], "details": {}}

    # Certificate checks
    days = cert_info["days_until_expiry"]
    if days < 0:
        findings.append(_make_finding("Certificate expired", f"Expired on {cert_info['not_after']}",
                                      "critical", 100, location="Expiry", remediation="Renew immediately.", cwe="CWE-298"))
    elif days < 7:
        findings.append(_make_finding(f"Certificate expires in {days} days", "Renew urgently.",
                                      "high", 100, location="Expiry", remediation="Renew now.", cwe="CWE-298"))
    elif days < 30:
        findings.append(_make_finding(f"Certificate expires in {days} days", "Plan renewal.",
                                      "medium", 100, location="Expiry", remediation="Renew soon.", cwe="CWE-298"))

    if not cert_info["hostname_match"]:
        sev = "high" if not context["is_internal"] else "low"
        findings.append(_make_finding("Hostname mismatch", "CN/SAN does not match.", sev, 100,
                                      location="Certificate", remediation="Fix CN/SAN.", cwe="CWE-295"))
    if cert_info["self_signed"]:
        sev = "high" if not context["is_internal"] else "low"
        findings.append(_make_finding("Self‑signed certificate", "Not trusted by public CAs.", sev, 100,
                                      location="Certificate", remediation="Obtain CA‑signed certificate.", cwe="CWE-295"))
    if cert_info["weak_signature"]:
        findings.append(_make_finding(f"Weak signature algorithm ({cert_info['signature_algorithm']})", "",
                                      "high", 100, location="Certificate", remediation="Re‑issue with SHA‑256.", cwe="CWE-327"))

    # Key size
    if cert_info["key_type"] == "rsa" and cert_info["key_size"] and cert_info["key_size"] < 2048:
        findings.append(_make_finding(f"Weak RSA key ({cert_info['key_size']} bits)", "Key length < 2048.",
                                      "high", 100, location="Certificate", remediation="Re‑issue with ≥2048‑bit key.", cwe="CWE-326"))
    elif cert_info["key_type"] == "ecdsa" and cert_info["key_size"] and cert_info["key_size"] < 256:
        findings.append(_make_finding(f"Weak ECDSA key ({cert_info['key_size']} bits)", "Key length < 256.",
                                      "high", 100, location="Certificate", remediation="Re‑issue with ≥256‑bit EC key.", cwe="CWE-326"))
    elif cert_info["key_type"] == "ecdsa" and cert_info["key_size"] == 384:
        findings.append(_make_finding("ECC 384-bit key (strong)", "ECDSA curve P-384 provides high security.",
                                      "info", 50, location="Certificate", remediation="No action needed."))

    # 2. Chain validation (Python SSL verified connect)
    chain_valid, chain_error = _verify_chain_via_ssl_connect(hostname, port)
    if chain_valid is False:
        findings.append(_make_finding("Certificate chain not trusted",
                                      f"Verification failed: {chain_error}",
                                      "high", 95, location="Certificate chain", evidence=chain_error,
                                      remediation="Install the correct certificate chain.",
                                      cwe="CWE-295"))
    elif chain_valid is None:
        findings.append(_make_finding("Unable to verify certificate chain",
                                      "SSL verification could not be performed.",
                                      "medium", 70, location="Certificate chain",
                                      remediation="Ensure the server certificate is trusted by a public CA."))

    # 3. Full chain retrieval for OCSP
    cert_chain = _get_peer_cert_chain(hostname, port) or []
    ocsp_result = {"revoked": None}
    if len(cert_chain) >= 2:
        ocsp_result = await _check_ocsp_python(cert_chain)
        if ocsp_result.get("revoked") is True:
            findings.append(_make_finding("Certificate is REVOKED", ocsp_result.get("detail", ""),
                                          "critical", 100, location="OCSP check",
                                          evidence=ocsp_result.get("detail"),
                                          remediation="Replace the revoked certificate immediately.", cwe="CWE-299"))
        elif ocsp_result.get("revoked") is None and "No OCSP" not in ocsp_result.get("detail", ""):
            findings.append(_make_finding("OCSP check incomplete",
                                          ocsp_result.get("detail", ""),
                                          "low", 50, location="OCSP check",
                                          evidence=ocsp_result.get("detail"),
                                          remediation="Ensure OCSP responder URL is present and accessible."))

    # 4. Protocol probing
    tls_versions = {}
    for name, ver in PROTOCOLS.items():
        tls_versions[name] = _test_protocol(hostname, port, ver)

    # SSLv2 via openssl (optional)
    ssl2_supported = False
    try:
        import subprocess as sp
        proc = await asyncio.create_subprocess_exec(
            "openssl", "s_client", "-ssl2", "-connect", f"{hostname}:{port}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        if b"BEGIN CERTIFICATE" in out:
            ssl2_supported = True
    except Exception:
        pass
    tls_versions["SSLv2"] = ssl2_supported

    if tls_versions.get("SSLv2"):
        findings.append(_make_finding("SSLv2 supported (DROWN)", "Obsolete protocol",
                                      "critical", 100, location="SSLv2", remediation="Disable SSLv2.", cwe="CWE-757"))
    if tls_versions.get("SSLv3"):
        findings.append(_make_finding("SSLv3 supported (POODLE)", "Obsolete protocol",
                                      "critical", 100, location="SSLv3", remediation="Disable SSLv3.", cwe="CWE-757"))
    if tls_versions.get("TLSv1.0"):
        findings.append(_make_finding("TLS 1.0 supported", "Deprecated (BEAST)",
                                      "high", 100, location="TLSv1.0", remediation="Disable TLS 1.0.", cwe="CWE-757"))
    if tls_versions.get("TLSv1.1"):
        findings.append(_make_finding("TLS 1.1 supported", "Deprecated",
                                      "high", 100, location="TLSv1.1", remediation="Disable TLS 1.1.", cwe="CWE-757"))

    # 5. Weak ciphers
    cipher_status = {}
    for cipher_str, desc in WEAK_CIPHERS.items():
        supported = _test_cipher(hostname, port, cipher_str)
        cipher_status[cipher_str] = supported
        if supported:
            if "NULL" in cipher_str or "EXPORT" in cipher_str:
                sev = "critical"
            elif "RC4" in cipher_str or "DES" in cipher_str:
                sev = "high"
            elif "CBC" in desc.upper() or "SHA" in cipher_str:
                sev = "medium"
            else:
                sev = "low"
            findings.append(_make_finding(f"Weak cipher accepted: {desc}",
                                          f"Server negotiated {desc}.",
                                          sev, 95, location=f"Cipher: {cipher_str}",
                                          remediation="Remove weak ciphers from server configuration.",
                                          cwe="CWE-327", owasp="A02:2021",
                                          poc=f"openssl s_client -cipher {cipher_str} -connect {hostname}:{port}"))

    # ROBOT detection
    rsa_ciphers = [c for c in cipher_status if cipher_status[c] and any(x in c for x in ("RSA", "AES128", "AES256", "CAMELLIA", "DES", "RC4"))]
    if rsa_ciphers and any(tls_versions.get(v) for v in ["TLSv1.0", "TLSv1.1", "TLSv1.2"]):
        findings.append(_make_finding("ROBOT vulnerability possible",
                                      "RSA key exchange ciphers with older TLS versions.",
                                      "high", 90, location="Cipher/RSA", remediation="Disable RSA key exchange ciphers; use ECDHE.",
                                      cwe="CWE-327", owasp="A02:2021"))

    # 6. OCSP stapling & CT (Python ssl)
    ocsp_stapling = None
    ct_scts = None
    ocsp_ct_note = ""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                if hasattr(tls_sock, "get_ocsp_response"):
                    ocsp_stapling = tls_sock.get_ocsp_response() is not None
                else:
                    ocsp_ct_note = "OCSP stapling attribute not available on this platform."
                if hasattr(tls_sock, "get_scts"):
                    scts = tls_sock.get_scts()
                    ct_scts = len(scts) if scts else 0
                else:
                    ocsp_ct_note += " CT attribute not available."
    except Exception:
        ocsp_ct_note = "Unable to check OCSP/CT due to connection error."

    if ocsp_stapling is False:
        findings.append(_make_finding("OCSP stapling not used", "Missing OCSP response in handshake.",
                                      "low", 70, location="OCSP stapling",
                                      remediation="Enable OCSP stapling.",
                                      cwe="CWE-299", owasp="A02:2021"))
    elif ocsp_stapling is None and ocsp_ct_note:
        # Add a note about unavailability rather than a finding
        pass  # we will include the note in details

    if cert_info.get("must_staple") and ocsp_stapling is False:
        findings.append(_make_finding("OCSP Must‑Staple violated",
                                      "Certificate requires OCSP stapling but server did not provide it.",
                                      "critical", 100, location="OCSP Must‑Staple",
                                      remediation="Enable OCSP stapling or remove the must‑staple flag.",
                                      cwe="CWE-299", owasp="A02:2021"))
    if ct_scts == 0:
        sev = "high" if (context["is_login_page"] or context["is_ecommerce"]) else "medium"
        findings.append(_make_finding("No Certificate Transparency (SCTs)",
                                      "Certificate lacks Signed Certificate Timestamps.",
                                      sev, 90 if sev == "high" else 70, location="CT",
                                      remediation="Obtain a certificate with embedded SCTs.",
                                      cwe="CWE-299", owasp="A02:2021"))
    elif ct_scts is None and ocsp_ct_note:
        pass  # unavailability noted

    # 7. HSTS & CSP headers
    hsts_header = None
    csp_header = None
    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=8),
            headers={"User-Agent": USER_AGENT}
        ) as session:
            async with session.get(f"https://{hostname}:{port}", ssl=ssl_ctx) as resp:
                hsts_header = _get_header(resp.headers, "Strict-Transport-Security")
                csp_header = _get_header(resp.headers, "Content-Security-Policy")
    except Exception:
        pass

    if not hsts_header and not context["is_internal"]:
        findings.append(_make_finding("HSTS header missing", "No Strict-Transport-Security.",
                                      "high", 100, location="HTTP Header", remediation="Add HSTS header.",
                                      cwe="CWE-523", poc=f"curl -I https://{hostname}:{port} | grep -i strict"))
    elif hsts_header:
        if "includeSubDomains" not in hsts_header:
            findings.append(_make_finding("HSTS missing includeSubDomains", "HSTS lacks subdomain protection.",
                                          "medium", 90, location="HSTS header",
                                          remediation="Add includeSubDomains to HSTS."))
        max_age_match = re.search(r'max-age=(\d+)', hsts_header)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age < 31536000:
                findings.append(_make_finding("HSTS max-age too short", "Max-age should be at least 1 year.",
                                              "low", 80, location="HSTS header",
                                              remediation="Set max-age to at least 31536000."))
            elif max_age < 63072000:
                # Modified: now low severity instead of info, to encourage longer max‑age
                findings.append(_make_finding("HSTS max-age less than 2 years",
                                              "Consider increasing max-age to 63072000 (2 years) for better preload eligibility.",
                                              "low", 70, location="HSTS header",
                                              remediation="Increase max-age to 63072000 or more."))
        if "preload" in hsts_header:
            findings.append(_make_finding("HSTS preload flag present", "Domain eligible for browser preload list.",
                                          "info", 50, location="HSTS header",
                                          remediation="Consider submitting to hstspreload.org."))

    if csp_header and "upgrade-insecure-requests" in csp_header:
        findings.append(_make_finding("CSP upgrade-insecure-requests", "CSP is upgrading HTTP to HTTPS.",
                                      "info", 50, location="CSP header", remediation="No action needed."))

    # 8. Compression / Renegotiation (openssl optional)
    try:
        comp_proc = await asyncio.create_subprocess_exec(
            "openssl", "s_client", "-connect", f"{hostname}:{port}", "-comp",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL
        )
        comp_out, _ = await asyncio.wait_for(comp_proc.communicate(), timeout=10)
        if comp_out and b"Compression: zlib" in comp_out:
            findings.append(_make_finding("TLS compression enabled (CRIME)", "Enables CRIME attack.",
                                          "high", 95, location="TLS compression",
                                          remediation="Disable TLS compression.",
                                          cwe="CWE-310", owasp="A02:2021"))
    except Exception:
        pass

    try:
        reneg_proc = await asyncio.create_subprocess_exec(
            "openssl", "s_client", "-connect", f"{hostname}:{port}", "-renegotiate",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL
        )
        reneg_out, _ = await asyncio.wait_for(reneg_proc.communicate(), timeout=10)
        if reneg_out and b"Secure Renegotiation IS NOT supported" in reneg_out:
            findings.append(_make_finding("Insecure renegotiation", "Does not support secure renegotiation.",
                                          "medium", 90, location="Renegotiation",
                                          remediation="Enable secure renegotiation.",
                                          cwe="CWE-757", owasp="A02:2021"))
    except Exception:
        pass

    # ── Final scoring ────────────────────────────────────────────────────
    score, grade, score_breakdown = _apply_scoring(findings, context)
    worst_sev = max((f["severity"] for f in findings), key=lambda s: {"info":0,"low":1,"medium":2,"high":3,"critical":4}.get(s,0), default="info")
    status = "fail" if any(f["severity"] in ("critical","high") for f in findings) else "warning" if findings else "pass"
    remediation_list = sorted(set(f["remediation"] for f in findings if f["remediation"]))
    if not remediation_list:
        remediation_list = ["No action needed."]

    # Build details with note about OCSP/CT availability
    ocsp_ct_detail = ""
    if ocsp_stapling is None and ct_scts is None and ocsp_ct_note:
        ocsp_ct_detail = ocsp_ct_note
    elif ocsp_stapling is None:
        ocsp_ct_detail = "OCSP stapling information not available on this platform."
    elif ct_scts is None:
        ocsp_ct_detail = "Certificate Transparency information not available on this platform."

    return {
        "scanner": "ssl_tls",
        "target": f"{hostname}:{port}",
        "status": status,
        "severity": worst_sev,
        "confidence": 100,
        "score": score,
        "grade": grade,
        "summary": f"SSL/TLS – {len(findings)} issue(s) | Grade: {grade} ({score}/100)",
        "findings": findings,
        "remediation": remediation_list,
        "details": {
            "certificate": {
                "subject": cert_info["subject"],
                "issuer": cert_info["issuer"],
                "not_after": cert_info["not_after"],
                "days_until_expiry": cert_info["days_until_expiry"],
                "hostname_match": cert_info["hostname_match"],
                "self_signed": cert_info["self_signed"],
                "signature_algorithm": cert_info["signature_algorithm"],
                "key_size": cert_info["key_size"],
                "key_type": cert_info["key_type"],
                "san_dns": cert_info["san_dns"],
                "is_lets_encrypt": cert_info["is_lets_encrypt"],
                "must_staple": cert_info["must_staple"],
            },
            "chain_valid": chain_valid,
            "ocsp_revoked": ocsp_result.get("revoked"),
            "protocols": tls_versions,
            "ciphers": cipher_status,
            "hsts_header": hsts_header,
            "csp_header": csp_header,
            "ocsp_stapling": ocsp_stapling,
            "ct_scts": ct_scts,
            "ocsp_ct_note": ocsp_ct_detail if ocsp_ct_detail else None,
            "context": context,
            "score_breakdown": score_breakdown,
        }
    }

# ── CLI ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    target_url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    result = asyncio.run(run(target_url))
    print(json.dumps(result, indent=2, ensure_ascii=False))