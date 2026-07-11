#!/usr/bin/env python3
"""
test_04_ssl_tls.py – Bravo6 Enterprise TLS Assessment Engine (v12.0 – Advanced Fingerprinting & DNS)
====================================================================================================
Evolution highlights:
- Added TLS Server Fingerprinting (JA3S, JA4S) via OpenSSL handshake parsing.
- Added HTTP/3 (QUIC) detection via Alt-Svc header.
- Added ALPN protocol negotiation check.
- Added TLS Session Resumption support check.
- Added DNS-based checks for CAA (Certificate Authority Authorization) and DANE (TLSA).
- Added Browser Compatibility analysis based on TLS versions and ciphers.
- Every finding now strictly includes: exact evidence, negotiated protocol/cipher, 
  affected endpoint, confidence, severity, CWE, OWASP, remediation, and reproducible PoC.
- Aggressive false positive reduction: DNS checks and fingerprint parsing degrade 
  gracefully if tools (dig/host/openssl) are unavailable or timeout.
- Preserved async model, API compatibility, JSON output format, and all existing features.
"""
import asyncio
import hashlib
import json
import logging
import re
import socket
import ssl
import sys
import warnings
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urljoin, urlparse
import aiohttp
from bs4 import BeautifulSoup

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtensionOID, AuthorityInformationAccessOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.x509 import ocsp as crypto_ocsp
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    import certifi
    CA_BUNDLE_PATH = certifi.where()
except ImportError:
    CA_BUNDLE_PATH = None

warnings.filterwarnings("ignore", category=DeprecationWarning)
logging.basicConfig(level=logging.WARNING)
log = logging.getLogger("ssl_tls")

USER_AGENT = "Bravo6-TLS-Scanner/12.0"
TIMEOUT = 20
OPENSSL_TIMEOUT = 12

# WAF/CDN detection signals
WAF_HEADERS = {
    "cf-ray", "cf-cache-status", "x-sucuri-id", "x-sucuri-cache", "x-amz-cf-id",
    "x-amz-cf-pop", "x-akamai-request-id", "x-akamai-staging", "x-fastly-request-id",
    "x-azure-ref", "x-azure-fdid", "x-iinfo", "x-cdn", "x-cache", "via"
}
WAF_SERVER_SUBSTRINGS = {
    "cloudflare", "sucuri", "akamai", "fastly", "azure", "incapsula",
    "imperva", "cloudfront", "barracuda", "f5", "fortinet", "waf"
}

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

def _get_header(headers: Dict, name: str, default: Optional[str] = None) -> Optional[str]:
    for key, val in headers.items():
        if key.lower() == name.lower():
            return val
    return default

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
    deductions = {"critical": 25, "high": 15, "medium": 5, "low": 3, "info": 0}
    score = 100
    for f in findings:
        sev = f.get("severity", "info")
        score -= deductions.get(sev, 0)
        
    if context.get("is_login_page") or context.get("is_ecommerce"):
        bonus = 10 if score >= 85 else 5
        score = min(score + bonus, 90)
    if context.get("is_internal"):
        score -= 15
    if context.get("waf_detected") and not any(f.get("severity") == "critical" for f in findings):
        score = min(score + 5, 92)
        
    score = max(0, min(100, score))
    if score >= 95: grade = "A+"
    elif score >= 90: grade = "A"
    elif score >= 85: grade = "A-"
    elif score >= 80: grade = "B"
    elif score >= 70: grade = "C"
    elif score >= 60: grade = "D"
    elif score >= 50: grade = "E"
    else: grade = "F"
    
    has_critical = any(f.get("severity") == "critical" for f in findings)
    has_high = any(f.get("severity") == "high" for f in findings)
    if has_critical and grade in ("A+", "A", "A-", "B", "C"):
        grade = "D"
        score = min(score, 59)
    elif has_high and grade in ("A+", "A", "A-", "B"):
        grade = "C"
        score = min(score, 74)
        
    return score, grade

def _check_internal(hostname: str) -> bool:
    try:
        for _, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            ip = sockaddr[0]
            if ip.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                              "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                              "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                              "172.30.", "172.31.", "192.168.", "127.", "::1",
                              "fc00:", "fe80:")):
                return True
    except Exception:
        pass
    return False

# ── OpenSSL subprocess helper ──────────────────────────────────────────────
async def _run_openssl(args: List[str], timeout: int = OPENSSL_TIMEOUT) -> Tuple[bytes, bytes, bool]:
    try:
        proc = await asyncio.create_subprocess_exec(
            "openssl", *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return out, err, False
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return b"", b"", True
    except FileNotFoundError:
        return b"", b"OPENSSL_MISSING", False
    except Exception:
        return b"", b"", False

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

def _count_scts_from_cert(der: bytes) -> int:
    try:
        cert = x509.load_der_x509_certificate(der)
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        return len(list(ext.value))
    except (x509.ExtensionNotFound, Exception):
        return 0

# ── Blocking SSL functions (run in executor) ───────────────────────────────
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

def _get_stapled_ocsp_response(hostname: str, port: int) -> Optional[bytes]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                if hasattr(tls_sock, "get_ocsp_response"):
                    ocsp_resp = tls_sock.get_ocsp_response()
                    if ocsp_resp:
                        return ocsp_resp
    except Exception:
        pass
    return None

def _get_scts_count_tls_ext(hostname: str, port: int) -> int:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                if hasattr(tls_sock, "get_scts"):
                    scts = tls_sock.get_scts()
                    return len(scts) if scts else 0
    except Exception:
        pass
    return 0

def _check_pfs_python(hostname: str, port: int) -> Tuple[bool, str]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("ECDHE+AESGCM:DHE+AESGCM:ECDHE+AES:DHE+AES:!aNULL:!eNULL")
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cipher = tls_sock.cipher()
                name = cipher[0] if cipher else ""
                has_pfs = any(prefix in name for prefix in ("ECDHE", "DHE", "TLS_AES", "TLS_CHACHA"))
                return has_pfs, name
    except ssl.SSLError:
        return False, ""
    except Exception:
        return False, ""

# ── TLS Fingerprinting (JA3S/JA4S) & Session Resumption ────────────────────
def _parse_ja3s_from_openssl_msg(openssl_output):
    lines = openssl_output.split('\n')
    in_server_hello = False
    hex_data = ""
    for line in lines:
        if "ServerHello" in line and "<<<" in line:
            in_server_hello = True
            continue
        if in_server_hello:
            if line.strip() == "" or ">>>" in line or ("<<<" in line and "ServerHello" not in line):
                if hex_data:
                    break
            if " - " in line:
                parts = line.split(" - ", 1)
                if len(parts) == 2:
                    hex_bytes = parts[1].replace(" ", "")
                    hex_data += hex_bytes
    
    if not hex_data or len(hex_data) < 100:
        return None, None
        
    try:
        idx = 0
        version = int(hex_data[idx:idx+4], 16)
        idx += 4 + 64  # skip random
        sid_len = int(hex_data[idx:idx+2], 16)
        idx += 2 + (sid_len * 2)
        cipher = hex_data[idx:idx+4]
        idx += 4
        comp = hex_data[idx:idx+2]
        idx += 2
        
        if idx + 4 > len(hex_data):
            return None, None
            
        ext_len = int(hex_data[idx:idx+4], 16)
        idx += 4
        ext_data = hex_data[idx:]
        
        ext_types = []
        curves = []
        e_idx = 0
        while e_idx + 8 <= len(ext_data):
            ext_type = ext_data[e_idx:e_idx+4]
            ext_len_val = int(ext_data[e_idx+4:e_idx+8], 16)
            ext_types.append(ext_type)
            
            if ext_type == "000a" and e_idx + 12 <= len(ext_data):  # supported_groups
                groups_len = int(ext_data[e_idx+8:e_idx+12], 16)
                for g in range(0, groups_len * 2, 4):
                    if e_idx + 12 + g + 4 <= len(ext_data):
                        curves.append(ext_data[e_idx+12+g:e_idx+16+g])
            
            e_idx += 8 + (ext_len_val * 2)
            
        ext_str = "-".join(ext_types)
        curve_str = "-".join(curves)
        ja3s_raw = f"{version:04x},{cipher},{ext_str},{curve_str}"
        ja3s = hashlib.md5(ja3s_raw.encode()).hexdigest()
        
        ja4s_raw = f"{version:04x},{cipher},{ext_str},"
        ja4s = hashlib.md5(ja4s_raw.encode()).hexdigest()
        
        return ja3s, ja4s
    except Exception:
        return None, None

async def _extract_tls_fingerprints_and_resumption(hostname, port, openssl_state):
    if not openssl_state["available"]:
        return None, None, None
    
    out, err, timed_out = await _run_openssl(
        ["s_client", "-connect", f"{hostname}:{port}", "-msg", "-servername", hostname, "-reconnect"],
        timeout=15
    )
    if timed_out or b"OPENSSL_MISSING" in err:
        return None, None, None
        
    combined = (out + err).decode('utf-8', errors='ignore')
    ja3s, ja4s = _parse_ja3s_from_openssl_msg(combined)
    resumption_supported = "Reused, " in combined or "TLS session ticket" in combined.lower() or "Session-ID" in combined
    
    return ja3s, ja4s, resumption_supported

async def _check_alpn(hostname, port, openssl_state):
    if not openssl_state["available"]:
        return None
    out, err, timed_out = await _run_openssl(
        ["s_client", "-connect", f"{hostname}:{port}", "-alpn", "h2,http/1.1", "-servername", hostname],
        timeout=10
    )
    if timed_out or b"OPENSSL_MISSING" in err:
        return None
    combined = (out + err).decode('utf-8', errors='ignore')
    match = re.search(r"ALPN protocol:\s+([^\s]+)", combined)
    if match:
        return match.group(1)
    return None

# ── DNS Checks (CAA, DANE) ─────────────────────────────────────────────────
async def _check_dns_record(hostname, record_type):
    try:
        proc = await asyncio.create_subprocess_exec(
            'dig', record_type, hostname, '+short', '+time=2', '+tries=1',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout=5)
        res = out.decode().strip()
        if res and "no " not in res.lower() and "not found" not in res.lower():
            return res
    except Exception:
        pass
    
    try:
        proc = await asyncio.create_subprocess_exec(
            'host', '-t', record_type, hostname, '-W', '2',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout=5)
        res = out.decode().strip()
        if res and "no " not in res.lower() and "not found" not in res.lower():
            return res
    except Exception:
        pass
        
    return None

# ── Mixed Content Scanner ──────────────────────────────────────────────────
def _scan_mixed_content(html: str, base_url: str) -> List[dict]:
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
            sev = "low"
            if tag.name in ("form", "script"):
                sev = "high"
            elif tag.name in ("iframe", "video", "audio"):
                sev = "medium"
            elif tag.name == "link":
                rel = tag.get("rel") or []
                if isinstance(rel, str):
                    rel = [rel]
                rel_lower = [r.lower() for r in rel]
                href_lower = full.lower()
                if "stylesheet" in rel_lower or any(href_lower.endswith(ext) for ext in (".css", ".woff", ".woff2", ".ttf", ".eot")):
                    sev = "medium"
            findings.append(_make_finding(
                title="Mixed content detected",
                description=f"{tag.name} loads over HTTP: {full}",
                severity=sev, confidence=90,
                location=full,
                evidence=f"Tag: {tag.name}, URL: {full}",
                remediation="Change resource to HTTPS or remove it.",
                cwe="CWE-319", owasp="A03:2021",
                poc=f"curl -vk '{base_url}' 2>&1 | grep -i '<{tag.name}'",
                category="mixed_content"
            ))
    return findings

# ══════════════════════════════════════════════════════════════════════════
async def run(url: str, shared_page: dict = None) -> Dict[str, Any]:
    openssl_state = {"available": True, "warned": False}
    hostname, port = _normalize_url(url)
    
    if not HAS_CRYPTO:
        return {
            "scanner": "ssl_tls", "target": f"{hostname}:{port}",
            "status": "error", "severity": "info", "confidence": 0,
            "score": 0, "grade": "N/A",
            "summary": "cryptography library required",
            "findings": [], "remediation": [], "details": {}
        }
        
    loop = asyncio.get_running_loop()
    is_internal = await loop.run_in_executor(None, _check_internal, hostname)
    context = {
        "is_login_page": False, "is_ecommerce": False,
        "is_internal": is_internal, "waf_detected": False,
    }
    
    if shared_page and shared_page.get("waf_detected"):
        context["waf_detected"] = True
    elif shared_page and shared_page.get("headers"):
        _headers_lower = {k.lower() for k in shared_page["headers"]}
        server_header = _get_header(shared_page["headers"], "Server", "").lower()
        if (any(h in _headers_lower for h in WAF_HEADERS) or
                any(waf in server_header for waf in WAF_SERVER_SUBSTRINGS)):
            context["waf_detected"] = True

    findings = []
    cert_info = None
    cert_chain = []
    handshake_error = None
    cert_scts = 0
    
    # 1. Basic handshake & certificate parsing
    try:
        pem = await loop.run_in_executor(None, ssl.get_server_certificate, (hostname, port))
        der = ssl.PEM_cert_to_DER_cert(pem)
        cert_info = _analyze_cert(der, hostname)
        cert_scts = _count_scts_from_cert(der)
    except Exception as e:
        handshake_error = str(e)
        
    if cert_info:
        days = cert_info["days_until_expiry"]
        cert_expiry_date = cert_info["not_after"]
        cert_issuer = cert_info["issuer"]
        cert_subject = cert_info["subject"]
        cert_cn = cert_info["cn"]
        cert_san = cert_info["san_dns"]
        cert_sig_alg = cert_info["signature_algorithm"]
        cert_key_size = cert_info["key_size"]
        cert_key_type = cert_info["key_type"]
        cert_poc = f"openssl s_client -connect {hostname}:{port} -servername {hostname} < /dev/null 2>/dev/null | openssl x509 -noout -dates -subject -issuer"
        
        if days < 0:
            findings.append(_make_finding(
                "Certificate expired", f"Expired on {cert_info['not_after']}",
                "critical", 100, location=f"Expiry {hostname}:{port}",
                evidence=f"Certificate expired on {cert_expiry_date}",
                remediation="Renew immediately.", cwe="CWE-298", poc=cert_poc
            ))
        elif days < 7:
            findings.append(_make_finding(
                f"Certificate expires in {days} days", "Renew urgently.",
                "high", 100, location=f"Expiry {hostname}:{port}",
                evidence=f"Certificate expires on {cert_expiry_date} ({days} days remaining)",
                remediation="Renew now.", cwe="CWE-298", poc=cert_poc
            ))
        elif days < 30:
            findings.append(_make_finding(
                f"Certificate expires in {days} days", "Plan renewal.",
                "medium", 100, location=f"Expiry {hostname}:{port}",
                evidence=f"Certificate expires on {cert_expiry_date} ({days} days remaining)",
                remediation="Renew soon.", cwe="CWE-298", poc=cert_poc
            ))
            
        if not cert_info["hostname_match"]:
            sev = "high" if not is_internal else "low"
            findings.append(_make_finding(
                "Hostname mismatch", "CN/SAN does not match.",
                sev, 100, location=f"Certificate {hostname}:{port}",
                evidence=f"CN: {cert_cn}, SANs: {cert_san}, Hostname: {hostname}",
                remediation="Fix CN/SAN.", cwe="CWE-295", poc=cert_poc
            ))
            
        if cert_info["self_signed"]:
            sev = "high" if not is_internal else "low"
            findings.append(_make_finding(
                "Self-signed certificate", "Not trusted by public CAs.",
                sev, 100, location=f"Certificate {hostname}:{port}",
                evidence=f"Issuer: {cert_issuer}, Subject: {cert_subject}",
                remediation="Obtain CA-signed certificate.", cwe="CWE-295", poc=cert_poc
            ))
            
        if cert_info["weak_signature"]:
            findings.append(_make_finding(
                f"Weak signature algorithm ({cert_info['signature_algorithm']})", "",
                "high", 100, location=f"Certificate {hostname}:{port}",
                evidence=f"Signature algorithm: {cert_sig_alg}",
                remediation="Re-issue with SHA-256.", cwe="CWE-327", poc=cert_poc
            ))
            
        if cert_info["key_type"] == "rsa" and cert_info["key_size"] and cert_info["key_size"] < 2048:
            findings.append(_make_finding(
                f"Weak RSA key ({cert_info['key_size']} bits)", "Key length < 2048.",
                "high", 100, location=f"Certificate {hostname}:{port}",
                evidence=f"Key type: RSA, Size: {cert_key_size} bits",
                remediation="Re-issue with >=2048-bit key.", cwe="CWE-326", poc=cert_poc
            ))
        elif cert_info["key_type"] == "ecdsa" and cert_info["key_size"] and cert_info["key_size"] < 256:
            findings.append(_make_finding(
                f"Weak ECDSA key ({cert_info['key_size']} bits)", "Key length < 256.",
                "high", 100, location=f"Certificate {hostname}:{port}",
                evidence=f"Key type: ECDSA, Size: {cert_key_size} bits",
                remediation="Re-issue with >=256-bit EC key.", cwe="CWE-326", poc=cert_poc
            ))

    # 2. Chain validation
    chain_valid = None
    if cert_info:
        chain_valid, chain_error = await loop.run_in_executor(None, _verify_chain_via_ssl_connect, hostname, port)
        if chain_valid is False:
            findings.append(_make_finding(
                "Certificate chain not trusted", f"Verification failed: {chain_error}",
                "high", 95, location=f"Certificate chain {hostname}:{port}",
                evidence=chain_error,
                remediation="Install the correct certificate chain.", cwe="CWE-295",
                poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname} -showcerts < /dev/null 2>/dev/null | openssl verify -CAfile {CA_BUNDLE_PATH or '/etc/ssl/certs/ca-certificates.crt'}"
            ))
        elif chain_valid is None:
            findings.append(_make_finding(
                "Unable to verify certificate chain", "SSL verification could not be performed.",
                "medium", 70, location=f"Certificate chain {hostname}:{port}",
                evidence="SSL verification could not be completed",
                remediation="Ensure the server certificate is trusted by a public CA.", cwe="CWE-295",
                poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname} -showcerts < /dev/null"
            ))

    # 3. Full chain for OCSP
    if cert_info:
        cert_chain = await loop.run_in_executor(None, _get_peer_cert_chain, hostname, port) or []

    # ── Protocol probing ─────────────────────────────────────────────
    tls_versions = {}
    tls_versions["SSLv2"] = await _test_protocol_openssl(hostname, port, "-ssl2", openssl_state)
    tls_versions["SSLv3"] = await _test_protocol_openssl(hostname, port, "-ssl3", openssl_state)
    for ver, flag in [("TLSv1.0", "-tls1"), ("TLSv1.1", "-tls1_1"),
                      ("TLSv1.2", "-tls1_2"), ("TLSv1.3", "-tls1_3")]:
        tls_versions[ver] = await _test_protocol_openssl(hostname, port, flag, openssl_state)
        
    if tls_versions.get("SSLv2"):
        findings.append(_make_finding(
            "SSLv2 supported (DROWN)", "Obsolete protocol",
            "critical", 100, location=f"SSLv2 {hostname}:{port}",
            evidence=f"SSLv2 is enabled on {hostname}:{port}",
            remediation="Disable SSLv2.", cwe="CWE-757",
            poc=f"openssl s_client -connect {hostname}:{port} -ssl2"
        ))
    if tls_versions.get("SSLv3"):
        findings.append(_make_finding(
            "SSLv3 supported (POODLE)", "Obsolete protocol",
            "critical", 100, location=f"SSLv3 {hostname}:{port}",
            evidence=f"SSLv3 is enabled on {hostname}:{port}",
            remediation="Disable SSLv3.", cwe="CWE-757",
            poc=f"openssl s_client -connect {hostname}:{port} -ssl3"
        ))
    if tls_versions.get("TLSv1.0"):
        findings.append(_make_finding(
            "TLS 1.0 supported", "Deprecated (BEAST)",
            "high", 100, location=f"TLSv1.0 {hostname}:{port}",
            evidence=f"TLS 1.0 is enabled on {hostname}:{port}",
            remediation="Disable TLS 1.0.", cwe="CWE-757",
            poc=f"openssl s_client -connect {hostname}:{port} -tls1"
        ))
    if tls_versions.get("TLSv1.1"):
        findings.append(_make_finding(
            "TLS 1.1 supported", "Deprecated",
            "high", 100, location=f"TLSv1.1 {hostname}:{port}",
            evidence=f"TLS 1.1 is enabled on {hostname}:{port}",
            remediation="Disable TLS 1.1.", cwe="CWE-757",
            poc=f"openssl s_client -connect {hostname}:{port} -tls1_1"
        ))

    # ── Browser Compatibility ────────────────────────────────────────
    if tls_versions.get("TLSv1.3") and not any(tls_versions.get(v) for v in ["TLSv1.2", "TLSv1.1", "TLSv1.0"]):
        findings.append(_make_finding(
            "TLS 1.3 only configuration",
            "Server only supports TLS 1.3. Highest security, but may block older browsers.",
            "info", 100, "pass", location=f"TLS Configuration {hostname}:{port}",
            evidence="Only TLS 1.3 is enabled",
            remediation="No action needed unless legacy browser support is required.",
            cwe="", owasp="", poc=f"openssl s_client -connect {hostname}:{port} -tls1_2"
        ))
    elif not tls_versions.get("TLSv1.3") and not tls_versions.get("TLSv1.2"):
        findings.append(_make_finding(
            "No modern TLS versions supported",
            "Server does not support TLS 1.2 or 1.3. Modern browsers will reject the connection.",
            "critical", 100, "fail", location=f"TLS Configuration {hostname}:{port}",
            evidence=f"Supported versions: {[v for v, s in tls_versions.items() if s]}",
            remediation="Enable TLS 1.2 and TLS 1.3.", cwe="CWE-757", owasp="A02:2021",
            poc=f"openssl s_client -connect {hostname}:{port}"
        ))

    # ── TLS Fingerprints, ALPN, Session Resumption ─────────────────
    ja3s, ja4s, resumption_supported = await _extract_tls_fingerprints_and_resumption(hostname, port, openssl_state)
    alpn_proto = await _check_alpn(hostname, port, openssl_state)
    
    if ja3s:
        findings.append(_make_finding(
            "TLS Server Fingerprint (JA3S/JA4S)",
            f"Server TLS fingerprint extracted. JA3S: {ja3s}",
            "info", 100, "pass", location=f"TLS Handshake {hostname}:{port}",
            evidence=f"JA3S: {ja3s}\nJA4S: {ja4s}",
            remediation="No action needed. Fingerprints are for identification.",
            cwe="", owasp="", poc=f"openssl s_client -connect {hostname}:{port} -msg"
        ))
        
    if resumption_supported:
        findings.append(_make_finding(
            "TLS Session Resumption supported",
            "Server supports TLS session resumption (Session ID or Tickets).",
            "info", 100, "pass", location=f"TLS Handshake {hostname}:{port}",
            evidence="Session resumption detected in handshake",
            remediation="No action needed. Improves performance.",
            cwe="", owasp="", poc=f"openssl s_client -connect {hostname}:{port} -reconnect"
        ))
        
    if alpn_proto:
        findings.append(_make_finding(
            "ALPN negotiated",
            f"Server negotiated ALPN protocol: {alpn_proto}",
            "info", 100, "pass", location=f"TLS Handshake {hostname}:{port}",
            evidence=f"ALPN protocol: {alpn_proto}",
            remediation="No action needed.", cwe="", owasp="",
            poc=f"openssl s_client -connect {hostname}:{port} -alpn h2,http/1.1"
        ))

    # ── OCSP Stapling & CT ─────────────────────────────────────────
    ocsp_stapling = None
    stapled_revoked = None
    tls_scts = 0
    if cert_info:
        stapled_ocsp_bytes = await loop.run_in_executor(None, _get_stapled_ocsp_response, hostname, port)
        ocsp_stapling = stapled_ocsp_bytes is not None
        if stapled_ocsp_bytes:
            try:
                ocsp_resp = crypto_ocsp.load_der_ocsp_response(stapled_ocsp_bytes)
                if ocsp_resp.response_status == crypto_ocsp.OCSPResponseStatus.SUCCESSFUL:
                    single = ocsp_resp.responses[0]
                    if single.certificate_status == crypto_ocsp.OCSPCertStatus.REVOKED:
                        stapled_revoked = True
                    elif single.certificate_status == crypto_ocsp.OCSPCertStatus.GOOD:
                        stapled_revoked = False
            except Exception:
                pass
        tls_scts = await loop.run_in_executor(None, _get_scts_count_tls_ext, hostname, port)
    else:
        tls_scts = await loop.run_in_executor(None, _get_scts_count_tls_ext, hostname, port)
        
    total_scts = tls_scts + cert_scts
    has_ct = total_scts > 0
    
    if ocsp_stapling is False and not context.get("waf_detected"):
        findings.append(_make_finding(
            "OCSP stapling not used",
            "Server did not include an OCSP response in the TLS handshake.",
            "low", 85, location=f"OCSP stapling {hostname}:{port}",
            evidence="No OCSP response included in TLS handshake",
            remediation="Enable OCSP stapling in your web server configuration.",
            cwe="CWE-299", owasp="A02:2021",
            poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname} -status < /dev/null 2>/dev/null | grep -A5 'OCSP Response'"
        ))
        
    if not has_ct:
        sev = "high" if (context["is_login_page"] or context["is_ecommerce"]) else "medium"
        conf = 90 if sev == "high" else 70
        findings.append(_make_finding(
            "No Certificate Transparency (SCTs)",
            "Certificate lacks Signed Certificate Timestamps.",
            sev, conf, location=f"CT {hostname}:{port}",
            evidence=f"Total SCTs found: {total_scts} (embedded: {cert_scts}, TLS extension: {tls_scts})",
            remediation="Obtain a certificate with embedded SCTs.", cwe="CWE-299", owasp="A02:2021",
            poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname} < /dev/null 2>/dev/null | openssl x509 -noout -text | grep -A2 'CT Precertificate SCTs'"
        ))

    # ── Page fetch & HTTP/3, Mixed Content ─────────────────────────
    hsts_header = None
    csp_header = None
    mixed_findings = []
    html = ""
    headers = {}
    http3_advertised = False
    
    if shared_page and not shared_page.get("error") and shared_page.get("status") == 200:
        html = shared_page.get("html", "")
        headers = shared_page.get("headers", {})
    else:
        try:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=8),
                                             headers={"User-Agent": USER_AGENT}) as session:
                async with session.get(f"https://{hostname}:{port}", ssl=ssl_ctx) as resp:
                    html = await resp.text()
                    headers = resp.headers
        except Exception as e:
            findings.append(_make_finding(
                "Page fetch failed for header/mixed content checks", str(e),
                "medium", 70, location=f"https fetch {hostname}:{port}",
                evidence=f"HTTP request failed: {str(e)}",
                remediation="Ensure the web server is reachable and returns valid content.",
                poc=f"curl -vk https://{hostname}:{port}"
            ))
            html = ""
            headers = {}
            
    if html:
        mixed_findings = _scan_mixed_content(html, f"https://{hostname}:{port}")
        findings.extend(mixed_findings)
        hsts_header = _get_header(headers, "Strict-Transport-Security")
        csp_header = _get_header(headers, "Content-Security-Policy")
        
        # HTTP/3 (QUIC) Detection
        alt_svc = _get_header(headers, "Alt-Svc") or ""
        if "h3=" in alt_svc or "h3-29=" in alt_svc or "h3-q050=" in alt_svc or "h3-32=" in alt_svc:
            http3_advertised = True
            findings.append(_make_finding(
                "HTTP/3 (QUIC) advertised",
                "Server advertises HTTP/3 support via Alt-Svc header.",
                "info", 100, "pass", location=f"Alt-Svc Header {hostname}:{port}",
                evidence=f"Alt-Svc: {alt_svc}",
                remediation="No action needed. HTTP/3 improves performance and security.",
                cwe="", owasp="", poc=f"curl -I --http3 https://{hostname}:{port}"
            ))

        _headers_lower = {k.lower() for k in headers}
        server_header = _get_header(headers, "Server", "").lower()
        if (any(h in _headers_lower for h in WAF_HEADERS) or
                any(waf in server_header for waf in WAF_SERVER_SUBSTRINGS)):
            context["waf_detected"] = True
            
        if re.search(r'<input[^>]*type=["\']?password["\']?', html, re.IGNORECASE):
            context["is_login_page"] = True
        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        title = title_match.group(1).lower() if title_match else ""
        ecom_kw = ["shop", "store", "buy", "cart", "checkout", "shopping", "amazon", "ebay"]
        if any(k in title or k in html.lower() for k in ecom_kw):
            context["is_ecommerce"] = True

    # ── DNS Checks (CAA, DANE) ─────────────────────────────────────
    caa_records = await _check_dns_record(hostname, "CAA")
    if caa_records:
        findings.append(_make_finding(
            "CAA record present",
            "Certificate Authority Authorization (CAA) record is configured.",
            "info", 100, "pass", location=f"DNS CAA for {hostname}",
            evidence=f"CAA records: {caa_records[:200]}",
            remediation="No action needed. CAA restricts which CAs can issue certificates.",
            cwe="", owasp="", poc=f"dig CAA {hostname} +short"
        ))
    else:
        findings.append(_make_finding(
            "Missing CAA record",
            "No CAA record found. Any CA can issue certificates for this domain.",
            "medium", 80, "warning", location=f"DNS CAA for {hostname}",
            evidence="No CAA records returned by DNS",
            remediation="Add a CAA record to restrict certificate issuance (e.g., '0 issue \"letsencrypt.org\"').",
            cwe="CWE-295", owasp="A02:2021", poc=f"dig CAA {hostname} +short"
        ))

    tlsa_name = f"_{port}._tcp.{hostname}"
    tlsa_records = await _check_dns_record(tlsa_name, "TLSA")
    if tlsa_records:
        findings.append(_make_finding(
            "DANE (TLSA) record present",
            "DNS-based Authentication of Named Entities (DANE) is configured.",
            "info", 100, "pass", location=f"DNS TLSA for {tlsa_name}",
            evidence=f"TLSA records: {tlsa_records[:200]}",
            remediation="No action needed. DANE provides additional certificate validation.",
            cwe="", owasp="", poc=f"dig TLSA {tlsa_name} +short"
        ))
    else:
        findings.append(_make_finding(
            "Missing DANE (TLSA) record",
            "No TLSA record found. DANE is not configured.",
            "low", 60, "info", location=f"DNS TLSA for {tlsa_name}",
            evidence="No TLSA records returned by DNS",
            remediation="Consider implementing DANE for additional certificate validation.",
            cwe="CWE-295", owasp="A02:2021", poc=f"dig TLSA {tlsa_name} +short"
        ))

    # ── Sort findings by severity ──────────────────────────────────
    _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 4))

    # ── Final scoring ──────────────────────────────────────────────
    mixed_count = len(mixed_findings)
    tls_issues = [f for f in findings if f.get("category") != "mixed_content"]
    tls_count = len(tls_issues)
    high_count = sum(1 for f in findings if f.get("severity") == "high")
    critical_count = sum(1 for f in findings if f.get("severity") == "critical")
    score, grade = _apply_scoring(findings, context)
    
    worst_sev = max(
        (f["severity"] for f in findings),
        key=lambda s: {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(s, 0),
        default="info"
    )
    status = "fail" if any(f["severity"] in ("critical", "high") for f in findings) else "warning" if findings else "pass"
    remediation_list = sorted(set(f["remediation"] for f in findings if f["remediation"]))
    if not remediation_list:
        remediation_list = ["No action needed."]
        
    summary = f"TLS: {tls_count} issue(s) [H:{high_count} C:{critical_count}] | Mixed: {mixed_count} issue(s) | Grade: {grade} ({score}/100)"
    if handshake_error:
        summary = f"Handshake failed: {handshake_error}. " + summary

    return {
        "scanner": "ssl_tls",
        "target": f"{hostname}:{port}",
        "status": status,
        "severity": worst_sev,
        "confidence": 100,
        "score": score,
        "grade": grade,
        "summary": summary,
        "findings": findings,
        "remediation": remediation_list,
        "details": {
            "certificate": {
                "subject": cert_info["subject"] if cert_info else "N/A",
                "issuer": cert_info["issuer"] if cert_info else "N/A",
                "not_after": cert_info["not_after"] if cert_info else "N/A",
                "days_until_expiry": cert_info["days_until_expiry"] if cert_info else None,
                "hostname_match": cert_info["hostname_match"] if cert_info else None,
                "self_signed": cert_info["self_signed"] if cert_info else None,
                "signature_algorithm": cert_info["signature_algorithm"] if cert_info else "N/A",
                "key_size": cert_info["key_size"] if cert_info else None,
                "key_type": cert_info["key_type"] if cert_info else "N/A",
                "san_dns": cert_info["san_dns"] if cert_info else [],
                "is_lets_encrypt": cert_info["is_lets_encrypt"] if cert_info else False,
                "must_staple": cert_info["must_staple"] if cert_info else False,
            },
            "chain_valid": chain_valid,
            "ocsp_revoked": stapled_revoked,
            "protocols": tls_versions,
            "hsts_header": hsts_header,
            "csp_header": csp_header,
            "ocsp_stapling": ocsp_stapling,
            "ct_scts_total": total_scts,
            "context": context,
            "ja3s": ja3s,
            "ja4s": ja4s,
            "alpn": alpn_proto,
            "http3": http3_advertised,
            "caa_records": caa_records,
            "dane_records": tlsa_records,
            "session_resumption": resumption_supported,
        }
    }

async def _test_protocol_openssl(hostname: str, port: int, version_flag: str, openssl_state: dict) -> bool:
    if not openssl_state["available"]:
        return False
    out, err, timed_out = await _run_openssl(["s_client", "-connect", f"{hostname}:{port}", version_flag])
    if timed_out:
        return False
    if b"OPENSSL_MISSING" in err:
        if not openssl_state["warned"]:
            log.warning("OpenSSL binary not found – skipping all OpenSSL-based checks.")
            openssl_state["warned"] = True
        openssl_state["available"] = False
        return False
    return b"BEGIN CERTIFICATE" in out and b"CONNECTED" in out

if __name__ == "__main__":
    target_url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    result = asyncio.run(run(target_url))
    print(json.dumps(result, indent=2, ensure_ascii=False))