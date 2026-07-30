#!/usr/bin/env python3
"""
test_04_ssl_tls.py – Bravo6 Enterprise TLS Assessment Engine (v13.0 – Local Dev Compatibility)
====================================================================================================
Evolution highlights:
- Removed overlapping responsibilities (HSTS, CSP) to focus strictly on TLS/DNS/Mixed Content.
- Added Weak Cipher Suite detection (RC4, DES, 3DES, EXPORT, NULL, aNULL) via OpenSSL probing.
- Removed internal scoring/grading; Orchestrator handles canonical scoring.
- Simplified finding generation to enforce strict schema compliance (10 mandatory fields).
- Implemented dependency injection for HTTP sessions and shared page context.
- Merged Scout 3 (Mixed Content) logic into this module.
- Preserved all advanced TLS fingerprinting, protocol probing, and DNS security checks.
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
from urllib.parse import urlparse

import aiohttp
from bs4 import BeautifulSoup

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtensionOID
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.x509 import ocsp as crypto_ocsp
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

USER_AGENT = "Bravo6-TLS-Scanner/13.0"
TIMEOUT = 20
OPENSSL_TIMEOUT = 12

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

def _make_finding(**kwargs) -> Dict[str, Any]:
    return kwargs

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

# ── TLS Fingerprinting (JA3S/JA4S) & Session Resumption ────────────────────
def _parse_ja3s_from_openssl_msg(openssl_output: str) -> Tuple[Optional[str], Optional[str]]:
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

async def _extract_tls_fingerprints_and_resumption(hostname: str, port: int, openssl_state: dict) -> Tuple[Optional[str], Optional[str], bool]:
    if not openssl_state["available"]:
        return None, None, False
    out, err, timed_out = await _run_openssl(
        ["s_client", "-connect", f"{hostname}:{port}", "-msg", "-servername", hostname, "-reconnect"],
        timeout=15
    )
    if timed_out or b"OPENSSL_MISSING" in err:
        return None, None, False
    combined = (out + err).decode('utf-8', errors='ignore')
    ja3s, ja4s = _parse_ja3s_from_openssl_msg(combined)
    resumption_supported = "Reused, " in combined or "TLS session ticket" in combined.lower() or "Session-ID" in combined
    return ja3s, ja4s, resumption_supported

async def _check_alpn(hostname: str, port: int, openssl_state: dict) -> Optional[str]:
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

# ── Weak Cipher Probing ────────────────────────────────────────────────────
async def _check_weak_ciphers_openssl(hostname: str, port: int, openssl_state: dict) -> List[Dict[str, Any]]:
    findings = []
    if not openssl_state["available"]:
        return findings
        
    weak_ciphers = ["RC4", "DES", "3DES", "EXPORT", "NULL", "aNULL"]
    for cipher in weak_ciphers:
        out, err, timed_out = await _run_openssl(
            ["s_client", "-connect", f"{hostname}:{port}", "-cipher", cipher, "-servername", hostname],
            timeout=10
        )
        if not timed_out and b"BEGIN CERTIFICATE" in out and b"CONNECTED" in out:
            out_str = out.decode('utf-8', errors='ignore')
            match = re.search(r"Cipher\s+:\s+([^\r\n]+)", out_str)
            if match:
                negotiated = match.group(1).strip()
                findings.append(_make_finding(
                    title=f"Weak Cipher Suite Supported: {negotiated}",
                    severity="high",
                    confidence=90,
                    cwe="CWE-326",
                    owasp="A02:2021",
                    location=f"{hostname}:{port}",
                    evidence=f"Server accepted weak cipher {negotiated} during TLS handshake",
                    poc=f"openssl s_client -connect {hostname}:{port} -cipher {cipher} -servername {hostname}",
                    remediation="Disable weak cipher suites on the server. Configure only TLS 1.2+ with strong ciphers (AES-GCM, ChaCha20-Poly1305).",
                    detection_method="Cipher Probe"
                ))
                break  # Found one weak cipher, stop to avoid spam
    return findings

async def _check_default_cipher(hostname: str, port: int, openssl_state: dict) -> List[Dict[str, Any]]:
    findings = []
    if not openssl_state["available"]:
        return findings
        
    out, err, timed_out = await _run_openssl(
        ["s_client", "-connect", f"{hostname}:{port}", "-servername", hostname],
        timeout=10
    )
    if not timed_out and b"CONNECTED" in out:
        out_str = out.decode('utf-8', errors='ignore')
        match = re.search(r"Cipher\s+:\s+([^\r\n]+)", out_str)
        if match:
            default_cipher = match.group(1).strip()
            weak_keywords = ["RC4", "DES", "3DES", "EXPORT", "NULL", "aNULL"]
            if any(w in default_cipher.upper() for w in weak_keywords):
                findings.append(_make_finding(
                    title=f"Weak Default Cipher Negotiated: {default_cipher}",
                    severity="high",
                    confidence=90,
                    cwe="CWE-326",
                    owasp="A02:2021",
                    location=f"{hostname}:{port}",
                    evidence=f"Default connection negotiated weak cipher: {default_cipher}",
                    poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname}",
                    remediation="Disable weak cipher suites on the server. Configure only TLS 1.2+ with strong ciphers.",
                    detection_method="Cipher Probe"
                ))
            else:
                findings.append(_make_finding(
                    title="Strong Default Cipher Configured",
                    severity="info",
                    confidence=100,
                    cwe="",
                    owasp="",
                    location=f"{hostname}:{port}",
                    evidence=f"Default connection negotiated strong cipher: {default_cipher}",
                    poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname}",
                    remediation="No action needed.",
                    detection_method="Cipher Probe"
                ))
    return findings

# ── Mixed Content Detection ────────────────────────────────────────────────
async def _check_mixed_content(url: str, shared_page: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    if not shared_page or not shared_page.get("html") or not url.lower().startswith("https://"):
        return findings
    
    html = shared_page.get("html", "")
    soup = BeautifulSoup(html, "html.parser")
    
    # script
    for tag in soup.find_all("script"):
        src = tag.get("src", "")
        if src and src.lower().startswith("http://"):
            findings.append(_make_finding(
                title="Mixed Content: Script loaded over HTTP",
                severity="high",
                confidence=95,
                cwe="CWE-829",
                owasp="A02:2021",
                location=src,
                evidence=f"Found <script> loading resource from {src} on HTTPS page {url}",
                poc=f"curl -I {src}",
                remediation="Serve all resources over HTTPS. Update the src attribute to use https:// or remove the resource.",
                detection_method="HTML Parsing"
            ))
            
    # link rel="stylesheet"
    for tag in soup.find_all("link"):
        if tag.get("rel") and "stylesheet" in tag.get("rel"):
            href = tag.get("href", "")
            if href and href.lower().startswith("http://"):
                findings.append(_make_finding(
                    title="Mixed Content: Stylesheet loaded over HTTP",
                    severity="high",
                    confidence=95,
                    cwe="CWE-829",
                    owasp="A02:2021",
                    location=href,
                    evidence=f"Found <link> loading resource from {href} on HTTPS page {url}",
                    poc=f"curl -I {href}",
                    remediation="Serve all resources over HTTPS. Update the href attribute to use https:// or remove the resource.",
                    detection_method="HTML Parsing"
                ))
                
    # img
    for tag in soup.find_all("img"):
        src = tag.get("src", "")
        if src and src.lower().startswith("http://"):
            findings.append(_make_finding(
                title="Mixed Content: Image loaded over HTTP",
                severity="medium",
                confidence=90,
                cwe="CWE-829",
                owasp="A02:2021",
                location=src,
                evidence=f"Found <img> loading resource from {src} on HTTPS page {url}",
                poc=f"curl -I {src}",
                remediation="Serve all resources over HTTPS. Update the src attribute to use https:// or remove the resource.",
                detection_method="HTML Parsing"
            ))
            
    # iframe
    for tag in soup.find_all("iframe"):
        src = tag.get("src", "")
        if src and src.lower().startswith("http://"):
            findings.append(_make_finding(
                title="Mixed Content: Iframe loaded over HTTP",
                severity="medium",
                confidence=90,
                cwe="CWE-829",
                owasp="A02:2021",
                location=src,
                evidence=f"Found <iframe> loading resource from {src} on HTTPS page {url}",
                poc=f"curl -I {src}",
                remediation="Serve all resources over HTTPS. Update the src attribute to use https:// or remove the resource.",
                detection_method="HTML Parsing"
            ))
            
    # form
    for tag in soup.find_all("form"):
        action = tag.get("action", "")
        if action and action.lower().startswith("http://"):
            findings.append(_make_finding(
                title="Mixed Content: Form action over HTTP",
                severity="high",
                confidence=95,
                cwe="CWE-319",
                owasp="A02:2021",
                location=action,
                evidence=f"Found <form> with action over HTTP: {action} on HTTPS page {url}",
                poc=f"curl -I {action}",
                remediation="Serve all resources over HTTPS. Update the action attribute to use https:// or remove the form.",
                detection_method="HTML Parsing"
            ))
            
    return findings

# ── DNS Checks (CAA, DANE) ─────────────────────────────────────────────────
async def _check_dns_record(hostname: str, record_type: str) -> Optional[str]:
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

# ══════════════════════════════════════════════════════════════════════════
async def run(url: str, **kwargs) -> Dict[str, Any]:
    temp_session = None
    try:
        session = kwargs.get("session")
        shared_page = kwargs.get("shared_page")
        waf_detected = kwargs.get("waf_detected") or (shared_page.get("waf_detected") if shared_page else None)
        min_confidence = kwargs.get("min_confidence", 50)
        
        hostname, port = _normalize_url(url)
        
        if not session:
            temp_session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=15))
            session = temp_session
            
        if not shared_page or shared_page.get("status") != 200 or shared_page.get("error"):
            try:
                async with session.get(url, ssl=False) as resp:
                    html = await resp.text()
                    shared_page = {
                        "status": resp.status,
                        "headers": dict(resp.headers),
                        "html": html,
                        "soup": BeautifulSoup(html, "html.parser"),
                        "error": None
                    }
            except Exception as e:
                shared_page = {"status": 0, "headers": {}, "html": "", "soup": None, "error": str(e)}
                
        findings = []
        details = {
            "openssl_available": True,
            "mixed_content_count": 0,
            "context": "internal" if _check_internal(hostname) else "external",
            "http3": False,
            "handshake_error": None
        }
        
        if waf_detected:
            details["waf_detected"] = waf_detected
            
        # Check openssl availability
        try:
            proc = await asyncio.create_subprocess_exec(
                "openssl", "version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            out, err = await proc.communicate()
            if proc.returncode != 0:
                details["openssl_available"] = False
        except FileNotFoundError:
            details["openssl_available"] = False
            
        openssl_state = {"available": details["openssl_available"], "warned": False}
        
        # 1. Basic handshake & certificate parsing
        cert_info = None
        chain_valid = None
        try:
            pem = await asyncio.get_running_loop().run_in_executor(None, ssl.get_server_certificate, (hostname, port))
            der = ssl.PEM_cert_to_DER_cert(pem)
            cert_info = _analyze_cert(der, hostname)
            cert_scts = _count_scts_from_cert(der)
            details["ct_scts_total"] = cert_scts
            details["certificate"] = cert_info
            
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
                    title="Certificate expired",
                    severity="critical",
                    confidence=100,
                    cwe="CWE-298",
                    owasp="A02:2021",
                    location=f"Expiry {hostname}:{port}",
                    evidence=f"Certificate expired on {cert_expiry_date}",
                    remediation="Renew immediately.",
                    poc=cert_poc,
                    detection_method="Certificate Analysis"
                ))
            elif days < 7:
                findings.append(_make_finding(
                    title=f"Certificate expires in {days} days",
                    severity="high",
                    confidence=100,
                    cwe="CWE-298",
                    owasp="A02:2021",
                    location=f"Expiry {hostname}:{port}",
                    evidence=f"Certificate expires on {cert_expiry_date} ({days} days remaining)",
                    remediation="Renew now.",
                    poc=cert_poc,
                    detection_method="Certificate Analysis"
                ))
            elif days < 30:
                findings.append(_make_finding(
                    title=f"Certificate expires in {days} days",
                    severity="medium",
                    confidence=100,
                    cwe="CWE-298",
                    owasp="A02:2021",
                    location=f"Expiry {hostname}:{port}",
                    evidence=f"Certificate expires on {cert_expiry_date} ({days} days remaining)",
                    remediation="Renew soon.",
                    poc=cert_poc,
                    detection_method="Certificate Analysis"
                ))
                
            if not cert_info["hostname_match"]:
                sev = "high" if details.get("context") != "internal" else "low"
                findings.append(_make_finding(
                    title="Hostname mismatch",
                    severity=sev,
                    confidence=100,
                    cwe="CWE-295",
                    owasp="A02:2021",
                    location=f"Certificate {hostname}:{port}",
                    evidence=f"CN: {cert_cn}, SANs: {cert_san}, Hostname: {hostname}",
                    remediation="Fix CN/SAN.",
                    poc=cert_poc,
                    detection_method="Certificate Analysis"
                ))
                
            if cert_info["self_signed"]:
                sev = "high" if details.get("context") != "internal" else "low"
                findings.append(_make_finding(
                    title="Self-signed certificate",
                    severity=sev,
                    confidence=100,
                    cwe="CWE-295",
                    owasp="A02:2021",
                    location=f"Certificate {hostname}:{port}",
                    evidence=f"Issuer: {cert_issuer}, Subject: {cert_subject}",
                    remediation="Obtain CA-signed certificate.",
                    poc=cert_poc,
                    detection_method="Certificate Analysis"
                ))
                
            if cert_info["weak_signature"]:
                findings.append(_make_finding(
                    title=f"Weak signature algorithm ({cert_info['signature_algorithm']})",
                    severity="high",
                    confidence=100,
                    cwe="CWE-327",
                    owasp="A02:2021",
                    location=f"Certificate {hostname}:{port}",
                    evidence=f"Signature algorithm: {cert_sig_alg}",
                    remediation="Re-issue with SHA-256.",
                    poc=cert_poc,
                    detection_method="Certificate Analysis"
                ))
                
            if cert_info["key_type"] == "rsa" and cert_info["key_size"] and cert_info["key_size"] < 2048:
                findings.append(_make_finding(
                    title=f"Weak RSA key ({cert_info['key_size']} bits)",
                    severity="high",
                    confidence=100,
                    cwe="CWE-326",
                    owasp="A02:2021",
                    location=f"Certificate {hostname}:{port}",
                    evidence=f"Key type: RSA, Size: {cert_key_size} bits",
                    remediation="Re-issue with >=2048-bit key.",
                    poc=cert_poc,
                    detection_method="Certificate Analysis"
                ))
            elif cert_info["key_type"] == "ecdsa" and cert_info["key_size"] and cert_info["key_size"] < 256:
                findings.append(_make_finding(
                    title=f"Weak ECDSA key ({cert_info['key_size']} bits)",
                    severity="high",
                    confidence=100,
                    cwe="CWE-326",
                    owasp="A02:2021",
                    location=f"Certificate {hostname}:{port}",
                    evidence=f"Key type: ECDSA, Size: {cert_key_size} bits",
                    remediation="Re-issue with >=256-bit EC key.",
                    poc=cert_poc,
                    detection_method="Certificate Analysis"
                ))
                
        except Exception as e:
            details["handshake_error"] = str(e)
            
        # 2. Chain validation
        if cert_info:
            chain_valid, chain_error = await asyncio.get_running_loop().run_in_executor(
                None, _verify_chain_via_ssl_connect, hostname, port
            )
            details["chain_valid"] = chain_valid
            if chain_valid is False:
                findings.append(_make_finding(
                    title="Certificate chain not trusted",
                    severity="high",
                    confidence=95,
                    cwe="CWE-295",
                    owasp="A02:2021",
                    location=f"Certificate chain {hostname}:{port}",
                    evidence=chain_error or "Chain validation failed",
                    remediation="Install the correct certificate chain.",
                    poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname} -showcerts < /dev/null 2>/dev/null | openssl verify",
                    detection_method="Certificate Analysis"
                ))
            elif chain_valid is None:
                findings.append(_make_finding(
                    title="Unable to verify certificate chain",
                    severity="medium",
                    confidence=70,
                    cwe="CWE-295",
                    owasp="A02:2021",
                    location=f"Certificate chain {hostname}:{port}",
                    evidence="SSL verification could not be completed",
                    remediation="Ensure the server certificate is trusted by a public CA.",
                    poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname} -showcerts < /dev/null",
                    detection_method="Certificate Analysis"
                ))
                
        # 3. Protocol probing
        tls_versions = {}
        if details["openssl_available"]:
            tls_versions["SSLv2"] = await _test_protocol_openssl(hostname, port, "-ssl2", openssl_state)
            tls_versions["SSLv3"] = await _test_protocol_openssl(hostname, port, "-ssl3", openssl_state)
            for ver, flag in [("TLSv1.0", "-tls1"), ("TLSv1.1", "-tls1_1"), ("TLSv1.2", "-tls1_2"), ("TLSv1.3", "-tls1_3")]:
                tls_versions[ver] = await _test_protocol_openssl(hostname, port, flag, openssl_state)
                
            details["protocols"] = [v for v, s in tls_versions.items() if s]
            
            if tls_versions.get("SSLv2"):
                findings.append(_make_finding(
                    title="SSLv2 supported (DROWN)",
                    severity="critical",
                    confidence=100,
                    cwe="CWE-757",
                    owasp="A02:2021",
                    location=f"SSLv2 {hostname}:{port}",
                    evidence=f"SSLv2 is enabled on {hostname}:{port}",
                    remediation="Disable SSLv2.",
                    poc=f"openssl s_client -connect {hostname}:{port} -ssl2",
                    detection_method="Protocol Probe"
                ))
            if tls_versions.get("SSLv3"):
                findings.append(_make_finding(
                    title="SSLv3 supported (POODLE)",
                    severity="critical",
                    confidence=100,
                    cwe="CWE-757",
                    owasp="A02:2021",
                    location=f"SSLv3 {hostname}:{port}",
                    evidence=f"SSLv3 is enabled on {hostname}:{port}",
                    remediation="Disable SSLv3.",
                    poc=f"openssl s_client -connect {hostname}:{port} -ssl3",
                    detection_method="Protocol Probe"
                ))
            if tls_versions.get("TLSv1.0"):
                findings.append(_make_finding(
                    title="TLS 1.0 supported",
                    severity="high",
                    confidence=100,
                    cwe="CWE-757",
                    owasp="A02:2021",
                    location=f"TLSv1.0 {hostname}:{port}",
                    evidence=f"TLS 1.0 is enabled on {hostname}:{port}",
                    remediation="Disable TLS 1.0.",
                    poc=f"openssl s_client -connect {hostname}:{port} -tls1",
                    detection_method="Protocol Probe"
                ))
            if tls_versions.get("TLSv1.1"):
                findings.append(_make_finding(
                    title="TLS 1.1 supported",
                    severity="high",
                    confidence=100,
                    cwe="CWE-757",
                    owasp="A02:2021",
                    location=f"TLSv1.1 {hostname}:{port}",
                    evidence=f"TLS 1.1 is enabled on {hostname}:{port}",
                    remediation="Disable TLS 1.1.",
                    poc=f"openssl s_client -connect {hostname}:{port} -tls1_1",
                    detection_method="Protocol Probe"
                ))
                
            if tls_versions.get("TLSv1.3") and not any(tls_versions.get(v) for v in ["TLSv1.2", "TLSv1.1", "TLSv1.0"]):
                findings.append(_make_finding(
                    title="TLS 1.3 only configuration",
                    severity="info",
                    confidence=100,
                    cwe="",
                    owasp="",
                    location=f"TLS Configuration {hostname}:{port}",
                    evidence="Only TLS 1.3 is enabled",
                    remediation="No action needed unless legacy browser support is required.",
                    poc=f"openssl s_client -connect {hostname}:{port} -tls1_2",
                    detection_method="Protocol Probe"
                ))
            elif not tls_versions.get("TLSv1.3") and not tls_versions.get("TLSv1.2"):
                findings.append(_make_finding(
                    title="No modern TLS versions supported",
                    severity="critical",
                    confidence=100,
                    cwe="CWE-757",
                    owasp="A02:2021",
                    location=f"TLS Configuration {hostname}:{port}",
                    evidence=f"Supported versions: {details['protocols']}",
                    remediation="Enable TLS 1.2 and TLS 1.3.",
                    poc=f"openssl s_client -connect {hostname}:{port}",
                    detection_method="Protocol Probe"
                ))
                
        # 4. Weak Cipher Checks
        if details["openssl_available"]:
            weak_cipher_findings = await _check_weak_ciphers_openssl(hostname, port, openssl_state)
            findings.extend(weak_cipher_findings)
            details["weak_ciphers_found"] = [f["title"] for f in weak_cipher_findings]
            
            default_cipher_findings = await _check_default_cipher(hostname, port, openssl_state)
            findings.extend(default_cipher_findings)
            
        # 5. TLS Fingerprints, ALPN, Session Resumption
        if details["openssl_available"]:
            ja3s, ja4s, resumption_supported = await _extract_tls_fingerprints_and_resumption(hostname, port, openssl_state)
            details["ja3s"] = ja3s
            details["ja4s"] = ja4s
            details["session_resumption"] = resumption_supported
            
            if ja3s:
                findings.append(_make_finding(
                    title="TLS Server Fingerprint (JA3S/JA4S)",
                    severity="info",
                    confidence=100,
                    cwe="",
                    owasp="",
                    location=f"TLS Handshake {hostname}:{port}",
                    evidence=f"JA3S: {ja3s}\nJA4S: {ja4s}",
                    remediation="No action needed. Fingerprints are for identification.",
                    poc=f"openssl s_client -connect {hostname}:{port} -msg",
                    detection_method="TLS Fingerprinting"
                ))
                
            if resumption_supported:
                findings.append(_make_finding(
                    title="TLS Session Resumption supported",
                    severity="info",
                    confidence=100,
                    cwe="",
                    owasp="",
                    location=f"TLS Handshake {hostname}:{port}",
                    evidence="Session resumption detected in handshake",
                    remediation="No action needed. Improves performance.",
                    poc=f"openssl s_client -connect {hostname}:{port} -reconnect",
                    detection_method="TLS Fingerprinting"
                ))
                
            alpn_proto = await _check_alpn(hostname, port, openssl_state)
            details["alpn"] = [alpn_proto] if alpn_proto else []
            if alpn_proto:
                findings.append(_make_finding(
                    title="ALPN negotiated",
                    severity="info",
                    confidence=100,
                    cwe="",
                    owasp="",
                    location=f"TLS Handshake {hostname}:{port}",
                    evidence=f"ALPN protocol: {alpn_proto}",
                    remediation="No action needed.",
                    poc=f"openssl s_client -connect {hostname}:{port} -alpn h2,http/1.1",
                    detection_method="TLS Fingerprinting"
                ))
                
        # 6. OCSP Stapling & CT
        ocsp_stapling = False
        stapled_revoked = None
        if cert_info:
            stapled_ocsp_bytes = await asyncio.get_running_loop().run_in_executor(
                None, _get_stapled_ocsp_response, hostname, port
            )
            ocsp_stapling = stapled_ocsp_bytes is not None
            details["ocsp_stapling"] = ocsp_stapling
            
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
            details["ocsp_revoked"] = stapled_revoked
            
            if ocsp_stapling is False and not waf_detected:
                findings.append(_make_finding(
                    title="OCSP stapling not used",
                    severity="low",
                    confidence=85,
                    cwe="CWE-299",
                    owasp="A02:2021",
                    location=f"OCSP stapling {hostname}:{port}",
                    evidence="No OCSP response included in TLS handshake",
                    remediation="Enable OCSP stapling in your web server configuration.",
                    poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname} -status < /dev/null 2>/dev/null | grep -A5 'OCSP Response'",
                    detection_method="OCSP Check"
                ))
                
            tls_scts = await asyncio.get_running_loop().run_in_executor(
                None, _get_scts_count_tls_ext, hostname, port
            )
            total_scts = tls_scts + cert_scts
            details["ct_scts_total"] = total_scts
            
            has_ct = total_scts > 0
            if not has_ct:
                sev = "high" if details.get("context") in ["login", "ecommerce"] else "medium"
                conf = 90 if sev == "high" else 70
                findings.append(_make_finding(
                    title="No Certificate Transparency (SCTs)",
                    severity=sev,
                    confidence=conf,
                    cwe="CWE-299",
                    owasp="A02:2021",
                    location=f"CT {hostname}:{port}",
                    evidence=f"Total SCTs found: {total_scts} (embedded: {cert_scts}, TLS extension: {tls_scts})",
                    remediation="Obtain a certificate with embedded SCTs.",
                    poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname} < /dev/null 2>/dev/null | openssl x509 -noout -text | grep -A2 'CT Precertificate SCTs'",
                    detection_method="CT Log Analysis"
                ))
                
        # 7. HTTP/3 & Mixed Content
        headers = shared_page.get("headers", {}) if shared_page else {}
        alt_svc = _get_header(headers, "Alt-Svc") or ""
        if "h3=" in alt_svc or "h3-29=" in alt_svc or "h3-q050=" in alt_svc or "h3-32=" in alt_svc:
            details["http3"] = True
            findings.append(_make_finding(
                title="HTTP/3 (QUIC) advertised",
                severity="info",
                confidence=100,
                cwe="",
                owasp="",
                location=f"Alt-Svc Header {hostname}:{port}",
                evidence=f"Alt-Svc: {alt_svc}",
                remediation="No action needed. HTTP/3 improves performance and security.",
                poc=f"curl -I --http3 https://{hostname}:{port}",
                detection_method="HTTP Header"
            ))
            
        mixed_content_findings = await _check_mixed_content(url, shared_page)
        findings.extend(mixed_content_findings)
        details["mixed_content_count"] = len(mixed_content_findings)
        
        # 8. DNS Checks (CAA, DANE)
        caa_records = await _check_dns_record(hostname, "CAA")
        details["caa_records"] = caa_records.split("\n") if caa_records else []
        if caa_records:
            findings.append(_make_finding(
                title="CAA record present",
                severity="info",
                confidence=100,
                cwe="",
                owasp="",
                location=f"DNS CAA for {hostname}",
                evidence=f"CAA records: {caa_records[:200]}",
                remediation="No action needed. CAA restricts which CAs can issue certificates.",
                poc=f"dig CAA {hostname} +short",
                detection_method="DNS Query"
            ))
        else:
            findings.append(_make_finding(
                title="Missing CAA record",
                severity="low",
                confidence=80,
                cwe="CWE-295",
                owasp="A02:2021",
                location=f"DNS CAA for {hostname}",
                evidence="No CAA records returned by DNS",
                remediation="Add a CAA record to restrict certificate issuance (e.g., '0 issue \"letsencrypt.org\"').",
                poc=f"dig CAA {hostname} +short",
                detection_method="DNS Query"
            ))
            
        tlsa_name = f"_{port}._tcp.{hostname}"
        tlsa_records = await _check_dns_record(tlsa_name, "TLSA")
        details["dane_records"] = tlsa_records.split("\n") if tlsa_records else []
        if tlsa_records:
            findings.append(_make_finding(
                title="DANE (TLSA) record present",
                severity="info",
                confidence=100,
                cwe="",
                owasp="",
                location=f"DNS TLSA for {tlsa_name}",
                evidence=f"TLSA records: {tlsa_records[:200]}",
                remediation="No action needed. DANE provides additional certificate validation.",
                poc=f"dig TLSA {tlsa_name} +short",
                detection_method="DNS Query"
            ))
        else:
            findings.append(_make_finding(
                title="Missing DANE (TLSA) record",
                severity="info",
                confidence=60,
                cwe="CWE-295",
                owasp="A02:2021",
                location=f"DNS TLSA for {tlsa_name}",
                evidence="No TLSA records returned by DNS",
                remediation="Consider implementing DANE for additional certificate validation.",
                poc=f"dig TLSA {tlsa_name} +short",
                detection_method="DNS Query"
            ))
            
        # Filter findings
        findings = [f for f in findings if f.get("confidence", 100) >= min_confidence]
        
        # Sort findings by severity
        _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 4))
        
        return {
            "findings": findings,
            "details": details
        }
        
    except Exception as e:
        return {
            "findings": [],
            "details": {"error": str(e), "error_type": type(e).__name__}
        }
    finally:
        if temp_session:
            await temp_session.close()

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