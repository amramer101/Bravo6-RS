#!/usr/bin/env python3
"""
test_04_ssl_tls.py – Bravo6 Enterprise TLS Assessment Engine (v8.5)
===================================================================
Evolution highlights:
- Adopted v8.5 ScannerContext standard (zero independent HTTP requests).
- Decoupled completely from HTTP layer success (runs perfectly on 403s/WAFs).
- Parallelized all OpenSSL probes (SSLv2-TLS1.3, Weak Ciphers) with bounded semaphores to respect scan budgets.
- Implemented environment capability detection (graceful degradation if `openssl` or `dig` missing) with explicit disclosure.
- Calibrated DNS hardening checks (folded missing DANE to reduce noise; CAA absence downgraded to informational).
"""

import asyncio
import hashlib
import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from urllib.parse import urlparse
from bs4 import BeautifulSoup

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtensionOID
    from cryptography.hazmat.primitives.asymmetric import rsa, ec
    from cryptography.x509 import ocsp as crypto_ocsp
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# ── Orchestrator Context Mock (For Standalone Type-Hinting) ────────────────
@dataclass
class ScannerContext:
    url: str
    session: Any
    config: Dict[str, Any]
    page_is_representative: bool
    waf_challenge_detected: Optional[str]
    sensitive_paths: List[str]
    main_page_cache: Dict[str, Any]

    async def fetch_js(self, js_url: str) -> str:
        return ""

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
    for key, val in (headers or {}).items():
        if key.lower() == name.lower():
            return val
    return default

def _make_finding(
    title: str, severity: str, confidence: str, cwe: str, owasp: str,
    location: str, evidence: str, poc: str, remediation: str, detection_method: str
) -> Dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "cwe": cwe,
        "owasp": owasp,
        "location": location,
        "evidence": evidence,
        "poc": poc,
        "remediation": remediation,
        "detection_method": detection_method
    }

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

# ── Environment & Subprocess execution ─────────────────────────────────────
async def _check_binary(cmd: str, arg: str) -> bool:
    try:
        proc = await asyncio.create_subprocess_exec(
            cmd, arg,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        await asyncio.wait_for(proc.communicate(), timeout=3)
        return proc.returncode == 0
    except (FileNotFoundError, asyncio.TimeoutError, Exception):
        return False

async def _run_openssl(args: List[str], timeout: int = 5) -> Tuple[bytes, bytes, bool]:
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
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            return b"", b"", True
    except Exception:
        return b"", b"", False

# ── Certificate retrieval & Analysis (Blocking but wrapped in Executor) ────
def _get_cert_der(hostname: str, port: int) -> bytes:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hostname, port), timeout=7) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            der = ssock.getpeercert(binary_form=True)
            if der:
                return der
            raise ValueError("No certificate returned")

def _verify_chain_via_ssl_connect(hostname: str, port: int) -> Tuple[Optional[bool], Optional[str]]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((hostname, port), timeout=7) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return True, None
    except ssl.SSLCertVerificationError as e:
        return False, str(e)
    except Exception:
        return None, None

def _get_stapled_ocsp_response(hostname: str, port: int) -> Optional[bytes]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=7) as sock:
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
        with socket.create_connection((hostname, port), timeout=7) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                if hasattr(tls_sock, "get_scts"):
                    scts = tls_sock.get_scts()
                    return len(scts) if scts else 0
    except Exception:
        pass
    return 0

def _analyze_cert(der: bytes, hostname: str) -> dict:
    if not HAS_CRYPTO:
        return {}
    cert = x509.load_der_x509_certificate(der)
    now = datetime.now(timezone.utc)
    days_left = (cert.not_valid_after_utc - now).days
    
    san_dns = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_dns = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    
    cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn = cn_attr[0].value if cn_attr else ""
    host_lower = hostname.lower()
    
    match = any(
        name.lower() == host_lower or (name.lower().startswith("*.") and host_lower.endswith(name.lower()[1:]))
        for name in san_dns
    )
    if not match and cn:
        match = (cn.lower() == host_lower or (cn.lower().startswith("*.") and host_lower.endswith(cn.lower()[1:])))
        
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
        
    must_staple = False
    try:
        tls_feature = cert.extensions.get_extension_for_oid(ExtensionOID.TLS_FEATURE)
        for feature in tls_feature.value:
            if feature == x509.TLSFeatureType.status_request:
                must_staple = True
                break
    except x509.ExtensionNotFound:
        pass
        
    # Count SCTs embedded
    cert_scts = 0
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        cert_scts = len(list(ext.value))
    except (x509.ExtensionNotFound, Exception):
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
        "self_signed": (cert.issuer == cert.subject),
        "signature_algorithm": sig_name,
        "weak_signature": weak_sig,
        "key_size": key_size,
        "key_type": key_type,
        "must_staple": must_staple,
        "cert_scts": cert_scts
    }

# ── Concurrent OpenSSL Probes ──────────────────────────────────────────────
async def _probe_protocol(hostname: str, port: int, flag: str, name: str, sem: asyncio.Semaphore) -> Tuple[str, str, bool]:
    async with sem:
        out, err, timed_out = await _run_openssl(["s_client", "-connect", f"{hostname}:{port}", flag, "-servername", hostname], timeout=5)
        if timed_out or b"OPENSSL_MISSING" in err:
            return ("protocol", name, False)
        supported = b"BEGIN CERTIFICATE" in out and b"CONNECTED" in out
        return ("protocol", name, supported)

async def _probe_weak_cipher(hostname: str, port: int, cipher: str, sem: asyncio.Semaphore) -> Tuple[str, str, Optional[str]]:
    async with sem:
        out, err, timed_out = await _run_openssl(["s_client", "-connect", f"{hostname}:{port}", "-cipher", cipher, "-servername", hostname], timeout=5)
        if not timed_out and b"BEGIN CERTIFICATE" in out and b"CONNECTED" in out:
            match = re.search(r"Cipher\s+:\s+([^\r\n]+)", out.decode('utf-8', errors='ignore'))
            if match:
                negotiated = match.group(1).strip()
                if negotiated != "0000":
                    return ("weak_cipher", cipher, negotiated)
        return ("weak_cipher", cipher, None)

async def _probe_default_cipher(hostname: str, port: int, sem: asyncio.Semaphore) -> Tuple[str, str, Optional[str]]:
    async with sem:
        out, err, timed_out = await _run_openssl(["s_client", "-connect", f"{hostname}:{port}", "-servername", hostname], timeout=5)
        if not timed_out and b"CONNECTED" in out:
            match = re.search(r"Cipher\s+:\s+([^\r\n]+)", out.decode('utf-8', errors='ignore'))
            if match:
                return ("default_cipher", "default", match.group(1).strip())
        return ("default_cipher", "default", None)

async def _probe_tls_fingerprints(hostname: str, port: int, sem: asyncio.Semaphore) -> Tuple[str, Optional[str], Optional[str], bool]:
    async with sem:
        out, err, timed_out = await _run_openssl(["s_client", "-connect", f"{hostname}:{port}", "-msg", "-servername", hostname, "-reconnect"], timeout=6)
        if timed_out or b"OPENSSL_MISSING" in err:
            return ("fingerprints", None, None, False)
        combined = (out + err).decode('utf-8', errors='ignore')
        
        # Simple extraction logic for JA3S/JA4S mimicking original implementation
        lines = combined.split('\n')
        in_server_hello = False
        hex_data = ""
        for line in lines:
            if "ServerHello" in line and "<<<" in line:
                in_server_hello = True
                continue
            if in_server_hello:
                if line.strip() == "" or ">>>" in line or ("<<<" in line and "ServerHello" not in line):
                    if hex_data: break
                if " - " in line:
                    parts = line.split(" - ", 1)
                    if len(parts) == 2:
                        hex_data += parts[1].replace(" ", "")
        
        ja3s, ja4s = None, None
        if hex_data and len(hex_data) >= 100:
            try:
                idx = 0
                version = int(hex_data[idx:idx+4], 16)
                idx += 4 + 64 # skip random
                sid_len = int(hex_data[idx:idx+2], 16)
                idx += 2 + (sid_len * 2)
                cipher = hex_data[idx:idx+4]
                idx += 4
                comp = hex_data[idx:idx+2]
                idx += 2
                if idx + 4 <= len(hex_data):
                    ext_len = int(hex_data[idx:idx+4], 16)
                    idx += 4
                    ext_data = hex_data[idx:]
                    ext_types, curves = [], []
                    e_idx = 0
                    while e_idx + 8 <= len(ext_data):
                        ext_type = ext_data[e_idx:e_idx+4]
                        ext_len_val = int(ext_data[e_idx+4:e_idx+8], 16)
                        ext_types.append(ext_type)
                        if ext_type == "000a" and e_idx + 12 <= len(ext_data):
                            groups_len = int(ext_data[e_idx+8:e_idx+12], 16)
                            for g in range(0, groups_len * 2, 4):
                                if e_idx + 12 + g + 4 <= len(ext_data):
                                    curves.append(ext_data[e_idx+12+g:e_idx+16+g])
                        e_idx += 8 + (ext_len_val * 2)
                    ext_str = "-".join(ext_types)
                    curve_str = "-".join(curves)
                    
                    ja3s = hashlib.md5(f"{version:04x},{cipher},{ext_str},{curve_str}".encode()).hexdigest()
                    ja4s = hashlib.md5(f"{version:04x},{cipher},{ext_str},".encode()).hexdigest()
            except Exception:
                pass
        
        resumption = "Reused, " in combined or "TLS session ticket" in combined.lower() or "Session-ID" in combined
        return ("fingerprints", ja3s, ja4s, resumption)

async def _probe_alpn(hostname: str, port: int, sem: asyncio.Semaphore) -> Tuple[str, Optional[str]]:
    async with sem:
        out, err, timed_out = await _run_openssl(["s_client", "-connect", f"{hostname}:{port}", "-alpn", "h2,http/1.1", "-servername", hostname], timeout=5)
        if not timed_out:
            combined = (out + err).decode('utf-8', errors='ignore')
            match = re.search(r"ALPN protocol:\s+([^\s]+)", combined)
            if match:
                return ("alpn", match.group(1))
        return ("alpn", None)

# ── DNS Checks (CAA) ───────────────────────────────────────────────────────
async def _check_dns_record(hostname: str, record_type: str) -> Optional[str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            'dig', record_type, hostname, '+short', '+time=2', '+tries=1',
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout=3)
        res = out.decode().strip()
        if res and "no " not in res.lower() and "not found" not in res.lower():
            return res
    except Exception:
        pass
    return None

# ── Main Entrypoint ────────────────────────────────────────────────────────
async def run(ctx: ScannerContext) -> dict:
    findings = []
    details = {
        "requests_made": 0,
        "openssl_available": False,
        "dig_available": False,
        "context": "external"
    }
    
    try:
        hostname, port = _normalize_url(ctx.url)
    except ValueError as e:
        return {"fatal_error": f"Invalid URL parsing: {e}"}

    details["context"] = "internal" if _check_internal(hostname) else "external"

    # Step 1: Subprocess capability detection (Crucial for correct reporting confidence)
    openssl_available = await _check_binary("openssl", "version")
    dig_available = await _check_binary("dig", "-v")
    details["openssl_available"] = openssl_available
    details["dig_available"] = dig_available

    if not openssl_available or not dig_available:
        missing = []
        if not openssl_available: missing.append("openssl")
        if not dig_available: missing.append("dig")
        findings.append(_make_finding(
            title="TLS/DNS deep-inspection unavailable in this environment",
            severity="info",
            confidence="informational",
            cwe="",
            owasp="",
            location="Scout Execution Environment",
            evidence=f"Missing binaries required for advanced analysis: {', '.join(missing)}",
            poc="which openssl; which dig",
            remediation="Ensure openssl and dig are installed in the scanner's runtime environment for deeper TLS/DNS protocol and cipher checks.",
            detection_method="Subprocess capability check"
        ))

    # Step 2: Fatal TLS Verification (If this fails, no HTTP checks would work anyway)
    der = None
    try:
        der = await asyncio.get_running_loop().run_in_executor(None, _get_cert_der, hostname, port)
    except Exception as e:
        # Cannot connect via TLS at all - fatal error for this module.
        return {"fatal_error": f"TLS Connection failed entirely: {type(e).__name__} - {str(e)}"}

    # Step 3: Parse and analyze the certificate
    cert_info = {}
    if HAS_CRYPTO and der:
        try:
            cert_info = await asyncio.get_running_loop().run_in_executor(None, _analyze_cert, der, hostname)
            details["certificate"] = cert_info
            
            days = cert_info.get("days_until_expiry", 0)
            cert_poc = f"openssl s_client -connect {hostname}:{port} -servername {hostname} < /dev/null 2>/dev/null | openssl x509 -noout -text"
            
            if days < 0:
                findings.append(_make_finding(
                    title="TLS Certificate Expired",
                    severity="critical",
                    confidence="verified-live",
                    cwe="CWE-298",
                    owasp="A02:2021-Cryptographic Failures",
                    location=f"Certificate {hostname}:{port}",
                    evidence=f"Certificate expired on {cert_info.get('not_after')}",
                    poc=cert_poc,
                    remediation="Renew the SSL/TLS certificate immediately.",
                    detection_method="Certificate Analysis"
                ))
            elif days < 7:
                findings.append(_make_finding(
                    title=f"TLS Certificate Expires Soon ({days} days)",
                    severity="high",
                    confidence="verified-live",
                    cwe="CWE-298",
                    owasp="A02:2021-Cryptographic Failures",
                    location=f"Certificate {hostname}:{port}",
                    evidence=f"Certificate expires on {cert_info.get('not_after')}",
                    poc=cert_poc,
                    remediation="Renew the SSL/TLS certificate to prevent service outage.",
                    detection_method="Certificate Analysis"
                ))
                
            if not cert_info.get("hostname_match"):
                sev = "high" if details["context"] != "internal" else "low"
                findings.append(_make_finding(
                    title="TLS Hostname Mismatch",
                    severity=sev,
                    confidence="verified-live",
                    cwe="CWE-295",
                    owasp="A02:2021-Cryptographic Failures",
                    location=f"Certificate {hostname}:{port}",
                    evidence=f"CN: {cert_info.get('cn')}, SANs: {cert_info.get('san_dns')}, Hostname requested: {hostname}",
                    poc=cert_poc,
                    remediation="Issue a certificate that explicitly includes the accessed hostname in its Subject Alternative Name (SAN) extension.",
                    detection_method="Certificate Analysis"
                ))
                
            if cert_info.get("self_signed"):
                sev = "high" if details["context"] != "internal" else "low"
                findings.append(_make_finding(
                    title="Self-Signed TLS Certificate",
                    severity=sev,
                    confidence="verified-live",
                    cwe="CWE-295",
                    owasp="A02:2021-Cryptographic Failures",
                    location=f"Certificate {hostname}:{port}",
                    evidence=f"Issuer: {cert_info.get('issuer')} matches Subject: {cert_info.get('subject')}",
                    poc=cert_poc,
                    remediation="Obtain a certificate signed by a trusted public or internal Certificate Authority.",
                    detection_method="Certificate Analysis"
                ))
                
            if cert_info.get("weak_signature"):
                findings.append(_make_finding(
                    title=f"Weak Signature Algorithm ({cert_info.get('signature_algorithm')})",
                    severity="high",
                    confidence="verified-live",
                    cwe="CWE-327",
                    owasp="A02:2021-Cryptographic Failures",
                    location=f"Certificate {hostname}:{port}",
                    evidence=f"Signature algorithm observed: {cert_info.get('signature_algorithm')}",
                    poc=cert_poc,
                    remediation="Re-issue the certificate using SHA-256 or stronger algorithms.",
                    detection_method="Certificate Analysis"
                ))
                
            key_sz = cert_info.get("key_size")
            key_typ = cert_info.get("key_type")
            if key_typ == "rsa" and key_sz and key_sz < 2048:
                findings.append(_make_finding(
                    title=f"Weak RSA Key Size ({key_sz} bits)",
                    severity="high",
                    confidence="verified-live",
                    cwe="CWE-326",
                    owasp="A02:2021-Cryptographic Failures",
                    location=f"Certificate {hostname}:{port}",
                    evidence=f"Key type: RSA, Size: {key_sz} bits",
                    poc=cert_poc,
                    remediation="Re-issue the certificate with an RSA key of at least 2048 bits.",
                    detection_method="Certificate Analysis"
                ))
            elif key_typ == "ecdsa" and key_sz and key_sz < 256:
                findings.append(_make_finding(
                    title=f"Weak ECDSA Key Size ({key_sz} bits)",
                    severity="high",
                    confidence="verified-live",
                    cwe="CWE-326",
                    owasp="A02:2021-Cryptographic Failures",
                    location=f"Certificate {hostname}:{port}",
                    evidence=f"Key type: ECDSA, Size: {key_sz} bits",
                    poc=cert_poc,
                    remediation="Re-issue the certificate with an Elliptic Curve key of at least 256 bits.",
                    detection_method="Certificate Analysis"
                ))
                
        except Exception as e:
            details["cert_analysis_error"] = str(e)

    # Step 4: Chain Validation & OCSP Stapling (Standard SSL blocking calls)
    chain_valid, chain_err = await asyncio.get_running_loop().run_in_executor(None, _verify_chain_via_ssl_connect, hostname, port)
    if chain_valid is False:
        findings.append(_make_finding(
            title="TLS Certificate Chain Not Trusted",
            severity="high",
            confidence="verified-live",
            cwe="CWE-295",
            owasp="A02:2021-Cryptographic Failures",
            location=f"Certificate Chain {hostname}:{port}",
            evidence=chain_err or "Chain validation failed to establish trust.",
            poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname} -showcerts < /dev/null 2>/dev/null | openssl verify",
            remediation="Ensure the server provides the complete certificate chain, and the root is trusted by public authorities.",
            detection_method="Local Trust Verification"
        ))

    stapled_ocsp = await asyncio.get_running_loop().run_in_executor(None, _get_stapled_ocsp_response, hostname, port)
    details["ocsp_stapling"] = stapled_ocsp is not None
    if not stapled_ocsp:
        evidence_msg = "No OCSP response was provided during the TLS handshake."
        if ctx.waf_challenge_detected:
            evidence_msg += f" (Note: CDN/WAF detected ({ctx.waf_challenge_detected}); OCSP stapling may be managed at the edge layer.)"

        findings.append(_make_finding(
            title="OCSP Stapling Not Enabled",
            severity="low",
            confidence="informational",
            cwe="CWE-299",
            owasp="A02:2021-Cryptographic Failures",
            location=f"TLS Handshake {hostname}:{port}",
            evidence=evidence_msg,
            poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname} -status < /dev/null 2>/dev/null | grep -A5 'OCSP Response'",
            remediation="Enable OCSP stapling on the web server to improve performance and privacy of revocation checks.",
            detection_method="TLS Handshake OCSP Extension Check"
        ))

    tls_scts = await asyncio.get_running_loop().run_in_executor(None, _get_scts_count_tls_ext, hostname, port)
    cert_scts = cert_info.get("cert_scts", 0) if cert_info else 0
    total_scts = tls_scts + cert_scts
    details["ct_scts_total"] = total_scts
    if total_scts == 0:
        sev = "high" if details["context"] == "external" else "medium"
        findings.append(_make_finding(
            title="Missing Certificate Transparency (SCTs)",
            severity=sev,
            confidence="verified-static",
            cwe="CWE-299",
            owasp="A02:2021-Cryptographic Failures",
            location=f"Certificate CT {hostname}:{port}",
            evidence=f"Total Signed Certificate Timestamps found: {total_scts}",
            poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname} < /dev/null 2>/dev/null | openssl x509 -noout -text | grep -i sct",
            remediation="Issue a certificate that participates in Certificate Transparency (CT) logs.",
            detection_method="CT Extension Parsing"
        ))

    # Step 5: Concurrent OpenSSL Probing for Protocols, Ciphers, and Fingerprints
    tls_versions = {}
    if openssl_available:
        sem = asyncio.Semaphore(4)  # Bounded concurrency to respect target
        tasks = []
        
        # Protocol tests
        for p in [("-ssl2", "SSLv2"), ("-ssl3", "SSLv3"), ("-tls1", "TLSv1.0"),
                  ("-tls1_1", "TLSv1.1"), ("-tls1_2", "TLSv1.2"), ("-tls1_3", "TLSv1.3")]:
            tasks.append(_probe_protocol(hostname, port, p[0], p[1], sem))
            
        # Weak cipher tests
        for c in ["RC4", "DES", "3DES", "EXPORT", "NULL", "aNULL"]:
            tasks.append(_probe_weak_cipher(hostname, port, c, sem))
            
        # Miscellaneous checks
        tasks.append(_probe_default_cipher(hostname, port, sem))
        tasks.append(_probe_tls_fingerprints(hostname, port, sem))
        tasks.append(_probe_alpn(hostname, port, sem))

        results = await asyncio.gather(*tasks)
        
        details["protocols"] = []
        for res in results:
            if res[0] == "protocol":
                name, supported = res[1], res[2]
                tls_versions[name] = supported
                if supported: details["protocols"].append(name)
            
            elif res[0] == "weak_cipher":
                cipher, negotiated = res[1], res[2]
                if negotiated:
                    findings.append(_make_finding(
                        title=f"Weak Cipher Suite Supported ({cipher})",
                        severity="high",
                        confidence="verified-live",
                        cwe="CWE-326",
                        owasp="A02:2021-Cryptographic Failures",
                        location=f"TLS Configuration {hostname}:{port}",
                        evidence=f"Server successfully negotiated weak cipher string '{cipher}', selecting: {negotiated}",
                        poc=f"openssl s_client -connect {hostname}:{port} -cipher {cipher} -servername {hostname}",
                        remediation="Disable deprecated and weak cipher suites in the server's TLS configuration.",
                        detection_method="Active Cipher Probing"
                    ))
            
            elif res[0] == "default_cipher":
                negotiated = res[2]
                if negotiated:
                    weak_keywords = ["RC4", "DES", "3DES", "EXPORT", "NULL", "aNULL"]
                    if any(w in negotiated.upper() for w in weak_keywords):
                        findings.append(_make_finding(
                            title=f"Weak Default Cipher Negotiated ({negotiated})",
                            severity="high",
                            confidence="verified-live",
                            cwe="CWE-326",
                            owasp="A02:2021-Cryptographic Failures",
                            location=f"TLS Configuration {hostname}:{port}",
                            evidence=f"The default connection negotiated a weak cipher: {negotiated}",
                            poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname}",
                            remediation="Prioritize strong cipher suites (e.g., AES-GCM, ChaCha20) in the TLS configuration.",
                            detection_method="Default Handshake Probing"
                        ))
                        
            elif res[0] == "fingerprints":
                ja3s, ja4s, resumption = res[1], res[2], res[3]
                details["ja3s"] = ja3s
                details["ja4s"] = ja4s
                details["session_resumption"] = resumption
                if ja3s:
                    findings.append(_make_finding(
                        title="TLS Server Fingerprint (JA3S/JA4S)",
                        severity="info",
                        confidence="verified-live",
                        cwe="",
                        owasp="",
                        location=f"TLS Handshake {hostname}:{port}",
                        evidence=f"JA3S: {ja3s}\nJA4S: {ja4s}",
                        poc=f"openssl s_client -connect {hostname}:{port} -msg -servername {hostname}",
                        remediation="No remediation required; informational fingerprint.",
                        detection_method="TLS Handshake Parsing"
                    ))
                    
            elif res[0] == "alpn":
                proto = res[1]
                if proto:
                    details["alpn"] = [proto]
                    findings.append(_make_finding(
                        title="ALPN Negotiated",
                        severity="info",
                        confidence="verified-live",
                        cwe="",
                        owasp="",
                        location=f"TLS Handshake {hostname}:{port}",
                        evidence=f"ALPN protocol negotiated: {proto}",
                        poc=f"openssl s_client -connect {hostname}:{port} -alpn h2,http/1.1 -servername {hostname}",
                        remediation="No remediation required.",
                        detection_method="ALPN Extension Probing"
                    ))

        # Protocol findings logic
        if tls_versions.get("SSLv2"):
            findings.append(_make_finding(
                title="SSLv2 Protocol Supported (DROWN)",
                severity="critical",
                confidence="verified-live",
                cwe="CWE-757",
                owasp="A02:2021-Cryptographic Failures",
                location=f"TLS Protocols {hostname}:{port}",
                evidence=f"SSLv2 handshake completed successfully.",
                poc=f"openssl s_client -connect {hostname}:{port} -ssl2",
                remediation="Completely disable SSLv2 support on the server.",
                detection_method="Protocol Probing"
            ))
        if tls_versions.get("SSLv3"):
            findings.append(_make_finding(
                title="SSLv3 Protocol Supported (POODLE)",
                severity="critical",
                confidence="verified-live",
                cwe="CWE-757",
                owasp="A02:2021-Cryptographic Failures",
                location=f"TLS Protocols {hostname}:{port}",
                evidence=f"SSLv3 handshake completed successfully.",
                poc=f"openssl s_client -connect {hostname}:{port} -ssl3",
                remediation="Completely disable SSLv3 support on the server.",
                detection_method="Protocol Probing"
            ))
        if tls_versions.get("TLSv1.0"):
            findings.append(_make_finding(
                title="Legacy TLS 1.0 Protocol Supported",
                severity="high",
                confidence="verified-live",
                cwe="CWE-757",
                owasp="A02:2021-Cryptographic Failures",
                location=f"TLS Protocols {hostname}:{port}",
                evidence=f"TLSv1.0 handshake completed successfully.",
                poc=f"openssl s_client -connect {hostname}:{port} -tls1",
                remediation="Disable TLS 1.0 and enforce TLS 1.2+ minimum.",
                detection_method="Protocol Probing"
            ))
        if tls_versions.get("TLSv1.1"):
            findings.append(_make_finding(
                title="Legacy TLS 1.1 Protocol Supported",
                severity="high",
                confidence="verified-live",
                cwe="CWE-757",
                owasp="A02:2021-Cryptographic Failures",
                location=f"TLS Protocols {hostname}:{port}",
                evidence=f"TLSv1.1 handshake completed successfully.",
                poc=f"openssl s_client -connect {hostname}:{port} -tls1_1",
                remediation="Disable TLS 1.1 and enforce TLS 1.2+ minimum.",
                detection_method="Protocol Probing"
            ))
        if tls_versions.get("TLSv1.3") and not any(tls_versions.get(v) for v in ["TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3", "SSLv2"]):
            findings.append(_make_finding(
                title="Modern TLS 1.3 Only Configuration",
                severity="info",
                confidence="verified-live",
                cwe="",
                owasp="",
                location=f"TLS Protocols {hostname}:{port}",
                evidence="Only TLS 1.3 is enabled.",
                poc=f"openssl s_client -connect {hostname}:{port} -tls1_2 (fails)",
                remediation="Excellent security posture. Ensure legacy clients aren't inadvertently broken.",
                detection_method="Protocol Probing"
            ))
        elif not tls_versions.get("TLSv1.3") and not tls_versions.get("TLSv1.2"):
            findings.append(_make_finding(
                title="No Modern TLS Versions Supported",
                severity="critical",
                confidence="verified-live",
                cwe="CWE-757",
                owasp="A02:2021-Cryptographic Failures",
                location=f"TLS Protocols {hostname}:{port}",
                evidence=f"Modern TLS (1.2/1.3) failed to negotiate. Supported: {details.get('protocols')}",
                poc=f"openssl s_client -connect {hostname}:{port} -tls1_2",
                remediation="Upgrade TLS stack to support and prefer TLS 1.2 and TLS 1.3.",
                detection_method="Protocol Probing"
            ))

    # Step 6: DNS Validation (CAA / DANE TLSA)
    if dig_available:
        caa_records = await _check_dns_record(hostname, "CAA")
        if caa_records:
            findings.append(_make_finding(
                title="DNS CAA Record Present",
                severity="info",
                confidence="verified-live",
                cwe="",
                owasp="",
                location=f"DNS CAA: {hostname}",
                evidence=f"CAA records found: {caa_records[:200]}",
                poc=f"dig CAA {hostname} +short",
                remediation="No remediation required. CAA adds excellent certificate issuance control.",
                detection_method="DNS Query"
            ))
        else:
            findings.append(_make_finding(
                title="Missing DNS CAA Record",
                severity="low",
                confidence="informational",
                cwe="CWE-295",
                owasp="A05:2021-Security Misconfiguration",
                location=f"DNS CAA: {hostname}",
                evidence="No CAA records were returned for the domain.",
                poc=f"dig CAA {hostname} +short",
                remediation="Add a CAA record to explicitly authorize specific Certificate Authorities for your domain.",
                detection_method="DNS Query"
            ))

        tlsa_name = f"_{port}._tcp.{hostname}"
        tlsa_records = await _check_dns_record(tlsa_name, "TLSA")
        if tlsa_records:
            findings.append(_make_finding(
                title="DANE (TLSA) Record Present",
                severity="info",
                confidence="verified-live",
                cwe="",
                owasp="",
                location=f"DNS TLSA: {tlsa_name}",
                evidence=f"TLSA records found: {tlsa_records[:200]}",
                poc=f"dig TLSA {tlsa_name} +short",
                remediation="No remediation required. DANE provides robust certificate validation.",
                detection_method="DNS Query"
            ))
        # Missing DANE check intentionally omitted to reduce noise across targets where adoption is virtually zero.

    # Step 7: HTTP/3 & Mixed Content (Only if we successfully fetched the main page previously)
    if ctx.page_is_representative and ctx.main_page_cache:
        headers = ctx.main_page_cache.get("headers", {})
        alt_svc = _get_header(headers, "Alt-Svc") or ""
        if any(h3_sig in alt_svc for h3_sig in ("h3=", "h3-29=", "h3-q050=", "h3-32=")):
            findings.append(_make_finding(
                title="HTTP/3 (QUIC) Advertised",
                severity="info",
                confidence="verified-static",
                cwe="",
                owasp="",
                location=f"Header: Alt-Svc",
                evidence=f"Alt-Svc: {alt_svc}",
                poc=f"curl -I --http3 https://{hostname}:{port}",
                remediation="No remediation required. Modern HTTP/3 enhances performance.",
                detection_method="Header Inspection"
            ))

        if ctx.url.lower().startswith("https://"):
            html = ctx.main_page_cache.get("html", "")
            if html:
                soup = BeautifulSoup(html, "html.parser")
                mixed_detected = 0
                
                # Active Mixed Content (Scripts/CSS/IFrames)
                for tag, attr, res_type in [("script", "src", "Script"), ("iframe", "src", "Iframe"), ("link", "href", "Stylesheet")]:
                    for el in soup.find_all(tag):
                        if tag == "link" and "stylesheet" not in (el.get("rel") or []):
                            continue
                        src = el.get(attr, "")
                        if src and str(src).lower().startswith("http://"):
                            mixed_detected += 1
                            findings.append(_make_finding(
                                title=f"Active Mixed Content: {res_type} loaded over HTTP",
                                severity="high",
                                confidence="verified-static",
                                cwe="CWE-829",
                                owasp="A02:2021-Cryptographic Failures",
                                location=f"Tag: <{tag}>, Attribute: {attr}={src}",
                                evidence=f"Found {tag} loading insecure resource from {src} on a secure page.",
                                poc=f"curl -I '{src}'",
                                remediation=f"Change the URL protocol from http:// to https:// or use protocol-relative URLs.",
                                detection_method="HTML Parsing"
                            ))
                
                # Forms submitting over HTTP
                for form in soup.find_all("form"):
                    action = form.get("action", "")
                    if action and str(action).lower().startswith("http://"):
                        mixed_detected += 1
                        findings.append(_make_finding(
                            title="Insecure Form Submission (Mixed Content)",
                            severity="high",
                            confidence="verified-static",
                            cwe="CWE-319",
                            owasp="A02:2021-Cryptographic Failures",
                            location=f"Tag: <form>, Attribute: action={action}",
                            evidence=f"Form submissions are configured to transmit over plain HTTP: {action}",
                            poc=f"curl -I '{action}'",
                            remediation="Update form actions to point to an HTTPS endpoint to protect data in transit.",
                            detection_method="HTML Parsing"
                        ))

                # Passive Mixed Content (Images)
                for img in soup.find_all("img"):
                    src = img.get("src", "")
                    if src and str(src).lower().startswith("http://"):
                        mixed_detected += 1
                        findings.append(_make_finding(
                            title="Passive Mixed Content: Image loaded over HTTP",
                            severity="medium",
                            confidence="verified-static",
                            cwe="CWE-319",
                            owasp="A02:2021-Cryptographic Failures",
                            location=f"Tag: <img>, Attribute: src={src}",
                            evidence=f"Image requested insecurely from {src}",
                            poc=f"curl -I '{src}'",
                            remediation="Load all image assets securely over HTTPS.",
                            detection_method="HTML Parsing"
                        ))
                
                details["mixed_content_count"] = mixed_detected

    return {
        "findings": findings,
        "details": details
    }