#!/usr/bin/env python3
"""
test_04_ssl_tls.py – Bravo6 Ultimate SSL/TLS + Mixed Content Scanner (v11.3 – Fixed)
============================================================================================
Fixes applied:
- Case-insensitive WAF detection (Issue 1)
- HSTS severity recalibration (Issue 2)
- HSTS missing finding title aligned with test_05 (Issue 3)
- OCSP stapling suppressed when CDN detected, confidence raised (Issue 4)
- Removed noisy P-384 “strong key” info finding (Issue 5)
- Grade capped when critical/high findings exist (Issue 6)
- ROBOT check limited to true RSA key-exchange ciphers (Issue 7)
- Renegotiation & compression output checked in stderr as well (Issue 8)
- Perfect Forward Secrecy check added (Issue 9)
- Blocking DNS call moved to executor (Issue 10)
- Concurrency-safe per-run OpenSSL state (Issue 11)
- Findings sorted by severity before return (Issue 12)
- Added evidence and poc for all findings (New)
- Aligned WAF detection with test_05 (New)
"""

import asyncio
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

USER_AGENT = "Bravo6-TLS-Scanner/11.0"
TIMEOUT = 20
OPENSSL_TIMEOUT = 12

# WAF/CDN detection signals - aligned with test_05_security_headers.py
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
    breakdown = []
    for f in findings:
        sev = f.get("severity", "info")
        ded = deductions.get(sev, 0)
        if ded:
            score -= ded
            breakdown.append(f"-{ded} ({sev}): {f['title']}")

    # مكافأة التجارة الإلكترونية / تسجيل الدخول (مقيدة)
    if context.get("is_login_page") or context.get("is_ecommerce"):
        bonus = 10 if score >= 85 else 5
        score = min(score + bonus, 90)
        breakdown.append(f"+{bonus} (Login / E-commerce context)")

    if context.get("is_internal"):
        score -= 15
        breakdown.append("-15 (Internal IP)")

    # مكافأة WAF (مقيدة، وتُطبق فقط في غياب نتائج حرجة)
    has_critical_pre = any(f.get("severity") == "critical" for f in findings)
    if context.get("waf_detected") and not has_critical_pre:
        score = min(score + 5, 92)
        breakdown.append("+5 (WAF/CDN detected)")

    score = max(0, min(100, score))
    if score >= 95: grade = "A+"
    elif score >= 90: grade = "A"
    elif score >= 85: grade = "A-"
    elif score >= 80: grade = "B"
    elif score >= 70: grade = "C"
    elif score >= 60: grade = "D"
    elif score >= 50: grade = "E"
    else: grade = "F"

    # عقوبات التصنيف بناءً على وجود نتائج حرجة أو عالية
    has_critical = any(f.get("severity") == "critical" for f in findings)
    has_high = any(f.get("severity") == "high" for f in findings)
    if has_critical and grade in ("A+", "A", "A-", "B", "C"):
        grade = "D"
        score = min(score, 59)
    elif has_high and grade in ("A+", "A", "A-", "B"):
        grade = "C"
        score = min(score, 74)

    # عقوبة إضافية إذا كان هناك ٣ نتائج متوسطة أو أكثر
    medium_count = sum(1 for f in findings if f.get("severity") == "medium")
    if medium_count >= 3 and grade in ("A+", "A", "A-"):
        grade = "B"
        score = min(score, 84)

    return score, grade, breakdown

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
    """Number of embedded SCTs in the certificate."""
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

# ── PFS check (runs in executor) ───────────────────────────────────────────
def _check_pfs_python(hostname: str, port: int) -> Tuple[bool, str]:
    """Return (has_pfs, cipher_name)."""
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

# ── OpenSSL‑based checks (with per-run state, Issue 11) ────────────────────
async def _test_protocol_openssl(
    hostname: str, port: int, version_flag: str,
    openssl_state: dict
) -> bool:
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

async def _test_cipher_openssl(
    hostname: str, port: int, cipher_string: str,
    openssl_state: dict
) -> bool:
    if not openssl_state["available"]:
        return False
    out, err, timed_out = await _run_openssl(
        ["s_client", "-connect", f"{hostname}:{port}", "-cipher", cipher_string]
    )
    if timed_out:
        return False
    if b"OPENSSL_MISSING" in err:
        if not openssl_state["warned"]:
            log.warning("OpenSSL binary not found – skipping all OpenSSL-based checks.")
            openssl_state["warned"] = True
        openssl_state["available"] = False
        return False
    return b"BEGIN CERTIFICATE" in out and b"Cipher    :" in out

# ── OCSP checking (HTTP) ───────────────────────────────────────────────────
async def _check_ocsp_python(cert_chain: List[str]) -> Dict[str, Any]:
    if not cert_chain or len(cert_chain) < 2:
        return {"revoked": None, "detail": "Insufficient certificate chain for OCSP"}
    try:
        leaf_pem = cert_chain[0]
        issuer_pem = cert_chain[1]
        leaf = x509.load_pem_x509_certificate(leaf_pem.encode())
        issuer = x509.load_pem_x509_certificate(issuer_pem.encode())
    except Exception as e:
        return {"revoked": None, "detail": f"Failed to parse certificates: {e}"}

    try:
        aia = leaf.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        ocsp_urls = [desc.access_location.value for desc in aia.value
                     if desc.access_method == AuthorityInformationAccessOID.OCSP]
        if not ocsp_urls:
            return {"revoked": None, "detail": "No OCSP responder URL in certificate"}
        ocsp_url = ocsp_urls[0]
    except Exception:
        return {"revoked": None, "detail": "OCSP responder URL not found"}

    builder = crypto_ocsp.OCSPRequestBuilder()
    builder = builder.add_certificate(leaf, issuer, hashes.SHA1())
    req = builder.build()

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            headers = {"Content-Type": "application/ocsp-request"}
            data = req.public_bytes(serialization.Encoding.DER)
            async with session.post(ocsp_url, data=data, headers=headers) as resp:
                if resp.status != 200:
                    return {"revoked": None, "detail": f"OCSP responder HTTP {resp.status}"}
                ocsp_resp_bytes = await resp.read()
    except Exception as e:
        return {"revoked": None, "detail": f"OCSP request failed: {e}"}

    try:
        ocsp_resp = crypto_ocsp.load_der_ocsp_response(ocsp_resp_bytes)
        if ocsp_resp.response_status != crypto_ocsp.OCSPResponseStatus.SUCCESSFUL:
            return {"revoked": None, "detail": f"OCSP response status: {ocsp_resp.response_status.name}"}
        if len(ocsp_resp.responses) != 1:
            return {"revoked": None, "detail": "Unexpected OCSP response count"}
        single_resp = ocsp_resp.responses[0]
        if single_resp.certificate_status == crypto_ocsp.OCSPCertStatus.GOOD:
            return {"revoked": False, "detail": "Certificate is GOOD"}
        elif single_resp.certificate_status == crypto_ocsp.OCSPCertStatus.REVOKED:
            return {"revoked": True, "detail": f"Certificate REVOKED at {single_resp.revocation_time}"}
        else:
            return {"revoked": None, "detail": "OCSP status UNKNOWN"}
    except Exception as e:
        return {"revoked": None, "detail": f"OCSP response parsing error: {e}"}

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
            # FIX: Added evidence and poc for mixed content findings
            findings.append(_make_finding(
                title="Mixed content detected",
                description=f"{tag.name} loads over HTTP: {full}",
                severity=sev,
                confidence=90,
                location=full,
                evidence=f"Tag: {tag.name}, URL: {full}",
                remediation="Change resource to HTTPS or remove it.",
                cwe="CWE-319",
                owasp="A03:2021",
                poc=f"curl -vk '{base_url}' 2>&1 | grep -i '<{tag.name}'",
                category="mixed_content"
            ))

    for style_tag in soup.find_all("style"):
        if not style_tag.string:
            continue
        urls = re.findall(r'url\(\s*[\'"]?([^)\'"]+)', style_tag.string)
        for url in urls:
            full = urljoin(base_url, url.strip())
            if full.startswith("http://"):
                # FIX: Added evidence and poc for CSS mixed content
                findings.append(_make_finding(
                    title="Mixed content in CSS",
                    description=f"Inline style loads HTTP resource: {full}",
                    severity="medium",
                    confidence=85,
                    location=full,
                    evidence=f"CSS url() reference: {full}",
                    remediation="Change CSS resource to HTTPS.",
                    cwe="CWE-319",
                    owasp="A03:2021",
                    poc=f"curl -vk '{base_url}' 2>&1 | grep -i 'url({url})'",
                    category="mixed_content"
                ))

    for tag in soup.find_all(True):
        style = tag.get("style")
        if not style:
            continue
        urls = re.findall(r'url\(\s*[\'"]?([^)\'"]+)', style)
        for url in urls:
            full = urljoin(base_url, url.strip())
            if full.startswith("http://"):
                # FIX: Added evidence and poc for style attribute mixed content
                findings.append(_make_finding(
                    title="Mixed content in style attribute",
                    description=f"Element <{tag.name}> style loads HTTP: {full}",
                    severity="medium",
                    confidence=85,
                    location=full,
                    evidence=f"Tag: {tag.name}, style attribute URL: {full}",
                    remediation="Change CSS resource to HTTPS.",
                    cwe="CWE-319",
                    owasp="A03:2021",
                    poc=f"curl -vk '{base_url}' 2>&1 | grep -i '<{tag.name}'",
                    category="mixed_content"
                ))

    return findings

# ══════════════════════════════════════════════════════════════════════════
async def run(url: str, shared_page: dict = None) -> Dict[str, Any]:
    # Per-run OpenSSL state (Issue 11)
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
    # Move DNS check to executor (Issue 10)
    is_internal = await loop.run_in_executor(None, _check_internal, hostname)

    context = {
        "is_login_page": False,
        "is_ecommerce": False,
        "is_internal": is_internal,
        "waf_detected": False,
    }

    # FIX: Aligned WAF/CDN detection with test_05_security_headers.py
    # Check if WAF info is already available from shared_page
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
            # FIX: Added evidence and poc for expired certificate
            findings.append(_make_finding(
                "Certificate expired",
                f"Expired on {cert_info['not_after']}",
                "critical", 100,
                location="Expiry",
                evidence=f"Certificate expired on {cert_expiry_date}",
                remediation="Renew immediately.",
                cwe="CWE-298",
                poc=cert_poc
            ))
        elif days < 7:
            # FIX: Added evidence and poc for certificate expiring soon (urgent)
            findings.append(_make_finding(
                f"Certificate expires in {days} days",
                "Renew urgently.",
                "high", 100,
                location="Expiry",
                evidence=f"Certificate expires on {cert_expiry_date} ({days} days remaining)",
                remediation="Renew now.",
                cwe="CWE-298",
                poc=cert_poc
            ))
        elif days < 30:
            # FIX: Added evidence and poc for certificate expiring soon (plan)
            findings.append(_make_finding(
                f"Certificate expires in {days} days",
                "Plan renewal.",
                "medium", 100,
                location="Expiry",
                evidence=f"Certificate expires on {cert_expiry_date} ({days} days remaining)",
                remediation="Renew soon.",
                cwe="CWE-298",
                poc=cert_poc
            ))

        if not cert_info["hostname_match"]:
            sev = "high" if not is_internal else "low"
            # FIX: Added evidence and poc for hostname mismatch
            findings.append(_make_finding(
                "Hostname mismatch",
                "CN/SAN does not match.",
                sev, 100,
                location="Certificate",
                evidence=f"CN: {cert_cn}, SANs: {cert_san}, Hostname: {hostname}",
                remediation="Fix CN/SAN.",
                cwe="CWE-295",
                poc=cert_poc
            ))
        if cert_info["self_signed"]:
            sev = "high" if not is_internal else "low"
            # FIX: Added evidence and poc for self-signed certificate
            findings.append(_make_finding(
                "Self-signed certificate",
                "Not trusted by public CAs.",
                sev, 100,
                location="Certificate",
                evidence=f"Issuer: {cert_issuer}, Subject: {cert_subject}",
                remediation="Obtain CA-signed certificate.",
                cwe="CWE-295",
                poc=cert_poc
            ))
        if cert_info["weak_signature"]:
            # FIX: Added evidence and poc for weak signature algorithm
            findings.append(_make_finding(
                f"Weak signature algorithm ({cert_info['signature_algorithm']})",
                "",
                "high", 100,
                location="Certificate",
                evidence=f"Signature algorithm: {cert_sig_alg}",
                remediation="Re-issue with SHA-256.",
                cwe="CWE-327",
                poc=cert_poc
            ))
        if cert_info["key_type"] == "rsa" and cert_info["key_size"] and cert_info["key_size"] < 2048:
            # FIX: Added evidence and poc for weak RSA key
            findings.append(_make_finding(
                f"Weak RSA key ({cert_info['key_size']} bits)",
                "Key length < 2048.",
                "high", 100,
                location="Certificate",
                evidence=f"Key type: RSA, Size: {cert_key_size} bits",
                remediation="Re-issue with >=2048-bit key.",
                cwe="CWE-326",
                poc=cert_poc
            ))
        elif cert_info["key_type"] == "ecdsa" and cert_info["key_size"] and cert_info["key_size"] < 256:
            # FIX: Added evidence and poc for weak ECDSA key
            findings.append(_make_finding(
                f"Weak ECDSA key ({cert_info['key_size']} bits)",
                "Key length < 256.",
                "high", 100,
                location="Certificate",
                evidence=f"Key type: ECDSA, Size: {cert_key_size} bits",
                remediation="Re-issue with >=256-bit EC key.",
                cwe="CWE-326",
                poc=cert_poc
            ))

    # 2. Chain validation
    chain_valid = None
    if cert_info:
        chain_valid, chain_error = await loop.run_in_executor(None, _verify_chain_via_ssl_connect, hostname, port)
        if chain_valid is False:
            # FIX: Added poc for certificate chain not trusted
            findings.append(_make_finding(
                "Certificate chain not trusted",
                f"Verification failed: {chain_error}",
                "high", 95,
                location="Certificate chain",
                evidence=chain_error,
                remediation="Install the correct certificate chain.",
                cwe="CWE-295",
                poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname} -showcerts < /dev/null 2>/dev/null | openssl verify -CAfile {CA_BUNDLE_PATH or '/etc/ssl/certs/ca-certificates.crt'}"
            ))
        elif chain_valid is None:
            # FIX: Added evidence and poc for unable to verify certificate chain
            findings.append(_make_finding(
                "Unable to verify certificate chain",
                "SSL verification could not be performed.",
                "medium", 70,
                location="Certificate chain",
                evidence="SSL verification could not be completed",
                remediation="Ensure the server certificate is trusted by a public CA.",
                cwe="CWE-295",
                poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname} -showcerts < /dev/null"
            ))

    # 3. Full chain for OCSP
    if cert_info:
        cert_chain = await loop.run_in_executor(None, _get_peer_cert_chain, hostname, port) or []

    # ── Protocol probing (OpenSSL, with per-run state) ─────────────────────
    tls_versions = {}
    tls_versions["SSLv2"] = await _test_protocol_openssl(hostname, port, "-ssl2", openssl_state)
    tls_versions["SSLv3"] = await _test_protocol_openssl(hostname, port, "-ssl3", openssl_state)
    for ver, flag in [("TLSv1.0", "-tls1"), ("TLSv1.1", "-tls1_1"),
                      ("TLSv1.2", "-tls1_2"), ("TLSv1.3", "-tls1_3")]:
        tls_versions[ver] = await _test_protocol_openssl(hostname, port, flag, openssl_state)

    if tls_versions.get("SSLv2"):
        # FIX: Added evidence and poc for SSLv2 support
        findings.append(_make_finding(
            "SSLv2 supported (DROWN)",
            "Obsolete protocol",
            "critical", 100,
            location="SSLv2",
            evidence=f"SSLv2 is enabled on {hostname}:{port}",
            remediation="Disable SSLv2.",
            cwe="CWE-757",
            poc=f"openssl s_client -connect {hostname}:{port} -ssl2"
        ))
    if tls_versions.get("SSLv3"):
        # FIX: Added evidence and poc for SSLv3 support
        findings.append(_make_finding(
            "SSLv3 supported (POODLE)",
            "Obsolete protocol",
            "critical", 100,
            location="SSLv3",
            evidence=f"SSLv3 is enabled on {hostname}:{port}",
            remediation="Disable SSLv3.",
            cwe="CWE-757",
            poc=f"openssl s_client -connect {hostname}:{port} -ssl3"
        ))
    if tls_versions.get("TLSv1.0"):
        # FIX: Added evidence and poc for TLS 1.0 support
        findings.append(_make_finding(
            "TLS 1.0 supported",
            "Deprecated (BEAST)",
            "high", 100,
            location="TLSv1.0",
            evidence=f"TLS 1.0 is enabled on {hostname}:{port}",
            remediation="Disable TLS 1.0.",
            cwe="CWE-757",
            poc=f"openssl s_client -connect {hostname}:{port} -tls1"
        ))
    if tls_versions.get("TLSv1.1"):
        # FIX: Added evidence and poc for TLS 1.1 support
        findings.append(_make_finding(
            "TLS 1.1 supported",
            "Deprecated",
            "high", 100,
            location="TLSv1.1",
            evidence=f"TLS 1.1 is enabled on {hostname}:{port}",
            remediation="Disable TLS 1.1.",
            cwe="CWE-757",
            poc=f"openssl s_client -connect {hostname}:{port} -tls1_1"
        ))

    # ── Weak cipher testing ────────────────────────────────────────────────
    WEAK_CIPHERS = {
        "NULL-MD5": "NULL cipher (MD5)",
        "NULL-SHA": "NULL cipher (SHA1)",
        "EXP-RC4-MD5": "EXPORT RC4-MD5 (512-bit)",
        "EXP-DES-CBC-SHA": "EXPORT DES-CBC-SHA (512-bit)",
        "EXP-EDH-DSS-DES-CBC-SHA": "EXPORT DH-DSS-DES",
        "EXP-EDH-RSA-DES-CBC-SHA": "EXPORT DH-RSA-DES",
        "RC4-MD5": "RC4-MD5",
        "RC4-SHA": "RC4-SHA",
        "DES-CBC3-SHA": "3DES-CBC-SHA (Sweet32)",
        "DES-CBC-SHA": "DES-CBC-SHA",
        "AES128-SHA": "AES128-CBC-SHA (BEAST)",
        "AES256-SHA": "AES256-CBC-SHA (BEAST)",
        "CAMELLIA128-SHA": "CAMELLIA128-CBC-SHA",
        "CAMELLIA256-SHA": "CAMELLIA256-CBC-SHA",
        "ECDHE-RSA-AES128-SHA": "ECDHE-RSA-AES128-CBC-SHA",
        "ECDHE-RSA-AES256-SHA": "ECDHE-RSA-AES256-CBC-SHA",
        "ADH-RC4-MD5": "Anonymous DH RC4-MD5",
        "AECDH-NULL-SHA": "Anonymous ECDH NULL-SHA",
    }
    cipher_status = {}
    for cipher_str, desc in WEAK_CIPHERS.items():
        supported = await _test_cipher_openssl(hostname, port, cipher_str, openssl_state)
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
            # FIX: Added evidence for weak cipher findings
            findings.append(_make_finding(
                f"Weak cipher accepted: {desc}",
                f"Server negotiated {desc}.",
                sev, 95,
                location=f"Cipher: {cipher_str}",
                evidence=f"Server accepted weak cipher: {desc} ({cipher_str})",
                remediation="Remove weak ciphers from server configuration.",
                cwe="CWE-327", owasp="A02:2021",
                poc=f"openssl s_client -cipher {cipher_str} -connect {hostname}:{port}"
            ))

    # ROBOT check – only true RSA key-exchange ciphers (Issue 7)
    RSA_KEX_CIPHERS = {
        "AES128-SHA", "AES256-SHA", "CAMELLIA128-SHA", "CAMELLIA256-SHA",
        "DES-CBC3-SHA", "DES-CBC-SHA", "RC4-MD5", "RC4-SHA",
        "NULL-MD5", "NULL-SHA",
    }
    rsa_ciphers = [c for c in cipher_status if cipher_status[c] and c in RSA_KEX_CIPHERS]
    if rsa_ciphers and any(tls_versions.get(v) for v in ["TLSv1.0", "TLSv1.1", "TLSv1.2"]):
        # FIX: Added evidence and poc for ROBOT vulnerability
        findings.append(_make_finding(
            "ROBOT vulnerability possible",
            "RSA key exchange ciphers with older TLS versions.",
            "high", 90,
            location="Cipher/RSA",
            evidence=f"RSA key exchange ciphers enabled: {', '.join(rsa_ciphers)}",
            remediation="Disable RSA key exchange ciphers; use ECDHE.",
            cwe="CWE-327", owasp="A02:2021",
            poc=f"openssl s_client -connect {hostname}:{port} -cipher 'RSA' < /dev/null"
        ))

    # ── PFS check (Issue 9) ────────────────────────────────────────────────
    pfs_ok, pfs_cipher = await loop.run_in_executor(None, _check_pfs_python, hostname, port)
    if not pfs_ok and cert_info:
        findings.append(_make_finding(
            "No Perfect Forward Secrecy (PFS)",
            "Server does not negotiate ECDHE or DHE cipher suites. "
            "If the private key is ever compromised, all past sessions can be decrypted.",
            "high", 85,
            location="Cipher negotiation",
            evidence=f"Negotiated cipher: {pfs_cipher or 'none'}; no ECDHE/DHE support detected",
            remediation=(
                "Configure the server to prefer ECDHE cipher suites and disable "
                "pure RSA key-exchange ciphers (e.g., AES128-SHA, AES256-SHA)."
            ),
            cwe="CWE-311", owasp="A02:2021",
            poc=f"openssl s_client -connect {hostname}:{port} -cipher 'ECDHE+AESGCM' < /dev/null",
            category="ssl"
        ))

    # ── OCSP Stapling & CT (combined) ─────────────────────────────────────
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

    # OCSP stapling suppressed if WAF/CDN detected (Issue 4)
    if ocsp_stapling is False and not context.get("waf_detected"):
        # FIX: Added evidence and poc for OCSP stapling not used
        findings.append(_make_finding(
            "OCSP stapling not used",
            "Server did not include an OCSP response in the TLS handshake.",
            "low", 85,
            location="OCSP stapling",
            evidence="No OCSP response included in TLS handshake",
            remediation="Enable OCSP stapling in your web server configuration (e.g., ssl_stapling on; in nginx).",
            cwe="CWE-299", owasp="A02:2021",
            poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname} -status < /dev/null 2>/dev/null | grep -A5 'OCSP Response'"
        ))
    if cert_info and cert_info.get("must_staple") and ocsp_stapling is False:
        # FIX: Added evidence and poc for OCSP Must-Staple violated
        findings.append(_make_finding(
            "OCSP Must-Staple violated",
            "Certificate requires OCSP stapling but server did not provide it.",
            "critical", 100,
            location="OCSP Must-Staple",
            evidence="Certificate has must-staple extension but no OCSP response was stapled",
            remediation="Enable OCSP stapling or remove the must-staple flag.",
            cwe="CWE-299", owasp="A02:2021",
            poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname} -status < /dev/null 2>/dev/null | grep -A5 'OCSP Response'"
        ))
    if not has_ct:
        sev = "high" if (context["is_login_page"] or context["is_ecommerce"]) else "medium"
        conf = 90 if sev == "high" else 70
        # FIX: Added evidence and poc for no Certificate Transparency
        findings.append(_make_finding(
            "No Certificate Transparency (SCTs)",
            "Certificate lacks Signed Certificate Timestamps.",
            sev, conf,
            location="CT",
            evidence=f"Total SCTs found: {total_scts} (embedded: {cert_scts}, TLS extension: {tls_scts})",
            remediation="Obtain a certificate with embedded SCTs.",
            cwe="CWE-299", owasp="A02:2021",
            poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname} < /dev/null 2>/dev/null | openssl x509 -noout -text | grep -A2 'CT Precertificate SCTs'"
        ))

    # ── OCSP HTTP check (only if no stapled info) ──────────────────────────
    ocsp_result = {"revoked": None, "detail": ""}
    if stapled_revoked is not None:
        ocsp_result["revoked"] = stapled_revoked
        ocsp_result["detail"] = "Stapled OCSP response parsed"
    elif cert_chain and len(cert_chain) >= 2:
        ocsp_result = await _check_ocsp_python(cert_chain)

    if ocsp_result.get("revoked") is True:
        # FIX: Added poc for certificate revoked finding
        findings.append(_make_finding(
            "Certificate is REVOKED",
            ocsp_result.get("detail", ""),
            "critical", 100,
            location="OCSP check",
            evidence=ocsp_result.get("detail", "Certificate revoked according to OCSP"),
            remediation="Replace the revoked certificate immediately.",
            cwe="CWE-299",
            poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname} -status < /dev/null 2>/dev/null | openssl ocsp -text"
        ))

    # ── Page fetch & mixed content / headers ───────────────────────────────
    hsts_header = None
    csp_header = None
    mixed_findings = []
    html = ""
    headers = {}

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
            # FIX: Added evidence and poc for page fetch failure
            findings.append(_make_finding(
                "Page fetch failed for header/mixed content checks",
                str(e),
                "medium", 70,
                location="https fetch",
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

        # WAF detection – case-insensitive (Issue 1) - now aligned with test_05
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

    # ── HSTS & CSP checks ──────────────────────────────────────────────────
    if not hsts_header and not is_internal:
        # FIX: Added evidence for missing HSTS header (poc already present)
        findings.append(_make_finding(
            "Missing HSTS header",
            "No Strict-Transport-Security.",
            "high", 100,
            location="HTTP Header",
            evidence="No Strict-Transport-Security header present in response",
            remediation="Add HSTS header.",
            cwe="CWE-523",
            poc=f"curl -I https://{hostname}:{port} | grep -i strict-transport-security"
        ))
    elif hsts_header:
        # HSTS max-age severity recalibrated (Issue 2)
        max_age_match = re.search(r'max-age=(\d+)', hsts_header)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            has_preload = "preload" in hsts_header.lower()
            if max_age < 2592000:   # < 30 days
                # FIX: Added evidence for HSTS max-age critically short
                findings.append(_make_finding(
                    "HSTS max-age critically short",
                    f"max-age={max_age} (under 30 days) — SSL stripping trivially possible.",
                    "high", 95,
                    location="HSTS header",
                    evidence=f"Current max-age={max_age}, recommended >=2592000 (30 days)",
                    remediation="Set max-age to at least 31536000 (1 year).",
                    cwe="CWE-523",
                    poc=f"curl -I https://{hostname}:{port} | grep -i strict-transport-security"
                ))
            elif max_age < 31536000: # 30 days – 1 year
                # FIX: Added evidence for HSTS max-age too short
                findings.append(_make_finding(
                    "HSTS max-age too short",
                    f"max-age={max_age} (under 1 year).",
                    "medium", 90,
                    location="HSTS header",
                    evidence=f"Current max-age={max_age}, recommended >=31536000 (1 year)",
                    remediation="Set max-age to at least 31536000.",
                    cwe="CWE-523",
                    poc=f"curl -I https://{hostname}:{port} | grep -i strict-transport-security"
                ))
            elif max_age < 63072000 and has_preload:  # 1–2 years WITH preload flag
                # FIX: Added evidence for HSTS preload requires max-age >= 2 years
                findings.append(_make_finding(
                    "HSTS preload requires max-age ≥ 2 years",
                    f"max-age={max_age} — preload list requires ≥63072000.",
                    "medium", 90,
                    location="HSTS header",
                    evidence=f"Current max-age={max_age}, preload requires >=63072000 (2 years)",
                    remediation="Increase max-age to 63072000.",
                    cwe="CWE-523",
                    poc=f"curl -I https://{hostname}:{port} | grep -i strict-transport-security"
                ))
            # max_age ≥ 1 year without preload, or ≥ 2 years with preload → no finding
            if has_preload and max_age >= 63072000:
                # FIX: Added evidence for HSTS preload flag present
                findings.append(_make_finding(
                    "HSTS preload flag present (ready)",
                    "Domain meets preload list requirements.",
                    "info", 50,
                    location="HSTS header",
                    evidence="HSTS header includes preload directive with max-age >=63072000",
                    remediation="Consider submitting to hstspreload.org.",
                    cwe="CWE-523"
                ))
            elif has_preload:
                pass  # already handled above
        if "includeSubDomains" not in hsts_header:
            # FIX: Added evidence for HSTS missing includeSubDomains
            findings.append(_make_finding(
                "HSTS missing includeSubDomains",
                "HSTS lacks subdomain protection.",
                "medium", 90,
                location="HSTS header",
                evidence="HSTS header does not contain includeSubDomains directive",
                remediation="Add includeSubDomains to HSTS.",
                cwe="CWE-523",
                poc=f"curl -I https://{hostname}:{port} | grep -i strict-transport-security"
            ))

    if csp_header and "upgrade-insecure-requests" in csp_header:
        # FIX: Added evidence for CSP upgrade-insecure-requests
        findings.append(_make_finding(
            "CSP upgrade-insecure-requests",
            "CSP is upgrading HTTP to HTTPS.",
            "info", 50,
            location="CSP header",
            evidence=f"CSP header contains upgrade-insecure-requests: {csp_header}",
            remediation="No action needed.",
            cwe="",
            poc=f"curl -I https://{hostname}:{port} | grep -i content-security-policy"
        ))

    # ── Compression / Renegotiation (Issue 8: check both out and err) ──────
    if openssl_state["available"]:
        out, err, timed = await _run_openssl(["s_client", "-connect", f"{hostname}:{port}", "-comp"])
        combined_comp = out + err
        if not timed and b"Compression: zlib" in combined_comp:
            # FIX: Added evidence and poc for TLS compression
            findings.append(_make_finding(
                "TLS compression enabled (CRIME)",
                "Enables CRIME attack.",
                "high", 95,
                location="TLS compression",
                evidence="Compression: zlib detected in TLS handshake",
                remediation="Disable TLS compression.",
                cwe="CWE-310", owasp="A02:2021",
                poc=f"openssl s_client -connect {hostname}:{port} -comp < /dev/null"
            ))

        out, err, timed = await _run_openssl(["s_client", "-connect", f"{hostname}:{port}", "-renegotiate"])
        combined_reneg = out + err
        if not timed and b"Secure Renegotiation IS NOT supported" in combined_reneg:
            # FIX: Added evidence and poc for insecure renegotiation
            findings.append(_make_finding(
                "Insecure renegotiation",
                "Does not support secure renegotiation.",
                "medium", 90,
                location="Renegotiation",
                evidence="Secure Renegotiation IS NOT supported",
                remediation="Enable secure renegotiation.",
                cwe="CWE-757", owasp="A02:2021",
                poc=f"openssl s_client -connect {hostname}:{port} -renegotiate < /dev/null"
            ))

    # ── Sort findings by severity (Issue 12) ───────────────────────────────
    _SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: _SEV_ORDER.get(f.get("severity", "info"), 4))

    # ── Final scoring ────────────────────────────────────────────────────
    mixed_count = len(mixed_findings)
    tls_issues = [f for f in findings if f.get("category") != "mixed_content"]
    tls_count = len(tls_issues)
    high_count = sum(1 for f in findings if f.get("severity") == "high")
    critical_count = sum(1 for f in findings if f.get("severity") == "critical")

    score, grade, score_breakdown = _apply_scoring(findings, context)
    worst_sev = max(
        (f["severity"] for f in findings),
        key=lambda s: {"info":0,"low":1,"medium":2,"high":3,"critical":4}.get(s,0),
        default="info"
    )
    status = "fail" if any(f["severity"] in ("critical","high") for f in findings) else "warning" if findings else "pass"
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
            "ocsp_revoked": ocsp_result.get("revoked"),
            "protocols": tls_versions,
            "ciphers": cipher_status,
            "hsts_header": hsts_header,
            "csp_header": csp_header,
            "ocsp_stapling": ocsp_stapling,
            "ct_scts_total": total_scts,
            "ct_scts_tls_ext": tls_scts,
            "ct_scts_cert": cert_scts,
            "ocsp_ct_note": "OCSP/CT checks performed" if not handshake_error else None,
            "pfs_supported": pfs_ok,
            "pfs_cipher": pfs_cipher,
            "context": context,
            "score_breakdown": score_breakdown,
        }
    }

if __name__ == "__main__":
    target_url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    result = asyncio.run(run(target_url))
    print(json.dumps(result, indent=2, ensure_ascii=False))