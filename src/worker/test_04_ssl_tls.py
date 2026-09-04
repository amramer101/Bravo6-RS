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
# JA4S (FoxIO JA4+ spec) requires ALPN extraction from the ServerHello plus a
# SHA256-truncated construction over the extension list — a materially
# different algorithm from JA3S, not implementable by extending the JA3S
# text-parsing probe below without a larger, spec-verified rewrite. Reported
# honestly as unsupported rather than a fabricated/mislabeled hash.
JA4S_NOT_IMPLEMENTED = "not_implemented"

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
    location: str, evidence: str, poc: str, remediation: str, detection_method: str,
    tier: Optional[str] = None
) -> Dict[str, Any]:
    finding = {
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
    # Only defense-in-depth findings carry an explicit tier. Everything else
    # is left untagged and the orchestrator scores it as "baseline" (its
    # documented default), so existing findings are byte-for-byte unchanged.
    if tier is not None:
        finding["raw_data"] = {"tier": tier}
    return finding

def _build_expiry_finding(cert_info: Dict[str, Any], hostname: str, port: int, cert_poc: str) -> Optional[Dict[str, Any]]:
    """
    Build a near-expiry finding for a still-valid certificate, or None if not
    yet in the warning window (or certificate data is missing/incomplete).
    Already-expired certificates are handled separately by their own finding.
    """
    if not cert_info or "days_until_expiry" not in cert_info:
        return None

    days = cert_info["days_until_expiry"]
    if days < 0:
        return None

    if days <= 7:
        severity = "critical"
    elif days <= 14:
        severity = "high"
    elif days <= 30:
        severity = "medium"
    else:
        return None

    return _make_finding(
        title=f"TLS Certificate Expires Soon ({days} day{'s' if days != 1 else ''} remaining)",
        severity=severity,
        confidence="verified-live",
        cwe="CWE-298",
        owasp="A02:2021-Cryptographic Failures",
        location=f"Certificate {hostname}:{port}",
        evidence=f"Certificate for {hostname} expires on {cert_info.get('not_after')} — {days} day(s) remaining.",
        poc=cert_poc,
        remediation="Renew the SSL/TLS certificate before it expires to avoid an unplanned outage or browser trust warnings.",
        detection_method="Certificate Analysis"
    )

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

async def _probe_ocsp_stapling(hostname: str, port: int) -> Optional[bool]:
    """Determine whether the server staples an OCSP response into the TLS
    handshake, using ``openssl s_client -status`` (the same subprocess tool
    the protocol/cipher probes below already use).

    Returns:
      * True  -- a stapled OCSP response was observed
                 ("OCSP Response Status: successful").
      * False -- the server explicitly sent none
                 ("OCSP response: no response sent").
      * None  -- the probe could not be completed or the output was
                 ambiguous (openssl missing, timeout, CDN/edge quirk).
                 None must NEVER be reported as "not stapled".

    Rationale for the rewrite: the previous implementation gated on
    ``hasattr(ssl_socket, "get_ocsp_response")``, an API that does not exist
    on CPython's ``ssl.SSLSocket``. It therefore always returned None and the
    "OCSP Stapling Not Enabled" finding fired unconditionally on every
    TLS-reachable host regardless of the server's real configuration.
    """
    out, err, timed_out = await _run_openssl(
        ["s_client", "-connect", f"{hostname}:{port}", "-status", "-servername", hostname],
        timeout=5,
    )
    if timed_out:
        return None
    combined = out + err
    if b"OCSP Response Status: successful" in combined:
        return True
    if b"OCSP response: no response sent" in combined:
        return False
    return None

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
async def _probe_protocol(hostname: str, port: int, flag: str, name: str, sem: asyncio.Semaphore) -> Tuple[str, str, bool, bool]:
    """Returns ("protocol", name, supported, completed). `completed` is False
    when the probe never finished (timeout / openssl missing) -- a distinct
    outcome from "completed and the protocol was refused" (supported=False,
    completed=True). Callers must not treat a probe that didn't complete as
    proof the protocol is unsupported."""
    async with sem:
        out, err, timed_out = await _run_openssl(["s_client", "-connect", f"{hostname}:{port}", flag, "-servername", hostname], timeout=5)
        if timed_out or b"OPENSSL_MISSING" in err:
            return ("protocol", name, False, False)
        supported = b"BEGIN CERTIFICATE" in out and b"CONNECTED" in out
        return ("protocol", name, supported, True)

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

_HEX_DUMP_LINE_RE = re.compile(r"^[0-9a-fA-F]{2}(\s+[0-9a-fA-F]{2})*$")

def _extract_server_hello_hex(openssl_msg_output: str) -> str:
    """
    Extract the raw hex bytes of the ServerHello Handshake message (including
    its 4-byte header: 1-byte msg_type + 3-byte length) from `openssl s_client
    -msg` output.

    `-msg` prints each handshake record as a header line (">>>"/"<<<" plus the
    message name) followed by plain space-separated hex byte lines with no
    offset or " - " delimiter. (The "XXXX - hex-hex...  ascii" dump format
    belongs to `-trace`'s opaque-extension dumps, not `-msg`.)
    """
    lines = openssl_msg_output.split('\n')
    in_server_hello = False
    hex_data = ""
    for line in lines:
        if "ServerHello" in line and "<<<" in line:
            in_server_hello = True
            continue
        if in_server_hello:
            stripped = line.strip()
            if stripped == "" or ">>>" in line or ("<<<" in line and "ServerHello" not in line):
                if hex_data:
                    break
                continue
            if _HEX_DUMP_LINE_RE.match(stripped):
                hex_data += stripped.replace(" ", "")
    return hex_data

def _compute_ja3s(hex_data: str) -> Optional[str]:
    """
    Compute a canonical JA3S fingerprint (md5 of "TLSVersion,Cipher,Extensions",
    all decimal, extensions dash-joined in wire order) from the raw ServerHello
    Handshake message bytes produced by `_extract_server_hello_hex`. Returns
    None if the bytes are too short or don't parse as a well-formed ServerHello.
    """
    if not hex_data or len(hex_data) < 100:
        return None
    try:
        idx = 8  # skip Handshake header (1-byte msg_type + 3-byte length)
        version = int(hex_data[idx:idx + 4], 16)
        idx += 4
        idx += 64  # skip 32-byte random
        sid_len = int(hex_data[idx:idx + 2], 16)
        idx += 2 + (sid_len * 2)
        cipher = int(hex_data[idx:idx + 4], 16)
        idx += 4
        idx += 2  # skip 1-byte compression_method
        ext_types: List[str] = []
        if idx + 4 <= len(hex_data):
            ext_len = int(hex_data[idx:idx + 4], 16)
            idx += 4
            ext_data = hex_data[idx:idx + (ext_len * 2)]
            e_idx = 0
            while e_idx + 8 <= len(ext_data):
                ext_type = int(ext_data[e_idx:e_idx + 4], 16)
                ext_len_val = int(ext_data[e_idx + 4:e_idx + 8], 16)
                ext_types.append(str(ext_type))
                e_idx += 8 + (ext_len_val * 2)
        ja3s_str = f"{version},{cipher}," + "-".join(ext_types)
        return hashlib.md5(ja3s_str.encode()).hexdigest()
    except Exception:
        return None

async def _probe_tls_fingerprints(hostname: str, port: int, sem: asyncio.Semaphore) -> Tuple[str, Optional[str], str, bool]:
    async with sem:
        out, err, timed_out = await _run_openssl(["s_client", "-connect", f"{hostname}:{port}", "-msg", "-servername", hostname, "-reconnect"], timeout=6)
        if timed_out or b"OPENSSL_MISSING" in err:
            return ("fingerprints", None, JA4S_NOT_IMPLEMENTED, False)
        combined = (out + err).decode('utf-8', errors='ignore')

        hex_data = _extract_server_hello_hex(combined)
        ja3s = _compute_ja3s(hex_data)

        resumption = "Reused, " in combined or "TLS session ticket" in combined.lower() or "Session-ID" in combined
        return ("fingerprints", ja3s, JA4S_NOT_IMPLEMENTED, resumption)

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
            else:
                expiry_finding = _build_expiry_finding(cert_info, hostname, port, cert_poc)
                if expiry_finding:
                    findings.append(expiry_finding)
                
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

    # OCSP stapling: a genuine three-state result (mirrors test_10's
    # PRESENT/ABSENT/INCONCLUSIVE pattern for the same reason -- misreading a
    # failed/ambiguous probe as a confirmed negative is a bug this project
    # has already hit, in this same file, more than once).
    #   True  -- server staples a valid response ("OCSP Response Status:
    #            successful"). No finding.
    #   False -- server explicitly sent none ("OCSP response: no response
    #            sent"). Confirmed-absent -> the "Not Enabled" finding, now
    #            with a real positive-negative observation behind it.
    #   None  -- probe did not complete or produced ambiguous output
    #            (openssl missing/timeout/edge quirk). NOT reported as "not
    #            enabled" -- reported as its own explicit inconclusive
    #            finding instead, confidence "informational" (reserved for
    #            exactly this "couldn't check" case, never for a confirmed
    #            result). Previously this probe always returned None (it
    #            used a non-existent ssl.SSLSocket API) and the finding
    #            fired unconditionally on 100% of TLS-reachable hosts.
    stapled_ocsp = await _probe_ocsp_stapling(hostname, port) if openssl_available else None
    details["ocsp_stapling"] = stapled_ocsp  # True / False / None
    if stapled_ocsp is False:
        evidence_msg = "The server sent no stapled OCSP response during the TLS handshake (openssl s_client -status reported 'no response sent')."
        if ctx.waf_challenge_detected:
            evidence_msg += f" (Note: CDN/WAF detected ({ctx.waf_challenge_detected}); OCSP stapling may be managed at the edge layer.)"

        findings.append(_make_finding(
            title="OCSP Stapling Not Enabled",
            severity="low",
            confidence="verified-live",
            cwe="CWE-299",
            owasp="A02:2021-Cryptographic Failures",
            location=f"TLS Handshake {hostname}:{port}",
            evidence=evidence_msg,
            poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname} -status < /dev/null 2>/dev/null | grep -A5 'OCSP Response'",
            remediation="Enable OCSP stapling on the web server to improve performance and privacy of revocation checks.",
            detection_method="TLS Handshake OCSP Status Probe (openssl -status)",
            tier="hardening"
        ))
    elif stapled_ocsp is None and openssl_available:
        findings.append(_make_finding(
            title="OCSP Stapling Status Could Not Be Determined",
            severity="info",
            confidence="informational",
            cwe="",
            owasp="",
            location=f"TLS Handshake {hostname}:{port}",
            evidence=(
                "The openssl -status probe did not complete or produced ambiguous output "
                "(timeout, subprocess contention, or an edge/CDN quirk). This is NOT evidence "
                "that OCSP stapling is disabled -- only that it could not be confirmed either "
                "way from here."
            ),
            poc=f"openssl s_client -connect {hostname}:{port} -servername {hostname} -status < /dev/null 2>/dev/null | grep -A5 'OCSP Response'",
            remediation="Re-run this check; if it consistently fails, verify the scanner's outbound path or re-run with lower concurrency.",
            detection_method="TLS Handshake OCSP Status Probe (inconclusive)",
            tier="hardening"
        ))

    # Certificate Transparency: the only working signal here is the count of
    # SCTs embedded in the certificate itself (parsed via `cryptography` in
    # _analyze_cert). The former TLS-extension SCT probe used a non-existent
    # ssl.SSLSocket API and always returned 0, so removing it changes no
    # observed behaviour.
    total_scts = cert_info.get("cert_scts", 0) if cert_info else 0
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
        protocol_probe_completed: Dict[str, bool] = {}
        for res in results:
            if res[0] == "protocol":
                name, supported = res[1], res[2]
                tls_versions[name] = supported
                protocol_probe_completed[name] = res[3] if len(res) > 3 else True
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
                        title="TLS Server Fingerprint (JA3S)",
                        severity="info",
                        confidence="verified-live",
                        cwe="",
                        owasp="",
                        location=f"TLS Handshake {hostname}:{port}",
                        evidence=f"JA3S: {ja3s}\nJA4S: not implemented by this scout (see 'ja4s' in scan details).",
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
        if (tls_versions.get("TLSv1.3")
                and not any(tls_versions.get(v) for v in ["TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3", "SSLv2"])
                and all(protocol_probe_completed.get(v, False) for v in ["TLSv1.2", "TLSv1.1", "TLSv1.0"])):
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
            # A probe that never completed (timeout / subprocess contention) is
            # NOT proof the protocol is unsupported. Only claim "no modern TLS"
            # when BOTH the TLS 1.2 AND the TLS 1.3 probe actually ran to
            # completion and the server refused each -- an `or` here is not
            # enough: a TLS-1.3-only server (the *best* configuration) whose
            # 1.2 probe completes with a genuine refusal but whose 1.3 probe
            # times out under load would otherwise satisfy the `or` and fire
            # this critical exactly backwards, on a server whose real TLS 1.3
            # status was never confirmed either way. Otherwise this is an
            # environment/probe failure -- and note that Step 2 above already
            # fetched the certificate over a default-context (TLS 1.2+ minimum)
            # handshake, so the server demonstrably DOES negotiate modern TLS.
            # Live-confirmed false positive: vkuseraudio.net (supports TLS 1.2
            # AND 1.3, verified independently with openssl s_client) was reported
            # critical "No Modern TLS Versions Supported" under evaluation-batch
            # load when all six concurrent openssl protocol probes timed out.
            modern_probe_completed = (
                protocol_probe_completed.get("TLSv1.2", False)
                and protocol_probe_completed.get("TLSv1.3", False)
            )
            if modern_probe_completed:
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
            else:
                findings.append(_make_finding(
                    title="TLS protocol enumeration inconclusive (openssl probes did not complete)",
                    severity="info",
                    confidence="informational",
                    cwe="",
                    owasp="",
                    location=f"TLS Protocols {hostname}:{port}",
                    evidence=(
                        "None of the openssl protocol probes completed (timeout or subprocess "
                        "contention), so supported TLS versions could not be enumerated. This is "
                        "NOT a finding of weak TLS: the certificate was successfully retrieved "
                        "earlier over a modern-TLS (1.2+) handshake, so the server does negotiate "
                        "modern TLS. Re-run with less concurrent load for a full protocol matrix."
                    ),
                    poc=f"openssl s_client -connect {hostname}:{port} -tls1_2 -servername {hostname}",
                    remediation="Re-run the TLS scan with lower concurrency to enumerate the full protocol/cipher matrix.",
                    detection_method="Protocol Probing (inconclusive)"
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
                detection_method="DNS Query",
                tier="hardening"
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

# ────────────────────────────────────────────── Standalone Testing ──────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(description="Bravo6 TLS/SSL Assessment Scout")
    parser.add_argument("url", nargs="?", default="https://example.com", help="Target URL")
    parser.add_argument("--test", action="store_true", help="Run Scout Regression Tests")
    args = parser.parse_args()

    if args.test:
        import unittest

        class TestCertExpiryFinding(unittest.TestCase):
            """Regression tests for the certificate near-expiry finding (days_until_expiry)."""

            def _cert_info(self, days: int) -> Dict[str, Any]:
                return {"days_until_expiry": days, "not_after": "2026-09-17T00:00:00+00:00"}

            def test_expires_in_3_days_is_critical(self):
                finding = _build_expiry_finding(self._cert_info(3), "example.com", 443, "openssl s_client ...")
                self.assertIsNotNone(finding, "Expected a finding for a certificate expiring in 3 days.")
                self.assertEqual(finding["severity"], "critical")
                self.assertEqual(finding["confidence"], "verified-live")
                self.assertEqual(finding["cwe"], "CWE-298")
                self.assertIn("3 day", finding["evidence"])

            def test_expires_in_20_days_is_medium(self):
                finding = _build_expiry_finding(self._cert_info(20), "example.com", 443, "openssl s_client ...")
                self.assertIsNotNone(finding, "Expected a finding for a certificate expiring in 20 days.")
                self.assertEqual(finding["severity"], "medium")

            def test_expires_in_200_days_no_finding(self):
                finding = _build_expiry_finding(self._cert_info(200), "example.com", 443, "openssl s_client ...")
                self.assertIsNone(finding, "A certificate valid for 200 more days should not raise a finding.")

            def test_missing_certificate_data_skips_cleanly(self):
                self.assertIsNone(_build_expiry_finding({}, "example.com", 443, "openssl s_client ..."))
                self.assertIsNone(_build_expiry_finding(None, "example.com", 443, "openssl s_client ..."))

            def test_already_expired_is_not_double_reported(self):
                # Negative days are owned by the separate "TLS Certificate Expired" finding.
                self.assertIsNone(_build_expiry_finding(self._cert_info(-5), "example.com", 443, "openssl s_client ..."))

        class TestJa3sFingerprint(unittest.TestCase):
            """
            Regression tests for JA3S extraction/computation. Previously ja3s/ja4s
            were always None: the parser looked for `-trace`'s "XXXX - hex...ascii"
            dump format, but the code actually shells out to `openssl s_client -msg`,
            which prints plain space-separated hex with no such delimiter, so
            hex_data was always empty. It also parsed fields starting at byte offset
            0 instead of skipping the 4-byte Handshake header, which would have
            produced a wrong (not merely missing) fingerprint even if hex_data had
            been non-empty.
            """

            def _build_synthetic_msg_output(self):
                # Minimal well-formed ServerHello: legacy_version=0x0303, empty
                # session_id, cipher=TLS_AES_128_GCM_SHA256 (0x1301), compression=0,
                # one extension: supported_versions (0x002b) -> TLS1.3 (0x0304).
                body = (
                    bytes.fromhex("0303")
                    + bytes(32)
                    + bytes.fromhex("00")
                    + bytes.fromhex("1301")
                    + bytes.fromhex("00")
                    + bytes.fromhex("0006")
                    + bytes.fromhex("002b00020304")
                )
                handshake = bytes([0x02]) + len(body).to_bytes(3, "big") + body
                hexstr = handshake.hex()
                pairs = [hexstr[i:i + 2] for i in range(0, len(hexstr), 2)]
                dump_lines = ["    " + " ".join(pairs[i:i + 16]) for i in range(0, len(pairs), 16)]
                openssl_output = (
                    f"<<< TLS 1.3, Handshake [length {len(handshake):04x}], ServerHello\n"
                    + "\n".join(dump_lines)
                    + "\n<<< TLS 1.2, RecordHeader [length 0005]\n"
                )
                return openssl_output, hexstr

            def test_extracts_hex_from_real_msg_format(self):
                openssl_output, expected_hex = self._build_synthetic_msg_output()
                self.assertEqual(_extract_server_hello_hex(openssl_output), expected_hex)

            def test_extraction_rejects_trace_dash_format(self):
                # The old bug assumed `-trace`'s dash/offset dump style; confirm the
                # `-msg` extractor correctly does NOT match that format (and thus
                # doesn't silently misparse text that isn't actually a hex dump).
                trace_style = (
                    "<<< TLS 1.3, Handshake [length 0031], ServerHello\n"
                    "    0000 - 02 00 00 2e 03 03-00 00   ....\n"
                    "<<< TLS 1.2, RecordHeader [length 0005]\n"
                )
                self.assertEqual(_extract_server_hello_hex(trace_style), "")

            def test_ja3s_computed_correctly_from_real_format(self):
                openssl_output, _ = self._build_synthetic_msg_output()
                hex_data = _extract_server_hello_hex(openssl_output)
                ja3s = _compute_ja3s(hex_data)
                self.assertIsNotNone(ja3s, "Expected a real JA3S hash from a well-formed ServerHello.")
                # version=771 (0x0303), cipher=4865 (0x1301), extensions=[43] (0x002b)
                expected = hashlib.md5("771,4865,43".encode()).hexdigest()
                self.assertEqual(ja3s, expected, "Parsed version/cipher/extensions do not match the raw bytes.")

            def test_ja3s_none_on_short_data(self):
                self.assertIsNone(_compute_ja3s("aabbcc"))

            def test_ja3s_none_on_empty_data(self):
                self.assertIsNone(_compute_ja3s(""))

            def test_ja4s_reported_as_honest_not_implemented_marker(self):
                # ja4s must never masquerade as a real hash; it should always be the
                # explicit sentinel, distinct from both a real hash and None.
                self.assertEqual(JA4S_NOT_IMPLEMENTED, "not_implemented")

        class TestProtocolProbeTimeoutNotTreatedAsUnsupported(unittest.IsolatedAsyncioTestCase):
            """Regression test for the live-confirmed false positive on
            vkuseraudio.net: under evaluation-batch subprocess load, all six
            concurrent `openssl s_client` protocol probes timed out, and the
            scout emitted a *critical* 'No Modern TLS Versions Supported' even
            though the site negotiates both TLS 1.2 and 1.3 (verified
            independently) and the scout had *already* fetched its certificate
            over a modern-TLS handshake in the same run. `_probe_protocol` must
            distinguish 'probe did not complete' from 'protocol refused'."""

            async def test_probe_reports_not_completed_on_timeout(self):
                async def fake_run_openssl(args, timeout=5):
                    return b"", b"", True  # timed_out
                orig = globals()["_run_openssl"]
                globals()["_run_openssl"] = fake_run_openssl
                try:
                    res = await _probe_protocol("example.com", 443, "-tls1_2", "TLSv1.2", asyncio.Semaphore(1))
                finally:
                    globals()["_run_openssl"] = orig
                self.assertEqual(res[:3], ("protocol", "TLSv1.2", False))
                self.assertEqual(res[3], False, "A timed-out probe must be marked not-completed, not just unsupported.")

            async def test_probe_reports_completed_on_clean_refusal(self):
                async def fake_run_openssl(args, timeout=5):
                    return b"CONNECTED(00000003)\n140: no protocols available\n", b"", False
                orig = globals()["_run_openssl"]
                globals()["_run_openssl"] = fake_run_openssl
                try:
                    res = await _probe_protocol("example.com", 443, "-tls1_1", "TLSv1.1", asyncio.Semaphore(1))
                finally:
                    globals()["_run_openssl"] = orig
                self.assertEqual(res, ("protocol", "TLSv1.1", False, True))

        class TestOcspStaplingProbe(unittest.IsolatedAsyncioTestCase):
            """Regression tests for _probe_ocsp_stapling. The previous
            implementation gated on ssl.SSLSocket.get_ocsp_response -- an API
            that does not exist on CPython -- so it always returned None and
            the "OCSP Stapling Not Enabled" finding fired on 100% of
            TLS-reachable hosts. The rewrite shells `openssl s_client -status`
            and returns a genuine tri-state (True/False/None); only False may
            produce the finding."""

            def _with_openssl(self, fake):
                orig = globals()["_run_openssl"]
                globals()["_run_openssl"] = fake
                self.addCleanup(lambda: globals().__setitem__("_run_openssl", orig))

            async def test_stapled_response_returns_true(self):
                async def fake(args, timeout=5):
                    self.assertIn("-status", args)
                    return (b"CONNECTED(00000003)\nOCSP Response Status: successful (0x0)\n"
                            b"OCSP Response Data:\n"), b"", False
                self._with_openssl(fake)
                self.assertIs(await _probe_ocsp_stapling("example.com", 443), True)

            async def test_no_response_sent_returns_false(self):
                async def fake(args, timeout=5):
                    return b"CONNECTED(00000003)\nOCSP response: no response sent\n", b"", False
                self._with_openssl(fake)
                self.assertIs(await _probe_ocsp_stapling("example.com", 443), False)

            async def test_timeout_returns_none_not_false(self):
                async def fake(args, timeout=5):
                    return b"", b"", True
                self._with_openssl(fake)
                result = await _probe_ocsp_stapling("example.com", 443)
                self.assertIsNone(result, "A timed-out probe must be 'unknown', never 'not stapled'.")

            async def test_ambiguous_output_returns_none(self):
                async def fake(args, timeout=5):
                    return b"CONNECTED(00000003)\n(nothing about OCSP here)\n", b"", False
                self._with_openssl(fake)
                self.assertIsNone(await _probe_ocsp_stapling("example.com", 443))

        class TestModernProbeCompletedRequiresBothProbes(unittest.IsolatedAsyncioTestCase):
            """Regression test for the guard-tightening: `modern_probe_completed`
            must require BOTH the TLS 1.2 AND the TLS 1.3 probe to have actually
            completed before 'No Modern TLS Versions Supported' can be claimed.

            Scenario closed here: the TLS 1.2 probe completes with a genuine
            refusal (supported=False, completed=True) while the TLS 1.3 probe
            times out (completed=False) -- a TLS-1.3-only server under load. The
            old `or` guard fired the *critical* here, exactly backwards. The
            scout must instead emit the 'TLS protocol enumeration inconclusive'
            info finding, same as the fully-timed-out case."""

            def _install(self, mapping):
                self._saved = {k: globals()[k] for k in mapping}
                globals().update(mapping)
                self.addCleanup(lambda: globals().update(self._saved))

            async def _run_scout(self):
                async def fake_check_binary(cmd, arg):
                    return cmd == "openssl"

                async def fake_run_openssl(args, timeout=5):
                    # TLS 1.2 probe: completes, server cleanly refuses (no cert).
                    if "-tls1_2" in args:
                        return b"CONNECTED(00000003)\nno peer certificate available\n", b"", False
                    # TLS 1.3 probe (and everything else): times out under load.
                    return b"", b"", True

                _cert = {
                    "days_until_expiry": 200, "not_after": "2030-01-01T00:00:00+00:00",
                    "hostname_match": True, "self_signed": False, "weak_signature": False,
                    "key_size": 2048, "key_type": "rsa", "cert_scts": 2,
                }
                self._install({
                    "_check_internal": lambda hostname: False,
                    "_check_binary": fake_check_binary,
                    "_run_openssl": fake_run_openssl,
                    "_get_cert_der": lambda hostname, port: b"dummy-der",
                    "_analyze_cert": lambda der, hostname: dict(_cert),
                    "_verify_chain_via_ssl_connect": lambda hostname, port: (None, None),
                })

                ctx = ScannerContext(
                    url="https://tls13-only.example",
                    session=None,
                    config={},
                    page_is_representative=True,
                    waf_challenge_detected=None,
                    sensitive_paths=[],
                    main_page_cache={},
                )
                return await run(ctx)

            async def test_tls12_refused_tls13_timed_out_is_inconclusive_not_critical(self):
                result = await self._run_scout()
                titles = [f["title"] for f in result["findings"]]

                self.assertNotIn(
                    "No Modern TLS Versions Supported", titles,
                    "A timed-out TLS 1.3 probe must NOT let the critical fire -- the "
                    "server's real TLS 1.3 status was never confirmed."
                )
                inconclusive = [f for f in result["findings"]
                                if f["title"].startswith("TLS protocol enumeration inconclusive")]
                self.assertEqual(len(inconclusive), 1, titles)
                self.assertEqual(inconclusive[0]["severity"], "info")
                self.assertEqual(inconclusive[0]["confidence"], "informational")

        class TestDefenseInDepthFindingsAreHardeningTier(unittest.IsolatedAsyncioTestCase):
            """Regression test for the tier fix: 'OCSP Stapling Not Enabled' and
            'Missing DNS CAA Record' are defense-in-depth absences (they only
            matter if something else is also compromised), so they MUST carry
            raw_data["tier"] == "hardening" -- landing them in the orchestrator's
            pooled/capped tier2 bucket, same as test_05's missing-header findings,
            not the uncapped "baseline" pool. Previously both fell through
            untagged and were scored as baseline."""

            def _install(self, mapping):
                self._saved = {k: globals()[k] for k in mapping}
                globals().update(mapping)
                self.addCleanup(lambda: globals().update(self._saved))

            async def _run_scout(self):
                async def fake_check_binary(cmd, arg):
                    return cmd in ("openssl", "dig")

                async def fake_run_openssl(args, timeout=5):
                    # The `-status` probe reports the server sent no stapled
                    # OCSP response, so the OCSP-stapling finding must fire.
                    if "-status" in args:
                        return (b"CONNECTED(00000003)\nOCSP response: no response sent\n"
                                b"no peer certificate available\n"), b"", False
                    # Every protocol probe completes with a clean refusal --
                    # keeps this test focused on the two DNS/OCSP findings.
                    return b"CONNECTED(00000003)\nno peer certificate available\n", b"", False

                async def fake_check_dns_record(hostname, record_type):
                    return None  # no CAA, no TLSA

                _cert = {
                    "days_until_expiry": 200, "not_after": "2030-01-01T00:00:00+00:00",
                    "hostname_match": True, "self_signed": False, "weak_signature": False,
                    "key_size": 2048, "key_type": "rsa", "cert_scts": 2,
                }
                self._install({
                    "_check_internal": lambda hostname: False,
                    "_check_binary": fake_check_binary,
                    "_run_openssl": fake_run_openssl,
                    "_check_dns_record": fake_check_dns_record,
                    "_get_cert_der": lambda hostname, port: b"dummy-der",
                    "_analyze_cert": lambda der, hostname: dict(_cert),
                    "_verify_chain_via_ssl_connect": lambda hostname, port: (None, None),
                })

                ctx = ScannerContext(
                    url="https://no-caa-no-ocsp.example",
                    session=None,
                    config={},
                    page_is_representative=True,
                    waf_challenge_detected=None,
                    sensitive_paths=[],
                    main_page_cache={},
                )
                return await run(ctx)

            def _tier_of(self, finding):
                return (finding.get("tier")
                        or finding.get("raw_data", {}).get("tier", ""))

            async def test_ocsp_and_caa_absence_are_tier_hardening(self):
                result = await self._run_scout()
                by_title = {f["title"]: f for f in result["findings"]}

                self.assertIn("OCSP Stapling Not Enabled", by_title,
                              "Expected the OCSP-stapling-absent finding to fire.")
                self.assertIn("Missing DNS CAA Record", by_title,
                              "Expected the CAA-absent finding to fire.")

                self.assertEqual(self._tier_of(by_title["OCSP Stapling Not Enabled"]), "hardening")
                self.assertEqual(self._tier_of(by_title["Missing DNS CAA Record"]), "hardening")

            async def test_confirmed_absent_ocsp_is_no_longer_informational(self):
                # The confirmed-absent case is now a real positive-negative
                # observation (a completed openssl -status probe explicitly
                # reporting "no response sent"), not a "couldn't check"
                # default -- confidence must reflect that.
                result = await self._run_scout()
                finding = next(f for f in result["findings"] if f["title"] == "OCSP Stapling Not Enabled")
                self.assertEqual(finding["confidence"], "verified-live")
                self.assertNotEqual(finding["confidence"], "informational")

            def test_make_finding_untagged_by_default(self):
                # The untagged path is unchanged: no tier arg -> no raw_data key.
                f = _make_finding(
                    title="x", severity="high", confidence="verified-live", cwe="",
                    owasp="", location="", evidence="", poc="", remediation="",
                    detection_method="",
                )
                self.assertNotIn("raw_data", f)

        class TestOcspStaplingRunLevelThreeStates(unittest.IsolatedAsyncioTestCase):
            """run()-level regression covering all three OCSP outcomes end to
            end: stapled -> no finding; confirmed-absent -> the "Not Enabled"
            finding (verified-live, hardening); probe inconclusive -> a
            distinct, separately-titled finding (informational, hardening),
            never conflated with a confirmed-absent result."""

            def _install(self, mapping):
                saved = {k: globals()[k] for k in mapping}
                globals().update(mapping)
                self.addCleanup(lambda: globals().update(saved))

            async def _run_scout(self, ocsp_openssl_output: bytes):
                async def fake_check_binary(cmd, arg):
                    return cmd in ("openssl", "dig")

                async def fake_run_openssl(args, timeout=5):
                    if "-status" in args:
                        return ocsp_openssl_output, b"", False
                    return b"CONNECTED(00000003)\nno peer certificate available\n", b"", False

                async def fake_check_dns_record(hostname, record_type):
                    return "0 issue \"letsencrypt.org\""  # CAA present -> keep this test focused on OCSP

                _cert = {
                    "days_until_expiry": 200, "not_after": "2030-01-01T00:00:00+00:00",
                    "hostname_match": True, "self_signed": False, "weak_signature": False,
                    "key_size": 2048, "key_type": "rsa", "cert_scts": 2,
                }
                self._install({
                    "_check_internal": lambda hostname: False,
                    "_check_binary": fake_check_binary,
                    "_run_openssl": fake_run_openssl,
                    "_check_dns_record": fake_check_dns_record,
                    "_get_cert_der": lambda hostname, port: b"dummy-der",
                    "_analyze_cert": lambda der, hostname: dict(_cert),
                    "_verify_chain_via_ssl_connect": lambda hostname, port: (None, None),
                })
                ctx = ScannerContext(
                    url="https://ocsp-three-state.example",
                    session=None, config={}, page_is_representative=True,
                    waf_challenge_detected=None, sensitive_paths=[], main_page_cache={},
                )
                return await run(ctx)

            def _titles(self, result):
                return [f["title"] for f in result["findings"]]

            async def test_stapled_success_produces_no_ocsp_finding(self):
                result = await self._run_scout(
                    b"CONNECTED(00000003)\nOCSP Response Status: successful (0x0)\n"
                    b"Cert Status: good\nno peer certificate available\n"
                )
                titles = self._titles(result)
                self.assertNotIn("OCSP Stapling Not Enabled", titles)
                self.assertNotIn("OCSP Stapling Status Could Not Be Determined", titles)

            async def test_confirmed_no_response_produces_the_not_enabled_finding(self):
                result = await self._run_scout(
                    b"CONNECTED(00000003)\nOCSP response: no response sent\n"
                )
                by_title = {f["title"]: f for f in result["findings"]}
                self.assertIn("OCSP Stapling Not Enabled", by_title)
                f = by_title["OCSP Stapling Not Enabled"]
                self.assertEqual(f["confidence"], "verified-live")
                self.assertEqual(f["severity"], "low")
                self.assertEqual(f.get("raw_data", {}).get("tier"), "hardening")

            async def test_ambiguous_probe_output_produces_a_distinct_inconclusive_finding(self):
                result = await self._run_scout(
                    b"CONNECTED(00000003)\n(nothing about OCSP in this output)\n"
                )
                by_title = {f["title"]: f for f in result["findings"]}
                self.assertNotIn("OCSP Stapling Not Enabled", by_title,
                                  "An inconclusive probe must never be reported as confirmed-absent.")
                self.assertIn("OCSP Stapling Status Could Not Be Determined", by_title)
                f = by_title["OCSP Stapling Status Could Not Be Determined"]
                self.assertEqual(f["confidence"], "informational")
                self.assertEqual(f["severity"], "info")
                self.assertEqual(f.get("raw_data", {}).get("tier"), "hardening")

        sys.argv = [sys.argv[0]]
        unittest.main()
    else:
        import aiohttp

        async def _live_scan():
            connector = aiohttp.TCPConnector(ssl=True)
            async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": "Bravo6-Scanner/8.5"}) as session:
                try:
                    async with session.get(args.url) as resp:
                        html = await resp.text()
                        main_page_cache = {
                            "status": resp.status,
                            "html": html,
                            "headers": dict(resp.headers)
                        }
                except Exception as e:
                    main_page_cache = {"error": str(e)}

                ctx = ScannerContext(
                    url=args.url,
                    session=session,
                    config={},
                    page_is_representative=True,
                    waf_challenge_detected=None,
                    sensitive_paths=[],
                    main_page_cache=main_page_cache
                )
                result = await run(ctx)
                print(json.dumps(result, indent=2, ensure_ascii=False, default=str))

        asyncio.run(_live_scan())