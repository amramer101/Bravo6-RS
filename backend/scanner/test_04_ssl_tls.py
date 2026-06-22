"""
test_04_ssl_tls.py — SSL/TLS Vulnerability Scanner (Fully Fixed v2)

- Fixed false positives: checks negotiated cipher name, not just handshake success.
- Fixed renegotiation: skips finding silently when openssl is not installed.
- Handles TLS version compatibility gracefully.
"""

import asyncio
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import aiohttp
from cryptography import x509
from cryptography.x509.oid import NameOID

CONNECT_TIMEOUT = 15
DEFAULT_HTTPS_PORT = 443
MAX_RETRIES = 2
USER_AGENT = "Bravo6-Scanner/1.0"

INTERNAL_IP_RANGES = [
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.",
    "127.", "::1", "fc00:", "fe80:"
]

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

WEAK_CIPHER_SUITES = {
    "NULL-MD5": "NULL cipher (MD5)",
    "NULL-SHA": "NULL cipher (SHA1)",
    "RC4-MD5": "RC4-MD5",
    "RC4-SHA": "RC4-SHA",
    "DES-CBC3-SHA": "3DES-CBC-SHA",
    "DES-CBC-SHA": "DES-CBC-SHA",
    "EXP-RC4-MD5": "EXPORT (512-bit) RC4-MD5",
    "EXP-DES-CBC-SHA": "EXPORT (512-bit) DES-CBC-SHA",
    "EXP-EDH-DSS-DES-CBC-SHA": "EXPORT DH-DSS-DES",
    "EXP-EDH-RSA-DES-CBC-SHA": "EXPORT DH-RSA-DES",
}


def _normalize_target(url: str) -> tuple[str, int]:
    raw = url.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    parsed = urlparse(raw)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Invalid hostname: {url}")
    port = parsed.port or DEFAULT_HTTPS_PORT
    return hostname, port


def _is_internal_ip(hostname: str) -> bool:
    try:
        addrs = socket.getaddrinfo(hostname, None)
        for addr in addrs:
            ip = addr[4][0]
            for prefix in INTERNAL_IP_RANGES:
                if ip.startswith(prefix):
                    return True
    except:
        pass
    return False


def _parse_dn(name) -> str:
    if not name:
        return ""
    return ", ".join(f"{a.oid._name}={a.value}" for a in name)


def _get_san(cert) -> list:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except:
        return []


def _hostname_matches(hostname: str, cert) -> bool:
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


def _check_self_signed(cert) -> bool:
    return _parse_dn(cert.issuer) == _parse_dn(cert.subject)


def _is_weak_signature(cert) -> bool:
    alg = cert.signature_algorithm_oid._name.lower()
    return "sha1" in alg or "md5" in alg


def _probe_protocol(hostname: str, port: int, version: ssl.TLSVersion) -> bool:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = version
        context.maximum_version = version
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                return True
    except Exception:
        return False


def _probe_cipher_suite(hostname: str, port: int, cipher_string: str) -> bool:
    """
    Check if a specific weak cipher is actually negotiated.
    Verifies the negotiated cipher name to avoid false positives.
    """
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.set_ciphers(cipher_string)

        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                negotiated = tls_sock.cipher()
                if not negotiated:
                    return False
                # ✅ Key fix: verify the negotiated cipher IS the requested one
                negotiated_name = negotiated[0].upper()
                requested_name = cipher_string.upper()
                return requested_name in negotiated_name

    except ssl.SSLError as e:
        if "no shared cipher" in str(e).lower():
            return False
        return False
    except OSError:
        return False
    except Exception:
        return False


async def _probe_async(func, *args) -> dict:
    loop = asyncio.get_event_loop()
    for attempt in range(MAX_RETRIES):
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, func, *args),
                timeout=CONNECT_TIMEOUT + 2
            )
            return {"success": result, "error": None}
        except asyncio.TimeoutError:
            return {"success": False, "error": "timeout"}
        except Exception as e:
            if attempt == MAX_RETRIES - 1:
                return {"success": False, "error": str(e)}
    return {"success": False, "error": "max retries"}


async def _check_ssl2(hostname: str, port: int) -> dict:
    cmd = ["openssl", "s_client", "-ssl2", "-connect", f"{hostname}:{port}", "-no_ign_eof"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=CONNECT_TIMEOUT)
        output = stdout.decode() + stderr.decode()
        if "SSL handshake succeeded" in output or "CONNECTED" in output:
            if "no cipher" not in output.lower() and "protocol not available" not in output.lower():
                return {"supported": True, "error": None}
        return {"supported": False, "error": None}
    except FileNotFoundError:
        return {"supported": False, "error": "openssl not installed"}
    except Exception as e:
        return {"supported": False, "error": str(e)}


async def _check_renegotiation(hostname: str, port: int) -> dict:
    cmd = ["openssl", "s_client", "-connect", f"{hostname}:{port}", "-renegotiate"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=CONNECT_TIMEOUT)
        output = stdout.decode() + stderr.decode()
        if "Secure Renegotiation IS NOT supported" in output:
            return {"supported": False, "error": None}
        elif "Secure Renegotiation IS supported" in output:
            return {"supported": True, "error": None}
        else:
            return {"supported": None, "error": "ambiguous output"}
    except FileNotFoundError:
        return {"supported": None, "error": "openssl not installed"}
    except Exception as e:
        return {"supported": None, "error": str(e)}


async def _check_compression(hostname: str, port: int) -> dict:
    cmd = ["openssl", "s_client", "-connect", f"{hostname}:{port}", "-comp"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=CONNECT_TIMEOUT)
        output = stdout.decode() + stderr.decode()
        if "Compression: zlib" in output or "Compression: 1" in output:
            return {"supported": True}
        return {"supported": False}
    except:
        return {"supported": None}


async def run(url: str) -> dict:
    test_name = "ssl_tls"
    try:
        hostname, port = _normalize_target(url)
    except Exception as e:
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "Invalid Target",
            "description": str(e),
            "evidence": {},
            "remediation": "Check the URL format."
        }

    is_internal = _is_internal_ip(hostname)

    hsts_value = None
    async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
        try:
            async with session.get(f"https://{hostname}:{port}", ssl=False, timeout=5) as resp:
                hsts_value = resp.headers.get("Strict-Transport-Security")
        except:
            pass

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
                if not der:
                    raise ValueError("No certificate")
                cert = x509.load_der_x509_certificate(der)
                negotiated_version = tls_sock.version()
                negotiated_cipher = tls_sock.cipher()
    except Exception as e:
        return {
            "test_name": test_name,
            "status": "error",
            "severity": "info",
            "title": "TLS Handshake Failed",
            "description": str(e)[:200],
            "evidence": {},
            "remediation": "Check network and TLS configuration."
        }

    now = datetime.now(timezone.utc)
    days_until_expiry = (cert.not_valid_after_utc - now).days

    evidence = {
        "hostname": hostname,
        "port": port,
        "cert_expiry": cert.not_valid_after_utc.strftime("%Y-%m-%d"),
        "days_until_expiry": days_until_expiry,
        "issuer": _parse_dn(cert.issuer),
        "subject": _parse_dn(cert.subject),
        "san": _get_san(cert),
        "hostname_match": _hostname_matches(hostname, cert),
        "self_signed": _check_self_signed(cert),
        "weak_signature": _is_weak_signature(cert),
        "negotiated_version": negotiated_version,
        "negotiated_cipher": negotiated_cipher[0] if negotiated_cipher else None,
        "hsts": hsts_value,
        "is_internal": is_internal,
        "weak_protocols": {},
        "weak_ciphers": {},
        "poc_commands": []
    }

    findings = []

    # Certificate checks
    if days_until_expiry < 0:
        findings.append(("fail", "critical", "Certificate expired",
                         f"Certificate expired on {cert.not_valid_after_utc.strftime('%Y-%m-%d')}.", None))
    elif days_until_expiry < 7:
        findings.append(("fail", "high", f"Certificate expires in {days_until_expiry} days",
                         "Renew immediately.", None))
    elif days_until_expiry < 30:
        findings.append(("warning", "medium", f"Certificate expires in {days_until_expiry} days",
                         "Renew soon.", None))

    if not evidence["hostname_match"] and not is_internal:
        findings.append(("fail", "critical", "Hostname mismatch",
                         "Certificate does not match the requested hostname.", None))
    elif not evidence["hostname_match"] and is_internal:
        findings.append(("warning", "low", "Hostname mismatch (internal)",
                         "Internal IP with certificate mismatch.", None))

    if evidence["self_signed"] and not is_internal:
        findings.append(("fail", "high", "Self-signed certificate",
                         "Public-facing server using self-signed cert.", None))
    elif evidence["self_signed"] and is_internal:
        findings.append(("warning", "low", "Self-signed certificate (internal)",
                         "Internal server using self-signed cert.", None))

    if evidence["weak_signature"]:
        findings.append(("fail", "high", "Weak signature algorithm (SHA-1/MD5)",
                         "Certificate uses weak hash algorithm.", None))

    # Protocol probing
    ssl2_result = await _check_ssl2(hostname, port)
    if ssl2_result.get("supported"):
        evidence["weak_protocols"]["SSLv2"] = True
        findings.append(("fail", "critical", "SSLv2 supported (DROWN)",
                         "SSLv2 is obsolete and allows DROWN attack.",
                         f"openssl s_client -ssl2 -connect {hostname}:{port}"))
    else:
        evidence["weak_protocols"]["SSLv2"] = False

    sslv3 = await _probe_async(_probe_protocol, hostname, port, ssl.TLSVersion.SSLv3)
    if sslv3["success"]:
        evidence["weak_protocols"]["SSLv3"] = True
        findings.append(("fail", "critical", "SSLv3 supported (POODLE)",
                         "SSLv3 is vulnerable to POODLE attack.",
                         f"openssl s_client -ssl3 -connect {hostname}:{port}"))
    else:
        evidence["weak_protocols"]["SSLv3"] = False

    tls10 = await _probe_async(_probe_protocol, hostname, port, ssl.TLSVersion.TLSv1)
    if tls10["success"]:
        evidence["weak_protocols"]["TLSv1.0"] = True
        findings.append(("warning", "high", "TLS 1.0 supported",
                         "TLS 1.0 is deprecated and vulnerable to BEAST.",
                         f"openssl s_client -tls1 -connect {hostname}:{port}"))
    else:
        evidence["weak_protocols"]["TLSv1.0"] = False

    tls11 = await _probe_async(_probe_protocol, hostname, port, ssl.TLSVersion.TLSv1_1)
    if tls11["success"]:
        evidence["weak_protocols"]["TLSv1.1"] = True
        findings.append(("warning", "high", "TLS 1.1 supported",
                         "TLS 1.1 is deprecated.",
                         f"openssl s_client -tls1_1 -connect {hostname}:{port}"))
    else:
        evidence["weak_protocols"]["TLSv1.1"] = False

    # Weak cipher probing (fixed)
    for cipher_string, description in WEAK_CIPHER_SUITES.items():
        result = await _probe_async(_probe_cipher_suite, hostname, port, cipher_string)
        if result["success"]:
            evidence["weak_ciphers"][cipher_string] = True
            if "NULL" in cipher_string or "EXPORT" in cipher_string:
                severity = "critical"
                risk = f"EXPORT/NULL cipher is critically weak (FREAK/no encryption)."
            elif "RC4" in cipher_string:
                severity = "high"
                risk = "RC4 is broken and allows plaintext recovery."
            elif "3DES" in cipher_string or "DES" in cipher_string:
                severity = "medium"
                risk = "3DES/DES is weak (Sweet32 attack)."
            else:
                severity = "medium"
                risk = f"Weak cipher: {description}."

            findings.append(("fail", severity, f"Weak cipher accepted: {description}",
                             risk,
                             f"openssl s_client -cipher {cipher_string} -connect {hostname}:{port} -tls1_2"))
        else:
            evidence["weak_ciphers"][cipher_string] = False

    # TLS Compression
    compress_result = await _check_compression(hostname, port)
    if compress_result.get("supported") is True:
        findings.append(("fail", "high", "TLS Compression supported (CRIME)",
                         "TLS compression enables CRIME attack against HTTPS.",
                         f"openssl s_client -comp -connect {hostname}:{port}"))
        evidence["tls_compression"] = True
    else:
        evidence["tls_compression"] = False

    # ✅ Renegotiation (fixed: skip silently if openssl not installed)
    reneg_result = await _check_renegotiation(hostname, port)
    if reneg_result.get("supported") is False:
        findings.append(("warning", "medium", "Insecure Renegotiation possible",
                         "Server does not support secure renegotiation.",
                         f"openssl s_client -connect {hostname}:{port} -renegotiate"))
    elif reneg_result.get("supported") is None and reneg_result.get("error"):
        error_msg = reneg_result.get("error", "")
        # ✅ Fix: skip silently if openssl is not available
        if "not installed" not in error_msg and "not found" not in error_msg:
            findings.append(("info", "info", "Renegotiation check inconclusive",
                             "Could not determine renegotiation status. Manual check recommended.",
                             f"openssl s_client -connect {hostname}:{port} -renegotiate"))

    # HSTS
    if not hsts_value and not is_internal:
        findings.append(("warning", "medium", "HSTS header missing",
                         "No HSTS header. SSL-stripping attacks possible.", None))

    # Compute overall status
    worst_sev = "info"
    for _, sev, _, _, _ in findings:
        if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(worst_sev, 0):
            worst_sev = sev

    if any(SEVERITY_RANK.get(sev, 0) >= 3 for _, sev, _, _, _ in findings):
        status = "fail"
    elif any(SEVERITY_RANK.get(sev, 0) >= 1 for _, sev, _, _, _ in findings):
        status = "warning"
    else:
        status = "pass"

    # Build remediation
    remediation_steps = []
    if days_until_expiry < 30:
        remediation_steps.append("Renew certificate immediately.")
    if not evidence["hostname_match"] and not is_internal:
        remediation_steps.append("Get a certificate with correct SAN/CN.")
    if evidence["self_signed"] and not is_internal:
        remediation_steps.append("Replace self-signed certificate with a trusted CA certificate.")
    if evidence["weak_signature"]:
        remediation_steps.append("Re-issue certificate with SHA-256 signature.")
    if evidence["weak_protocols"].get("SSLv2"):
        remediation_steps.append("Disable SSLv2 immediately.")
    if evidence["weak_protocols"].get("SSLv3"):
        remediation_steps.append("Disable SSLv3.")
    if evidence["weak_protocols"].get("TLSv1.0"):
        remediation_steps.append("Disable TLS 1.0.")
    if evidence["weak_protocols"].get("TLSv1.1"):
        remediation_steps.append("Disable TLS 1.1.")
    if any(v for v in evidence["weak_ciphers"].values()):
        weak = [k for k, v in evidence["weak_ciphers"].items() if v]
        remediation_steps.append(f"Remove weak ciphers: {', '.join(weak)}.")
    if evidence.get("tls_compression"):
        remediation_steps.append("Disable TLS compression.")
    if not hsts_value and not is_internal:
        remediation_steps.append("Add HSTS header: max-age=63072000; includeSubDomains; preload.")
    if not remediation_steps:
        remediation_steps.append("No immediate action required.")

    # Build findings list
    findings_list = []
    for status_f, sev, title, desc, poc in findings:
        findings_list.append({
            "test_name": test_name,
            "status": status_f,
            "severity": sev,
            "title": title,
            "description": desc,
            "evidence": {"poc": poc} if poc else {}
        })

    return {
        "test_name": test_name,
        "status": status,
        "severity": worst_sev,
        "title": f"SSL/TLS scan: {len(findings)} issues found",
        "description": f"Found {len(findings)} SSL/TLS issues for {hostname}.",
        "evidence": evidence,
        "remediation": " ".join(remediation_steps),
        "findings": findings_list,
    }


if __name__ == "__main__":
    if len(sys.argv) > 1:
        result = asyncio.run(run(sys.argv[1]))
        print(f"Status: {result['status']} | Severity: {result['severity']}")
        print(f"Title: {result['title']}")
        for f in result.get("findings", []):
            print(f"  [{f['status']}] {f['title']} ({f['severity']})")
    else:
        print("Usage: python test_04_ssl_tls.py <url>")