"""
Bravo6 Security Scanner - SSL/TLS Configuration Module

Analyzes a target's SSL/TLS configuration:
  - Certificate validity (expiry)
  - Certificate chain trust (self-signed) and hostname match
  - Supported TLS protocol versions (looks for legacy/weak protocols)
  - Negotiated cipher suite strength

Built on ssl + socket + cryptography (for X.509 parsing, since
ssl.SSLSocket.getpeercert()'s dict form is only populated when certificate
verification is enabled -- and we deliberately disable it here so invalid/
self-signed/expired certs can be inspected and reported on rather than
causing the handshake to fail outright). Driven via asyncio executor since
these are blocking calls with no native asyncio equivalent.
"""

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from cryptography import x509
from cryptography.x509.oid import NameOID

USER_AGENT = "Bravo6-Scanner/1.0"  # unused here: this module speaks raw TLS, not HTTP, so there's no request to attach a header to. Kept for consistency with the other scanner modules' shared constants.
CONNECT_TIMEOUT = 10
DEFAULT_HTTPS_PORT = 443

# Cipher substrings that indicate weak/broken crypto, mapped to severity.
# Checked against the OpenSSL cipher name returned by the socket.
NULL_CIPHER_MARKERS = ("NULL",)
RC4_MARKERS = ("RC4",)
DES_MARKERS = ("3DES", "DES-CBC", "-DES-")
SHA1_MARKERS = ("-SHA", "SHA1")  # note: "-SHA" alone (not SHA256/SHA384) signals SHA1 MAC


def _normalize_target(url: str) -> tuple[str, int]:
    """Normalize input into (hostname, port). Adds https:// if no scheme present."""
    raw = url.strip()
    if "://" not in raw:
        raw = "https://" + raw

    parsed = urlparse(raw)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Could not parse hostname from input: {url!r}")

    port = parsed.port or DEFAULT_HTTPS_PORT
    return hostname, port


def _make_result(
    status: str,
    severity: str,
    title: str,
    description: str,
    evidence: dict,
    remediation: str,
) -> dict:
    return {
        "test_name": "ssl_tls",
        "status": status,
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
    }


def _error_result(reason: str, hostname: str = "", evidence_extra: dict | None = None) -> dict:
    evidence = {
        "cert_expiry": None,
        "tls_version": None,
        "issuer": None,
        "subject": None,
    }
    if evidence_extra:
        evidence.update(evidence_extra)
    return _make_result(
        status="error",
        severity="info",
        title="SSL/TLS scan could not complete",
        description=f"The scanner could not complete TLS analysis for {hostname or 'the target'}: {reason}",
        evidence=evidence,
        remediation="Verify the target is reachable on the expected port and accepts TLS connections, then re-run the scan.",
    )


def _parse_dn_from_name(name: "x509.Name") -> str:
    """Flatten a cryptography x509.Name into a 'k=v,k=v' string."""
    if name is None:
        return ""
    parts = []
    for attr in name:
        parts.append(f"{attr.oid._name}={attr.value}")
    return ", ".join(parts)


def _get_common_name_from_name(name: "x509.Name") -> str | None:
    if name is None:
        return None
    cns = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return cns[0].value if cns else None


def _get_san_dns_names_from_cert(cert: "x509.Certificate") -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return []


def _hostname_matches(hostname: str, cert: "x509.Certificate") -> bool:
    """Wildcard-aware hostname match against SAN (falling back to CN)."""
    san_names = _get_san_dns_names_from_cert(cert)
    cn = _get_common_name_from_name(cert.subject)
    candidates = san_names or ([cn] if cn else [])

    hostname_lower = hostname.lower()
    for candidate in candidates:
        if not candidate:
            continue
        candidate_lower = candidate.lower()
        if candidate_lower == hostname_lower:
            return True
        if candidate_lower.startswith("*."):
            suffix = candidate_lower[1:]  # ".example.com"
            if hostname_lower.endswith(suffix) and hostname_lower.count(".") == candidate_lower.count("."):
                return True
    return False


def _fetch_cert_and_session(hostname: str, port: int, min_version=None, max_version=None):
    """
    Blocking call: connect via TLS, return (cert, negotiated_version, negotiated_cipher).

    cert is a cryptography.x509.Certificate (parsed manually from DER bytes,
    since ssl.SSLSocket.getpeercert() only returns the parsed dict form when
    verify_mode != CERT_NONE -- and we deliberately disable verification so we
    can inspect and report on invalid/self-signed/expired certs ourselves
    rather than having the handshake fail outright).

    Raises on failure (timeout, refused, handshake failure, cert error).
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    if min_version is not None:
        context.minimum_version = min_version
    if max_version is not None:
        context.maximum_version = max_version

    with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            der_cert = tls_sock.getpeercert(binary_form=True)
            negotiated_version = tls_sock.version()
            negotiated_cipher = tls_sock.cipher()  # (name, protocol, secret_bits)

            if not der_cert:
                return None, negotiated_version, negotiated_cipher

            cert = x509.load_der_x509_certificate(der_cert)
            return cert, negotiated_version, negotiated_cipher


def _probe_protocol_support(hostname: str, port: int, version) -> bool:
    """
    Attempt a handshake pinned to a single TLS version to see if the server
    will negotiate it. Returns True if supported, False if rejected/unsupported.
    """
    import warnings

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with warnings.catch_warnings():
            # Python deprecates the legacy TLSVersion enum members themselves
            # (since they represent protocols nobody should use) -- but probing
            # for their presence is exactly this scanner's job, so suppress.
            warnings.simplefilter("ignore", DeprecationWarning)
            context.minimum_version = version
            context.maximum_version = version
    except (ValueError, AttributeError):
        # This Python/OpenSSL build doesn't expose this version at all -> can't probe it.
        raise RuntimeError("version_not_supported_by_client")

    try:
        with socket.create_connection((hostname, port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return True
    except ssl.SSLError:
        return False
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def _check_self_signed(cert: "x509.Certificate") -> bool:
    issuer = _parse_dn_from_name(cert.issuer)
    subject = _parse_dn_from_name(cert.subject)
    return bool(issuer) and issuer == subject


def _classify_cipher(cipher_name: str) -> tuple[str | None, str | None]:
    """
    Returns (issue_label, severity) for the worst issue found in the cipher name,
    or (None, None) if the cipher looks fine.
    """
    upper = cipher_name.upper()
    if any(marker in upper for marker in NULL_CIPHER_MARKERS):
        return "NULL cipher (no encryption)", "critical"
    if any(marker in upper for marker in RC4_MARKERS):
        return "RC4 (broken stream cipher)", "critical"
    if any(marker in upper for marker in DES_MARKERS):
        return "DES/3DES (weak block cipher)", "high"
    if any(marker in upper for marker in SHA1_MARKERS) and "SHA256" not in upper and "SHA384" not in upper:
        return "SHA1-based MAC (weak hash)", "medium"
    return None, None


async def _analyze(hostname: str, port: int, cert, negotiated_version: str, negotiated_cipher, _bounded) -> dict:
    """
    Runs the remaining analysis given an already-established connection's
    cert/version/cipher. Performs additional protocol-downgrade probes,
    each individually time-bounded via the `_bounded` executor helper
    passed in from `run()`.
    """
    # --- Step 2: certificate expiry ---
    days_until_expiry = None
    expiry_issue = None  # (status, severity, title) if a problem is found
    try:
        not_after_dt = cert.not_valid_after_utc
        not_before_dt = cert.not_valid_before_utc
        now = datetime.now(timezone.utc)
        days_until_expiry = (not_after_dt - now).days
        cert_expiry_str = not_after_dt.strftime("%b %d %H:%M:%S %Y UTC")
        cert_not_before_str = not_before_dt.strftime("%b %d %H:%M:%S %Y UTC")
        if days_until_expiry < 0:
            expiry_issue = ("fail", "critical", "Certificate has expired")
        elif days_until_expiry < 30:
            expiry_issue = ("fail", "high", f"Certificate expires in {days_until_expiry} day(s)")
        elif days_until_expiry < 90:
            expiry_issue = ("warning", "medium", f"Certificate expires in {days_until_expiry} day(s)")
    except Exception:
        cert_expiry_str = "unknown"
        cert_not_before_str = None
        days_until_expiry = None  # couldn't parse; don't fail the scan over it

    # --- Step 3: chain trust (self-signed) + hostname match ---
    is_self_signed = _check_self_signed(cert)
    hostname_ok = _hostname_matches(hostname, cert)
    subject_cn = _get_common_name_from_name(cert.subject)
    san_names = _get_san_dns_names_from_cert(cert)

    chain_issue = None
    if not hostname_ok:
        chain_issue = ("fail", "critical", "Certificate does not match hostname")
    elif is_self_signed:
        chain_issue = ("fail", "high", "Certificate is self-signed")

    # --- Step 4: protocol version probing ---
    protocol_findings = {}
    protocol_issue = None  # worst protocol issue found

    probe_matrix = [
        ("SSLv3", getattr(ssl.TLSVersion, "SSLv3", None), "critical"),
        ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None), "high"),
        ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None), "medium"),
    ]

    for label, version_enum, severity in probe_matrix:
        if version_enum is None:
            protocol_findings[label] = "not probeable (unsupported by client library)"
            continue
        try:
            supported = await _bounded(_probe_protocol_support, hostname, port, version_enum)
        except asyncio.TimeoutError:
            protocol_findings[label] = f"probe timed out after {CONNECT_TIMEOUT}s (treated as not supported)"
            continue
        except RuntimeError:
            protocol_findings[label] = "not probeable (disabled in client OpenSSL build)"
            continue
        except Exception:
            protocol_findings[label] = "probe failed"
            continue

        if supported:
            protocol_findings[label] = "supported (weak)"
            if protocol_issue is None or severity == "critical":
                protocol_issue = (severity, f"Server supports legacy protocol {label}")
                if severity == "critical":
                    break  # nothing worse than critical
        else:
            protocol_findings[label] = "not supported"

    # Determine overall protocol posture from the negotiated default-handshake version
    # if no legacy protocol issue was found.
    protocol_findings["negotiated_default"] = negotiated_version or "unknown"

    # --- Step 5: cipher suite check (negotiated cipher) + cert signature algorithm check ---
    severity_rank = {"info": 0, "low": 1, "medium": 2, "warning": 2, "high": 3, "critical": 4}

    def severity_rank_lookup(sev: str) -> int:
        return severity_rank.get(sev, 0)

    cipher_issue = None
    cipher_name = negotiated_cipher[0] if negotiated_cipher else "unknown"
    cipher_label, cipher_severity = _classify_cipher(cipher_name)
    if cipher_label:
        cipher_issue = (cipher_severity, f"Negotiated cipher uses {cipher_label}: {cipher_name}")

    # The certificate's own signature hash algorithm is a separate concern from
    # the negotiated cipher suite -- a SHA1-signed cert is weak (collision risk
    # for the CA's signature) even if the live handshake uses a modern cipher.
    try:
        sig_hash_algo = cert.signature_hash_algorithm
        sig_hash_name = sig_hash_algo.name if sig_hash_algo else "unknown"
    except Exception:
        sig_hash_name = "unknown"

    if sig_hash_name and sig_hash_name.lower() in ("sha1", "md5"):
        sev = "critical" if sig_hash_name.lower() == "md5" else "medium"
        sig_issue = (sev, f"Certificate is signed using weak hash algorithm: {sig_hash_name.upper()}")
        if cipher_issue is None or severity_rank_lookup(sev) > severity_rank_lookup(cipher_issue[0]):
            cipher_issue = sig_issue
    else:
        sig_issue = None

    # --- Aggregate findings into a single worst-case result ---
    candidates = []  # list of (status, severity, title)
    if expiry_issue:
        candidates.append(expiry_issue)
    if chain_issue:
        candidates.append(chain_issue)
    if protocol_issue:
        sev, title = protocol_issue
        status = "fail" if sev in ("critical", "high") else "warning"
        candidates.append((status, sev, title))
    if cipher_issue:
        sev, title = cipher_issue
        status = "fail" if sev in ("critical", "high") else "warning"
        candidates.append((status, sev, title))
    # sig_issue may be the same object as cipher_issue (if it won), or distinct --
    # only add it separately if it wasn't already folded into cipher_issue above.
    if sig_issue and sig_issue is not cipher_issue:
        sev, title = sig_issue
        status = "fail" if sev in ("critical", "high") else "warning"
        candidates.append((status, sev, title))

    evidence = {
        "cert_expiry": cert_expiry_str,
        "cert_not_before": cert_not_before_str,
        "days_until_expiry": days_until_expiry,
        "tls_version": negotiated_version,
        "issuer": _parse_dn_from_name(cert.issuer) or "unknown",
        "subject": _parse_dn_from_name(cert.subject) or "unknown",
        "subject_common_name": subject_cn,
        "subject_alt_names": san_names,
        "is_self_signed": is_self_signed,
        "hostname_matches_cert": hostname_ok,
        "negotiated_cipher": cipher_name,
        "cert_signature_hash_algorithm": sig_hash_name,
        "cipher_protocol": negotiated_cipher[1] if negotiated_cipher else None,
        "cipher_secret_bits": negotiated_cipher[2] if negotiated_cipher else None,
        "legacy_protocol_probe_results": protocol_findings,
    }

    if not candidates:
        # No issues found. Decide pass vs warning based on negotiated protocol.
        if negotiated_version == "TLSv1.3":
            return _make_result(
                status="pass",
                severity="info",
                title="Strong TLS configuration",
                description=f"{hostname} negotiated TLS 1.3 with a strong cipher and a valid, properly matched certificate.",
                evidence=evidence,
                remediation="No action needed. Continue monitoring certificate expiry and periodically re-scan for configuration drift.",
            )
        elif negotiated_version == "TLSv1.2":
            return _make_result(
                status="warning",
                severity="info",
                title="Acceptable TLS configuration (TLS 1.2 only)",
                description=(
                    f"{hostname} negotiated TLS 1.2 with no critical weaknesses detected. "
                    "TLS 1.2 is currently considered acceptable, but TLS 1.3 is recommended for "
                    "improved performance and security (e.g. 0-RTT removal of older handshake risks, "
                    "mandatory forward secrecy)."
                ),
                evidence=evidence,
                remediation="Enable TLS 1.3 support on the server and prefer it over TLS 1.2 where client compatibility allows.",
            )
        else:
            return _make_result(
                status="warning",
                severity="low",
                title=f"Unexpected negotiated protocol: {negotiated_version}",
                description=f"{hostname} negotiated {negotiated_version}, which fell outside the explicit checks in this scan.",
                evidence=evidence,
                remediation="Manually review the server's TLS configuration to confirm intended protocol support.",
            )

    # Pick the worst candidate as the headline finding.
    candidates.sort(key=lambda c: severity_rank.get(c[1], 0), reverse=True)
    worst_status, worst_severity, worst_title = candidates[0]

    other_titles = [c[2] for c in candidates[1:]]
    description = f"SSL/TLS scan of {hostname} found: {worst_title}."
    if other_titles:
        description += " Additional findings: " + "; ".join(other_titles) + "."

    remediation_parts = []
    if expiry_issue:
        remediation_parts.append("Renew the TLS certificate before it expires.")
    if chain_issue:
        if not hostname_ok:
            remediation_parts.append("Issue a certificate whose CN/SAN matches the domain being served.")
        elif is_self_signed:
            remediation_parts.append("Replace the self-signed certificate with one issued by a trusted public CA.")
    if protocol_issue:
        remediation_parts.append("Disable legacy protocol versions (SSLv3/TLS 1.0/TLS 1.1) and require TLS 1.2+.")
    if cipher_issue:
        remediation_parts.append("Reconfigure the server's cipher suite list to remove NULL/RC4/DES/3DES and SHA1-based ciphers in favor of AEAD ciphers (AES-GCM, ChaCha20-Poly1305).")

    return _make_result(
        status=worst_status,
        severity=worst_severity,
        title=worst_title,
        description=description,
        evidence=evidence,
        remediation=" ".join(remediation_parts) or "Review the server's TLS configuration against current best practices (e.g. Mozilla SSL Configuration Generator).",
    )


async def run(url: str) -> dict:
    """
    Entry point. Analyzes SSL/TLS configuration of the target domain/URL.
    Never raises -- all exceptions are caught and returned as an 'error' result.

    Each blocking network step is individually bounded by CONNECT_TIMEOUT via
    asyncio.wait_for, rather than relying solely on the underlying socket's
    own timeout -- this guarantees the overall scan can't exceed roughly
    CONNECT_TIMEOUT per network round-trip even if a particular environment's
    network stack doesn't honor socket-level timeouts cleanly (e.g. certain
    proxied/sandboxed networks where a blocked port hangs instead of
    refusing or timing out).
    """
    try:
        hostname, port = _normalize_target(url)
    except ValueError as exc:
        return _error_result(str(exc))
    except Exception as exc:  # noqa: BLE001
        return _error_result(f"failed to parse input ({exc})")

    loop = asyncio.get_event_loop()

    async def _bounded(fn, *args):
        return await asyncio.wait_for(loop.run_in_executor(None, fn, *args), timeout=CONNECT_TIMEOUT)

    # --- Step 1: main connection (default modern handshake) ---
    try:
        cert, negotiated_version, negotiated_cipher = await _bounded(_fetch_cert_and_session, hostname, port)
    except asyncio.TimeoutError:
        return _error_result(f"connection timed out after {CONNECT_TIMEOUT}s", hostname)
    except socket.timeout:
        return _error_result(f"connection timed out after {CONNECT_TIMEOUT}s", hostname)
    except ConnectionRefusedError:
        return _error_result(f"connection refused on port {port}", hostname)
    except ssl.SSLError as exc:
        return _error_result(f"TLS handshake failed ({exc})", hostname)
    except OSError as exc:
        return _error_result(f"network error ({exc})", hostname)
    except ValueError as exc:
        return _error_result(f"could not parse server certificate ({exc})", hostname)
    except Exception as exc:  # noqa: BLE001
        return _error_result(f"unexpected error ({exc})", hostname)

    if cert is None:
        return _error_result("server did not present a certificate", hostname)

    # --- Steps 2-5: run the remaining (mostly CPU-bound + a few more blocking
    # network probes) analysis in the executor, each protocol probe individually
    # bounded so a single unresponsive probe can't exhaust the whole budget. ---
    try:
        return await _analyze(hostname, port, cert, negotiated_version, negotiated_cipher, _bounded)
    except Exception as exc:  # noqa: BLE001 - final safety net, must never crash caller
        return _error_result(f"unexpected error during scan ({exc})", hostname)


if __name__ == "__main__":
    import json
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "example.com"

    async def _main():
        result = await run(target)
        print(json.dumps(result, indent=2, default=str))

    asyncio.run(_main())