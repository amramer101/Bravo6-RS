#!/usr/bin/env python3
"""
test_07_email_security.py - Bravo6 Email Security Scanner (SPF/DMARC/DKIM) (v1.0)
=====================================================================
- Pure DNS. Zero contact with the target's web server -- does not gate on
  ctx.page_is_representative (SPF/DMARC/DKIM live on a separate protocol
  from HTTP; a WAF-blocked or down website has no bearing on whether the
  domain's mail security records are healthy).
- The one thing this scout must get right: a DNS query can fail in two
  structurally different ways, and they must never produce the same
  outcome. (1) The query succeeds and the resolver authoritatively reports
  no such record exists (NXDOMAIN / NoAnswer) -- a genuine "missing record"
  finding. (2) The query itself fails to complete (timeout, SERVFAIL, no
  reachable nameservers, network error) -- this must NEVER be treated as
  "missing"; it produces a distinct, clearly-separate informational
  "inconclusive" finding instead. See _dns_query() below, which is the
  single place this distinction is made.
- DKIM selectors are not discoverable in general (chosen by the sending
  mail provider, not published anywhere passive). This scout only ever
  checks a small, documented list of common default selectors and reports
  a positive "found" finding or an honest "inconclusive coverage" note --
  it never claims "DKIM missing" from an absent lookup at a guessed
  selector, because absence of evidence here is not evidence of absence.
- Strict 12-field finding schema with explicit raw_data["tier"]
  ("baseline" for required checks, "hardening" for nice-to-have checks)
  on every finding.
"""

import asyncio
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import tldextract

DNS_TIMEOUT = 5

# ------------------------------------------------------------------------------
# Registrable-domain extraction via the real Public Suffix List (tldextract),
# not a hand-maintained list of multi-part suffixes. A hardcoded list (the
# previous approach here) silently mis-truncates every domain under a
# suffix it doesn't happen to include -- confirmed live against
# gs.alexu.edu.eg, which was originally stripped to the bare "edu.eg"
# instead of "alexu.edu.eg", producing a false "Missing SPF/DMARC" finding
# even though alexu.edu.eg genuinely publishes a valid SPF record. The PSL
# covers co.uk/com.au/org.br/gov.cn/etc. and every other registered public
# suffix without needing a bespoke entry per ccTLD.
#
# Constructed once at module scope (mirroring how test_01/test_05 compile
# their regexes once at module scope rather than per call) with
# suffix_list_urls=() so it NEVER makes a live network call to refresh the
# PSL at scan time -- it relies only on the snapshot bundled with the
# tldextract package. This matters for two reasons specific to this
# project: the scanner is passive-only and shouldn't make an extra
# outbound request per scan that has nothing to do with the target site,
# and a reproducible evaluation run (same inputs, same outputs, rerunnable
# later) shouldn't depend on whatever the live PSL happens to say on the
# day it runs.
# ------------------------------------------------------------------------------
_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


def _extract_domain(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    hostname = (urlparse(url).hostname or "").lower().strip(".")
    if not hostname:
        return ""
    return _TLD_EXTRACTOR(hostname).top_domain_under_public_suffix


# ------------------------------------------------------------------------------
# DNS query boundary -- the single place that decides "confirmed absent" vs
# "query failed, inconclusive". Every check below MUST go through this
# function rather than calling dns.resolver directly, so the distinction
# can't be silently reintroduced somewhere else in the file.
# ------------------------------------------------------------------------------
async def _dns_query(domain: str, record_type: str) -> Tuple[str, List[str]]:
    """Perform a DNS query in a thread executor (dns.resolver is a blocking,
    synchronous API -- run_in_executor here mirrors how test_04_ssl_tls.py
    wraps its own blocking socket/ssl calls).

    Returns (status, values):
      - "answered": the query completed; values holds the record data
        (TXT record strings, or str(rdata) for other types). An empty list
        here still means "answered", i.e. genuinely no matching data --
        distinct from a query that never completed at all.
      - "nxdomain": the resolver AUTHORITATIVELY reports no such record
        exists (NXDOMAIN, or NoAnswer -- domain exists but has no record of
        this type). This is the ONLY status a "missing record" finding may
        ever be based on.
      - "failed": the query itself did not complete (timeout, SERVFAIL, no
        reachable nameservers, or any other resolution error). This must
        NEVER be treated the same as "nxdomain" -- it means "we don't
        know", not "it's absent".
    """
    loop = asyncio.get_running_loop()

    def _resolve_sync():
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        return resolver.resolve(domain, record_type)

    try:
        answers = await loop.run_in_executor(None, _resolve_sync)
    except dns.resolver.NXDOMAIN:
        return "nxdomain", []
    except dns.resolver.NoAnswer:
        # The domain exists but publishes no record of this type -- also a
        # genuine, confirmed-absent outcome, not a failed query.
        return "nxdomain", []
    except (dns.exception.Timeout, dns.resolver.NoNameservers):
        return "failed", []
    except Exception:
        # Any other unexpected dnspython/network exception: treat
        # conservatively as inconclusive, never as a confirmed absence.
        return "failed", []

    if record_type == "TXT":
        values = []
        for r in answers:
            try:
                joined = "".join(
                    part.decode("utf-8", errors="replace") if isinstance(part, bytes) else str(part)
                    for part in r.strings
                )
            except AttributeError:
                joined = str(r)
            values.append(joined)
        return "answered", values

    return "answered", [str(r) for r in answers]


# ------------------------------------------------------------------------------
# Finding factory (same convention as test_05/test_03: explicit tier param
# nested under raw_data).
# ------------------------------------------------------------------------------
def _make_finding(title: str, severity: str, confidence: str, cwe: str, owasp: str,
                   location: str, evidence: str, poc: str, remediation: str,
                   detection_method: str, tier: str) -> Dict[str, Any]:
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
        "detection_method": detection_method,
        "raw_data": {"tier": tier},
    }


def _inconclusive_finding(check_name: str, location: str, poc: str) -> Dict[str, Any]:
    """Shared shape for the 'DNS query failed' outcome -- deliberately NOT
    the same title/severity/confidence as a confirmed-missing finding, so a
    report reader (or an automated consumer) can never mistake one for the
    other."""
    return _make_finding(
        title=f"{check_name} check inconclusive (DNS query failed)",
        severity="info",
        confidence="plausible-unconfirmed",
        cwe="", owasp="",
        location=location,
        evidence=(
            f"The DNS query for this {check_name} check did not complete (timeout, "
            "SERVFAIL, or resolver error). This is NOT confirmation that the record "
            "is absent -- only that it could not be checked from here."
        ),
        poc=poc,
        remediation="Re-run this check; if it consistently fails, verify the scanner's DNS resolution path or the domain's nameservers.",
        detection_method="DNS Query (inconclusive)",
        tier="baseline",
    )


# ------------------------------------------------------------------------------
# SPF
# ------------------------------------------------------------------------------
def _spf_all_qualifier(record: str) -> Optional[str]:
    """Return the qualifier ('+', '-', '~', '?') of the 'all' mechanism in an
    SPF record, or None if no 'all' mechanism is present. A bare 'all' with
    no explicit qualifier defaults to '+' per RFC 7208."""
    for tok in record.split()[1:]:
        m = re.match(r'^([+\-~?])?all$', tok, re.IGNORECASE)
        if m:
            return m.group(1) or "+"
    return None


async def _check_spf(domain: str) -> List[Dict[str, Any]]:
    location = f"DNS TXT: {domain}"
    poc = f"dig TXT {domain} +short"
    status, txt_records = await _dns_query(domain, "TXT")

    if status == "failed":
        return [_inconclusive_finding("SPF", location, poc)]

    spf_records = [r for r in txt_records if r.strip().lower().startswith("v=spf1")]

    if not spf_records:
        return [_make_finding(
            title="Missing SPF record",
            severity="high",
            confidence="verified-live",
            cwe="CWE-290", owasp="A07:2021-Identification and Authentication Failures",
            location=location,
            evidence=f"No TXT record starting with 'v=spf1' was found for {domain} (DNS query completed).",
            poc=poc,
            remediation="Publish an SPF record (e.g. 'v=spf1 include:_spf.example.com -all') to specify which servers are authorized to send mail for this domain.",
            detection_method="DNS TXT Record Analysis",
            tier="baseline",
        )]

    findings: List[Dict[str, Any]] = []

    # RFC 7208: a domain must publish at most one SPF TXT record. Multiple
    # records are undefined ("PermError") behavior for receiving mail
    # servers -- worth flagging on its own even when one of the records
    # individually looks fine.
    if len(spf_records) > 1:
        findings.append(_make_finding(
            title="Multiple SPF records published",
            severity="medium",
            confidence="verified-live",
            cwe="CWE-1188", owasp="A05:2021-Security Misconfiguration",
            location=location,
            evidence=f"{len(spf_records)} separate 'v=spf1' TXT records found: {'; '.join(spf_records)}. RFC 7208 treats multiple SPF records as a PermError -- behavior across mail receivers is undefined/unreliable.",
            poc=poc,
            remediation="Publish exactly one SPF TXT record per RFC 7208; merge the mechanisms from all records into a single record.",
            detection_method="DNS TXT Record Analysis",
            tier="baseline",
        ))

    for rec in spf_records:
        qualifier = _spf_all_qualifier(rec)
        if qualifier == "+":
            findings.append(_make_finding(
                title="SPF record ends in an overly permissive 'all' mechanism",
                severity="high",
                confidence="verified-live",
                cwe="CWE-290", owasp="A07:2021-Identification and Authentication Failures",
                location=location,
                evidence=f"SPF record allows ANY server to send mail as this domain, defeating SPF's purpose even though a record technically exists: {rec}",
                poc=poc,
                remediation="Change 'all' (or '+all') to '-all' (hardfail), or at minimum '~all' (softfail), to actually constrain authorized senders.",
                detection_method="SPF Policy Analysis",
                tier="baseline",
            ))

    return findings


# ------------------------------------------------------------------------------
# DMARC
# ------------------------------------------------------------------------------
def _parse_dmarc_tags(record: str) -> Dict[str, str]:
    tags: Dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if part and "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


async def _check_dmarc(domain: str) -> List[Dict[str, Any]]:
    dmarc_domain = f"_dmarc.{domain}"
    location = f"DNS TXT: {dmarc_domain}"
    poc = f"dig TXT {dmarc_domain} +short"
    status, txt_records = await _dns_query(dmarc_domain, "TXT")

    if status == "failed":
        return [_inconclusive_finding("DMARC", location, poc)]

    dmarc_records = [r for r in txt_records if r.strip().lower().startswith("v=dmarc1")]

    if not dmarc_records:
        return [_make_finding(
            title="Missing DMARC record",
            severity="high",
            confidence="verified-live",
            cwe="CWE-290", owasp="A07:2021-Identification and Authentication Failures",
            location=location,
            evidence=f"No 'v=DMARC1' TXT record was found at {dmarc_domain} (DNS query completed).",
            poc=poc,
            remediation="Publish a DMARC record (e.g. 'v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com') to instruct mail receivers how to handle SPF/DKIM failures.",
            detection_method="DNS TXT Record Analysis",
            tier="baseline",
        )]

    findings: List[Dict[str, Any]] = []
    record = dmarc_records[0]
    tags = _parse_dmarc_tags(record)
    p = tags.get("p", "").lower()

    if not p:
        findings.append(_make_finding(
            title="DMARC record missing required 'p' policy tag",
            severity="high",
            confidence="verified-live",
            cwe="CWE-290", owasp="A07:2021-Identification and Authentication Failures",
            location=location,
            evidence=f"DMARC record: {record}. No 'p=' policy tag was found; the record is malformed per RFC 7489.",
            poc=poc,
            remediation="Add a 'p=' tag (e.g. p=reject) -- it is required by the DMARC specification.",
            detection_method="DMARC Policy Analysis",
            tier="baseline",
        ))
    elif p == "none":
        findings.append(_make_finding(
            title="DMARC policy set to p=none (monitoring only)",
            severity="medium",
            confidence="verified-live",
            cwe="CWE-290", owasp="A07:2021-Identification and Authentication Failures",
            location=location,
            evidence=f"DMARC record: {record}. p=none takes no enforcement action against spoofed mail -- reports are collected but nothing is blocked or quarantined.",
            poc=poc,
            remediation="Move to p=quarantine, and ultimately p=reject, once monitoring confirms legitimate mail flows aren't affected.",
            detection_method="DMARC Policy Analysis",
            tier="baseline",
        ))
    elif p == "quarantine":
        findings.append(_make_finding(
            title="DMARC policy set to p=quarantine (weaker than reject)",
            severity="low",
            confidence="verified-live",
            cwe="CWE-290", owasp="A07:2021-Identification and Authentication Failures",
            location=location,
            evidence=f"DMARC record: {record}. p=quarantine routes suspicious mail to spam rather than rejecting it outright.",
            poc=poc,
            remediation="Consider moving to p=reject for the strongest enforcement once monitoring confirms it's safe.",
            detection_method="DMARC Policy Analysis",
            tier="hardening",
        ))
    # p == "reject": the strong, correct state -- no finding for the p tag itself.

    # 'pct' is a distinct, separate signal from 'p': it limits what fraction
    # of qualifying mail the policy actually applies to. A strong p=reject
    # with a low pct is only partially enforced -- worth its own finding
    # ALONGSIDE (not instead of) the p= read above.
    if p in ("quarantine", "reject"):
        pct_raw = tags.get("pct")
        if pct_raw is not None:
            try:
                pct = int(pct_raw)
            except ValueError:
                pct = None
            if pct is not None and pct < 100:
                findings.append(_make_finding(
                    title=f"DMARC policy only enforced on {pct}% of mail (pct={pct})",
                    severity="medium",
                    confidence="verified-live",
                    cwe="CWE-290", owasp="A07:2021-Identification and Authentication Failures",
                    location=location,
                    evidence=f"DMARC record: {record}. The 'pct' tag limits enforcement of the '{p}' policy to {pct}% of mail that fails DMARC -- the remaining {100 - pct}% is delivered as if the policy were p=none.",
                    poc=poc,
                    remediation="Set pct=100 once monitoring confirms the policy doesn't affect legitimate mail, so enforcement applies to all matching mail.",
                    detection_method="DMARC Policy Analysis",
                    tier="baseline",
                ))

    return findings


# ------------------------------------------------------------------------------
# DKIM (best-effort only -- see module docstring)
# ------------------------------------------------------------------------------
DKIM_COMMON_SELECTORS = ["default", "selector1", "selector2", "google", "dkim"]


def _is_genuine_dkim_record(txt: str) -> bool:
    """A DKIM TXT record only counts as a genuine, active key if it
    actually declares itself as DKIM (v=DKIM1) AND its public-key ('p=')
    tag has a non-empty value. An empty p= tag is DKIM's own explicit
    key-revocation signal per RFC 6376 section 3.6.1 -- not a usable key.
    Live-confirmed root cause: a wildcard DNS record on awsdns-44.com (an
    AWS-infrastructure domain with no actual web server) answers
    'v=DKIM1; p=' -- literally empty -- for every selector queried,
    including all 5 of this scout's common selectors simultaneously. The
    previous check (`"v=dkim1" in r.lower() or re.search(r'p=', r)`) was an
    OR: presence of EITHER signal alone was enough, so it both accepted the
    empty-key case and could have accepted an unrelated TXT record that
    merely contains "p=" as a substring with no DKIM version tag at all.
    Requiring both, with a non-empty p=, is the actual shape of a real key.
    """
    if "v=dkim1" not in txt.lower():
        return False
    m = re.search(r'(?i)\bp\s*=\s*([^;]*)', txt)
    return bool(m and m.group(1).strip())


async def _check_dkim(domain: str) -> List[Dict[str, Any]]:
    tasks = [_dns_query(f"{sel}._domainkey.{domain}", "TXT") for sel in DKIM_COMMON_SELECTORS]
    results = await asyncio.gather(*tasks)

    found_selectors = []
    any_query_failed = False
    for sel, (status, txt_records) in zip(DKIM_COMMON_SELECTORS, results):
        if status == "failed":
            any_query_failed = True
            continue
        if status == "answered" and any(_is_genuine_dkim_record(r) for r in txt_records):
            found_selectors.append(sel)

    location = f"DNS TXT: {domain} (DKIM selectors)"

    if found_selectors:
        first = found_selectors[0]
        return [_make_finding(
            title=f"DKIM record found at common selector(s): {', '.join(found_selectors)}",
            severity="info",
            confidence="verified-live",
            cwe="", owasp="",
            location=location,
            evidence=(
                f"A DKIM public key record was found at "
                f"{', '.join(f'{s}._domainkey.{domain}' for s in found_selectors)}. "
                "This confirms DKIM is configured for at least this selector; other "
                "selectors not on this scout's checked list may also exist."
            ),
            poc=f"dig TXT {first}._domainkey.{domain} +short",
            remediation="No action required for the discovered selector(s).",
            detection_method="DKIM Selector Probing (best-effort)",
            tier="baseline",
        )]

    # No common selector resolved. This is explicitly NOT evidence that DKIM
    # is unused -- selectors are chosen by the sending mail provider and are
    # not discoverable via passive DNS enumeration in general. Report the
    # coverage limit honestly instead of a confident "DKIM missing" claim.
    note = (
        f"None of the {len(DKIM_COMMON_SELECTORS)} common DKIM selectors checked "
        f"({', '.join(DKIM_COMMON_SELECTORS)}) resolved for {domain}. This does NOT "
        "confirm DKIM is unused -- the domain's actual selector(s) may not be in "
        "this list, since selectors are chosen by the sending mail provider and are "
        "not discoverable via passive DNS. Manual verification (e.g. inspecting a "
        "real email's DKIM-Signature header) is required for a confident answer."
    )
    if any_query_failed:
        note += " (At least one of the selector queries also failed to complete, further limiting this check's coverage.)"

    return [_make_finding(
        title="DKIM coverage inconclusive (no common selector resolved)",
        severity="info",
        confidence="informational",
        cwe="", owasp="",
        location=location,
        evidence=note,
        poc=f"dig TXT default._domainkey.{domain} +short",
        remediation="Manually confirm DKIM configuration with the domain owner or by inspecting real outbound mail headers; do not treat this scout's silence as confirmation of absence.",
        detection_method="DKIM Selector Probing (best-effort)",
        tier="baseline",
    )]


# ------------------------------------------------------------------------------
# Main entry point
# ------------------------------------------------------------------------------
async def run(ctx: Any) -> dict:
    """Entry point for the Email Security scout. Pure DNS -- deliberately
    does NOT gate on ctx.page_is_representative: SPF/DMARC/DKIM records live
    on DNS, a separate protocol from the web server's HTTP responses, so a
    WAF-blocked or down website has no bearing on whether the domain's mail
    security records are healthy."""
    url = getattr(ctx, "url", "https://example.com")
    domain = _extract_domain(url)

    if not domain or "." not in domain:
        return {"fatal_error": f"Could not extract a valid domain from URL: {url}"}

    spf_findings, dmarc_findings, dkim_findings = await asyncio.gather(
        _check_spf(domain), _check_dmarc(domain), _check_dkim(domain)
    )

    return {
        "findings": spf_findings + dmarc_findings + dkim_findings,
        "details": {
            "requests_made": 0,
            "domain_checked": domain,
        },
    }


# ────────────────────────────────────────────── Standalone Testing ──────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(description="Bravo6 Email Security Scout (SPF/DMARC/DKIM)")
    parser.add_argument("url", nargs="?", default="https://example.com", help="Target URL")
    parser.add_argument("--test", action="store_true", help="Run Scout Regression Tests")
    args = parser.parse_args()

    if args.test:
        import unittest
        from unittest import mock

        class TestDnsQueryTimeoutVsNxdomainDistinction(unittest.TestCase):
            """Core regression test for the bug this rewrite exists to
            prevent: a failed DNS query must NEVER be treated the same as an
            authoritative NXDOMAIN/NoAnswer response. This mocks the real
            dnspython exception classes at the resolver boundary, not this
            file's own logic, so it tests the actual boundary the historical
            bug lived in."""

            def test_nxdomain_maps_to_nxdomain_status(self):
                with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NXDOMAIN()):
                    status, values = asyncio.run(_dns_query("nonexistent.example.invalid", "TXT"))
                self.assertEqual(status, "nxdomain")
                self.assertEqual(values, [])

            def test_noanswer_maps_to_nxdomain_status(self):
                with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NoAnswer()):
                    status, values = asyncio.run(_dns_query("example.com", "TXT"))
                self.assertEqual(status, "nxdomain")

            def test_timeout_maps_to_failed_status_never_nxdomain(self):
                with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.exception.Timeout()):
                    status, values = asyncio.run(_dns_query("example.com", "TXT"))
                self.assertEqual(status, "failed")
                self.assertNotEqual(status, "nxdomain", "A DNS timeout must never be treated as a confirmed-absent record.")

            def test_no_nameservers_maps_to_failed_status(self):
                with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=dns.resolver.NoNameservers()):
                    status, values = asyncio.run(_dns_query("example.com", "TXT"))
                self.assertEqual(status, "failed")

            def test_generic_connection_error_maps_to_failed_status(self):
                with mock.patch.object(dns.resolver.Resolver, "resolve", side_effect=OSError("network unreachable")):
                    status, values = asyncio.run(_dns_query("example.com", "TXT"))
                self.assertEqual(status, "failed")

            def test_successful_answer_maps_to_answered_status(self):
                class FakeRdata:
                    strings = [b"v=spf1 -all"]
                with mock.patch.object(dns.resolver.Resolver, "resolve", return_value=[FakeRdata()]):
                    status, values = asyncio.run(_dns_query("example.com", "TXT"))
                self.assertEqual(status, "answered")
                self.assertEqual(values, ["v=spf1 -all"])

        def _mock_dns_query(mapping: Dict[Tuple[str, str], Tuple[str, List[str]]]):
            async def fake(domain, record_type):
                return mapping.get((domain, record_type), ("answered", []))
            return fake

        class _DnsQueryPatchMixin:
            def _patch_dns(self, mapping):
                patcher = mock.patch("__main__._dns_query", new=_mock_dns_query(mapping))
                patcher.start()
                self.addCleanup(patcher.stop)

        class TestSpfChecks(unittest.TestCase, _DnsQueryPatchMixin):
            def test_valid_spf_no_finding(self):
                self._patch_dns({("example.com", "TXT"): ("answered", ["v=spf1 include:_spf.example.com -all"])})
                findings = asyncio.run(_check_spf("example.com"))
                self.assertEqual(findings, [])

            def test_missing_spf_via_confirmed_nxdomain(self):
                self._patch_dns({("example.com", "TXT"): ("nxdomain", [])})
                findings = asyncio.run(_check_spf("example.com"))
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["title"], "Missing SPF record")
                self.assertEqual(findings[0]["severity"], "high")
                self.assertEqual(findings[0]["confidence"], "verified-live")

            def test_failed_dns_query_produces_no_missing_finding(self):
                self._patch_dns({("example.com", "TXT"): ("failed", [])})
                findings = asyncio.run(_check_spf("example.com"))
                self.assertEqual(len(findings), 1)
                self.assertNotEqual(findings[0]["title"], "Missing SPF record")
                self.assertIn("inconclusive", findings[0]["title"].lower())
                self.assertEqual(findings[0]["confidence"], "plausible-unconfirmed")

            def test_permissive_all_spf_flagged(self):
                self._patch_dns({("example.com", "TXT"): ("answered", ["v=spf1 include:_spf.example.com +all"])})
                findings = asyncio.run(_check_spf("example.com"))
                self.assertTrue(any("permissive" in f["title"].lower() for f in findings))

            def test_bare_all_is_also_permissive(self):
                self._patch_dns({("example.com", "TXT"): ("answered", ["v=spf1 include:_spf.example.com all"])})
                findings = asyncio.run(_check_spf("example.com"))
                self.assertTrue(any("permissive" in f["title"].lower() for f in findings))

            def test_softfail_all_not_flagged_permissive(self):
                self._patch_dns({("example.com", "TXT"): ("answered", ["v=spf1 include:_spf.example.com ~all"])})
                findings = asyncio.run(_check_spf("example.com"))
                self.assertFalse(any("permissive" in f["title"].lower() for f in findings))

            def test_multiple_spf_records_flagged(self):
                self._patch_dns({("example.com", "TXT"): ("answered", [
                    "v=spf1 include:_spf.example.com -all",
                    "v=spf1 include:other-provider.com -all",
                ])})
                findings = asyncio.run(_check_spf("example.com"))
                self.assertTrue(any("multiple spf" in f["title"].lower() for f in findings))

        class TestDmarcChecks(unittest.TestCase, _DnsQueryPatchMixin):
            def test_valid_dmarc_reject_no_finding(self):
                self._patch_dns({("_dmarc.example.com", "TXT"): ("answered", ["v=DMARC1; p=reject; pct=100; rua=mailto:a@example.com"])})
                findings = asyncio.run(_check_dmarc("example.com"))
                self.assertEqual(findings, [])

            def test_missing_dmarc_via_confirmed_nxdomain(self):
                self._patch_dns({("_dmarc.example.com", "TXT"): ("nxdomain", [])})
                findings = asyncio.run(_check_dmarc("example.com"))
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0]["title"], "Missing DMARC record")

            def test_failed_dns_query_produces_no_missing_finding(self):
                self._patch_dns({("_dmarc.example.com", "TXT"): ("failed", [])})
                findings = asyncio.run(_check_dmarc("example.com"))
                self.assertEqual(len(findings), 1)
                self.assertNotEqual(findings[0]["title"], "Missing DMARC record")
                self.assertIn("inconclusive", findings[0]["title"].lower())

            def test_p_none_is_distinct_from_missing(self):
                self._patch_dns({("_dmarc.example.com", "TXT"): ("answered", ["v=DMARC1; p=none; rua=mailto:a@example.com"])})
                findings = asyncio.run(_check_dmarc("example.com"))
                titles = [f["title"] for f in findings]
                self.assertTrue(any("p=none" in t for t in titles))
                self.assertFalse(any("Missing DMARC" in t for t in titles))

            def test_p_reject_with_low_pct_flags_partial_enforcement_alongside_strong_policy(self):
                self._patch_dns({("_dmarc.example.com", "TXT"): ("answered", ["v=DMARC1; p=reject; pct=25; rua=mailto:a@example.com"])})
                findings = asyncio.run(_check_dmarc("example.com"))
                titles = [f["title"] for f in findings]
                self.assertTrue(any("25%" in t or "pct=25" in t for t in titles), titles)
                # p=reject itself is the strong/correct state -- must not
                # ALSO produce a "weak policy" finding.
                self.assertFalse(any("p=none" in t or "p=quarantine" in t for t in titles))

            def test_p_quarantine_flagged_as_weaker_than_reject(self):
                self._patch_dns({("_dmarc.example.com", "TXT"): ("answered", ["v=DMARC1; p=quarantine; pct=100"])})
                findings = asyncio.run(_check_dmarc("example.com"))
                titles = [f["title"] for f in findings]
                self.assertTrue(any("p=quarantine" in t for t in titles))
                quarantine_finding = next(f for f in findings if "p=quarantine" in f["title"])
                self.assertEqual(quarantine_finding["severity"], "low")
                self.assertEqual(quarantine_finding["raw_data"]["tier"], "hardening")

        class TestDkimChecks(unittest.TestCase):
            def test_selector_found_reports_positively_not_as_missing(self):
                async def fake(domain, record_type):
                    if domain.startswith("default."):
                        return "answered", ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3"]
                    return "answered", []
                with mock.patch("__main__._dns_query", new=fake):
                    findings = asyncio.run(_check_dkim("example.com"))
                self.assertEqual(len(findings), 1)
                self.assertIn("found", findings[0]["title"].lower())
                self.assertNotIn("missing", findings[0]["title"].lower())
                self.assertEqual(findings[0]["confidence"], "verified-live")

            def test_no_selector_resolves_is_inconclusive_not_missing(self):
                async def fake(domain, record_type):
                    return "nxdomain", []
                with mock.patch("__main__._dns_query", new=fake):
                    findings = asyncio.run(_check_dkim("example.com"))
                self.assertEqual(len(findings), 1)
                self.assertNotIn("missing", findings[0]["title"].lower())
                self.assertIn("inconclusive", findings[0]["title"].lower())
                self.assertEqual(findings[0]["confidence"], "informational")

            def test_failed_selector_queries_also_never_report_missing(self):
                async def fake(domain, record_type):
                    return "failed", []
                with mock.patch("__main__._dns_query", new=fake):
                    findings = asyncio.run(_check_dkim("example.com"))
                self.assertEqual(len(findings), 1)
                self.assertNotIn("missing", findings[0]["title"].lower())
                self.assertIn("failed to complete", findings[0]["evidence"].lower())

            def test_empty_p_tag_wildcard_record_not_reported_as_found(self):
                # Live-confirmed regression: awsdns-44.com has a wildcard DNS
                # record answering 'v=DKIM1; p=' (empty public key -- DKIM's
                # own revocation signal per RFC 6376) for every selector,
                # including all 5 common ones simultaneously. This must NOT
                # be reported as a genuine "DKIM record found".
                async def fake(domain, record_type):
                    return "answered", ["v=DKIM1; p="]
                with mock.patch("__main__._dns_query", new=fake):
                    findings = asyncio.run(_check_dkim("awsdns-44.com"))
                self.assertEqual(len(findings), 1)
                self.assertNotIn("found", findings[0]["title"].lower())
                self.assertIn("inconclusive", findings[0]["title"].lower())

            def test_record_with_p_but_no_dkim_version_tag_not_reported_as_found(self):
                # A TXT record that merely contains the substring "p=" with
                # no "v=DKIM1" at all is not a DKIM record -- both signals
                # are required, not either alone.
                async def fake(domain, record_type):
                    return "answered", ["some-unrelated-verification-token p=abc123"]
                with mock.patch("__main__._dns_query", new=fake):
                    findings = asyncio.run(_check_dkim("example.com"))
                self.assertIn("inconclusive", findings[0]["title"].lower())

            def test_genuine_dkim_record_with_real_key_still_reported_as_found(self):
                # Regression guard: the fix must not become so strict that it
                # rejects real, live-confirmed DKIM keys (olx.pl's actual
                # published record, captured during this audit).
                real_record = (
                    "v=DKIM1; g=*; k=rsa; "
                    "p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAqB0ia/Ng5rk8NlFId9tMrRikb9gon49XKb3KQlqfVZ8fg0xqtp8270TS23IhSt9WjnPZ26kteFbDpw"
                )
                self.assertTrue(_is_genuine_dkim_record(real_record))

        class TestExtractDomain(unittest.TestCase):
            """_extract_domain is now backed by tldextract's bundled Public
            Suffix List snapshot (offline, suffix_list_urls=()), not a
            hand-maintained list of multi-part suffixes -- these tests
            confirm the real PSL-backed path, not the old hardcoded set."""

            def test_strips_subdomain_to_apex(self):
                self.assertEqual(_extract_domain("https://mentorship.lfx.linuxfoundation.org"), "linuxfoundation.org")

            def test_handles_co_uk_multi_part_suffix(self):
                self.assertEqual(_extract_domain("https://shop.example.co.uk"), "example.co.uk")

            def test_handles_com_au_multi_part_suffix(self):
                # A second, unrelated multi-part suffix outside Egypt's TLD --
                # proves the fix generalizes rather than being another
                # one-off hand-added entry.
                self.assertEqual(_extract_domain("https://sub.example.com.au"), "example.com.au")

            def test_handles_edu_eg_multi_part_suffix(self):
                # Live-validation regression: gs.alexu.edu.eg was originally
                # stripped to the bare "edu.eg" (a public-suffix-like registry
                # namespace, not Alexandria University's actual domain) by the
                # old hardcoded MULTI_PART_SUFFIXES list, producing a false
                # "Missing SPF/DMARC" finding even though alexu.edu.eg
                # genuinely publishes a valid SPF record. Now goes through
                # the real PSL, which covers edu.eg (and every other
                # registered public suffix) without a bespoke entry.
                self.assertEqual(_extract_domain("https://gs.alexu.edu.eg/FCDS"), "alexu.edu.eg")

            def test_bare_apex_domain_unchanged(self):
                self.assertEqual(_extract_domain("https://example.com"), "example.com")

        class TestRunEndToEnd(unittest.IsolatedAsyncioTestCase):
            async def test_run_extracts_domain_and_aggregates_all_three_checks(self):
                class Ctx:
                    url = "https://mail.example.com"

                async def fake(domain, record_type):
                    return "nxdomain", []

                with mock.patch("__main__._dns_query", new=fake):
                    result = await run(Ctx())

                self.assertEqual(result["details"]["domain_checked"], "example.com")
                titles = [f["title"] for f in result["findings"]]
                self.assertIn("Missing SPF record", titles)
                self.assertIn("Missing DMARC record", titles)
                self.assertTrue(any("inconclusive" in t.lower() for t in titles))  # DKIM

        sys.argv = [sys.argv[0]]
        unittest.main()
    else:
        import asyncio as _asyncio

        class DummyContext:
            def __init__(self, url):
                self.url = url

        async def _live_scan():
            result = await run(DummyContext(url=args.url))
            print(json.dumps(result, indent=2, ensure_ascii=False, default=str))

        _asyncio.run(_live_scan())
