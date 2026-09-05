#!/usr/bin/env python3
"""
Bravo6 API Gateway -- Blocklist Enforcement
=====================================================================
Per the paper's design, submissions targeting government, military,
financial, healthcare, and educational-institution domains are rejected
outright -- independent of anything else about the request (auth, quota,
SSRF safety). Compiled into code as an immutable constant, deliberately
NOT read from Cosmos DB, an environment variable, or any request
parameter: extending it is a reviewed code change, not something a
compromised component or a crafted request can influence at runtime.

This is a representative, illustrative set per category, not an
exhaustive registry of every government/military/financial/healthcare/
educational domain on the internet -- the paper commits to the
*mechanism* (a fixed blocklist checked before any downstream action), not
to a complete real-world domain census. Financial and healthcare
institutions in particular mostly sit on ordinary .com/.org domains with
no dedicated TLD, so those two categories are enumerated as specific,
well-known domains rather than a suffix.
"""
from typing import FrozenSet

# Suffix-matched against the full hostname (exact match or any subdomain).
# Government, military, and educational institutions are the categories
# that actually cluster under dedicated TLDs/second-level domains.
BLOCKED_DOMAIN_SUFFIXES: FrozenSet[str] = frozenset({
    # Government
    "gov", "gov.uk", "gov.au", "gc.ca", "gob.mx",
    # Military
    "mil", "mil.uk",
    # Healthcare (UK's National Health Service is the one major exception
    # that does cluster under a dedicated second-level domain)
    "nhs.uk",
    # Educational institution
    "edu", "ac.uk", "edu.au", "ac.in",
})

# Specific, named domains for the categories with no common dedicated
# TLD. A handful of well-known, publicly-known institutions per category,
# illustrative rather than exhaustive -- adding an entry is the intended
# way to extend coverage, reviewed like any other code change.
BLOCKED_SPECIFIC_DOMAINS: FrozenSet[str] = frozenset({
    # Financial
    "federalreserve.gov", "treasury.gov", "sec.gov", "swift.com",
    "jpmorganchase.com", "bankofamerica.com",
    # Healthcare
    "cdc.gov", "nih.gov", "who.int", "mayoclinic.org", "clevelandclinic.org",
})


def _normalize_host(hostname: str) -> str:
    return hostname.strip().lower().rstrip(".")


def is_blocklisted(hostname: str) -> bool:
    """True if hostname is the blocked domain itself or any subdomain of
    one. Suffix/exact-domain matching only -- no substring matching, so
    e.g. "notgov.com" is never confused with "gov"."""
    host = _normalize_host(hostname)
    if not host:
        return False

    for domain in BLOCKED_SPECIFIC_DOMAINS:
        if host == domain or host.endswith("." + domain):
            return True

    for suffix in BLOCKED_DOMAIN_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return True

    return False
