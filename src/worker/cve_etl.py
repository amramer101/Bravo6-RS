#!/usr/bin/env python3
"""
osv_fetch_etl.py — Build an up-to-date, real CVE/advisory dataset for the
frontend libraries BRAVO6's test_02_frontend_libs.py already knows how to
fingerprint, using OSV.dev (Open Source Vulnerabilities) instead of a
hand-typed cve_database.csv.

WHY OSV.dev:
    - Free, no API key, no rate-limit headaches for this scale of use.
    - Structured per-package "affected version range" data (SEMVER ranges
      or explicit version lists), which is exactly the shape test_02's
      LIBRARY_VERSION_RANGES sanity-check wants.
    - Aggregates GitHub Security Advisories + npm advisories, so it's kept
      current without you maintaining it by hand.

WHY THIS SCRIPT USES TARGETED PER-PACKAGE QUERIES, NOT THE FULL NPM DUMP:
    BRAVO6 only fingerprints a fixed, small list of libraries (see
    LIBRARY_SIGNATURES below — keep it in sync with test_02's own
    detection patterns). Downloading OSV's entire npm ecosystem archive
    (osv-vulnerabilities.storage.googleapis.com/npm/all.zip) would pull
    down data for thousands of packages BRAVO6 will never look for. The
    targeted approach below asks OSV directly "what vulnerabilities exist
    for jquery / lodash / moment / ..." — a handful of small HTTP calls,
    typically well under a few MB total, done in well under a minute.

    If you later want the full bulk dump anyway (e.g. to browse coverage
    before deciding which new libraries to add fingerprinting for), fetch
    it separately with:
        curl -I https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip
    to check its current Content-Length before committing to the download —
    the exact current size isn't something to assume; check it live.

WHERE TO RUN THIS:
    Run this on your own machine, not through a Claude-mediated sandbox or
    the device bridge — both of those sit behind a network egress allowlist
    that does not include api.osv.dev, so the request will simply fail
    there. Your own regular Terminal has no such restriction.

USAGE:
    pip install requests cvss
    python3 osv_fetch_etl.py

OUTPUT:
    cve_database_v2.csv  — same 8 columns as the existing cve_database.csv
                            (library, version, cve, cvss, cwe, summary,
                            signature, upgrade_rec), sourced from OSV.
    osv_raw_cache/<pkg>.json — raw API responses, cached so re-runs don't
                            re-hit the network unnecessarily. Delete a file
                            in here (or the whole folder) to force a refresh
                            for that package.

EXTENDING COVERAGE:
    Adding a new library here (e.g. react, vue, handlebars, underscore,
    chart.js — all plausible next candidates given the frontend_libs recall
    gap seen on amazon.eg) requires two changes, not just one:
      1. Add its npm package name + detection regex to LIBRARY_SIGNATURES
         below, so this ETL script pulls its CVE data.
      2. Add the matching fingerprint pattern to test_02_frontend_libs.py
         itself, so the scanner can actually recognize the library on a
         page in the first place.
    Doing only #1 is wasted effort — CVE data for a library BRAVO6 never
    detects on a page will never be matched against anything.
"""

import csv
import json
import time
from pathlib import Path

import requests

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
CACHE_DIR = Path("osv_raw_cache")
OUTPUT_CSV = Path("cve_database_v2.csv")

# ---------------------------------------------------------------------------
# The exact set of libraries BRAVO6 currently fingerprints, with the same
# detection regex used in test_02_frontend_libs.py / cve_database.csv.
# OSV has no concept of "what regex detects this library in a bundled JS
# file" — that stays BRAVO6-specific knowledge, so we own this mapping.
# ---------------------------------------------------------------------------
LIBRARY_SIGNATURES = {
    "jquery": r"jQuery\.fn\.jquery",
    "lodash": r"_\.VERSION",
    "moment": r"moment\.version",
    "bootstrap": r"Bootstrap\.VERSION",
    "axios": r"axios\.VERSION",
    # Add more here once test_02 gains matching fingerprint patterns, e.g.:
    # "react": r"...",
    # "vue": r"...",
    # "handlebars": r"...",
    # "underscore": r"...",
    # "chart.js": r"...",
}


def fetch_package_vulns(pkg_name: str) -> list:
    """Query OSV for every known vulnerability affecting any version of
    pkg_name in the npm ecosystem. Cached to disk after the first fetch."""
    cache_file = CACHE_DIR / f"{pkg_name}.json"
    if cache_file.exists():
        return json.loads(cache_file.read_text()).get("vulns", [])

    resp = requests.post(
        OSV_QUERY_URL,
        json={"package": {"name": pkg_name, "ecosystem": "npm"}},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()

    CACHE_DIR.mkdir(exist_ok=True)
    cache_file.write_text(json.dumps(data, indent=2))
    return data.get("vulns", [])


# Approximate numeric CVSS base score for advisories that only carry a
# qualitative severity label (common for GHSA-only entries with no NVD
# CVSS vector). These are midpoints of each official CVSS severity band —
# an approximation, not a substitute for the real score, but needed so
# every row in the output CSV has a single, comparable numeric type.
QUALITATIVE_CVSS_MAP = {
    "LOW": 2.5,
    "MODERATE": 5.4,
    "MEDIUM": 5.4,
    "HIGH": 8.0,
    "CRITICAL": 9.5,
}

# OSV "MAL-" ids mark a specific published package version as outright
# malicious (a supply-chain compromise), not a code-level vulnerability.
# There is no meaningful CVSS/CWE for these in the normal sense, so they
# get a fixed severity and a dedicated CWE (Embedded Malicious Code)
# instead of being left with blank fields that look like missing data.
MALICIOUS_PACKAGE_CVSS = 9.8
MALICIOUS_PACKAGE_CWE = "CWE-506"


def extract_cve_id(vuln: dict) -> str:
    """Prefer a real CVE id if one exists among the aliases; otherwise fall
    back to the OSV/GHSA/MAL id itself (not every advisory has a CVE)."""
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return vuln.get("id", "")


def is_malicious_package_entry(vuln: dict) -> bool:
    return vuln.get("id", "").startswith("MAL-")


def extract_cvss(vuln: dict) -> float:
    """Always returns a numeric CVSS-scale float, never a bare qualitative
    string, so downstream code can safely do float(cvss) on every row."""
    if is_malicious_package_entry(vuln):
        return MALICIOUS_PACKAGE_CVSS

    for sev in vuln.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            try:
                from cvss import CVSS3

                return CVSS3(sev["score"]).base_score
            except Exception:
                continue

    qualitative = vuln.get("database_specific", {}).get("severity", "")
    if qualitative.upper() in QUALITATIVE_CVSS_MAP:
        return QUALITATIVE_CVSS_MAP[qualitative.upper()]
    return 0.0  # unknown severity; treat as "needs manual review", not critical


def extract_cwe(vuln: dict) -> str:
    if is_malicious_package_entry(vuln):
        return MALICIOUS_PACKAGE_CWE
    cwes = vuln.get("database_specific", {}).get("cwe_ids", [])
    return cwes[0] if cwes else ""


def extract_affected_range(vuln: dict, pkg_name: str) -> tuple:
    """Returns (introduced_version, fixed_version) as strings, pulled from
    the SEMVER range OSV records for this package in this advisory."""
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name") != pkg_name:
            continue
        for r in affected.get("ranges", []):
            if r.get("type") != "SEMVER":
                continue
            introduced, fixed = "0", ""
            for event in r.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    fixed = event["fixed"]
            return introduced, fixed
        if affected.get("versions"):
            versions = affected["versions"]
            return versions[0], versions[-1]
    return "", ""


def _parse_version_tuple(v: str):
    """Best-effort semver-ish sort key. Falls back to (0,) for anything
    that isn't cleanly numeric (e.g. prerelease tags like '3.0.0-rc.1') so
    those simply sort first rather than crashing the merge step."""
    core = v.split("-")[0]
    parts = []
    for p in core.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            return (0,)
    return tuple(parts) if parts else (0,)


def dedupe_rows(rows: list) -> list:
    """OSV sometimes surfaces the same CVE twice for the same library (once
    via a GHSA-sourced record, once via an NVD-derived one) with slightly
    different CWE/CVSS/version-range values. Merge those into a single row:
    the widest (most conservative) affected-version range, the higher of
    the two CVSS scores (favor flagging over silently under-reporting),
    and whichever CWE/summary is non-empty."""
    merged = {}
    for row in rows:
        key = (row["library"], row["cve"])
        if key not in merged:
            merged[key] = row
            continue

        existing = merged[key]
        existing["cvss"] = max(existing["cvss"], row["cvss"])
        if not existing["cwe"] and row["cwe"]:
            existing["cwe"] = row["cwe"]
        if len(row["summary"]) > len(existing["summary"]):
            existing["summary"] = row["summary"]
        if _parse_version_tuple(row["version"]) < _parse_version_tuple(existing["version"]):
            existing["version"] = row["version"]
        if _parse_version_tuple(row["upgrade_rec"]) > _parse_version_tuple(existing["upgrade_rec"]):
            existing["upgrade_rec"] = row["upgrade_rec"]

    return list(merged.values())


def main():
    rows = []
    for pkg_name, signature in LIBRARY_SIGNATURES.items():
        print(f"Fetching {pkg_name} from OSV...")
        vulns = fetch_package_vulns(pkg_name)
        print(f"  -> {len(vulns)} advisories found")

        for vuln in vulns:
            introduced, fixed = extract_affected_range(vuln, pkg_name)
            rows.append(
                {
                    "library": pkg_name,
                    "version": introduced or "unknown",
                    "cve": extract_cve_id(vuln),
                    "cvss": extract_cvss(vuln),
                    "cwe": extract_cwe(vuln),
                    "summary": (vuln.get("summary") or vuln.get("details", ""))[:200],
                    "signature": signature,
                    "upgrade_rec": fixed or "see advisory",
                }
            )
        time.sleep(0.5)  # be polite to the free public API

    before = len(rows)
    rows = dedupe_rows(rows)
    print(f"\nDeduped {before} raw entries down to {len(rows)} unique (library, CVE) rows.")

    with OUTPUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "library",
                "version",
                "cve",
                "cvss",
                "cwe",
                "summary",
                "signature",
                "upgrade_rec",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} vulnerability rows to {OUTPUT_CSV}")
    print("Review it, then swap it in for the worker's cve_database.csv "
          "once you're happy with it (keep the old file around for a "
          "before/after comparison in the paper's Evaluation section).")


if __name__ == "__main__":
    main()