#!/usr/bin/env python3
"""
Bravo6 Worker -- OSV CVE Sync (Timer Function backing logic)
=====================================================================
Populates the Table Storage cache test_02_frontend_libs.py reads from
(fetch_cve_dataset_from_table()) by querying OSV.dev for the same fixed
set of npm libraries src/cve-pipeline/cve_etl.py already tracks, on a
schedule (see function_app.py's sync_osv_cve_cache Timer Function) rather
than as a manual, run-on-your-own-machine step.

WHY A SEPARATE MODULE FROM cve_etl.py, NOT A SHARED IMPORT: cve_etl.py
lives in src/cve-pipeline/, a separate tool directory that is never part
of any Azure Functions deployment package -- it's explicitly a "run this
on your own machine" script (see its own docstring). This module lives
inside src/worker/, the Worker Function App's OWN deployment package, so
it can be imported by function_app.py and actually run on a schedule in
Azure. LIBRARY_SIGNATURES below is a deliberate duplicate of
cve_etl.py's dict of the same name -- keep the two in sync by hand (same
convention cve_etl.py already asks of test_02_frontend_libs.py's
fingerprint patterns).

WHY THIS MODULE'S FAULT-HANDLING DIFFERS FROM cve_etl.py'S: cve_etl.py's
fetch_package_vulns() calls resp.raise_for_status(), which propagates an
HTTP error out of main()'s loop and aborts the WHOLE batch over one bad
package -- acceptable for a manual script a human re-runs, not
acceptable for an unattended Timer Function that must not skip every
OTHER library because one OSV query timed out or rate-limited. sync_all()
below catches per-package failures individually (timeout, non-2xx,
malformed JSON) and logs + skips that package, continuing with the rest
-- this is a NEW property, not a port of cve_etl.py's existing behavior.

CACHE-MISS DESIGN NOTE (see test_02_frontend_libs.py's
fetch_cve_dataset_from_table() for the read side of this same decision):
a library this Timer Function fails to fetch (or hasn't reached yet)
simply doesn't get a row written for it -- it is NOT retried inline, and
the scout does NOT fall back to a live OSV call on a per-scan cache miss.
This matches the project's existing fail-safe pattern of treating "no
CVE data available" as "skip CVE correlation for this library, emit the
informational finding instead" (already true today whenever no
cve_csv_url is configured at all) rather than blocking or slowing down a
live scan on a third-party API's availability -- which would silently
reintroduce the exact per-scan OSV coupling this whole change exists to
remove. A cache miss self-heals on the next scheduled run (at most
SYNC_SCHEDULE's interval later), not by paying for a live call mid-scan.
"""
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("Bravo6-Worker.osv_cve_sync")

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_REQUEST_TIMEOUT_SECONDS = 30
# Be polite to the free public API between per-package requests -- same
# figure and rationale as cve_etl.py's time.sleep(0.5).
INTER_REQUEST_DELAY_SECONDS = 0.5

# The exact set of libraries BRAVO6 currently fingerprints, with the same
# detection regex used in test_02_frontend_libs.py / cve_database_v2.csv.
# DUPLICATE of src/cve-pipeline/cve_etl.py's LIBRARY_SIGNATURES -- OSV has
# no concept of "what regex detects this library in a bundled JS file",
# so both copies exist because both sync paths (manual CSV regen, this
# Timer Function) need it, and neither should import across the
# tool-script/deployment-package boundary. Keep both in sync by hand.
LIBRARY_SIGNATURES: Dict[str, str] = {
    "jquery": r"jQuery\.fn\.jquery",
    "lodash": r"_\.VERSION",
    "moment": r"moment\.version",
    "bootstrap": r"Bootstrap\.VERSION",
    "axios": r"axios\.VERSION",
}

# Same ecosystem for every library above today -- Table Storage
# PartitionKey (see write_rows_to_table()). A future PyPI-based library
# would use a different ecosystem value here, in its own partition.
NPM_ECOSYSTEM = "npm"

# Approximate numeric CVSS base score for advisories that only carry a
# qualitative severity label -- same mapping and rationale as
# cve_etl.py's QUALITATIVE_CVSS_MAP.
QUALITATIVE_CVSS_MAP = {
    "LOW": 2.5,
    "MODERATE": 5.4,
    "MEDIUM": 5.4,
    "HIGH": 8.0,
    "CRITICAL": 9.5,
}

MALICIOUS_PACKAGE_CVSS = 9.8
MALICIOUS_PACKAGE_CWE = "CWE-506"


# ------------------------------------------------------------------------------
# OSV response parsing -- ported from src/cve-pipeline/cve_etl.py (see that
# file's docstring for the field-by-field rationale); adapted to fail
# per-vuln rather than raise, since a single malformed advisory must not
# take down the whole sync.
# ------------------------------------------------------------------------------
def extract_cve_id(vuln: dict) -> str:
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return vuln.get("id", "")


def is_malicious_package_entry(vuln: dict) -> bool:
    return vuln.get("id", "").startswith("MAL-")


def extract_cvss(vuln: dict) -> float:
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
    return 0.0


def extract_cwe(vuln: dict) -> str:
    if is_malicious_package_entry(vuln):
        return MALICIOUS_PACKAGE_CWE
    cwes = vuln.get("database_specific", {}).get("cwe_ids", [])
    return cwes[0] if cwes else ""


def extract_affected_range(vuln: dict, pkg_name: str) -> Tuple[str, str]:
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


def build_rows_for_package(pkg_name: str, signature: str, vulns: List[dict]) -> List[Dict[str, Any]]:
    """One row per (library, CVE) -- mirrors cve_database_v2.csv's shape
    exactly (library/min_affected/fixed_in/cve/cvss/cwe/summary/signature/
    upgrade_rec), plus LastUpdated. A single malformed vuln entry is
    logged and skipped, not fatal to the rest of this package's rows."""
    rows = []
    for vuln in vulns:
        try:
            introduced, fixed = extract_affected_range(vuln, pkg_name)
            rows.append({
                "library": pkg_name,
                "min_affected": introduced,
                "fixed_in": fixed,
                "cve": extract_cve_id(vuln),
                "cvss": extract_cvss(vuln),
                "cwe": extract_cwe(vuln),
                "summary": (vuln.get("summary") or vuln.get("details", ""))[:200],
                "signature": signature,
                "upgrade_rec": fixed or "see advisory",
            })
        except Exception as e:
            logger.warning(f"[osv_cve_sync] Skipping malformed OSV advisory for {pkg_name}: {e}")
    return rows


# ------------------------------------------------------------------------------
# Network fetch -- injectable so tests never hit api.osv.dev for real.
# ------------------------------------------------------------------------------
def fetch_package_vulns(http_post: Any, pkg_name: str) -> List[dict]:
    """http_post(url, json, timeout) -> an object with .status_code and
    .json() (matching `requests`' Response shape) OR raises on a network
    failure. Any exception (timeout, connection error, non-2xx, malformed
    JSON) is caught by the caller (sync_all_packages) and treated as
    "this package's data is unavailable this run" -- never fatal to the
    rest of the sync."""
    resp = http_post(
        OSV_QUERY_URL,
        json={"package": {"name": pkg_name, "ecosystem": NPM_ECOSYSTEM}},
        timeout=OSV_REQUEST_TIMEOUT_SECONDS,
    )
    if getattr(resp, "status_code", 200) >= 400:
        raise RuntimeError(f"OSV returned HTTP {resp.status_code} for {pkg_name}")
    data = resp.json()
    return data.get("vulns", [])


def dedupe_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Same (library, cve) merge as cve_etl.py's dedupe_rows() -- OSV can
    surface the same CVE twice (GHSA-sourced + NVD-derived) with slightly
    different values; keep the most conservative/complete of each."""
    merged: Dict[Tuple[str, str], Dict[str, Any]] = {}
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
    return list(merged.values())


def sync_all_packages(http_post: Any, libraries: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
    """Fetches every library in `libraries` (default LIBRARY_SIGNATURES)
    from OSV via http_post, tolerating per-package failures. Returns the
    deduped, flat list of CVE rows ready to write to Table Storage.
    Never raises on a single package's failure -- only an exception from
    http_post itself escaping every retry-worthy path would propagate,
    and http_post has none of its own retries here by design (a skipped
    package this run is retried automatically next run, at most
    SYNC_SCHEDULE's interval later -- see this module's docstring)."""
    libraries = libraries if libraries is not None else LIBRARY_SIGNATURES
    rows: List[Dict[str, Any]] = []
    skipped: List[str] = []

    for pkg_name, signature in libraries.items():
        try:
            vulns = fetch_package_vulns(http_post, pkg_name)
            rows.extend(build_rows_for_package(pkg_name, signature, vulns))
        except Exception as e:
            logger.warning(f"[osv_cve_sync] Failed to fetch {pkg_name} from OSV, skipping this run: {e}")
            skipped.append(pkg_name)
        time.sleep(INTER_REQUEST_DELAY_SECONDS)

    if skipped:
        logger.warning(f"[osv_cve_sync] {len(skipped)}/{len(libraries)} package(s) skipped this run: {skipped}")

    return dedupe_rows(rows)


# ------------------------------------------------------------------------------
# Table Storage write -- injectable so tests never hit real Azure Table
# Storage. table_client matches azure.data.tables[.aio].TableClient's
# upsert_entity() shape.
# ------------------------------------------------------------------------------
def _sanitize_key_part(value: str) -> str:
    """Table Storage forbids '/', '\\', '#', '?' and control characters in
    PartitionKey/RowKey. Library names and CVE ids are alphanumeric plus
    hyphens/dots in practice, but this defends against a surprising OSV
    id shape rather than assuming it."""
    return "".join(c for c in value if c not in "/\\#?" and ord(c) >= 32) or "unknown"


def row_to_entity(row: Dict[str, Any], now: Optional[datetime] = None) -> Dict[str, Any]:
    """Table Storage entity for one CVE row. RowKey is
    "<library>_<cve>" -- unique per (library, CVE), matching
    dedupe_rows()'s own merge key, so a re-sync upserts the same row
    instead of accumulating duplicates."""
    now = now or datetime.now(timezone.utc)
    library = _sanitize_key_part(str(row.get("library", "")))
    cve = _sanitize_key_part(str(row.get("cve", "")) or "no-cve")
    return {
        "PartitionKey": NPM_ECOSYSTEM,
        "RowKey": f"{library}_{cve}",
        "Library": row.get("library", ""),
        "MinAffected": row.get("min_affected", ""),
        "FixedIn": row.get("fixed_in", ""),
        "CveId": row.get("cve", ""),
        "Cvss": float(row.get("cvss", 0.0)),
        "Cwe": row.get("cwe", ""),
        "Summary": row.get("summary", ""),
        "Signature": row.get("signature", ""),
        "UpgradeRec": row.get("upgrade_rec", ""),
        "LastUpdated": now.isoformat(),
    }


def write_rows_to_table(table_client: Any, rows: List[Dict[str, Any]]) -> Tuple[int, int]:
    """table_client.upsert_entity(entity) -- matches
    azure.data.tables.TableClient's synchronous method (the Timer
    Function's real caller awaits the async equivalent; this function
    itself stays sync so it's trivially unit-testable with a plain fake
    object, same as this project's other injected-client patterns).
    Returns (written, failed) counts. A single entity write failure
    (e.g. a transient throttle) is logged and skipped, not fatal to
    writing the rest of the batch -- same fail-isolated philosophy as
    the fetch side."""
    written = 0
    failed = 0
    for row in rows:
        entity = row_to_entity(row)
        try:
            table_client.upsert_entity(entity)
            written += 1
        except Exception as e:
            failed += 1
            logger.warning(
                f"[osv_cve_sync] Failed to write Table Storage row "
                f"{entity['PartitionKey']}/{entity['RowKey']}: {e}"
            )
    return written, failed


def run_sync(http_post: Any, table_client: Any, libraries: Optional[Dict[str, str]] = None) -> Dict[str, int]:
    """The Timer Function's full orchestration, sync (network + Table
    Storage calls are both injected, so this has no I/O of its own to
    mock around in tests). function_app.py's async Timer Function wraps
    this with real, async, Managed-Identity-authenticated clients."""
    rows = sync_all_packages(http_post, libraries)
    written, failed = write_rows_to_table(table_client, rows)
    logger.info(f"[osv_cve_sync] Sync complete: {written} row(s) written, {failed} failed, from {len(rows)} total rows.")
    return {"rows_fetched": len(rows), "rows_written": written, "rows_failed": failed}


# ------------------------------------------------------------------------------
# Test Execution block (matches this project's --test convention)
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse
    import sys
    import unittest

    parser = argparse.ArgumentParser(description="Bravo6 OSV CVE Sync")
    parser.add_argument("--test", action="store_true", help="Run regression suite")
    args = parser.parse_args()

    if args.test:
        class FakeOsvResponse:
            def __init__(self, status_code=200, payload=None):
                self.status_code = status_code
                self._payload = payload or {}

            def json(self):
                return self._payload

        class FakeTableClient:
            """Records every upsert_entity() call; can be told to raise
            for a specific RowKey to simulate a per-entity write failure."""
            def __init__(self, fail_row_keys=None):
                self.entities = {}
                self.fail_row_keys = fail_row_keys or set()

            def upsert_entity(self, entity):
                if entity["RowKey"] in self.fail_row_keys:
                    raise RuntimeError("simulated Table Storage failure")
                self.entities[(entity["PartitionKey"], entity["RowKey"])] = entity

        JQUERY_XSS_VULN = {
            "id": "GHSA-jquery-xss",
            "aliases": ["CVE-2020-11022"],
            "summary": "jQuery XSS via html()",
            "affected": [{
                "package": {"name": "jquery", "ecosystem": "npm"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.2.0"}, {"fixed": "3.5.0"}]}],
            }],
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}],
            "database_specific": {"cwe_ids": ["CWE-79"]},
        }

        MALICIOUS_VULN = {
            "id": "MAL-2024-0001",
            "summary": "Backdoored package version",
            "affected": [{"package": {"name": "leftpad-evil", "ecosystem": "npm"}, "versions": ["9.9.9"]}],
        }

        class TestOsvParsing(unittest.TestCase):
            def test_extract_cve_id_prefers_real_cve(self):
                self.assertEqual(extract_cve_id(JQUERY_XSS_VULN), "CVE-2020-11022")

            def test_extract_cve_id_falls_back_to_advisory_id(self):
                vuln = {"id": "GHSA-no-cve", "aliases": []}
                self.assertEqual(extract_cve_id(vuln), "GHSA-no-cve")

            def test_extract_affected_range_semver(self):
                introduced, fixed = extract_affected_range(JQUERY_XSS_VULN, "jquery")
                self.assertEqual(introduced, "1.2.0")
                self.assertEqual(fixed, "3.5.0")

            def test_malicious_package_gets_fixed_cvss_and_cwe(self):
                self.assertTrue(is_malicious_package_entry(MALICIOUS_VULN))
                self.assertEqual(extract_cvss(MALICIOUS_VULN), MALICIOUS_PACKAGE_CVSS)
                self.assertEqual(extract_cwe(MALICIOUS_VULN), MALICIOUS_PACKAGE_CWE)

            def test_qualitative_severity_maps_to_numeric_cvss(self):
                vuln = {"id": "GHSA-x", "database_specific": {"severity": "HIGH"}}
                self.assertEqual(extract_cvss(vuln), QUALITATIVE_CVSS_MAP["HIGH"])

            def test_unknown_severity_defaults_to_zero_not_raise(self):
                vuln = {"id": "GHSA-y"}
                self.assertEqual(extract_cvss(vuln), 0.0)

            def test_build_rows_for_package_shape_matches_csv_schema(self):
                rows = build_rows_for_package("jquery", LIBRARY_SIGNATURES["jquery"], [JQUERY_XSS_VULN])
                self.assertEqual(len(rows), 1)
                row = rows[0]
                for key in ["library", "min_affected", "fixed_in", "cve", "cvss", "cwe", "summary", "signature", "upgrade_rec"]:
                    self.assertIn(key, row)
                self.assertEqual(row["cve"], "CVE-2020-11022")

            def test_build_rows_for_package_skips_one_malformed_vuln_not_whole_package(self):
                malformed = {"affected": "not-a-list-should-not-crash"}
                rows = build_rows_for_package("jquery", "sig", [JQUERY_XSS_VULN, malformed])
                self.assertEqual(len(rows), 1, "the good vuln must still produce a row despite the bad one")

            def test_dedupe_merges_same_library_cve_keeping_higher_cvss(self):
                low = {"library": "jquery", "cve": "CVE-X", "cvss": 3.0, "cwe": "", "summary": "short"}
                high = {"library": "jquery", "cve": "CVE-X", "cvss": 7.5, "cwe": "CWE-79", "summary": "much longer summary text"}
                merged = dedupe_rows([low, high])
                self.assertEqual(len(merged), 1)
                self.assertEqual(merged[0]["cvss"], 7.5)
                self.assertEqual(merged[0]["cwe"], "CWE-79")
                self.assertEqual(merged[0]["summary"], "much longer summary text")

        class TestFetchFaultIsolation(unittest.TestCase):
            def test_one_bad_package_does_not_abort_the_whole_sync(self):
                """The exact regression cve_etl.py's raise_for_status()
                does NOT protect against: one package timing out must not
                lose every other package's data for this run."""
                def flaky_http_post(url, json, timeout):
                    pkg = json["package"]["name"]
                    if pkg == "lodash":
                        raise TimeoutError("OSV request timed out")
                    return FakeOsvResponse(200, {"vulns": [JQUERY_XSS_VULN]} if pkg == "jquery" else {"vulns": []})

                rows = sync_all_packages(flaky_http_post, {"jquery": "sig1", "lodash": "sig2", "axios": "sig3"})
                libs_with_rows = {r["library"] for r in rows}
                self.assertIn("jquery", libs_with_rows)
                self.assertNotIn("lodash", libs_with_rows, "the timed-out package must simply be absent, not crash the run")

            def test_non_2xx_response_is_skipped_not_fatal(self):
                def http_post(url, json, timeout):
                    return FakeOsvResponse(500, {})

                rows = sync_all_packages(http_post, {"jquery": "sig1"})
                self.assertEqual(rows, [])

            def test_malformed_json_response_is_skipped_not_fatal(self):
                class BrokenJsonResponse:
                    status_code = 200
                    def json(self):
                        raise ValueError("not valid JSON")

                def http_post(url, json, timeout):
                    return BrokenJsonResponse()

                rows = sync_all_packages(http_post, {"jquery": "sig1"})
                self.assertEqual(rows, [])

            def test_all_packages_succeed_normal_case(self):
                def http_post(url, json, timeout):
                    pkg = json["package"]["name"]
                    return FakeOsvResponse(200, {"vulns": [JQUERY_XSS_VULN]} if pkg == "jquery" else {"vulns": []})

                rows = sync_all_packages(http_post, {"jquery": "sig1", "axios": "sig2"})
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["library"], "jquery")

        class TestTableStorageWrite(unittest.TestCase):
            def test_row_to_entity_has_expected_keys_and_partition_scheme(self):
                row = {"library": "jquery", "cve": "CVE-2020-11022", "min_affected": "1.2.0", "fixed_in": "3.5.0",
                       "cvss": 6.1, "cwe": "CWE-79", "summary": "xss", "signature": "sig", "upgrade_rec": "3.5.0"}
                entity = row_to_entity(row)
                self.assertEqual(entity["PartitionKey"], "npm")
                self.assertEqual(entity["RowKey"], "jquery_CVE-2020-11022")
                self.assertEqual(entity["Library"], "jquery")
                self.assertEqual(entity["Cvss"], 6.1)
                self.assertIn("LastUpdated", entity)

            def test_row_key_sanitizes_forbidden_table_storage_characters(self):
                row = {"library": "weird/lib#name", "cve": "CVE?123"}
                entity = row_to_entity(row)
                for forbidden in "/\\#?":
                    self.assertNotIn(forbidden, entity["RowKey"])

            def test_write_rows_to_table_upserts_every_row(self):
                table = FakeTableClient()
                rows = [
                    {"library": "jquery", "cve": "CVE-1", "cvss": 5.0},
                    {"library": "lodash", "cve": "CVE-2", "cvss": 7.0},
                ]
                written, failed = write_rows_to_table(table, rows)
                self.assertEqual(written, 2)
                self.assertEqual(failed, 0)
                self.assertEqual(len(table.entities), 2)

            def test_one_failed_entity_write_does_not_block_the_rest(self):
                table = FakeTableClient(fail_row_keys={"jquery_CVE-1"})
                rows = [
                    {"library": "jquery", "cve": "CVE-1", "cvss": 5.0},
                    {"library": "lodash", "cve": "CVE-2", "cvss": 7.0},
                ]
                written, failed = write_rows_to_table(table, rows)
                self.assertEqual(written, 1)
                self.assertEqual(failed, 1)
                self.assertIn(("npm", "lodash_CVE-2"), table.entities)

            def test_resync_upserts_same_row_instead_of_duplicating(self):
                """Same (library, CVE) synced twice (e.g. two Timer runs)
                must overwrite, not accumulate, matching RowKey's
                uniqueness-per-(library,CVE) design."""
                table = FakeTableClient()
                row = {"library": "jquery", "cve": "CVE-1", "cvss": 5.0, "summary": "first pass"}
                write_rows_to_table(table, [row])
                updated_row = {"library": "jquery", "cve": "CVE-1", "cvss": 9.0, "summary": "second pass, rescored"}
                write_rows_to_table(table, [updated_row])
                self.assertEqual(len(table.entities), 1)
                self.assertEqual(table.entities[("npm", "jquery_CVE-1")]["Cvss"], 9.0)

        class TestRunSyncOrchestration(unittest.TestCase):
            def test_run_sync_end_to_end_with_fakes(self):
                def http_post(url, json, timeout):
                    pkg = json["package"]["name"]
                    return FakeOsvResponse(200, {"vulns": [JQUERY_XSS_VULN]} if pkg == "jquery" else {"vulns": []})

                table = FakeTableClient()
                summary = run_sync(http_post, table, {"jquery": "sig1", "axios": "sig2"})
                self.assertEqual(summary["rows_written"], 1)
                self.assertEqual(summary["rows_failed"], 0)
                self.assertEqual(len(table.entities), 1)

        sys.argv = [sys.argv[0]]
        unittest.main()
