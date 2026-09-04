#!/usr/bin/env python3
"""
aggregate_results.py - Bravo6 Evaluation Harness: Result Aggregator
=====================================================================
Reads a batch folder written by run_evaluation.py (its manifest.csv plus
the per-site JSON result files it references) and produces a single CSV,
aggregate.csv, with one row per site -- the direct input for the paper's
Evaluation tables/charts.

Column values are pulled straight from main_scanner.py's final_result
schema (see run_scout()'s return value) -- no field is renamed, reshaped,
or invented. For a site that failed entirely (manifest status != success,
so there is no JSON result file at all), the row is still emitted with
rank/domain/url filled in and every scanner-derived field left blank,
per the spec: "leave it blank rather than guessing or omitting the row."

`modules_discovered` is not a literal field in final_result -- it's
derived as len(result["tests"]), since main_scanner.py populates one
"tests" entry per discovered plugin regardless of whether that plugin
completed, errored, or timed out (see run_scout()'s dispatch loop). This
is a read of an existing field's cardinality, not an invented value.

Two more derived columns, added so a future per-scout or per-check
question doesn't require re-opening every per-site JSON (or writing a new
one-off script) the way this session had to for the n=500 FINAL batch:

  - `findings_by_scout`: a compact JSON object string, {module_name:
    finding_count}, built from result["findings"][*]["module"]. Answers
    "how many sites had >=1 finding from scout X" or "mean findings per
    scout" directly from aggregate.csv (e.g.
    json.loads(row["findings_by_scout"]).get("test_09_sri", 0)).
  - `ocsp_stapling`: the tri-state OCSP result from
    tests.test_04_ssl_tls.details.ocsp_stapling ("true" / "false" /
    "unknown" -- stapled / confirmed-not-stapled / could-not-be-determined,
    per the openssl -status probe). Recorded directly rather than via the
    finding's confidence string so "checked and confirmed absent" is
    visible without re-deriving it from finding text.

Usage:
    python3 aggregate_results.py results/20260829T214512Z
    python3 aggregate_results.py results/20260829T214512Z --output custom_name.csv
"""
import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, Optional

AGGREGATE_FIELDS = [
    "url", "rank", "score", "raw_score", "grade", "grade_reliable", "coverage_note",
    "total_findings", "critical", "high", "medium", "low", "info",
    "tests_run", "modules_discovered", "waf", "page_is_representative", "duration_seconds",
    "findings_by_scout", "ocsp_stapling",
]


def _findings_by_scout(result: Dict[str, Any]) -> str:
    counts: Dict[str, int] = {}
    for f in result.get("findings") or []:
        module = f.get("module")
        if module:
            counts[module] = counts.get(module, 0) + 1
    return json.dumps(counts, sort_keys=True)


def _ocsp_stapling_status(result: Dict[str, Any]) -> Optional[str]:
    """Tri-state OCSP result from test_04_ssl_tls's own `details` dict:
    True (stapled) / False (server confirmed it sent none) / None (probe
    could not be completed, or test_04 didn't run at all -- e.g. a
    WAF-blocked scan still runs test_04, but a scan that predates the
    openssl -status fix won't carry this key)."""
    test_04 = (result.get("tests") or {}).get("test_04_ssl_tls") or {}
    details = test_04.get("details") or {}
    if "ocsp_stapling" not in details:
        return None
    value = details["ocsp_stapling"]
    if value is True:
        return "true"
    if value is False:
        return "false"
    return "unknown"


def _load_manifest(batch_dir: Path):
    manifest_path = batch_dir / "manifest.csv"
    if not manifest_path.exists():
        raise FileNotFoundError(f"{manifest_path} not found -- run run_evaluation.py first.")
    with manifest_path.open("r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _row_from_result(url: str, rank: Optional[str], result: Dict[str, Any]) -> Dict[str, Any]:
    summary = result.get("summary") or {}
    tests = result.get("tests") or {}
    return {
        "url": result.get("url", url),
        "rank": rank,
        "score": result.get("score"),
        "raw_score": result.get("raw_score"),
        "grade": result.get("grade"),
        "grade_reliable": result.get("grade_reliable"),
        "coverage_note": result.get("coverage_note"),
        "total_findings": result.get("total_findings"),
        "critical": summary.get("critical"),
        "high": summary.get("high"),
        "medium": summary.get("medium"),
        "low": summary.get("low"),
        "info": summary.get("info"),
        "tests_run": result.get("tests_run"),
        "modules_discovered": len(tests) if tests else None,
        "waf": result.get("waf"),
        "page_is_representative": result.get("page_is_representative"),
        "duration_seconds": result.get("duration_seconds"),
        "findings_by_scout": _findings_by_scout(result),
        "ocsp_stapling": _ocsp_stapling_status(result),
    }


def _blank_row(url: str, rank: Optional[str]) -> Dict[str, Any]:
    row = {field: None for field in AGGREGATE_FIELDS}
    row["url"] = url
    row["rank"] = rank
    return row


def aggregate(batch_dir: Path, output_path: Optional[Path] = None) -> Path:
    manifest_rows = _load_manifest(batch_dir)
    output_path = output_path or (batch_dir / "aggregate.csv")

    out_rows = []
    for m in manifest_rows:
        url = m.get("url", "")
        rank = m.get("rank") or None

        if m.get("status") == "success" and m.get("result_file"):
            result_path = batch_dir / m["result_file"]
            if result_path.exists():
                with result_path.open("r", encoding="utf-8") as f:
                    result = json.load(f)
                out_rows.append(_row_from_result(url, rank, result))
                continue
            # manifest claims success but the file is missing -- don't
            # silently drop the row, fall through to the blank-row path.

        out_rows.append(_blank_row(url, rank))

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=AGGREGATE_FIELDS)
        writer.writeheader()
        for row in out_rows:
            writer.writerow(row)

    print(f"[*] Wrote {len(out_rows)} row(s) to {output_path}")
    return output_path


def build_arg_parser():
    parser = argparse.ArgumentParser(description="Aggregate a run_evaluation.py batch folder into a single CSV.")
    parser.add_argument("batch_dir", help="Path to the batch folder (evaluation/results/<batch_id>).")
    parser.add_argument("--output", default=None, help="Output CSV path. Default: <batch_dir>/aggregate.csv")
    return parser


if __name__ == "__main__":
    args = build_arg_parser().parse_args()
    aggregate(Path(args.batch_dir), Path(args.output) if args.output else None)
