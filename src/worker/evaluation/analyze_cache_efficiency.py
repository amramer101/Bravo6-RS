#!/usr/bin/env python3
"""
analyze_cache_efficiency.py - Bravo6 Evaluation Harness: Cache-Read Efficiency
=====================================================================
Reconstructs, as permanent/reusable tooling, the ScannerContext cache-read
efficiency analysis originally computed by a one-off script for the paper's
§V.2 (the 20260903T182513Z_n500_c3_10scouts_FINAL batch's
cache_counter_n500_summary.json). That script was never committed -- only
its JSON output sat in the (gitignored) batch results directory, so neither
the method nor the number was reproducible from what was in the repo. This
is its committed replacement.

Reads ctx.metrics (base_url_gets, cache_reads -- see main_scanner.py's
ScannerContext and fetch_main_page_and_analyze()) from each per-site result
JSON in a batch directory, and reports cache-read efficiency separately for
three subsets, reusing analyze_evaluation.py's own coverage-breakdown
categorization so the two analyses can't drift apart on what counts as
"reliable" / "partial" / "non-representative":

  - reliable:            grade_reliable == True (all discovered modules ran
                          on a representative page)
  - partial:              partial module completion despite a
                          representative page (categorize_unreliable_reason
                          == "partial_completion_representative_page")
  - non_representative:  everything else (no reachable web server, or a
                          WAF/anti-bot block) -- the six cache-consuming
                          scouts bail at the representativeness gate before
                          ever reading the cache, so 0 reads / 1 base_url_get
                          here is the EXPECTED, correct shape, not a caching
                          failure.

For each subset: the full distribution of cache_reads and base_url_gets
per scan (not just the mean -- "zero variance" is a claim about the
distribution having one single value, which a mean alone can't show),
pooled totals, and the pct of would-be redundant requests avoided.

Usage:
    python3 analyze_cache_efficiency.py results/<batch_id>
"""
import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from analyze_evaluation import (
    load_aggregate_rows,
    load_result_jsons_by_url,
    categorize_unreliable_reason,
)


def _subset_for_row(row: Dict[str, Any], jsons_by_url: Dict[str, Dict[str, Any]]) -> str:
    if row["grade_reliable"] is True:
        return "reliable"
    result = jsons_by_url.get(row["url"])
    if result and categorize_unreliable_reason(result) == "partial_completion_representative_page":
        return "partial"
    return "non_representative"


def analyze_cache_efficiency(batch_dir: Path) -> Dict[str, Any]:
    all_rows = load_aggregate_rows(batch_dir)
    jsons_by_url = load_result_jsons_by_url(batch_dir)

    subsets: Dict[str, List[Dict[str, int]]] = defaultdict(list)
    skipped_no_metrics = 0

    for row in all_rows:
        result = jsons_by_url.get(row["url"])
        if not result:
            continue  # scan failed entirely -- no result JSON, nothing to read
        metrics = result.get("metrics") or {}
        cache_reads = metrics.get("cache_reads")
        base_url_gets = metrics.get("base_url_gets")
        if cache_reads is None or base_url_gets is None:
            skipped_no_metrics += 1  # result predates this counter existing
            continue
        subset = _subset_for_row(row, jsons_by_url)
        subsets[subset].append({"cache_reads": cache_reads, "base_url_gets": base_url_gets})

    out: Dict[str, Any] = {
        "batch_id": batch_dir.name,
        "sites_skipped_no_cache_metrics": skipped_no_metrics,
        "subsets": {},
    }

    pooled_reads = pooled_gets = 0
    for name, entries in subsets.items():
        reads = [e["cache_reads"] for e in entries]
        gets = [e["base_url_gets"] for e in entries]
        total_reads, total_gets = sum(reads), sum(gets)
        pooled_reads += total_reads
        pooled_gets += total_gets
        would_be = total_reads + total_gets
        out["subsets"][name] = {
            "n": len(entries),
            "cache_reads_distribution": dict(sorted(Counter(reads).items())),
            "base_url_gets_distribution": dict(sorted(Counter(gets).items())),
            "total_cache_reads": total_reads,
            "total_base_url_gets": total_gets,
            "total_would_be_requests": would_be,
            "requests_avoided": total_reads,
            "pct_avoided": round(100.0 * total_reads / would_be, 1) if would_be else None,
        }

    pooled_would_be = pooled_reads + pooled_gets
    out["pooled"] = {
        "total_cache_reads": pooled_reads,
        "total_base_url_gets": pooled_gets,
        "total_would_be_requests": pooled_would_be,
        "requests_avoided": pooled_reads,
        "pct_avoided": round(100.0 * pooled_reads / pooled_would_be, 1) if pooled_would_be else None,
    }
    return out


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Compute ScannerContext cache-read efficiency for a run_evaluation.py batch."
    )
    parser.add_argument("batch_dir", help="Path to the batch folder (evaluation/results/<batch_id>).")
    parser.add_argument("--output", default=None, help="Output JSON path. Default: <batch_dir>/cache_efficiency.json")
    return parser


if __name__ == "__main__":
    args = build_arg_parser().parse_args()
    batch_dir = Path(args.batch_dir)
    analysis = analyze_cache_efficiency(batch_dir)
    out_path = Path(args.output) if args.output else (batch_dir / "cache_efficiency.json")
    out_path.write_text(json.dumps(analysis, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(analysis, indent=2, ensure_ascii=False))
    print(f"[*] Wrote {out_path}")
