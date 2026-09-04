#!/usr/bin/env python3
"""
tier_fix_counterfactual.py - Bravo6 Evaluation Harness: Tier-Fix Impact
=====================================================================
Reconstructs, as permanent/reusable tooling, the tier-assignment-fix
counterfactual originally computed by a one-off script for the paper's
§XII.3 (d9beb5d: "OCSP Stapling Not Enabled" / "Missing DNS CAA Record"
moved from the uncapped baseline scoring pool into the pooled, capped
hardening pool). That script was never committed -- only its conclusions
made it into the paper -- so the number wasn't reproducible from what was
in the repo. This is its committed replacement.

Isolates the fix's OWN scoring impact by re-scoring each site's ALREADY-
COMPUTED findings twice with the REAL, current main_scanner.compute_
bravo6_score() (not a reimplementation):

  - "fixed": as actually scored today (each finding's own current `tier`)
  - "buggy": as if AFFECTED_TITLES had never been tagged tier="hardening"
             (the pre-d9beb5d behavior -- untagged findings fall through
             to the uncapped baseline pool)

holding every other input (the scan's actual findings, tests_run,
page_is_representative, ...) fixed. Comparing two full batches run on
different dates instead would also pick up target-side churn, the new
scouts, and any other code changes between them -- exactly the confound
§XII.4 discusses, which is why this project's own evaluation methodology
insists on a same-batch counterfactual rather than a batch-to-batch
subtraction for this specific claim.

Usage:
    python3 tier_fix_counterfactual.py results/<batch_id>
"""
import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any, Dict, List

WORKER_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(WORKER_DIR))
import main_scanner  # noqa: E402

# Finding titles the d9beb5d fix moved from the uncapped baseline pool into
# the pooled, capped hardening pool. Extend this set (and the commit this
# docstring cites) if any other finding's default tier is ever corrected
# the same way.
AFFECTED_TITLES = {
    "OCSP Stapling Not Enabled",
    "Missing DNS CAA Record",
}


def _buggy_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """A copy of `findings` with every AFFECTED_TITLES finding's tier
    cleared, reproducing the pre-fix behavior -- without mutating the
    caller's data (compute_bravo6_score() doesn't mutate its input either,
    but this keeps the two re-scoring passes below fully independent)."""
    out = []
    for f in findings:
        if f.get("title") in AFFECTED_TITLES and f.get("tier") == "hardening":
            f = dict(f)
            f["tier"] = ""
            f.pop("raw_data", None)  # pre-item-3 results may still carry a nested tier here
        out.append(f)
    return out


def _score(findings: List[Dict[str, Any]], result: Dict[str, Any]) -> Dict[str, Any]:
    return main_scanner.compute_bravo6_score(
        findings,
        waf=result.get("waf"),
        tests_run=result.get("tests_run"),
        modules_discovered=len(result.get("tests") or {}) or None,
        page_is_representative=result.get("page_is_representative", True),
    )


def analyze_tier_fix_counterfactual(batch_dir: Path) -> Dict[str, Any]:
    result_paths = sorted(batch_dir.glob("rank_*.json"))
    per_site = []

    for path in result_paths:
        try:
            result = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        findings = result.get("findings") or []
        affected = [f for f in findings if f.get("title") in AFFECTED_TITLES and f.get("tier") == "hardening"]
        if not affected:
            continue

        fixed_info = _score(findings, result)
        buggy_info = _score(_buggy_findings(findings), result)

        # Positive score_shift = the fix INCREASED the visible score (the
        # capped hardening pool deducts less than the old uncapped baseline
        # pool did) -- matches the paper's "+3.44 mean, max +4" framing.
        per_site.append({
            "url": result.get("url"),
            "affected_finding_titles": sorted({f["title"] for f in affected}),
            "fixed_score": fixed_info["score"],
            "fixed_grade": fixed_info["grade"],
            "buggy_score": buggy_info["score"],
            "buggy_grade": buggy_info["grade"],
            "score_shift": fixed_info["score"] - buggy_info["score"],
            "grade_crossed": fixed_info["grade"] != buggy_info["grade"],
        })

    shifted = [s for s in per_site if s["score_shift"] != 0]
    crossed = [s for s in per_site if s["grade_crossed"]]
    shifts = [s["score_shift"] for s in shifted]

    return {
        "batch_id": batch_dir.name,
        "n_total_sites": len(result_paths),
        "n_sites_carrying_an_affected_finding": len(per_site),
        "n_sites_with_a_different_visible_score": len(shifted),
        "mean_score_shift_among_shifted": round(statistics.mean(shifts), 2) if shifts else None,
        "max_score_shift": max(shifts, key=abs) if shifts else None,
        "n_letter_grade_crossings": len(crossed),
        "letter_grade_crossings": [
            {"url": s["url"], "fixed_grade": s["fixed_grade"], "buggy_grade": s["buggy_grade"]}
            for s in crossed
        ],
        "per_site": per_site,
    }


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Re-score a run_evaluation.py batch's findings under the pre-d9beb5d "
                    "(buggy) OCSP/CAA tier assignment to isolate the fix's own scoring impact."
    )
    parser.add_argument("batch_dir", help="Path to the batch folder (evaluation/results/<batch_id>).")
    parser.add_argument("--output", default=None, help="Output JSON path. Default: <batch_dir>/tier_fix_counterfactual.json")
    return parser


if __name__ == "__main__":
    args = build_arg_parser().parse_args()
    batch_dir = Path(args.batch_dir)
    analysis = analyze_tier_fix_counterfactual(batch_dir)
    out_path = Path(args.output) if args.output else (batch_dir / "tier_fix_counterfactual.json")
    out_path.write_text(json.dumps(analysis, indent=2, ensure_ascii=False), encoding="utf-8")
    summary = {k: v for k, v in analysis.items() if k not in ("per_site", "letter_grade_crossings")}
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"[*] Wrote {out_path}")
