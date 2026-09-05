#!/usr/bin/env python3
"""
ocsp_fix_impact.py - Bravo6 Evaluation Harness: OCSP-Check-Fix Scoring Impact
=====================================================================
Isolates the OCSP-stapling-check fix's (test_04: make OCSP-stapling check
functional) downstream scoring impact on a batch's ALREADY-COMPUTED
findings, the same way tier_fix_counterfactual.py isolates the tier-
assignment fix's impact -- a same-batch counterfactual, not a
batch-to-batch subtraction, so it can't be confounded by target-side churn
between two scans run on different dates (see §XII.4's discussion of that
exact confound for the tier fix).

Background: the fix did not change the "OCSP Stapling Not Enabled"
finding's tier (still "hardening", pooled/capped) or its base severity
(still "low") -- only WHETHER it fires at all. Before the fix, every
TLS-reachable site got it unconditionally. After the fix, it fires only on
a confirmed-absent (openssl -status "no response sent") result; a
confirmed-stapled site gets no finding, and an inconclusive probe gets a
separate, differently-titled finding instead. So the counterfactual here is
narrower than the tier fix's: for every site where the NEW code did NOT
fire "OCSP Stapling Not Enabled" (test_04_ssl_tls.details.ocsp_stapling is
True or None) but test_04 ran, synthesize that finding (as the old,
unconditional code would have emitted it) into that site's real findings
and re-score with the REAL, current main_scanner.compute_bravo6_score() --
then compare against the actual (fixed) score. A site that already got the
finding under the new code (confirmed-absent) has NO counterfactual to
construct: the fix didn't change its outcome.

Usage:
    python3 ocsp_fix_impact.py results/<batch_id>
"""
import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

WORKER_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(WORKER_DIR))
import main_scanner  # noqa: E402

OCSP_TITLE = "OCSP Stapling Not Enabled"


def _synthetic_old_ocsp_finding(hostname_port: str) -> Dict[str, Any]:
    """Reconstructs the pre-fix finding shape: unconditional, tier
    "hardening" (that part never changed), confidence "informational" (the
    pre-fix blanket value -- the fix's other change was upgrading
    confirmed-absent results to "verified-live", which is irrelevant to
    scoring but kept here for an accurate reconstruction)."""
    return {
        "title": OCSP_TITLE,
        "severity": "low",
        "confidence": "informational",
        "tier": "hardening",
    }


def _score(findings: List[Dict[str, Any]], result: Dict[str, Any]) -> Dict[str, Any]:
    return main_scanner.compute_bravo6_score(
        findings,
        waf=result.get("waf"),
        tests_run=result.get("tests_run"),
        modules_discovered=len(result.get("tests") or {}) or None,
        page_is_representative=result.get("page_is_representative", True),
    )


def analyze_ocsp_fix_impact(batch_dir: Path) -> Dict[str, Any]:
    result_paths = sorted(batch_dir.glob("rank_*.json"))
    per_site = []
    test04_ran = 0

    for path in result_paths:
        try:
            result = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue

        test_04 = (result.get("tests") or {}).get("test_04_ssl_tls") or {}
        details = test_04.get("details") or {}
        if "ocsp_stapling" not in details:
            continue  # test_04 didn't run (or predates this key) -- nothing to compare
        test04_ran += 1

        ocsp_stapling = details["ocsp_stapling"]
        if ocsp_stapling is False:
            continue  # confirmed-absent under the NEW code too -- the fix changed nothing here

        findings = result.get("findings") or []
        location = f"TLS Handshake {result.get('url', '')}"
        buggy_findings = findings + [_synthetic_old_ocsp_finding(location)]

        fixed_info = _score(findings, result)
        buggy_info = _score(buggy_findings, result)

        per_site.append({
            "url": result.get("url"),
            "new_ocsp_stapling_result": "stapled" if ocsp_stapling is True else "inconclusive",
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
        "n_sites_test04_ran": test04_ran,
        "n_sites_where_fix_changed_the_ocsp_outcome": len(per_site),
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
        description="Re-score a batch's findings under the pre-fix (unconditional) OCSP-stapling "
                    "behavior to isolate that fix's own scoring impact."
    )
    parser.add_argument("batch_dir", help="Path to the batch folder (evaluation/results/<batch_id>).")
    parser.add_argument("--output", default=None, help="Output JSON path. Default: <batch_dir>/ocsp_fix_impact.json")
    return parser


if __name__ == "__main__":
    args = build_arg_parser().parse_args()
    batch_dir = Path(args.batch_dir)
    analysis = analyze_ocsp_fix_impact(batch_dir)
    out_path = Path(args.output) if args.output else (batch_dir / "ocsp_fix_impact.json")
    out_path.write_text(json.dumps(analysis, indent=2, ensure_ascii=False), encoding="utf-8")
    summary = {k: v for k, v in analysis.items() if k not in ("per_site", "letter_grade_crossings")}
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    print(f"[*] Wrote {out_path}")
