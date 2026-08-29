#!/usr/bin/env python3
"""
analyze_evaluation.py - Bravo6 Evaluation Harness: Descriptive Statistics
=====================================================================
Reads a batch folder written by run_evaluation.py / aggregate_results.py
(aggregate.csv for per-site summary fields, the individual rank_*.json
files for anything needing a per-finding/per-module breakdown that
aggregate.csv doesn't carry) and computes the descriptive statistics the
paper's Evaluation section needs.

THE CENTRAL RULE THIS SCRIPT ENFORCES: score/grade statistics and findings
statistics are computed ONLY over grade_reliable == True rows. A site the
scanner could only partially assess (WAF-blocked, no web server at all,
etc.) has no business being averaged into "the typical score" or "the
typical findings per site" -- doing so would misrepresent what the
scanner actually found. Every function that touches score/grade/findings
numbers filters to reliable rows first; the coverage and WAF/vendor
sections deliberately use ALL rows instead, since those are about
characterizing the sample itself, not the scanner's assessment quality.

Usage:
    python3 analyze_evaluation.py results/<batch_id>
"""
import argparse
import csv
import json
import re
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

# ------------------------------------------------------------------------------
# grade_reliable == False sub-categorization
# ------------------------------------------------------------------------------
# Reuses, programmatically, exactly the signal the manual audit used by hand
# to tell "no web server at all" (vkuseraudio.net vs awsdns-44.com /
# bilivideo.com) apart: test_04_ssl_tls connects independently of the
# orchestrator's own HTTP fetch (it operates below the HTTP layer). If IT
# also failed to complete a TLS handshake at all, there's no real web
# server to speak of. If it completed, DNS + TLS both worked, and the
# block is happening at the HTTP/application layer instead (WAF, anti-bot,
# hard error) -- exactly what happened on vkuseraudio.net (HTTP 418) and
# elcorteingles.es (Akamai "Access Denied").
CONNECTION_FAILURE_MARKERS = (
    "no address associated with hostname",
    "gaierror",
    "connection failed entirely",
    "name or service not known",
    "connection refused",
    "timed out",
    "cannot connect to host",
    "nodename nor servname provided",
)

CATEGORY_LABELS = {
    "no_web_server": "No resolvable web server at all (DNS/connection failure)",
    "waf_or_anti_bot_block": "WAF/anti-bot block on a real web server",
    "partial_completion_representative_page": "Partial module completion despite a representative page",
    "other_unclassified": "Other / unclassified",
}


def categorize_unreliable_reason(result: Dict[str, Any]) -> str:
    """Sub-categorize one grade_reliable=False site's full JSON result by
    root cause. See module docstring / CONNECTION_FAILURE_MARKERS comment
    for the reasoning."""
    page_is_representative = result.get("page_is_representative")
    tests = result.get("tests") or {}
    tls = tests.get("test_04_ssl_tls") or {}
    tls_status = tls.get("status")
    tls_error = str(tls.get("fatal_error") or "").lower()

    if page_is_representative is False:
        if tls_status == "incomplete" and any(marker in tls_error for marker in CONNECTION_FAILURE_MARKERS):
            return "no_web_server"
        return "waf_or_anti_bot_block"

    tests_run = result.get("tests_run")
    modules_discovered = len(tests) if tests else None
    if tests_run is not None and modules_discovered is not None and tests_run < modules_discovered:
        return "partial_completion_representative_page"

    return "other_unclassified"


# ------------------------------------------------------------------------------
# Loading
# ------------------------------------------------------------------------------
def _coerce_bool(v: Any) -> Optional[bool]:
    if v in (True, "True", "true"):
        return True
    if v in (False, "False", "false"):
        return False
    return None  # blank/missing -- distinct from False, see analyze()


def _coerce_float(v: Any) -> Optional[float]:
    try:
        if v is None or v == "":
            return None
        return float(v)
    except (TypeError, ValueError):
        return None


def _coerce_int(v: Any) -> Optional[int]:
    f = _coerce_float(v)
    return int(f) if f is not None else None


def load_aggregate_rows(batch_dir: Path) -> List[Dict[str, Any]]:
    path = batch_dir / "aggregate.csv"
    if not path.exists():
        raise FileNotFoundError(f"{path} not found -- run aggregate_results.py first.")
    rows = []
    with path.open("r", newline="", encoding="utf-8") as f:
        for raw in csv.DictReader(f):
            rows.append({
                "url": raw.get("url", ""),
                "rank": _coerce_int(raw.get("rank")),
                "score": _coerce_float(raw.get("score")),
                "raw_score": _coerce_float(raw.get("raw_score")),
                "grade": raw.get("grade") or None,
                "grade_reliable": _coerce_bool(raw.get("grade_reliable")),
                "coverage_note": raw.get("coverage_note") or None,
                "total_findings": _coerce_int(raw.get("total_findings")),
                "critical": _coerce_int(raw.get("critical")),
                "high": _coerce_int(raw.get("high")),
                "medium": _coerce_int(raw.get("medium")),
                "low": _coerce_int(raw.get("low")),
                "info": _coerce_int(raw.get("info")),
                "tests_run": _coerce_int(raw.get("tests_run")),
                "modules_discovered": _coerce_int(raw.get("modules_discovered")),
                "waf": raw.get("waf") or None,
                "page_is_representative": _coerce_bool(raw.get("page_is_representative")),
                "duration_seconds": _coerce_float(raw.get("duration_seconds")),
            })
    return rows


def load_result_jsons_by_url(batch_dir: Path) -> Dict[str, Dict[str, Any]]:
    """Load every rank_*.json in the batch folder, keyed by each result's
    own "url" field (authoritative -- not parsed from the filename)."""
    by_url = {}
    for path in sorted(batch_dir.glob("rank_*.json")):
        try:
            with path.open("r", encoding="utf-8") as f:
                result = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        url = result.get("url")
        if url:
            by_url[url] = result
    return by_url


def load_batch_wall_clock_seconds(batch_dir: Path) -> Optional[float]:
    path = batch_dir / "run_summary.txt"
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    m = re.search(r"Total wall-clock time:\s*([\d.]+)s", text)
    return float(m.group(1)) if m else None


# ------------------------------------------------------------------------------
# 1. Coverage breakdown (all sites)
# ------------------------------------------------------------------------------
def compute_coverage_breakdown(all_rows: List[Dict[str, Any]], jsons_by_url: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    total = len(all_rows)
    reliable = [r for r in all_rows if r["grade_reliable"] is True]
    unreliable = [r for r in all_rows if r["grade_reliable"] is False]
    # grade_reliable blank (neither True nor False) means the scan never
    # produced a result at all -- aggregate_results.py's documented
    # "blank rather than guess" contract for a site run_evaluation.py
    # recorded as failed. Distinct from "scanned but unreliable".
    scan_failed = [r for r in all_rows if r["grade_reliable"] is None]

    def pct(n, d):
        return round(100.0 * n / d, 1) if d else None

    sub_counts = Counter()
    sub_sites = defaultdict(list)
    for r in unreliable:
        result = jsons_by_url.get(r["url"])
        cat = categorize_unreliable_reason(result) if result else "other_unclassified"
        sub_counts[cat] += 1
        sub_sites[cat].append(r["url"])

    return {
        "total_sites": total,
        "reliable": {"count": len(reliable), "pct_of_total": pct(len(reliable), total)},
        "unreliable": {"count": len(unreliable), "pct_of_total": pct(len(unreliable), total)},
        "scan_failed_entirely": {"count": len(scan_failed), "pct_of_total": pct(len(scan_failed), total)},
        "unreliable_subcategories": {
            CATEGORY_LABELS[cat]: {
                "count": c,
                "pct_of_unreliable": pct(c, len(unreliable)),
                "sites": sub_sites[cat],
            }
            for cat, c in sub_counts.most_common()
        },
    }


# ------------------------------------------------------------------------------
# 2. Score/grade statistics -- grade_reliable == True rows ONLY
# ------------------------------------------------------------------------------
def compute_score_stats(reliable_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    n = len(reliable_rows)
    scores = [r["score"] for r in reliable_rows if r["score"] is not None]
    grades = [r["grade"] for r in reliable_rows if r["grade"]]
    grade_counts = Counter(grades)

    return {
        "n_reliable_sites": n,
        "mean_score": round(statistics.mean(scores), 2) if scores else None,
        "median_score": statistics.median(scores) if scores else None,
        "stdev_score": round(statistics.stdev(scores), 2) if len(scores) >= 2 else None,
        "grade_distribution": {
            g: {"count": c, "pct": round(100.0 * c / n, 1) if n else None}
            for g, c in sorted(grade_counts.items())
        },
    }


# ------------------------------------------------------------------------------
# 3. Findings breakdown -- grade_reliable == True rows ONLY
# ------------------------------------------------------------------------------
def compute_findings_stats(reliable_rows: List[Dict[str, Any]], jsons_by_url: Dict[str, Dict[str, Any]], top_n: int = 15) -> Dict[str, Any]:
    n = len(reliable_rows)
    totals = [r["total_findings"] for r in reliable_rows if r["total_findings"] is not None]

    sev_means = {}
    for sev in ("critical", "high", "medium", "low", "info"):
        vals = [r[sev] for r in reliable_rows if r[sev] is not None]
        sev_means[sev] = round(statistics.mean(vals), 2) if vals else None

    # Site-presence count, not raw occurrence count: does this title appear
    # at least once on this site's findings? (A title could in principle
    # repeat within one site's own findings list, but that would just mean
    # deduplicate_findings() let a real distinct-location duplicate
    # through -- we still want "how many SITES had this finding", not an
    # inflated count from one site.)
    title_site_counts = Counter()
    for r in reliable_rows:
        result = jsons_by_url.get(r["url"])
        if not result:
            continue
        titles_on_this_site = {f.get("title", "") for f in (result.get("findings") or [])}
        for title in titles_on_this_site:
            if title:
                title_site_counts[title] += 1

    top_titles = [
        {"title": title, "site_count": count, "pct_of_reliable_sites": round(100.0 * count / n, 1) if n else None}
        for title, count in title_site_counts.most_common(top_n)
    ]

    return {
        "n_reliable_sites": n,
        "mean_total_findings": round(statistics.mean(totals), 2) if totals else None,
        "mean_findings_by_severity": sev_means,
        "top_finding_titles": top_titles,
    }


# ------------------------------------------------------------------------------
# 4. WAF/vendor distribution -- ALL sites (characterizes the sample, not scan quality)
# ------------------------------------------------------------------------------
def compute_waf_distribution(all_rows: List[Dict[str, Any]], jsons_by_url: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    vendor_counts = Counter()
    blocked_unattributed = 0

    for r in all_rows:
        waf = (r["waf"] or "").strip()
        if waf:
            vendor_counts[waf] += 1
            continue
        # "Blocked but unattributed" specifically means: this scout
        # concluded it WAS a WAF/anti-bot block (not simply "no web server
        # at all", which isn't a named-vendor-list gap -- there's no vendor
        # to attribute when there's no server responding) but couldn't
        # name the vendor. That's the coverage limitation of the 5-vendor
        # named list the last audit flagged (e.g. vkuseraudio.net's
        # unrecognized "kittenx" anti-bot product).
        if r["grade_reliable"] is False:
            result = jsons_by_url.get(r["url"])
            if result and categorize_unreliable_reason(result) == "waf_or_anti_bot_block":
                blocked_unattributed += 1

    return {
        "total_sites": len(all_rows),
        "vendor_counts": dict(vendor_counts.most_common()),
        "blocked_unattributed": blocked_unattributed,
    }


# ------------------------------------------------------------------------------
# 5. Runtime statistics -- ALL sites
# ------------------------------------------------------------------------------
def compute_runtime_stats(all_rows: List[Dict[str, Any]], batch_dir: Path) -> Dict[str, Any]:
    durations = [r["duration_seconds"] for r in all_rows if r["duration_seconds"] is not None]
    return {
        "mean_duration_seconds": round(statistics.mean(durations), 2) if durations else None,
        "median_duration_seconds": statistics.median(durations) if durations else None,
        "max_duration_seconds": max(durations) if durations else None,
        "batch_wall_clock_seconds": load_batch_wall_clock_seconds(batch_dir),
    }


# ------------------------------------------------------------------------------
# Orchestration
# ------------------------------------------------------------------------------
def analyze(batch_dir: Path) -> Dict[str, Any]:
    all_rows = load_aggregate_rows(batch_dir)
    jsons_by_url = load_result_jsons_by_url(batch_dir)
    reliable_rows = [r for r in all_rows if r["grade_reliable"] is True]

    return {
        "batch_id": batch_dir.name,
        "coverage": compute_coverage_breakdown(all_rows, jsons_by_url),
        "score_stats": compute_score_stats(reliable_rows),
        "findings_stats": compute_findings_stats(reliable_rows, jsons_by_url),
        "waf_distribution": compute_waf_distribution(all_rows, jsons_by_url),
        "runtime_stats": compute_runtime_stats(all_rows, batch_dir),
    }


# ------------------------------------------------------------------------------
# Text formatting
# ------------------------------------------------------------------------------
def format_summary_text(analysis: Dict[str, Any]) -> str:
    lines = []
    lines.append(f"Bravo6 Evaluation Analysis — batch {analysis['batch_id']}")
    lines.append("=" * 60)

    cov = analysis["coverage"]
    lines.append("")
    lines.append(f"COVERAGE ({cov['total_sites']} sites total)")
    lines.append(f"  grade_reliable=True  (assessable):   {cov['reliable']['count']} ({cov['reliable']['pct_of_total']}%)")
    lines.append(f"  grade_reliable=False (unreliable):   {cov['unreliable']['count']} ({cov['unreliable']['pct_of_total']}%)")
    if cov["scan_failed_entirely"]["count"]:
        lines.append(f"  scan failed entirely (no result):    {cov['scan_failed_entirely']['count']} ({cov['scan_failed_entirely']['pct_of_total']}%)")
    if cov["unreliable_subcategories"]:
        lines.append("")
        lines.append("  Unreliable breakdown by cause:")
        for label, info in cov["unreliable_subcategories"].items():
            lines.append(f"    - {label}: {info['count']} ({info['pct_of_unreliable']}% of unreliable)")
            for site in info["sites"]:
                lines.append(f"        · {site}")

    ss = analysis["score_stats"]
    lines.append("")
    lines.append(f"SCORE STATISTICS (n={ss['n_reliable_sites']} reliable sites only)")
    lines.append(f"  mean score:   {ss['mean_score']}")
    lines.append(f"  median score: {ss['median_score']}")
    lines.append(f"  stdev score:  {ss['stdev_score']}")
    lines.append("  grade distribution:")
    for g in ["A", "B", "C", "D", "F"]:
        info = ss["grade_distribution"].get(g)
        if info:
            lines.append(f"    {g}: {info['count']} ({info['pct']}%)")

    fs = analysis["findings_stats"]
    lines.append("")
    lines.append(f"FINDINGS BREAKDOWN (n={fs['n_reliable_sites']} reliable sites only)")
    lines.append(f"  mean total findings per site: {fs['mean_total_findings']}")
    lines.append("  mean findings per site by severity:")
    for sev, val in fs["mean_findings_by_severity"].items():
        lines.append(f"    {sev}: {val}")
    lines.append(f"  top {len(fs['top_finding_titles'])} most common finding titles:")
    for t in fs["top_finding_titles"]:
        lines.append(f"    {t['site_count']:>3} sites ({t['pct_of_reliable_sites']:>5}%)  {t['title']}")

    waf = analysis["waf_distribution"]
    lines.append("")
    lines.append(f"WAF / VENDOR DISTRIBUTION (all {waf['total_sites']} sites)")
    if waf["vendor_counts"]:
        for vendor, count in waf["vendor_counts"].items():
            lines.append(f"  {vendor}: {count}")
    else:
        lines.append("  (no named vendor detected on any site)")
    lines.append(f"  blocked but unattributed (unrecognized vendor): {waf['blocked_unattributed']}")

    rt = analysis["runtime_stats"]
    lines.append("")
    lines.append(f"RUNTIME (all {cov['total_sites']} sites)")
    lines.append(f"  mean duration:   {rt['mean_duration_seconds']}s")
    lines.append(f"  median duration: {rt['median_duration_seconds']}s")
    lines.append(f"  max duration:    {rt['max_duration_seconds']}s")
    lines.append(f"  batch wall-clock total: {rt['batch_wall_clock_seconds']}s")

    return "\n".join(lines) + "\n"


def build_arg_parser():
    parser = argparse.ArgumentParser(description="Compute descriptive statistics for a run_evaluation.py batch.")
    parser.add_argument("batch_dir", help="Path to the batch folder (evaluation/results/<batch_id>).")
    parser.add_argument("--top-n", type=int, default=15, help="Number of most-common finding titles to report. Default: 15.")
    return parser


if __name__ == "__main__":
    args = build_arg_parser().parse_args()
    batch_dir = Path(args.batch_dir)

    analysis = analyze(batch_dir)
    if args.top_n != 15:
        analysis["findings_stats"] = compute_findings_stats(
            [r for r in load_aggregate_rows(batch_dir) if r["grade_reliable"] is True],
            load_result_jsons_by_url(batch_dir),
            top_n=args.top_n,
        )

    summary_text = format_summary_text(analysis)

    (batch_dir / "analysis_summary.txt").write_text(summary_text, encoding="utf-8")
    (batch_dir / "analysis_summary.json").write_text(json.dumps(analysis, indent=2, ensure_ascii=False), encoding="utf-8")

    print(summary_text)
    print(f"[*] Wrote {batch_dir / 'analysis_summary.txt'}")
    print(f"[*] Wrote {batch_dir / 'analysis_summary.json'}")
