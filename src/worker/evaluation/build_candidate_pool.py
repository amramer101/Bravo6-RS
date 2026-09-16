#!/usr/bin/env python3
"""
build_candidate_pool.py - Bravo6 Evaluation Harness: Big-Run Candidate Pool
=============================================================================
Builds the stratified candidate pool for the large evaluation run (target:
500 successfully-scanned domains after attrition -> ~800-850 candidates).
List-building only -- does NOT scan anything (see run_evaluation.py for that).

Three strata, each tagged in the output so the paper's methodology section
can describe the sample composition precisely:

  1. tranco-low-rank / tranco-mid-rank / tranco-high-rank
     A NEW stratified draw from the SAME frozen Tranco snapshot
     (data/tranco_N2Q8W.csv) sample_sites.py already uses -- reproducibility
     precedent preserved (same frozen list, same RANDOM_SEED convention),
     but across three rank bands instead of one, specifically so the sample
     isn't dominated by mega-corporations the way a top-500 draw would be.
     Reuses sample_sites.load_ranked_domains()/sample() by import rather
     than reimplementing the same logic -- but writes to NEW filenames
     (candidate_pool_n800.*), never touching sample_sites.csv/.txt, which
     are the ALREADY-SCANNED, paper-cited n=500 FINAL batch's input and
     must stay exactly as they are (see results/20260903T182513Z_n500_c3_
     10scouts_FINAL/ and .gitignore's explicit carve-out for it).

  2. ai-generated
     Publicly-discoverable sites built with AI app builders (Lovable,
     Bolt.new, v0, etc.), found via legitimate public discovery only
     (platform showcase pages, GitHub code search for scaffolding
     signatures) -- see the research notes this script's caller pastes in;
     this script only merges/tags/dedupes the resulting list, it does not
     do the discovery itself.

  3. prior-candidate-list
     A reproducible re-sample FROM the existing sample_sites.csv (the
     already-scanned n=500 FINAL batch's own input list) -- reusing
     domains from prior work, per the task. Read-only against
     sample_sites.csv; never writes to it.

Global dedup: a domain that lands in more than one stratum (e.g. a
prior-candidate-list domain that also happens to fall in the new Tranco
mid-rank draw) is kept exactly once, attributed to whichever stratum is
listed first in STRATUM_PRIORITY below, and the collision is reported.

Usage:
    python3 build_candidate_pool.py --ai-generated-csv data/ai_generated_candidates.csv
"""
import argparse
import csv
import random
import sys
from pathlib import Path
from typing import Dict, List, Tuple

EVAL_DIR = Path(__file__).parent
DATA_DIR = EVAL_DIR / "data"
sys.path.insert(0, str(EVAL_DIR))
import sample_sites  # noqa: E402 -- reuse load_ranked_domains()/sample(), not reimplement

# Same fixed seed as sample_sites.py, for the same reason: reproducibility.
# This is a NEW, independent draw (different rank bands, different n, and a
# different source file for stratum 3) so it is not expected to reproduce
# sample_sites.py's own n=500 output -- the point of reusing the seed value
# is consistency of convention across this repo's evaluation tooling, not
# byte-identical overlap with a different sampling call.
RANDOM_SEED = sample_sites.RANDOM_SEED

TRANCO_BANDS: List[Tuple[str, int, int, int]] = [
    # (stratum_tag, rank_min, rank_max, n)
    ("tranco-low-rank", 1, 1000, 50),
    ("tranco-mid-rank", 1000, 50000, 250),
    ("tranco-high-rank", 50000, 500000, 250),
]
PRIOR_CANDIDATE_N = 125

STRATUM_PRIORITY = [
    "tranco-low-rank", "tranco-mid-rank", "tranco-high-rank",
    "prior-candidate-list", "ai-generated",
]


def build_tranco_strata(tranco_csv: Path) -> List[Dict]:
    rows = []
    all_ranked = sample_sites.load_ranked_domains(tranco_csv)
    for tag, rank_min, rank_max, n in TRANCO_BANDS:
        band = [(r, d) for (r, d) in all_ranked if rank_min <= r <= rank_max]
        rng = random.Random(RANDOM_SEED)
        chosen = rng.sample(band, n)
        chosen.sort(key=lambda rd: rd[0])
        for rank, domain in chosen:
            rows.append({"domain": domain, "url": f"https://{domain}", "stratum": tag, "rank": rank})
        print(f"[*] {tag}: sampled {len(chosen)} from rank band {rank_min}-{rank_max} "
              f"({len(band)} candidates in that band)")
    return rows


def build_prior_candidate_stratum(sample_sites_csv: Path, n: int) -> List[Dict]:
    if not sample_sites_csv.exists():
        print(f"[!] {sample_sites_csv} not found -- prior-candidate-list stratum will be empty.")
        return []
    prior = []
    with sample_sites_csv.open("r", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                rank = int(row["rank"])
            except (KeyError, ValueError):
                continue
            domain = row.get("domain", "").strip()
            if domain:
                prior.append((rank, domain))
    if len(prior) < n:
        print(f"[!] Only {len(prior)} domains available in {sample_sites_csv.name}, "
              f"requested {n} -- taking all of them.")
        n = len(prior)
    rng = random.Random(RANDOM_SEED)
    chosen = rng.sample(prior, n)
    chosen.sort(key=lambda rd: rd[0])
    rows = [{"domain": d, "url": f"https://{d}", "stratum": "prior-candidate-list", "rank": r} for r, d in chosen]
    print(f"[*] prior-candidate-list: sampled {len(rows)} of {len(prior)} domains from {sample_sites_csv.name}")
    return rows


def load_ai_generated_stratum(ai_csv: Path) -> List[Dict]:
    if not ai_csv or not ai_csv.exists():
        print("[!] No ai-generated candidate CSV provided/found -- ai-generated stratum will be empty.")
        return []
    rows = []
    with ai_csv.open("r", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            domain = row.get("domain", "").strip()
            if not domain:
                continue
            rows.append({
                "domain": domain,
                "url": row.get("url") or f"https://{domain}",
                "stratum": "ai-generated",
                "rank": "",
                "platform": row.get("platform", ""),
                "discovery_method": row.get("discovery_method", ""),
                "source_url": row.get("source_url", ""),
            })
    print(f"[*] ai-generated: loaded {len(rows)} candidates from {ai_csv.name}")
    return rows


def dedupe(all_rows: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    priority_index = {tag: i for i, tag in enumerate(STRATUM_PRIORITY)}
    by_domain: Dict[str, Dict] = {}
    collisions = []
    # Stable pass in stratum-priority order so the first (highest-priority)
    # occurrence of a domain always wins, regardless of input row order.
    ordered = sorted(all_rows, key=lambda r: priority_index.get(r["stratum"], 99))
    for row in ordered:
        key = row["domain"].strip().lower().removeprefix("www.")
        if key in by_domain:
            collisions.append({"domain": row["domain"], "dropped_stratum": row["stratum"],
                                "kept_stratum": by_domain[key]["stratum"]})
            continue
        by_domain[key] = row
    deduped = list(by_domain.values())
    return deduped, collisions


def write_outputs(rows: List[Dict], out_stem: str = "candidate_pool_n800") -> Tuple[Path, Path]:
    csv_path = DATA_DIR / f"{out_stem}.csv"
    txt_path = DATA_DIR / f"{out_stem}.txt"

    fieldnames = ["domain", "url", "stratum", "rank", "platform", "discovery_method", "source_url"]
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in fieldnames})

    with txt_path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(row["url"] + "\n")

    return csv_path, txt_path


def build_arg_parser():
    parser = argparse.ArgumentParser(description="Build the stratified big-run candidate pool.")
    parser.add_argument("--tranco-csv", default=None, help="Frozen tranco_<id>.csv path. Default: auto-detect in data/.")
    parser.add_argument("--sample-sites-csv", default=str(DATA_DIR / "sample_sites.csv"),
                         help="Existing (already-scanned) prior-work sample to reuse from.")
    parser.add_argument("--ai-generated-csv", default=None,
                         help="CSV of {domain,url,platform,discovery_method,source_url} rows for the ai-generated stratum.")
    parser.add_argument("--out-stem", default="candidate_pool_n800")
    return parser


def main():
    args = build_arg_parser().parse_args()
    tranco_csv = Path(args.tranco_csv) if args.tranco_csv else sample_sites._find_default_tranco_csv()

    rows: List[Dict] = []
    rows += build_tranco_strata(tranco_csv)
    rows += build_prior_candidate_stratum(Path(args.sample_sites_csv), PRIOR_CANDIDATE_N)
    rows += load_ai_generated_stratum(Path(args.ai_generated_csv) if args.ai_generated_csv else None)

    deduped, collisions = dedupe(rows)
    deduped.sort(key=lambda r: (STRATUM_PRIORITY.index(r["stratum"]), r.get("rank") if isinstance(r.get("rank"), int) else 0))

    csv_path, txt_path = write_outputs(deduped, args.out_stem)

    counts: Dict[str, int] = {}
    for r in deduped:
        counts[r["stratum"]] = counts.get(r["stratum"], 0) + 1

    print(f"\n[*] Total candidates after dedup: {len(deduped)} (from {len(rows)} raw rows, {len(collisions)} collisions dropped)")
    for tag in STRATUM_PRIORITY:
        print(f"    {tag}: {counts.get(tag, 0)}")
    if collisions:
        print(f"\n[*] Collisions (domain appeared in >1 stratum -- kept the higher-priority one):")
        for c in collisions:
            print(f"    {c['domain']}: dropped from {c['dropped_stratum']}, kept in {c['kept_stratum']}")
    print(f"\n[*] Wrote {csv_path}")
    print(f"[*] Wrote {txt_path}")


if __name__ == "__main__":
    main()
