#!/usr/bin/env python3
"""
apply_pool_exclusions.py - Bravo6 Evaluation Harness: Candidate Pool Exclusion Pass
=====================================================================================
Two targeted exclusion passes over the already-built candidate_pool_n800.csv,
each with a same-stratum, same-rank-band seeded replacement so per-stratum
counts stay exactly 50/250/250/125/189:

  1. Adult/NSFW content: matched against a maintained, CC-BY-SA-licensed
     public categorized blocklist (UT1 Blacklists, Universite Toulouse
     Capitole, https://dsi.ut-capitole.fr/blacklists/ -- "adult" +
     "mixed_adult" categories, ~4.6M domains combined), PLUS the two
     domains already manually confirmed adult-content in this repo's own
     prior conversation turn (aznude.com, xxxpostpic.org -- the second of
     which UT1's list does not itself catch, documented as a known
     blocklist recall gap, not silently patched over).
  2. Cross-tool-calibration overlap: the 6 domains already used in
     validation-benchmark/cross-tool-calibration/sample_sites.json, removed
     so the calibration evidence and the big-run dataset stay
     methodologically independent (no site both calibrates AND counts
     toward the paper's headline n=500 evaluation).

Replacement method (documented for reproducibility): for each stratum/band
that lost domains, the SAME rank band (or, for prior-candidate-list, the
same source sample_sites.csv pool) is re-consulted, already-used and
newly-excluded domains are removed from consideration, and
random.Random(RANDOM_SEED).sample(remaining, k=needed) draws the exact
number of replacements needed -- deterministic and re-runnable, though NOT
a "continuation" of the original per-band random.sample() call (Python's
sample() isn't prefix-stable across different k values with the same seed,
so a true continuation isn't a well-defined operation) -- a fresh seeded
draw against the reduced eligible pool is the reproducible alternative used
here instead, and is what a re-run of this exact script reproduces
byte-for-byte.

Does NOT scan anything. Read-only against tranco_N2Q8W.csv and
sample_sites.csv; only candidate_pool_n800.csv/.txt are rewritten (in
place, from the ALREADY-BUILT pool, not regenerated from scratch -- rows
not excluded here are carried over unchanged).

Usage:
    python3 apply_pool_exclusions.py --ut1-adult-domains /path/to/adult/domains \\
                                      --ut1-mixed-adult-domains /path/to/mixed_adult/domains
"""
import argparse
import csv
import random
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

EVAL_DIR = Path(__file__).parent
DATA_DIR = EVAL_DIR / "data"
sys.path.insert(0, str(EVAL_DIR))
import sample_sites  # noqa: E402
import build_candidate_pool as bcp  # noqa: E402

RANDOM_SEED = sample_sites.RANDOM_SEED
POOL_CSV = DATA_DIR / "candidate_pool_n800.csv"
FIELDNAMES = ["domain", "url", "stratum", "rank", "platform", "discovery_method", "source_url"]

# Confirmed adult-content in this repo's own prior conversation turn.
# aznude.com IS also caught by UT1's "adult" list; xxxpostpic.org is NOT --
# kept here explicitly so it's still excluded despite that blocklist gap.
MANUALLY_CONFIRMED_ADULT = {"aznude.com", "xxxpostpic.org"}

CALIBRATION_OVERLAP = {
    "github.com", "paypal.com", "olx.pl", "buzzoola.com",
    "openweathermap.org", "fastpanel.direct",
}

CALIBRATION_SAMPLE_JSON = (
    EVAL_DIR.parent.parent.parent / "validation-benchmark" / "cross-tool-calibration" / "sample_sites.json"
)


def _normalize(domain: str) -> str:
    d = domain.strip().lower()
    return d[4:] if d.startswith("www.") else d


def load_pool() -> List[Dict]:
    with POOL_CSV.open("r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_blocklist(adult_path: Path, mixed_adult_path: Path) -> Set[str]:
    domains: Set[str] = set()
    for path in (adult_path, mixed_adult_path):
        if path and path.exists():
            with path.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        domains.add(line)
    return domains


def confirm_calibration_overlap_set() -> Set[str]:
    """Cross-check CALIBRATION_OVERLAP against the actual calibration sample
    file rather than trusting the hardcoded set blindly."""
    if not CALIBRATION_SAMPLE_JSON.exists():
        print(f"[!] {CALIBRATION_SAMPLE_JSON} not found -- using the hardcoded "
              f"CALIBRATION_OVERLAP set as-is, unverified.")
        return set(CALIBRATION_OVERLAP)
    import json
    data = json.loads(CALIBRATION_SAMPLE_JSON.read_text(encoding="utf-8"))
    actual = {s["domain"] for s in data.get("sites", [])}
    missing_from_actual = CALIBRATION_OVERLAP - actual
    if missing_from_actual:
        print(f"[!] These domains were expected in the calibration sample but aren't there: {missing_from_actual}")
    return actual


def classify_exclusions(pool: List[Dict], blocklist: Set[str], calibration_domains: Set[str]) -> Dict[str, Dict]:
    """Returns {domain: {"reasons": [...]}} for every pool row that must be excluded."""
    excluded: Dict[str, Dict] = {}
    for row in pool:
        norm = _normalize(row["domain"])
        reasons = []
        if norm in blocklist:
            reasons.append("ut1-adult-blocklist")
        if norm in MANUALLY_CONFIRMED_ADULT:
            reasons.append("manually-confirmed-adult")
        if row["domain"] in calibration_domains:
            reasons.append("cross-tool-calibration-overlap")
        if reasons:
            excluded[row["domain"]] = {"stratum": row["stratum"], "rank": row["rank"], "reasons": reasons}
    return excluded


def build_tranco_band_lookup(tranco_csv: Path) -> Dict[str, List[Tuple[int, str]]]:
    all_ranked = sample_sites.load_ranked_domains(tranco_csv)
    bands = {}
    for tag, rank_min, rank_max, _n in bcp.TRANCO_BANDS:
        bands[tag] = [(r, d) for (r, d) in all_ranked if rank_min <= r <= rank_max]
    return bands


def load_prior_pool(sample_sites_csv: Path) -> List[Tuple[int, str]]:
    rows = []
    with sample_sites_csv.open("r", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            try:
                rank = int(row["rank"])
            except (KeyError, ValueError):
                continue
            domain = row.get("domain", "").strip()
            if domain:
                rows.append((rank, domain))
    return rows


def draw_replacements(candidates: List[Tuple[int, str]], excluded_from_consideration: Set[str], k: int) -> List[Tuple[int, str]]:
    eligible = [(r, d) for (r, d) in candidates if d not in excluded_from_consideration]
    if len(eligible) < k:
        raise ValueError(f"Only {len(eligible)} eligible replacements available, need {k}.")
    rng = random.Random(RANDOM_SEED)
    chosen = rng.sample(eligible, k)
    chosen.sort(key=lambda rd: rd[0])
    return chosen


def main():
    parser = argparse.ArgumentParser(description="Apply adult-content and calibration-overlap exclusions with seeded replacements.")
    parser.add_argument("--ut1-adult-domains", required=True, help="Path to UT1 'adult' category's extracted domains file.")
    parser.add_argument("--ut1-mixed-adult-domains", required=True, help="Path to UT1 'mixed_adult' category's extracted domains file.")
    parser.add_argument("--tranco-csv", default=None)
    parser.add_argument("--sample-sites-csv", default=str(DATA_DIR / "sample_sites.csv"))
    parser.add_argument("--ai-generated-csv", default=str(DATA_DIR / "ai_generated_candidates.csv"))
    args = parser.parse_args()

    pool = load_pool()
    blocklist = load_blocklist(Path(args.ut1_adult_domains), Path(args.ut1_mixed_adult_domains))
    print(f"[*] Loaded {len(blocklist):,} domains from the UT1 adult+mixed_adult blocklist.")

    calibration_domains = confirm_calibration_overlap_set()
    print(f"[*] Cross-tool-calibration sample: {len(calibration_domains)} domains.")

    excluded = classify_exclusions(pool, blocklist, calibration_domains)
    print(f"\n[*] {len(excluded)} domains excluded total:")
    task1_count = sum(1 for v in excluded.values() if "ut1-adult-blocklist" in v["reasons"] or "manually-confirmed-adult" in v["reasons"])
    task2_count = sum(1 for v in excluded.values() if "cross-tool-calibration-overlap" in v["reasons"])
    for domain, info in sorted(excluded.items(), key=lambda kv: (kv[1]["stratum"], kv[0])):
        print(f"    [{info['stratum']}] {domain} -- {', '.join(info['reasons'])}")
    print(f"\n[*] Task 1 (adult/NSFW) exclusions: {task1_count}")
    print(f"[*] Task 2 (calibration overlap) exclusions: {task2_count}")

    all_current_domains = {row["domain"] for row in pool}
    never_use = all_current_domains | set(excluded.keys()) | blocklist | MANUALLY_CONFIRMED_ADULT | calibration_domains

    tranco_csv = Path(args.tranco_csv) if args.tranco_csv else sample_sites._find_default_tranco_csv()
    tranco_bands = build_tranco_band_lookup(tranco_csv)
    prior_pool = load_prior_pool(Path(args.sample_sites_csv))
    ai_pool_rows = bcp.load_ai_generated_stratum(Path(args.ai_generated_csv)) if Path(args.ai_generated_csv).exists() else []

    needed_by_stratum: Dict[str, int] = {}
    for info in excluded.values():
        needed_by_stratum[info["stratum"]] = needed_by_stratum.get(info["stratum"], 0) + 1

    replacements: List[Dict] = []
    for stratum, k in needed_by_stratum.items():
        if stratum.startswith("tranco-"):
            chosen = draw_replacements(tranco_bands[stratum], never_use, k)
            for rank, domain in chosen:
                replacements.append({"domain": domain, "url": f"https://{domain}", "stratum": stratum, "rank": rank})
                never_use.add(domain)
        elif stratum == "prior-candidate-list":
            chosen = draw_replacements(prior_pool, never_use, k)
            for rank, domain in chosen:
                replacements.append({"domain": domain, "url": f"https://{domain}", "stratum": stratum, "rank": rank})
                never_use.add(domain)
        elif stratum == "ai-generated":
            eligible = [r for r in ai_pool_rows if r["domain"] not in never_use]
            rng = random.Random(RANDOM_SEED)
            chosen = rng.sample(eligible, k)
            for row in chosen:
                replacements.append(row)
                never_use.add(row["domain"])
        else:
            raise ValueError(f"Unknown stratum: {stratum}")
        print(f"[*] Drew {k} replacement(s) for {stratum}: {[r['domain'] for r in replacements[-k:]]}")

    kept = [row for row in pool if row["domain"] not in excluded]
    new_pool = kept + replacements

    counts = {}
    for row in new_pool:
        counts[row["stratum"]] = counts.get(row["stratum"], 0) + 1
    print(f"\n[*] Post-exclusion per-stratum counts: {counts}")
    assert len(new_pool) == len(pool), f"Pool size changed: {len(pool)} -> {len(new_pool)}"
    assert len({r["domain"] for r in new_pool}) == len(new_pool), "Duplicate domains introduced!"

    csv_path = POOL_CSV
    txt_path = DATA_DIR / "candidate_pool_n800.txt"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        for row in new_pool:
            writer.writerow({k: row.get(k, "") for k in FIELDNAMES})
    with txt_path.open("w", encoding="utf-8") as f:
        for row in new_pool:
            f.write(row["url"] + "\n")

    print(f"\n[*] Rewrote {csv_path} and {txt_path}. Total: {len(new_pool)}")


if __name__ == "__main__":
    main()
