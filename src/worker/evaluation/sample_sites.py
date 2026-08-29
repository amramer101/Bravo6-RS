#!/usr/bin/env python3
"""
sample_sites.py - Bravo6 Evaluation Harness: Reproducible Site Sampler
=====================================================================
Reads the frozen local Tranco CSV (never re-fetches live -- see
fetch_tranco_list.py) and draws a fixed-seed random sample of N domains
from a configurable rank band.

WHY rank 1,000-100,000 by default, not the top ~50: the very top of any
site ranking is dominated by extremely well-resourced sites (Google,
Facebook, major CDNs) that are not representative of the ordinary
production sites this scanner is actually meant to evaluate. Sampling
further down the list gives a much more representative picture.

Reproducibility is the entire point of this script: given the same frozen
Tranco CSV, the same rank band, and the same N, RANDOM_SEED below
guarantees byte-identical output on every re-run. Verified manually: run
this script twice against the same inputs and diff sample_sites.csv /
sample_sites.txt -- they must be identical. (Re-verify this any time the
sampling logic changes.)

Usage:
    python3 sample_sites.py                                   # defaults: rank 1000-100000, n=100
    python3 sample_sites.py --rank-min 500 --rank-max 50000 --n 25
    python3 sample_sites.py --input data/tranco_N2Q8W.csv      # explicit source, skips auto-detect
"""
import argparse
import csv
import glob
import random
from pathlib import Path
from typing import List, Tuple

DATA_DIR = Path(__file__).parent / "data"

# Fixed, hardcoded seed -- THIS is what makes the sample reproducible, not
# just freezing the source list. Chosen arbitrarily once (the date this
# harness was built) and then held fixed permanently: do not change this
# value for the paper's canonical sample -- changing it produces a
# different (still valid, but DIFFERENT, non-comparable) sample.
RANDOM_SEED = 20260829


def _find_default_tranco_csv() -> Path:
    candidates = sorted(glob.glob(str(DATA_DIR / "tranco_*.csv")))
    candidates = [c for c in candidates if not c.endswith("_metadata.txt")]
    if not candidates:
        raise FileNotFoundError(
            f"No tranco_*.csv found in {DATA_DIR}. Run fetch_tranco_list.py first, "
            "or pass --input explicitly."
        )
    if len(candidates) > 1:
        raise RuntimeError(
            f"Multiple tranco_*.csv files found in {DATA_DIR}: {candidates}. "
            "Pass --input explicitly to disambiguate which frozen list to sample from."
        )
    return Path(candidates[0])


def load_ranked_domains(csv_path: Path) -> List[Tuple[int, str]]:
    rows: List[Tuple[int, str]] = []
    with csv_path.open("r", newline="", encoding="utf-8") as f:
        for line in csv.reader(f):
            if len(line) < 2:
                continue
            try:
                rank = int(line[0])
            except ValueError:
                continue  # tolerate a header row if the source CSV ever has one
            domain = line[1].strip()
            if domain:
                rows.append((rank, domain))
    return rows


def sample(csv_path: Path, rank_min: int, rank_max: int, n: int, seed: int = RANDOM_SEED) -> List[Tuple[int, str]]:
    all_rows = load_ranked_domains(csv_path)
    band = [(r, d) for (r, d) in all_rows if rank_min <= r <= rank_max]
    if len(band) < n:
        raise ValueError(
            f"Rank band {rank_min}-{rank_max} only contains {len(band)} domains in "
            f"{csv_path.name}, cannot sample {n}."
        )
    rng = random.Random(seed)
    chosen = rng.sample(band, n)
    chosen.sort(key=lambda rd: rd[0])
    return chosen


def write_outputs(chosen: List[Tuple[int, str]], out_dir: Path = DATA_DIR) -> Tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_out = out_dir / "sample_sites.csv"
    txt_out = out_dir / "sample_sites.txt"

    with csv_out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["rank", "domain"])
        for rank, domain in chosen:
            writer.writerow([rank, domain])

    with txt_out.open("w", encoding="utf-8") as f:
        for _, domain in chosen:
            f.write(f"https://{domain}\n")

    return csv_out, txt_out


def build_arg_parser():
    parser = argparse.ArgumentParser(description="Draw a reproducible, fixed-seed sample of domains from a frozen Tranco list.")
    parser.add_argument("--input", default=None, help="Path to the frozen tranco_<id>.csv. Default: auto-detect the single tranco_*.csv in evaluation/data/.")
    parser.add_argument("--rank-min", type=int, default=1000)
    parser.add_argument("--rank-max", type=int, default=100000)
    parser.add_argument("--n", type=int, default=100)
    parser.add_argument("--seed", type=int, default=RANDOM_SEED,
                         help="Override the fixed seed. NOT recommended for the paper's canonical "
                              "sample -- produces a different, non-comparable sample.")
    return parser


if __name__ == "__main__":
    args = build_arg_parser().parse_args()
    input_path = Path(args.input) if args.input else _find_default_tranco_csv()
    chosen = sample(input_path, args.rank_min, args.rank_max, args.n, seed=args.seed)
    csv_out, txt_out = write_outputs(chosen)
    print(f"[*] Sampled {len(chosen)} domains (rank {args.rank_min}-{args.rank_max}) "
          f"from {input_path.name} using seed={args.seed}")
    print(f"[*] Wrote {csv_out}")
    print(f"[*] Wrote {txt_out}")
