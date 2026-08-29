#!/usr/bin/env python3
"""
fetch_tranco_list.py - Bravo6 Evaluation Harness: Tranco List Fetcher
=====================================================================
Downloads a citable, permanent-list-ID snapshot of the Tranco top-sites
list (https://tranco-list.eu) and freezes it locally under evaluation/data/.
Every later step in this harness reads that frozen local file -- nothing
downstream re-fetches Tranco live, so the sample stays reproducible even
if Tranco's "latest" list changes on a later day.

Tranco generates a new daily list each day, each with a permanent, citable
list ID (e.g. "Tranco list ID N2Q8W, generated 2026-08-28,
https://tranco-list.eu/list/N2Q8W") that a reviewer can look up or
re-download identically years later. This script resolves the list ID via
Tranco's documented API (https://tranco-list.eu/api_documentation) --
GET https://tranco-list.eu/api/lists/date/{date|"latest"} -- which returns
JSON containing the list_id and the actual download URL; it never guesses
a download URL pattern directly.

Usage:
    python3 fetch_tranco_list.py                     # today's daily list
    python3 fetch_tranco_list.py --date 20260801      # a specific past date (YYYYMMDD)
    python3 fetch_tranco_list.py --list-id N2Q8W      # a known list ID directly (skips date lookup)
"""
import argparse
import csv
from datetime import datetime, timezone
from pathlib import Path

import requests

DATA_DIR = Path(__file__).parent / "data"
API_DATE_URL = "https://tranco-list.eu/api/lists/date"
API_ID_URL = "https://tranco-list.eu/api/lists/id"
CITATION_BASE_URL = "https://tranco-list.eu/list"


def _resolve_list_metadata(date: str = None, list_id: str = None) -> dict:
    """Resolve Tranco's list metadata (list_id, download URL, created_on)
    via their documented API. Never constructs/guesses a download URL --
    always uses the "download" field the API itself returns."""
    if list_id:
        resp = requests.get(f"{API_ID_URL}/{list_id}", timeout=30)
    else:
        resp = requests.get(f"{API_DATE_URL}/{date or 'latest'}", timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if data.get("failed") or not data.get("available", True):
        raise RuntimeError(f"Tranco reports this list as unavailable/failed: {data}")
    if "list_id" not in data or "download" not in data:
        raise RuntimeError(f"Unexpected Tranco API response shape (missing list_id/download): {data}")
    return data


def fetch_and_freeze(date: str = None, list_id: str = None) -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    meta = _resolve_list_metadata(date=date, list_id=list_id)
    resolved_list_id = meta["list_id"]
    download_url = meta["download"]
    created_on = meta.get("created_on", "")

    csv_path = DATA_DIR / f"tranco_{resolved_list_id}.csv"
    if csv_path.exists():
        print(f"[*] {csv_path.name} already exists locally -- not re-downloading "
              "(this is the frozen snapshot; delete it first to force a fresh fetch of this exact list ID).")
    else:
        print(f"[*] Downloading Tranco list {resolved_list_id} from {download_url} ...")
        resp = requests.get(download_url, timeout=180)
        resp.raise_for_status()
        csv_path.write_bytes(resp.content)
        print(f"[*] Saved {len(resp.content):,} bytes to {csv_path}")

    # Sanity check: confirm the frozen file actually parses as rank,domain rows.
    with csv_path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        sample_rows = []
        for row in reader:
            sample_rows.append(row)
            if len(sample_rows) >= 3:
                break
    row_count = sum(1 for _ in csv_path.open("r", encoding="utf-8"))

    citation_url = f"{CITATION_BASE_URL}/{resolved_list_id}"
    fetched_at = datetime.now(timezone.utc).isoformat()

    metadata_text = (
        f"Tranco list ID: {resolved_list_id}\n"
        f"Generated on (per Tranco API 'created_on'): {created_on}\n"
        f"Fetched/frozen at (this run, UTC): {fetched_at}\n"
        f"Citation URL: {citation_url}\n"
        f"Download URL used: {download_url}\n"
        f"Local frozen CSV: {csv_path.name}\n"
        f"Row count: {row_count:,}\n"
        f"First rows sampled: {sample_rows}\n"
        f"\n"
        f"Citation for the paper's Methodology section:\n"
        f'  "Tranco list ID {resolved_list_id}, generated {created_on}, {citation_url}"\n'
        f"\n"
        f"IMPORTANT: every downstream script in this harness (sample_sites.py,\n"
        f"run_evaluation.py, aggregate_results.py) reads {csv_path.name} from disk --\n"
        f"none of them re-fetch Tranco live. This file is the permanent source of\n"
        f"truth for this evaluation run; do not overwrite or delete it once a sample\n"
        f"has been drawn from it, or the sample can no longer be regenerated.\n"
    )
    meta_path = DATA_DIR / "tranco_metadata.txt"
    meta_path.write_text(metadata_text, encoding="utf-8")

    print("\n" + metadata_text)
    return csv_path


def build_arg_parser():
    parser = argparse.ArgumentParser(description="Fetch and freeze a citable Tranco top-sites list snapshot.")
    parser.add_argument("--date", default=None, help="Specific date (YYYYMMDD) to fetch the daily list for. Default: latest.")
    parser.add_argument("--list-id", default=None, help="A known, already-generated Tranco list ID to fetch directly (takes precedence over --date).")
    return parser


if __name__ == "__main__":
    args = build_arg_parser().parse_args()
    fetch_and_freeze(date=args.date, list_id=args.list_id)
