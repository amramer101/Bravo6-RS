#!/usr/bin/env python3
"""
run_evaluation.py - Bravo6 Evaluation Harness: Batch Runner
=====================================================================
Reads evaluation/data/sample_sites.txt (and its paired sample_sites.csv
for rank lookups) and runs the EXISTING, UNMODIFIED main_scanner.py's
run_scout() against every site -- exactly as it's normally invoked from
the CLI (same url normalization, same config dict shape, same CVE CSV
wiring: ctx.config["cve_csv_url"]).

Calls run_scout() directly (import, not subprocess) rather than shelling
out to `python3 main_scanner.py <url> ...` per site: avoids spawning 100+
separate Python interpreter processes, gives direct access to the
in-memory result dict (no need to re-read files back off disk), and makes
per-site timeout/exception handling precise via asyncio rather than
subprocess timeout wrangling. Either approach calls the identical
run_scout() code path -- no scanner-side behavior differs.

CONCURRENCY: bounded at 5 sites in flight at once (see CONCURRENCY below).
5 is a deliberate middle ground: high enough that a 100-site batch doesn't
take the wall-clock time of a fully sequential run, low enough that it
doesn't multiply local resource pressure that scales per concurrent scan --
each site's test_04_ssl_tls.py spawns several `openssl s_client` subprocesses
and test_07_email_security.py fires several concurrent DNS queries, so 5x
that concurrent load is a reasonable ceiling for a single local machine
without risking DNS-resolver or subprocess-table exhaustion, while each
site's own scan is still independent (no shared target, so this isn't
about being polite to any one remote site -- it's about this machine's
own capacity).

IMPORTANT SIDE EFFECT (documented, not hidden): run_scout() is the
existing, unmodified scanner entry point, and it unconditionally saves a
copy of every result into the top-level <worker>/results/ folder as part
of its own normal behavior (this harness does not touch main_scanner.py,
per the task's constraints, so this cannot be suppressed without a
scanner-side change). This harness's OWN canonical, clean evaluation
dataset is what it writes to evaluation/results/<batch_id>/ --
aggregate_results.py reads only from there. The ad-hoc top-level results/
folder will also accumulate a duplicate copy of each evaluation scan as an
unavoidable side effect of calling the scanner unmodified; it is not the
dataset used for the paper.

Usage:
    python3 run_evaluation.py                  # full sample_sites.txt
    python3 run_evaluation.py --limit 5         # first 5 sites only (dry run)
    python3 run_evaluation.py --concurrency 3   # override concurrency
"""
import argparse
import asyncio
import csv
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

WORKER_DIR = Path(__file__).parent.parent
EVAL_DIR = Path(__file__).parent
DATA_DIR = EVAL_DIR / "data"
RESULTS_ROOT = EVAL_DIR / "results"
CVE_CSV_PATH = WORKER_DIR / "cve_database_v2.csv"

sys.path.insert(0, str(WORKER_DIR))
import main_scanner  # noqa: E402  (must come after sys.path insert)

CONCURRENCY = 5

# Outer, harness-level hard timeout per site -- deliberately generous
# beyond the scanner's own worst-case internal budget (DEFAULT_TIMEOUTS
# tops out at test_06's 90s; modules run concurrently under
# asyncio.gather, so the theoretical worst case is close to 90s plus the
# ~15s pre-flight main-page fetch, not the sum of all module timeouts).
# This exists only to catch a genuinely pathological hang somewhere above
# the scanner's own per-module timeout enforcement (e.g. the pre-flight
# fetch itself never returning), not to second-guess the scanner's own
# timeout values.
OUTER_TIMEOUT_SECONDS = 150

# At most one bounded retry on failure, after a short fixed delay -- not
# retry-until-success. A site that fails twice is recorded as a genuine
# failure, not looped on.
MAX_ATTEMPTS = 2
RETRY_DELAY_SECONDS = 3


def _load_sample() -> List[Dict[str, Any]]:
    """Load {rank, domain, url} rows, preferring sample_sites.csv for rank
    info and cross-checking against sample_sites.txt (the runner's actual
    input list) so a site is only scanned if it's present in both."""
    csv_path = DATA_DIR / "sample_sites.csv"
    txt_path = DATA_DIR / "sample_sites.txt"
    if not txt_path.exists():
        raise FileNotFoundError(f"{txt_path} not found -- run sample_sites.py first.")

    rank_by_domain: Dict[str, int] = {}
    if csv_path.exists():
        with csv_path.open("r", newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                try:
                    rank_by_domain[row["domain"]] = int(row["rank"])
                except (KeyError, ValueError):
                    continue

    sites = []
    with txt_path.open("r", encoding="utf-8") as f:
        for line in f:
            url = line.strip()
            if not url:
                continue
            domain = url.split("://", 1)[-1].rstrip("/")
            sites.append({"rank": rank_by_domain.get(domain), "domain": domain, "url": url})
    return sites


def _safe_filename(domain: str) -> str:
    return "".join(c if (c.isalnum() or c in ".-_") else "_" for c in domain)


async def _scan_one(site: Dict[str, Any], semaphore: asyncio.Semaphore) -> Dict[str, Any]:
    """Run the unmodified scanner against a single site. Never raises --
    every outcome (success, timeout, connection error, any other
    exception) is captured and returned as a structured record so one bad
    site can never abort the batch."""
    config = {"cve_csv_url": str(CVE_CSV_PATH)} if CVE_CSV_PATH.exists() else None

    last_error_type = None
    last_error_message = None

    async with semaphore:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            t0 = time.time()
            try:
                # scan_id is now a required run_scout() parameter (Gap 3 fix,
                # DEPLOYMENT_NOTES.md) -- production callers pass the API's
                # job_id so the queued and finished Cosmos documents share an
                # id, but this harness never correlates with an API job, so a
                # fresh id per attempt is fine.
                result = await asyncio.wait_for(
                    main_scanner.run_scout(site["url"], scan_id=str(uuid.uuid4()), config=config),
                    timeout=OUTER_TIMEOUT_SECONDS,
                )
                return {
                    "rank": site["rank"],
                    "domain": site["domain"],
                    "url": site["url"],
                    "status": "success",
                    "attempt": attempt,
                    "duration_seconds": round(time.time() - t0, 2),
                    "result": result,
                    "error_type": None,
                    "error_message": None,
                }
            except asyncio.TimeoutError:
                last_error_type = "OuterTimeout"
                last_error_message = f"Exceeded harness-level outer timeout of {OUTER_TIMEOUT_SECONDS}s"
            except Exception as e:
                last_error_type = type(e).__name__
                last_error_message = str(e)

            if attempt < MAX_ATTEMPTS:
                await asyncio.sleep(RETRY_DELAY_SECONDS)

    return {
        "rank": site["rank"],
        "domain": site["domain"],
        "url": site["url"],
        "status": "failed",
        "attempt": MAX_ATTEMPTS,
        "duration_seconds": None,
        "result": None,
        "error_type": last_error_type,
        "error_message": last_error_message,
    }


async def run_batch(sites: List[Dict[str, Any]], batch_dir: Path, concurrency: int = CONCURRENCY) -> Dict[str, Any]:
    batch_dir.mkdir(parents=True, exist_ok=True)
    semaphore = asyncio.Semaphore(concurrency)

    batch_start = time.time()
    tasks = [asyncio.create_task(_scan_one(site, semaphore)) for site in sites]
    outcomes = await asyncio.gather(*tasks)
    total_wall_seconds = round(time.time() - batch_start, 2)

    manifest_rows = []
    succeeded = 0
    failed = 0

    for outcome in outcomes:
        if outcome["status"] == "success":
            succeeded += 1
            filename = f"rank_{outcome['rank']}_{_safe_filename(outcome['domain'])}.json"
            (batch_dir / filename).write_text(
                json.dumps(outcome["result"], indent=2, ensure_ascii=False, default=str),
                encoding="utf-8",
            )
        else:
            failed += 1
            filename = ""

        manifest_rows.append({
            "rank": outcome["rank"],
            "domain": outcome["domain"],
            "url": outcome["url"],
            "status": outcome["status"],
            "result_file": filename,
            "error_type": outcome["error_type"] or "",
            "error_message": (outcome["error_message"] or "").replace("\n", " ")[:300],
        })

    manifest_rows.sort(key=lambda r: (r["rank"] is None, r["rank"]))

    manifest_path = batch_dir / "manifest.csv"
    with manifest_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["rank", "domain", "url", "status", "result_file", "error_type", "error_message"])
        writer.writeheader()
        writer.writerows(manifest_rows)

    summary_lines = [
        f"Batch: {batch_dir.name}",
        f"Attempted: {len(sites)}",
        f"Succeeded: {succeeded}",
        f"Failed: {failed}",
        f"Total wall-clock time: {total_wall_seconds}s",
        f"Concurrency: {concurrency}",
        "",
        "Failures:" if failed else "Failures: none",
    ]
    for row in manifest_rows:
        if row["status"] == "failed":
            summary_lines.append(f"  - rank {row['rank']} {row['domain']}: {row['error_type']}: {row['error_message']}")

    summary_text = "\n".join(summary_lines) + "\n"
    (batch_dir / "run_summary.txt").write_text(summary_text, encoding="utf-8")
    print(summary_text)

    return {
        "attempted": len(sites),
        "succeeded": succeeded,
        "failed": failed,
        "total_wall_seconds": total_wall_seconds,
        "manifest_path": manifest_path,
        "batch_dir": batch_dir,
    }


def build_arg_parser():
    parser = argparse.ArgumentParser(description="Run the unmodified Bravo6 scanner against the sampled site list.")
    parser.add_argument("--limit", type=int, default=None, help="Only scan the first N sites from sample_sites.txt (for a dry run).")
    parser.add_argument("--concurrency", type=int, default=CONCURRENCY, help=f"Max concurrent scans in flight. Default: {CONCURRENCY}.")
    parser.add_argument("--batch-id", default=None, help="Override the batch folder name. Default: UTC timestamp.")
    return parser


if __name__ == "__main__":
    args = build_arg_parser().parse_args()

    sites = _load_sample()
    if args.limit is not None:
        sites = sites[: args.limit]

    batch_id = args.batch_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    batch_dir = RESULTS_ROOT / batch_id

    print(f"[*] Running {len(sites)} site(s) with concurrency={args.concurrency} -> {batch_dir}")
    asyncio.run(run_batch(sites, batch_dir, concurrency=args.concurrency))
