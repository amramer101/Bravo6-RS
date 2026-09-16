#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set

import requests

ROOT = Path(__file__).resolve().parents[2]
WORKER_DIR = ROOT / "src" / "worker"
if str(WORKER_DIR) not in sys.path:
    sys.path.insert(0, str(WORKER_DIR))

import main_scanner

SAMPLE_PATH = Path(__file__).with_name("sample_sites.json")
RESULTS_PATH = Path(__file__).with_name("results.json")

BRAVO6_SIGNAL_KEYWORDS = {
    "content-security-policy": ["content-security-policy", "content security policy", "csp"],
    "strict-transport-security": ["strict-transport-security", "strict transport security", "hsts"],
    "cookies": ["cookie", "cookies", "same-site", "samesite", "httponly", "secure attribute"],
    "cross-origin-resource-sharing": ["cors", "cross-origin-resource-sharing", "cross origin resource sharing"],
    "subresource-integrity": ["subresource integrity", "sri", "cross-origin script loaded without subresource integrity"],
    "x-frame-options": [
        "x-frame-options",
        "x frame options",
        "frame-options",
        "missing clickjacking protection",
        "x-frame-options insecure value",
    ],
    "x-content-type-options": ["x-content-type-options", "x content type options"],
    "referrer-policy": ["referrer-policy", "referrer policy"],
    "cross-origin-opener-policy": ["cross-origin-opener-policy", "cross origin opener policy"],
    "cross-origin-embedder-policy": ["cross-origin-embedder-policy", "cross origin embedder policy"],
    "cross-origin-resource-policy": ["cross-origin-resource-policy", "cross origin resource policy"],
}


def _normalize_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


def extract_bravo6_signals(titles: Iterable[str]) -> Set[str]:
    signals: Set[str] = set()
    for title in titles:
        # Pad with boundary spaces so a short keyword like "csp" only
        # matches as a whole word/phrase, not as a substring of an
        # unrelated token like "ocsp" ("OCSP Stapling Not Enabled").
        normalized = f" {_normalize_text(str(title))} "
        for canonical, keywords in BRAVO6_SIGNAL_KEYWORDS.items():
            if any(f" {keyword} " in normalized for keyword in keywords):
                signals.add(canonical)
    return signals


# Mozilla Observatory checks that have no Bravo6 equivalent and are therefore
# excluded from the comparison entirely (not counted as a Bravo6 gap):
# "redirection" is Mozilla's HTTP->HTTPS enforcement check; Bravo6 has no
# corresponding passive check, so comparing against it would unfairly
# inflate the apparent disagreement rate.
MOZILLA_SIGNALS_WITHOUT_BRAVO6_EQUIVALENT = {"redirection"}


def extract_mozilla_signals(payload: Dict[str, Any]) -> Set[str]:
    tests = payload.get("tests") or {}
    return set(str(k) for k in tests.keys()) - MOZILLA_SIGNALS_WITHOUT_BRAVO6_EQUIVALENT


async def scan_site(domain: str) -> Dict[str, Any]:
    url = f"https://{domain}"
    try:
        result = await main_scanner.run_scout(
            url,
            scan_id=f"calibration-{domain}",
            config={"cve_csv_url": str(ROOT / "src" / "worker" / "cve_database_v2.csv")},
        )
        findings = result.get("findings") or []
        titles = [str(item.get("title", "")) for item in findings if isinstance(item, dict)]
        # run_scout() already computes exactly this signal (see
        # compute_bravo6_score's grade_reliable/coverage_note in
        # main_scanner.py): False whenever fewer scout modules completed
        # than were discovered, or the pre-flight page wasn't representative
        # (WAF/anti-bot block, or a transient fetch failure that survived
        # the pre-flight retry). A scan flagged unreliable here must not be
        # read as "Bravo6 found nothing" -- it may not have evaluated the
        # site's headers/cookies/SRI/etc at all.
        grade_reliable = result.get("grade_reliable", True)
        return {
            "domain": domain,
            "url": url,
            "status": "ok",
            "bravo6_signals": sorted(extract_bravo6_signals(titles)),
            "titles": titles,
            "raw_findings": len(findings),
            "tests_run": result.get("tests_run"),
            "page_is_representative": result.get("page_is_representative"),
            "errors": result.get("errors") or [],
            "errors_count": result.get("errors_count", 0),
            "coverage_note": result.get("coverage_note"),
            "grade_reliable": grade_reliable,
            "incomplete_scan": not grade_reliable,
        }
    except Exception as exc:  # pragma: no cover - network/remote-site variance is expected here
        return {
            "domain": domain,
            "url": url,
            "status": "error",
            "error": str(exc),
            "bravo6_signals": [],
            "titles": [],
            "raw_findings": 0,
            "tests_run": None,
            "page_is_representative": None,
            "errors": [str(exc)],
            "errors_count": 1,
            "coverage_note": None,
            "grade_reliable": False,
            "incomplete_scan": True,
        }


def fetch_mozilla(domain: str) -> Dict[str, Any]:
    url = "https://observatory-api.mdn.mozilla.net/api/v2/analyze"
    last_exc: Exception | None = None
    for attempt in range(3):
        try:
            response = requests.get(url, params={"host": domain, "wait": 0}, timeout=45)
            if response.status_code == 429:
                return {"domain": domain, "status": "rate_limited", "error": "429 rate limited"}
            response.raise_for_status()
            payload = response.json()
            return {
                "domain": domain,
                "status": "ok",
                "grade": payload.get("scan", {}).get("grade"),
                "score": payload.get("scan", {}).get("score"),
                "mozilla_signals": sorted(extract_mozilla_signals(payload)),
            }
        except Exception as exc:
            last_exc = exc
            if attempt < 2:
                continue
    return {"domain": domain, "status": "error", "error": str(last_exc) if last_exc else "unknown error"}


def summarize(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    successful = [
        row for row in rows
        if row.get("bravo6_status") == "ok" and row.get("mozilla_status") == "ok"
    ]
    overlap_count = sum(1 for row in successful if row.get("overlap"))
    disagreement_count = sum(
        1 for row in successful if (row.get("bravo6_only") or row.get("mozilla_only"))
    )

    total_overlap = 0
    total_union = 0
    for row in successful:
        bravo_set = set(row.get("bravo6_signals") or [])
        mozilla_set = set(row.get("mozilla_signals") or [])
        overlap = set(row.get("overlap") or [])
        union = bravo_set | mozilla_set
        total_overlap += len(overlap)
        total_union += len(union)
    aggregate_agreement_rate_percent = (
        (total_overlap / total_union * 100.0) if total_union else 0.0
    )

    return {
        "sites_scanned": len(rows),
        "successful_sites": len(successful),
        "overlap_sites": overlap_count,
        "disagreement_sites": disagreement_count,
        "aggregate_agreement_rate_percent": aggregate_agreement_rate_percent,
        "agreement_rate": aggregate_agreement_rate_percent / 100.0,
        "rows": rows,
    }


async def main() -> None:
    data = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    sites = data.get("sites", [])
    tasks = [scan_site(item["domain"]) for item in sites]
    bravo_results = await asyncio.gather(*tasks)
    rows: List[Dict[str, Any]] = []
    for item in sites:
        domain = item["domain"]
        bravo = next((row for row in bravo_results if row.get("domain") == domain), {"domain": domain, "status": "missing"})
        mozilla = fetch_mozilla(domain)
        bravo_signals = set(bravo.get("bravo6_signals", []))
        mozilla_signals = set(mozilla.get("mozilla_signals", []))
        overlap = sorted(bravo_signals & mozilla_signals)
        bravo_only = sorted(bravo_signals - mozilla_signals)
        mozilla_only = sorted(mozilla_signals - bravo_signals)
        row = {
            "domain": domain,
            "source": item.get("source", "unknown"),
            "url": f"https://{domain}",
            "bravo6_status": bravo.get("status"),
            "mozilla_status": mozilla.get("status"),
            "bravo6_signals": sorted(bravo_signals),
            "mozilla_signals": sorted(mozilla_signals),
            "overlap": overlap,
            "bravo6_only": bravo_only,
            "mozilla_only": mozilla_only,
            "bravo6_title_count": len(bravo.get("titles", [])),
            "titles": bravo.get("titles", []),
            # Bravo6's own coverage signal (main_scanner.py's run_scout()
            # result), read as-is -- not re-derived here. See scan_site():
            # incomplete_scan=True means this scan should be excluded from
            # any pass/fail verdict comparison, not counted as a "clean
            # pass" just because bravo6_signals/titles came back empty.
            "bravo6_tests_run": bravo.get("tests_run"),
            "bravo6_page_is_representative": bravo.get("page_is_representative"),
            "bravo6_errors": bravo.get("errors", []),
            "bravo6_errors_count": bravo.get("errors_count", 0),
            "bravo6_coverage_note": bravo.get("coverage_note"),
            "bravo6_grade_reliable": bravo.get("grade_reliable"),
            "incomplete_scan": bravo.get("incomplete_scan", False),
            "mozilla_grade": mozilla.get("grade"),
            "mozilla_score": mozilla.get("score"),
            "error": bravo.get("error") or mozilla.get("error"),
        }
        rows.append(row)

    summary = summarize(rows)
    payload = {
        "sample": {
            "source_file": str(SAMPLE_PATH.name),
            "site_count": len(sites),
            "source_types": sorted({item.get("source", "unknown") for item in sites}),
        },
        "summary": {
            "sites_scanned": summary["sites_scanned"],
            "successful_sites": summary["successful_sites"],
            "overlap_sites": summary["overlap_sites"],
            "disagreement_sites": summary["disagreement_sites"],
            "aggregate_agreement_rate_percent": summary["aggregate_agreement_rate_percent"],
            "agreement_rate": summary["agreement_rate"],
        },
        "rows": rows,
    }
    RESULTS_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(payload["summary"], indent=2))


if __name__ == "__main__":
    asyncio.run(main())
