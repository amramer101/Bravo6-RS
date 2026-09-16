#!/usr/bin/env python3
"""Recompute Bravo6 vs Mozilla Observatory agreement on PASS/FAIL VERDICTS
(not raw signal-set overlap). Read-only: does not touch results.json,
run_calibration.py, or any src/worker file.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

RESULTS_PATH = Path(__file__).with_name("results.json")
VERDICTS_PATH = Path(__file__).with_name("mozilla_verdicts.json")

# Same keyword map as run_calibration.py (BRAVO6_SIGNAL_KEYWORDS), reused verbatim.
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

CANONICAL_SIGNALS = list(BRAVO6_SIGNAL_KEYWORDS.keys())

# Titles confirmed via source (severity="info" in test_03_cookies.py,
# test_08_cors.py, test_09_sri.py) that are NOT genuine fail findings --
# they are informational "nothing to evaluate" / "this is fine" notices,
# not violations. Counting them as a Bravo6 "fail" would be a keyword
# artifact: it would conflate "scout emitted an info note mentioning this
# header" with "scout flagged a violation of this header". Confirmed by
# grep against test_03_cookies.py:351-352, test_08_cors.py, test_09_sri.py:398-399,432.
NON_FAIL_INFO_TITLES = {
    "No cookies observed on the response",
    "CORS check inconclusive (probe request failed)",
    "No CORS response headers observed",
    "Subresource Integrity not applicable to this page",
    "All cross-origin subresources correctly pinned with SRI",
}


def _normalize_text(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


def bravo6_verdict_for_signal(titles: list[str], signal: str) -> str:
    """'fail' if a genuine (non-info) finding title matches this signal's
    keywords, else 'pass' (scout has capability, reported nothing genuine)."""
    keywords = BRAVO6_SIGNAL_KEYWORDS[signal]
    for title in titles:
        if title in NON_FAIL_INFO_TITLES:
            continue
        normalized = f" {_normalize_text(str(title))} "
        if any(f" {kw} " in normalized for kw in keywords):
            return "fail"
    return "pass"


def mozilla_verdict_for_signal(verdicts: dict, signal: str) -> str | None:
    v = verdicts.get(signal)
    if v is None or not v.get("present"):
        return None  # not run at all -- not comparable
    p = v.get("pass")
    if p is True:
        return "pass"
    if p is False:
        return "fail"
    return None  # pass is null -- Mozilla itself scored this neutral/N/A, not comparable


def main() -> None:
    results = json.loads(RESULTS_PATH.read_text(encoding="utf-8"))
    mozilla_rows = {r["domain"]: r for r in json.loads(VERDICTS_PATH.read_text(encoding="utf-8"))}

    per_signal = {s: {"agree": 0, "disagree": 0, "not_comparable": 0, "sites_compared": []} for s in CANONICAL_SIGNALS}
    disagreements = []
    total_agree = 0
    total_compared = 0
    not_comparable_total = 0
    excluded_incomplete_scans = []

    per_site_detail = {}

    for row in results["rows"]:
        domain = row["domain"]
        titles = row.get("titles", [])

        # Site-level exclusion: Bravo6's own coverage signal (run_calibration.py's
        # scan_site(), which reads it straight from run_scout()'s
        # grade_reliable/coverage_note) says this scan didn't actually
        # complete -- e.g. page_is_representative was False (WAF/anti-bot
        # block, or a pre-flight fetch failure that survived retry) or fewer
        # scout modules ran than were discovered. Bravo6's titles/findings
        # for this site cannot be trusted as "nothing wrong was found" --
        # it may not have looked at all. Excluded entirely: not counted as
        # agree, disagree, or even not_comparable, since there was no real
        # Bravo6 evaluation to compare Mozilla's verdict against.
        if row.get("incomplete_scan"):
            excluded_incomplete_scans.append({
                "domain": domain,
                "bravo6_tests_run": row.get("bravo6_tests_run"),
                "bravo6_page_is_representative": row.get("bravo6_page_is_representative"),
                "bravo6_coverage_note": row.get("bravo6_coverage_note"),
                "bravo6_errors": row.get("bravo6_errors"),
            })
            continue

        mrow = mozilla_rows.get(domain)
        if mrow is None or mrow.get("status") != "ok":
            print(f"SKIP SITE (mozilla verdict fetch failed): {domain}")
            continue
        verdicts = mrow["verdicts"]

        site_detail = {}
        for signal in CANONICAL_SIGNALS:
            b_verdict = bravo6_verdict_for_signal(titles, signal)
            m_verdict = mozilla_verdict_for_signal(verdicts, signal)

            if m_verdict is None:
                per_signal[signal]["not_comparable"] += 1
                not_comparable_total += 1
                site_detail[signal] = {
                    "bravo6": b_verdict,
                    "mozilla": None,
                    "mozilla_raw_result": verdicts.get(signal, {}).get("result"),
                    "comparable": False,
                }
                continue

            total_compared += 1
            per_signal[signal]["sites_compared"].append(domain)
            if b_verdict == m_verdict:
                total_agree += 1
                per_signal[signal]["agree"] += 1
                agree = True
            else:
                per_signal[signal]["disagree"] += 1
                agree = False
                disagreements.append({
                    "domain": domain,
                    "signal": signal,
                    "mozilla_verdict": m_verdict,
                    "bravo6_verdict": b_verdict,
                    "mozilla_result": verdicts.get(signal, {}).get("result"),
                    "direction": (
                        "mozilla=pass, bravo6=fail (bravo6 flagged something mozilla did not)"
                        if m_verdict == "pass" else
                        "mozilla=fail, bravo6=pass (bravo6 missed something mozilla flagged)"
                    ),
                })

            site_detail[signal] = {
                "bravo6": b_verdict,
                "mozilla": m_verdict,
                "mozilla_raw_result": verdicts.get(signal, {}).get("result"),
                "comparable": True,
                "agree": agree,
            }

        per_site_detail[domain] = site_detail

    summary = {
        "total_comparable_checks": total_compared,
        "total_agreeing_checks": total_agree,
        "aggregate_agreement_rate": (total_agree / total_compared) if total_compared else None,
        "aggregate_agreement_rate_percent": (total_agree / total_compared * 100.0) if total_compared else None,
        "total_not_comparable_checks": not_comparable_total,
        "sites": len(results["rows"]),
        "excluded_incomplete_scan_sites": len(excluded_incomplete_scans),
        "sites_included_in_comparison": len(results["rows"]) - len(excluded_incomplete_scans),
        "signals_evaluated": len(CANONICAL_SIGNALS),
        "max_possible_checks": (len(results["rows"]) - len(excluded_incomplete_scans)) * len(CANONICAL_SIGNALS),
    }

    per_signal_summary = {}
    for signal, d in per_signal.items():
        compared = d["agree"] + d["disagree"]
        per_signal_summary[signal] = {
            "agree": d["agree"],
            "disagree": d["disagree"],
            "compared": compared,
            "not_comparable": d["not_comparable"],
            "agreement_rate": (d["agree"] / compared) if compared else None,
        }

    out = {
        "summary": summary,
        "per_signal": per_signal_summary,
        "disagreements": disagreements,
        "excluded_incomplete_scans": excluded_incomplete_scans,
        "per_site_detail": per_site_detail,
    }

    out_path = Path(__file__).with_name("verdict_agreement_results.json")
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")

    print(json.dumps(summary, indent=2))
    print()
    print(f"EXCLUDED (incomplete_scan=true, {len(excluded_incomplete_scans)}):")
    for e in excluded_incomplete_scans:
        print(f"  {e['domain']:25s} tests_run={e['bravo6_tests_run']} page_is_representative={e['bravo6_page_is_representative']}  ({e['bravo6_coverage_note']})")
    print()
    print("PER-SIGNAL:")
    for signal, s in per_signal_summary.items():
        print(f"  {signal}: agree {s['agree']}/{s['compared']}"
              f" (rate={s['agreement_rate']:.3f})" if s['agreement_rate'] is not None else f"  {signal}: no comparable checks",
              f" | not_comparable={s['not_comparable']}")
    print()
    print(f"DISAGREEMENTS ({len(disagreements)}):")
    for d in disagreements:
        print(f"  {d['domain']:25s} {d['signal']:32s} mozilla={d['mozilla_verdict']:5s} bravo6={d['bravo6_verdict']:5s}  ({d['mozilla_result']})")

    print()
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
