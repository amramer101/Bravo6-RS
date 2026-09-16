#!/usr/bin/env python3
"""Re-fetch Mozilla Observatory results and persist per-test pass/fail verdicts.

results.json only stored test *names* (signal presence), not the boolean
pass/fail verdict Mozilla assigns to each test. This script re-fetches the
live API response for each of the 25 sample sites and dumps the raw
tests[signal] -> {"pass": bool, "result": str} detail so we can recompute
agreement on verdicts instead of raw signal-set overlap.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import requests

SAMPLE_PATH = Path(__file__).with_name("sample_sites.json")
OUT_PATH = Path(__file__).with_name("mozilla_verdicts.json")

CANONICAL_SIGNALS = [
    "content-security-policy",
    "strict-transport-security",
    "cookies",
    "cross-origin-resource-sharing",
    "subresource-integrity",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
]


def fetch(domain: str) -> dict:
    url = "https://observatory-api.mdn.mozilla.net/api/v2/analyze"
    last_exc = None
    for attempt in range(4):
        try:
            resp = requests.get(url, params={"host": domain, "wait": 0}, timeout=45)
            if resp.status_code == 429:
                time.sleep(5)
                continue
            resp.raise_for_status()
            payload = resp.json()
            tests = payload.get("tests") or {}
            verdicts = {}
            for signal in CANONICAL_SIGNALS:
                t = tests.get(signal)
                if t is None:
                    verdicts[signal] = {"present": False}
                else:
                    verdicts[signal] = {
                        "present": True,
                        "pass": t.get("pass"),
                        "result": t.get("result"),
                    }
            return {
                "domain": domain,
                "status": "ok",
                "grade": (payload.get("scan") or {}).get("grade"),
                "score": (payload.get("scan") or {}).get("score"),
                "verdicts": verdicts,
            }
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            time.sleep(2)
    return {"domain": domain, "status": "error", "error": str(last_exc)}


def main() -> None:
    data = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    sites = data.get("sites", [])
    out = []
    for item in sites:
        domain = item["domain"]
        row = fetch(domain)
        print(domain, row.get("status"), row.get("grade"))
        out.append(row)
        time.sleep(1)
    OUT_PATH.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
