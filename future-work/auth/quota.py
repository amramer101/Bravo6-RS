#!/usr/bin/env python3
"""
DEFERRED (2026-09-12): moved out of src/api/ -- not part of the active API
Gateway deployment package. See future-work/auth/README.md for why and how
to bring it back. Code below is unmodified from its last active version.
=====================================================================

Bravo6 API Gateway -- Per-User Quota Enforcement
=====================================================================
This is the control that closes the paper's Threat Model / Limitations /
Future Work Denial-of-Wallet gap -- ONLY once this Function App is
actually deployed and observed enforcing it. The code existing here does
not retroactively close that gap in the paper's own language; see the
top-level report for this pass.

Rule: at most MAX_SCANS_PER_WINDOW scan submissions per user within a
rolling WINDOW_SECONDS window.

Why 10 scans / 3600s specifically: main_scanner.py's DEFAULT_TIMEOUTS
enumerates 10 scout modules per scan, each issuing at least one outbound
request against the target (some several -- e.g. test_06_info_disclosure
issues ~23). A ceiling of 10 scans/hour per user bounds a single
compromised or malicious credential to roughly 100-250 outbound
target requests/hour, not an unbounded flood -- generous enough for a
legitimate user re-scanning a handful of sites after making fixes over
the course of an hour, small enough to cap the actual cost driver (Worker
compute time + outbound bandwidth) at a known multiple of one scan's
cost. This is a starting point chosen from the scanner's own known
per-scan cost shape, not a value measured from live traffic (none
exists yet) -- revisit once the Gateway is deployed and real submission
patterns can be observed.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

MAX_SCANS_PER_WINDOW = 10
WINDOW_SECONDS = 3600


@dataclass(frozen=True)
class QuotaDecision:
    allowed: bool
    count_in_window: int
    limit: int


def check_quota(
    user_id: str,
    count_recent_scans: Callable[[str, datetime], int],
) -> QuotaDecision:
    """count_recent_scans(user_id, window_start) must return the number
    of scan-job records owned by user_id with submitted_at >= window_start.
    Injected so tests can supply a fake count (above/at/below the
    threshold) instead of a real Cosmos DB query."""
    window_start = datetime.now(timezone.utc) - timedelta(seconds=WINDOW_SECONDS)
    count = count_recent_scans(user_id, window_start)
    return QuotaDecision(
        allowed=count < MAX_SCANS_PER_WINDOW,
        count_in_window=count,
        limit=MAX_SCANS_PER_WINDOW,
    )
