#!/usr/bin/env python3
"""
DEFERRED (2026-09-12): moved out of src/api/ -- not part of the active API
Gateway deployment package. See future-work/auth/README.md for why and how
to bring it back. Code below is unmodified from its last active version.
=====================================================================

Bravo6 API Gateway -- Scan-Job Record (Schema + Cosmos DB Persistence)
=====================================================================
No "scan-job" schema exists anywhere else in the codebase to reuse:
src/report/report_generator.py's build_html() consumes a scan RESULT dict
(main_scanner.py's run_scout() return value -- a finished scan's
findings), which is a different concept from a scan-job record: this one
represents a *submitted, queued* request, created before the Worker ever
runs. This module defines that schema from scratch.

Storage target: reuses the "scans" Cosmos SQL container already
provisioned in terraform/modules/cosmos_db/main.tf (partition key path
/scanId) rather than adding a new container -- this record's id doubles
as its scanId, satisfying that partition key directly.

Retry-then-local-fallback: the paper's Data-Layer Resilience description
implies the Worker's own Cosmos write already retries before falling
back to a local JSON file. Reading main_scanner.py's actual
run_scout() during this pass found that isn't true today: it's a single
attempt, straight to the local-JSON fallback on any exception, no retry
loop in between (and it authenticates with an account key via
COSMOS_KEY, not Managed Identity). write_scan_job() below implements the
retry-then-fallback behavior the paper describes, rather than silently
reproducing the Worker's narrower real behavior under that description.
"""
import json
import logging
import time
import uuid
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from azure.cosmos import exceptions as cosmos_exceptions
from azure.cosmos.container import ContainerProxy

logger = logging.getLogger("Bravo6-Gateway.scan_job")

COSMOS_WRITE_MAX_ATTEMPTS = 3
COSMOS_WRITE_RETRY_BACKOFF_SECONDS = 1.0

STATUS_QUEUED = "queued"


@dataclass
class ScanJob:
    id: str          # == scanId; Cosmos requires "id", container's partition key path is /scanId
    scanId: str
    user_id: str
    url: str
    submitted_at: str  # ISO 8601 UTC
    status: str        # "queued"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def new_scan_job(user_id: str, url: str) -> ScanJob:
    job_id = str(uuid.uuid4())
    return ScanJob(
        id=job_id,
        scanId=job_id,
        user_id=user_id,
        url=url,
        submitted_at=datetime.now(timezone.utc).isoformat(),
        status=STATUS_QUEUED,
    )


class ScanJobWriteError(Exception):
    """Cosmos DB write failed after all retries AND the local-JSON
    fallback also failed -- there is no record of this job anywhere.
    Callers must treat this as a 503, the same as an enqueue failure."""


def write_scan_job(job: ScanJob, container: ContainerProxy, fallback_dir: Optional[Path] = None) -> None:
    """Write job to the given Cosmos container client, retrying up to
    COSMOS_WRITE_MAX_ATTEMPTS times with a linear backoff.

    IMPORTANT (found while writing this pass's tests, not the Worker's
    behavior): unlike main_scanner.py's run_scout(), where a local-JSON
    fallback is an acceptable degraded-success outcome (nothing else in
    the system depends on that write having happened), a scan-job record
    invisible to Cosmos DB here is NOT an acceptable substitute -- Step
    3's quota enforcement counts a user's recent jobs by querying Cosmos
    DB directly, so a job that only exists in a local file would
    silently escape every future quota count, undermining the very
    control this pass exists to add. So: ALWAYS raises ScanJobWriteError
    if the Cosmos write itself never succeeds, even if a local forensic
    copy could be written -- that copy is a best-effort debugging trace,
    not a recovery path, and callers must still return 503.
    """
    last_error: Optional[Exception] = None
    for attempt in range(1, COSMOS_WRITE_MAX_ATTEMPTS + 1):
        try:
            container.create_item(body=job.to_dict())
            return
        except cosmos_exceptions.CosmosHttpResponseError as e:
            last_error = e
            logger.warning(
                f"Cosmos DB write attempt {attempt}/{COSMOS_WRITE_MAX_ATTEMPTS} "
                f"failed for job {job.id}: {e}"
            )
            if attempt < COSMOS_WRITE_MAX_ATTEMPTS:
                time.sleep(COSMOS_WRITE_RETRY_BACKOFF_SECONDS * attempt)

    fallback_dir = fallback_dir or (Path(__file__).parent / "results")
    fallback_note = "no local forensic copy could be saved either"
    try:
        fallback_dir.mkdir(parents=True, exist_ok=True)
        fallback_path = fallback_dir / f"scan_job_{job.id}.json"
        fallback_path.write_text(json.dumps(job.to_dict(), indent=2), encoding="utf-8")
        fallback_note = f"local forensic copy saved to {fallback_path}"
    except Exception as fallback_error:
        fallback_note = f"local forensic copy ALSO failed: {fallback_error}"

    logger.error(
        f"Cosmos DB write failed after {COSMOS_WRITE_MAX_ATTEMPTS} attempts "
        f"for job {job.id} ({fallback_note}). Last error: {last_error}"
    )
    raise ScanJobWriteError(
        f"Cosmos DB write failed for job {job.id} after {COSMOS_WRITE_MAX_ATTEMPTS} "
        f"attempts ({fallback_note}). Last error: {last_error}"
    )


def count_recent_scans_for_user(user_id: str, window_start: datetime, container: ContainerProxy) -> int:
    """Real Cosmos DB implementation of quota.check_quota()'s
    count_recent_scans callback -- queries the "scans" container for the
    number of jobs owned by user_id submitted at or after window_start.
    Cross-partition (the container is partitioned by /scanId, not
    /user_id) -- acceptable at this scale; a per-user counter document
    would avoid the cross-partition query but is a heavier design not
    justified before any real traffic volume exists."""
    query = (
        "SELECT VALUE COUNT(1) FROM c "
        "WHERE c.user_id = @user_id AND c.submitted_at >= @window_start"
    )
    parameters = [
        {"name": "@user_id", "value": user_id},
        {"name": "@window_start", "value": window_start.isoformat()},
    ]
    results = list(
        container.query_items(
            query=query,
            parameters=parameters,
            enable_cross_partition_query=True,
        )
    )
    return int(results[0]) if results else 0
