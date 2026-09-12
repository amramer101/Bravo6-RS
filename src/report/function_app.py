#!/usr/bin/env python3
"""
Bravo6 Report Function
=====================================================================
The read path: two HTTP routes over the "scans" Cosmos DB container
(src/api/scan_job.py's schema), Managed-Identity-authenticated to Cosmos
DB, read-only end to end -- no Cosmos write action anywhere in this file
or in this Function App's Terraform-granted role (terraform/iam.tf's
report_reader: readMetadata, items/read, executeQuery, readChangeFeed).

DEFERRED-AUTH NOTE (2026-09-12, see future-work/auth/README.md): this
Function App previously did JWT validation (Microsoft Entra External ID)
plus an ownership check (JWT "sub" claim vs. the document's "user_id")
before either route would read anything -- removed in the same pass as
the API Gateway's (src/api/function_app.py), for the same reason: there
is no authenticated user identity left to check ownership against.
auth.py and the ownership-check gate are fully written and tested, just
not wired in -- see future-work/auth/report_auth.py and
future-work/auth/report_function_auth_gate.py to bring them back.

CONSEQUENCE: both routes are now genuinely anonymous-and-answerable --
ANY caller who knows or guesses a scanId can read its status/result. This
is the same read-path information-disclosure/enumeration concern the
original JWT-gating comment (now in report_function_auth_gate.py) named
explicitly; it is not re-litigated here, just noted as the current,
deliberate state pending a real auth decision project-wide.

OUTPUT FORMAT NOTE (2026-09-12, independent of the auth change above):
/report/result now returns the scan result document as JSON directly
(json.dumps(doc)), not rendered HTML. future-work/report-html/README.md
has the reasoning (no report frontend is planned) and how to restore
build_html() if that changes -- this is a separate decision from auth
removal; restoring one does not require restoring the other.

---------------------------------------------------------------------
FORMERLY-KNOWN UPSTREAM GAP, FIXED (DEPLOYMENT_NOTES.md's Gap 3):
src/api/scan_job.py writes the queued job record under id = the scanId
the API generates and returns to the caller in its 202 response.
src/api/servicebus_queue.py's build_scan_message() sends that same id
as "job_id" in the Service Bus message; src/worker/function_app.py's
process_scan() now reads it and threads it through to
main_scanner.py's run_scout(url, scan_id=job_id, ...), which uses it
as "scanId" on both the blocked_ssrf early-exit path and the
normal-completion path -- no more internally-minted uuid.uuid4(). The
queued job document and the Worker's finished result document now
share an id, so /report/status and /report/result can observe a real
Pending -> Complete transition -- see _derive_status() below for
exactly what shape each state is inferred from.

Note (2026-09-12): the API Gateway's own Cosmos write was ALSO removed
in Task 1 (see future-work/auth/README.md), so today nothing seeds a
"queued" record at all -- the Worker's own result write is the only
document that will ever exist for a given scanId. /report/status will
therefore go straight from "not found" (404) to "Complete", never
observably "Pending", until the Gateway's Cosmos write is restored
alongside its auth.
"""
import json
import logging
import os
from typing import Any, Dict, Optional, Tuple

import azure.functions as func
from azure.cosmos import exceptions as cosmos_exceptions
from azure.cosmos import CosmosClient
from azure.cosmos.container import ContainerProxy
from azure.identity import DefaultAzureCredential

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Bravo6-Report")

# Must match src/api/scan_job.py's STATUS_QUEUED and
# src/worker/main_scanner.py's "blocked_ssrf" early-exit status string --
# duplicated here for the same reason report_auth.py was vendored before
# it moved to future-work/ (separate deployment package, no cross-package
# import at runtime).
_STATUS_QUEUED = "queued"
_STATUS_BLOCKED_SSRF = "blocked_ssrf"
_STATUS_RUNNING = "running"  # not written by any code path today; accepted
# here so a future Worker change that adds an explicit "running" update
# needs no change on this side.
_FAILED_STATUS_VALUES = {_STATUS_BLOCKED_SSRF, "failed", "error"}

_ERROR_MESSAGES = {
    400: "missing scanId",
    404: "scan not found",
}


def _derive_status(doc: Dict[str, Any]) -> str:
    """Normalize a "scans" container document into one of the four states
    docs/data-flow.md documents (Pending, Running, Complete, Failed).

    Order matters: an explicit "status" field (written by the API at
    submission, or by main_scanner.py's blocked_ssrf early exit) is
    checked first; only once that's absent do we infer Complete from the
    presence of result-shaped fields (score/findings/total_findings),
    which is exactly the "final_result" dict shape main_scanner.py's
    normal-completion path writes -- that path never sets a top-level
    "status" key at all.
    """
    status = doc.get("status")
    if status in _FAILED_STATUS_VALUES:
        return "Failed"
    if status == _STATUS_RUNNING:
        return "Running"
    if status == _STATUS_QUEUED:
        return "Pending"
    if "score" in doc or "findings" in doc or "total_findings" in doc:
        return "Complete"
    # Unknown/unexpected shape: fail closed to "Pending" rather than
    # guessing Complete for a document we don't recognize.
    return "Pending"


def _load_scan(
    scan_id: Optional[str],
    cosmos_container: ContainerProxy,
) -> Tuple[Optional[int], Optional[Dict[str, Any]]]:
    """Shared point-read gate for both routes below. Returns (None, doc)
    on success, or (status_code, None) with the status the caller must
    return immediately -- the same two-outcome shape (400/404) for both
    routes so neither one has to reimplement this."""
    if not scan_id:
        return 400, None

    # Point read, not a query: the "scans" container's partition key path
    # is /scanId and the document's own "id" is always set equal to its
    # "scanId" (scan_job.py's ScanJob.id, main_scanner.py's
    # final_result["id"] = final_result["scanId"]) -- an
    # items/read point read is the correct, cheapest action for this,
    # and it's already covered by the report_reader role's items/read
    # action without needing executeQuery.
    try:
        doc = cosmos_container.read_item(item=scan_id, partition_key=scan_id)
    except cosmos_exceptions.CosmosResourceNotFoundError:
        logger.info(f"404 scan not found: {scan_id}")
        return 404, None

    return None, doc


def handle_status_request(
    scan_id: Optional[str],
    cosmos_container: ContainerProxy,
) -> Tuple[int, Dict[str, Any]]:
    """GET /report/status -- returns (status_code, response_body)."""
    err_status, doc = _load_scan(scan_id, cosmos_container)
    if err_status is not None:
        return err_status, {"error": _ERROR_MESSAGES[err_status]}

    return 200, {"scanId": scan_id, "status": _derive_status(doc)}


def handle_result_request(
    scan_id: Optional[str],
    cosmos_container: ContainerProxy,
) -> Tuple[int, Dict[str, Any]]:
    """GET /report/result -- returns (status_code, response_body). JSON
    only -- see this module's OUTPUT FORMAT NOTE above."""
    err_status, doc = _load_scan(scan_id, cosmos_container)
    if err_status is not None:
        return err_status, {"error": _ERROR_MESSAGES[err_status]}

    status = _derive_status(doc)
    if status != "Complete":
        logger.info(f"409 not complete: scanId={scan_id} status={status}")
        return 409, {"error": "scan not complete", "status": status}

    return 200, doc


# ------------------------------------------------------------------------------
# Azure Functions HTTP entry points -- thin wrappers around the two pure
# handlers above, the same "pure function wrapped by a thin Functions entry
# point" shape used throughout this project (main_scanner.py's run_scout(),
# src/api/function_app.py's handle_scan_request()).
# ------------------------------------------------------------------------------
app = func.FunctionApp()

_credential = None
_cosmos_container = None


def _get_credential() -> DefaultAzureCredential:
    global _credential
    if _credential is None:
        _credential = DefaultAzureCredential()
    return _credential


def _get_cosmos_container() -> ContainerProxy:
    global _cosmos_container
    if _cosmos_container is None:
        client = CosmosClient(os.environ["COSMOS_URL"], credential=_get_credential())
        db = client.get_database_client(os.environ.get("COSMOS_DATABASE", "bravo6-db"))
        _cosmos_container = db.get_container_client(os.environ.get("COSMOS_CONTAINER", "scans"))
    return _cosmos_container


@app.route(route="report/status", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def get_status(req: func.HttpRequest) -> func.HttpResponse:
    # auth_level=ANONYMOUS disables the Azure Functions *host-level*
    # function-key gate. There is currently no application-level auth
    # either -- see this module's docstring.
    status_code, body = handle_status_request(
        scan_id=req.params.get("scanId"),
        cosmos_container=_get_cosmos_container(),
    )
    return func.HttpResponse(json.dumps(body), status_code=status_code, mimetype="application/json")


@app.route(route="report/result", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def get_result(req: func.HttpRequest) -> func.HttpResponse:
    status_code, body = handle_result_request(
        scan_id=req.params.get("scanId"),
        cosmos_container=_get_cosmos_container(),
    )
    return func.HttpResponse(json.dumps(body), status_code=status_code, mimetype="application/json")
