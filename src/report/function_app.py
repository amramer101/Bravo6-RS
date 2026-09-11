#!/usr/bin/env python3
"""
Bravo6 Report Function
=====================================================================
The read path: two HTTP routes over the "scans" Cosmos DB container
(src/api/scan_job.py's schema), Managed-Identity-authenticated, read-only
end to end -- no Cosmos write action anywhere in this file or in this
Function App's Terraform-granted role (terraform/iam.tf's report_reader:
readMetadata, items/read, executeQuery, readChangeFeed).

---------------------------------------------------------------------
DECISION RECORD -- the full-result route's contract (docs/data-flow.md
and docs/architecture-overview.md specify the status-poll route exactly
but leave "the frontend fetches the full results" [data-flow.md, step 11]
completely open: no route name, no method, no content type, no
before-Complete behavior). This is that decision, made explicit and
intentional rather than implicit:

  - Route: GET /report/result?scanId=<id>   (query param, matching the
    status route's own established convention -- docs/data-flow.md's
    `GET /report/status?scanId` -- rather than inventing a different
    path-param style for the sibling route).
  - Content-Type: text/html, body = report_generator.build_html()'s
    output verbatim. NOT wrapped in a JSON envelope: build_html() exists
    specifically to produce a complete, self-contained HTML document
    (own <style>, own escaping) for a browser to render directly: adding
    a JSON wrapper (e.g. {"html": "..."}) would buy nothing here and
    would force every caller to unwrap it before use.
  - Auth: identical JWT validation to the status route and to the API
    Gateway (same Entra External ID tenant, same audience) -- see the
    ownership section below for why this route needs it even though it
    only reads.
  - Before status reaches Complete: 409 Conflict, JSON body
    {"error": "scan not complete", "status": "<Pending|Running|Failed>"}.
    Chosen over a redirect back to /report/status because the caller
    already knows that route (this project's own polling loop hits it
    every 2s) -- a 409 with the current status inline lets a caller
    branch on the SAME response shape /report/status already returns,
    without a second round trip.

  Applying JWT + ownership to the STATUS route too (not just /result),
  even though docs/architecture-overview.md's Master Component Reference
  Table doesn't call this out explicitly for Report: the alternative --
  an anonymous status endpoint -- would let anyone enumerate scanIds and
  learn whether a given one exists and what state it's in, which is
  exactly the kind of read-path information disclosure the "ownership
  enforcement on read" gap (this project's paper names it as an open
  limitation) is about. Both routes go through the same
  authenticate-then-authorize gate below.

  Ownership enforcement: ANY authenticated caller can call either route
  with ANY scanId. The gate compares the JWT's "sub" claim (the stable
  per-user identifier scan_job.py's write path already uses to key
  user_id) against the target document's own "user_id" field -- a
  mismatch is 403, not 404, matching the API Gateway's own convention of
  a specific status per failure mode rather than uniformly hiding
  existence (a 404 is still returned separately when the document
  genuinely doesn't exist at all).

---------------------------------------------------------------------
KNOWN UPSTREAM GAP (found while wiring this, NOT fixed here -- Worker
and API Gateway are explicitly out of scope for this pass; see
DEPLOYMENT_NOTES.md): src/api/scan_job.py writes the queued job record
under id = the scanId the API generates and returns to the caller in its
202 response. src/worker/main_scanner.py's run_scout() never receives
that scanId at all -- src/api/servicebus_queue.py's build_scan_message()
sends it as "job_id" in the Service Bus message, but
src/worker/function_app.py's process_scan() only ever reads "url" and
"config" from that message body, and run_scout() mints its OWN fresh
uuid.uuid4() for "scanId" internally (main_scanner.py, both the
blocked_ssrf early-exit and the normal-completion path). The practical
effect: today, the job-record document a user's scanId points at is
NEVER updated past status="queued", and the Worker's actual completed
result lands under a completely different, uncorrelated id nothing ever
surfaces back to the caller. This means /report/status and /report/result
will only ever observe Pending for a real scanId until that correlation
is fixed -- a Worker/API-side bug, not a Report-side one. Everything in
this file implements the CORRECT, intended behavior for a single
evolving document (same id, status transitioning as the job progresses)
so that once the upstream fix lands, no change is needed here -- see
_derive_status() below for exactly what shape each state is inferred
from.
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
from jwt import PyJWKClient

from auth import AuthError, build_jwks_client, extract_bearer_token, validate_jwt
from report_generator import build_html

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Bravo6-Report")

# Must match src/api/scan_job.py's STATUS_QUEUED and
# src/worker/main_scanner.py's "blocked_ssrf" early-exit status string --
# duplicated here for the same reason auth.py is vendored (separate
# deployment package, no cross-package import at runtime).
_STATUS_QUEUED = "queued"
_STATUS_BLOCKED_SSRF = "blocked_ssrf"
_STATUS_RUNNING = "running"  # not written by any code path today; accepted
# here so a future Worker change that adds an explicit "running" update
# needs no change on this side.
_FAILED_STATUS_VALUES = {_STATUS_BLOCKED_SSRF, "failed", "error"}

_ERROR_MESSAGES = {
    400: "missing scanId",
    401: "unauthorized",
    403: "forbidden",
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


def _load_owned_scan(
    authorization_header: Optional[str],
    scan_id: Optional[str],
    jwks_client: PyJWKClient,
    issuer: str,
    audience: str,
    cosmos_container: ContainerProxy,
) -> Tuple[Optional[int], Optional[Dict[str, Any]]]:
    """Shared JWT-validate -> point-read -> ownership-check gate for both
    routes below. Returns (None, doc) on success, or (status_code, None)
    with the status the caller must return immediately -- deliberately
    the same four-outcome shape (400/401/403/404) for both routes so
    neither one has to reimplement this.
    """
    if not scan_id:
        return 400, None

    try:
        token = extract_bearer_token(authorization_header)
        user = validate_jwt(token, jwks_client, issuer, audience)
    except AuthError as e:
        logger.info(f"401 unauthorized: {e}")
        return 401, None

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

    if doc.get("user_id") != user.subject:
        logger.info(f"403 ownership mismatch: scanId={scan_id} caller={user.subject}")
        return 403, None

    return None, doc


def handle_status_request(
    authorization_header: Optional[str],
    scan_id: Optional[str],
    jwks_client: PyJWKClient,
    issuer: str,
    audience: str,
    cosmos_container: ContainerProxy,
) -> Tuple[int, Dict[str, Any]]:
    """GET /report/status -- returns (status_code, response_body)."""
    err_status, doc = _load_owned_scan(
        authorization_header, scan_id, jwks_client, issuer, audience, cosmos_container
    )
    if err_status is not None:
        return err_status, {"error": _ERROR_MESSAGES[err_status]}

    return 200, {"scanId": scan_id, "status": _derive_status(doc)}


def handle_result_request(
    authorization_header: Optional[str],
    scan_id: Optional[str],
    jwks_client: PyJWKClient,
    issuer: str,
    audience: str,
    cosmos_container: ContainerProxy,
) -> Tuple[int, str, str]:
    """GET /report/result -- returns (status_code, content_type, body)."""
    err_status, doc = _load_owned_scan(
        authorization_header, scan_id, jwks_client, issuer, audience, cosmos_container
    )
    if err_status is not None:
        return err_status, "application/json", json.dumps({"error": _ERROR_MESSAGES[err_status]})

    status = _derive_status(doc)
    if status != "Complete":
        logger.info(f"409 not complete: scanId={scan_id} status={status}")
        return 409, "application/json", json.dumps({"error": "scan not complete", "status": status})

    return 200, "text/html", build_html(doc)


# ------------------------------------------------------------------------------
# Azure Functions HTTP entry points -- thin wrappers around the two pure
# handlers above, the same "pure function wrapped by a thin Functions entry
# point" shape used throughout this project (main_scanner.py's run_scout(),
# src/api/function_app.py's handle_scan_request()).
# ------------------------------------------------------------------------------
app = func.FunctionApp()

_credential = None
_jwks_client = None
_cosmos_container = None


def _get_credential() -> DefaultAzureCredential:
    global _credential
    if _credential is None:
        _credential = DefaultAzureCredential()
    return _credential


def _get_jwks_client() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        _jwks_client = build_jwks_client(os.environ["ENTRA_JWKS_URI"])
    return _jwks_client


def _get_cosmos_container() -> ContainerProxy:
    global _cosmos_container
    if _cosmos_container is None:
        client = CosmosClient(os.environ["COSMOS_URL"], credential=_get_credential())
        db = client.get_database_client(os.environ.get("COSMOS_DATABASE", "bravo6-db"))
        _cosmos_container = db.get_container_client(os.environ.get("COSMOS_CONTAINER", "scans"))
    return _cosmos_container


@app.route(route="report/status", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def get_status(req: func.HttpRequest) -> func.HttpResponse:
    # auth_level=ANONYMOUS disables only the host-level function-key gate,
    # not authentication -- the real check is handle_status_request's
    # unconditional JWT validation, same rationale as
    # src/api/function_app.py's submit_scan.
    status_code, body = handle_status_request(
        authorization_header=req.headers.get("Authorization"),
        scan_id=req.params.get("scanId"),
        jwks_client=_get_jwks_client(),
        issuer=os.environ["ENTRA_ISSUER"],
        audience=os.environ["ENTRA_AUDIENCE"],
        cosmos_container=_get_cosmos_container(),
    )
    return func.HttpResponse(json.dumps(body), status_code=status_code, mimetype="application/json")


@app.route(route="report/result", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def get_result(req: func.HttpRequest) -> func.HttpResponse:
    status_code, content_type, body = handle_result_request(
        authorization_header=req.headers.get("Authorization"),
        scan_id=req.params.get("scanId"),
        jwks_client=_get_jwks_client(),
        issuer=os.environ["ENTRA_ISSUER"],
        audience=os.environ["ENTRA_AUDIENCE"],
        cosmos_container=_get_cosmos_container(),
    )
    return func.HttpResponse(body, status_code=status_code, mimetype=content_type)
