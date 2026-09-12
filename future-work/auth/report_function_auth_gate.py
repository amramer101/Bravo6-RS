#!/usr/bin/env python3
"""
DEFERRED (2026-09-12): moved out of src/report/function_app.py -- not
part of the active Report Function. See future-work/auth/README.md for
why and how to bring it back.

This is the JWT-validate -> point-read -> ownership-check gate that used
to wrap BOTH of src/report/function_app.py's routes (handle_status_request,
handle_result_request), plus those two handlers themselves in their last
auth-gated shape -- including handle_result_request's HTML output via
future-work/report-html/report_generator.py's build_html(), which was
still the active behavior when auth was removed. HTML output and auth are
independent decisions (see future-work/report-html/README.md) that
happened to both be true at the same moment this snapshot was taken --
restoring auth does NOT require also restoring HTML; pair this gate with
either build_html() or json.dumps() for the Complete-status branch,
whichever the active src/report/function_app.py uses at the time.

Depends on report_auth.py (this same directory) for AuthError/
extract_bearer_token/validate_jwt, and on
future-work/report-html/report_generator.py for build_html -- both moved
out alongside this file, see their own README.md notes.
"""
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from azure.cosmos import exceptions as cosmos_exceptions
from azure.cosmos.container import ContainerProxy
from jwt import PyJWKClient

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "report-html"))

from report_auth import AuthError, extract_bearer_token, validate_jwt
from report_generator import build_html

# Must match src/api/scan_job.py's STATUS_QUEUED and
# src/worker/main_scanner.py's "blocked_ssrf" early-exit status string.
_STATUS_QUEUED = "queued"
_STATUS_BLOCKED_SSRF = "blocked_ssrf"
_STATUS_RUNNING = "running"
_FAILED_STATUS_VALUES = {_STATUS_BLOCKED_SSRF, "failed", "error"}

_ERROR_MESSAGES = {
    400: "missing scanId",
    401: "unauthorized",
    403: "forbidden",
    404: "scan not found",
}


def derive_status(doc: Dict[str, Any]) -> str:
    """Normalize a "scans" container document into one of Pending,
    Running, Complete, Failed. Identical logic to the active
    src/report/function_app.py's _derive_status() -- this doesn't depend
    on auth, it's duplicated here only so this file is self-contained and
    independently runnable/testable without importing the live module."""
    status = doc.get("status")
    if status in _FAILED_STATUS_VALUES:
        return "Failed"
    if status == _STATUS_RUNNING:
        return "Running"
    if status == _STATUS_QUEUED:
        return "Pending"
    if "score" in doc or "findings" in doc or "total_findings" in doc:
        return "Complete"
    return "Pending"


def load_owned_scan(
    authorization_header: Optional[str],
    scan_id: Optional[str],
    jwks_client: PyJWKClient,
    issuer: str,
    audience: str,
    cosmos_container: ContainerProxy,
) -> Tuple[Optional[int], Optional[Dict[str, Any]]]:
    """Shared JWT-validate -> point-read -> ownership-check gate. Returns
    (None, doc) on success, or (status_code, None) with the status the
    caller must return immediately."""
    if not scan_id:
        return 400, None

    try:
        token = extract_bearer_token(authorization_header)
        user = validate_jwt(token, jwks_client, issuer, audience)
    except AuthError:
        return 401, None

    try:
        doc = cosmos_container.read_item(item=scan_id, partition_key=scan_id)
    except cosmos_exceptions.CosmosResourceNotFoundError:
        return 404, None

    if doc.get("user_id") != user.subject:
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
    """GET /report/status (auth-gated shape) -- returns (status_code, response_body)."""
    err_status, doc = load_owned_scan(
        authorization_header, scan_id, jwks_client, issuer, audience, cosmos_container
    )
    if err_status is not None:
        return err_status, {"error": _ERROR_MESSAGES[err_status]}

    return 200, {"scanId": scan_id, "status": derive_status(doc)}


def handle_result_request(
    authorization_header: Optional[str],
    scan_id: Optional[str],
    jwks_client: PyJWKClient,
    issuer: str,
    audience: str,
    cosmos_container: ContainerProxy,
) -> Tuple[int, str, str]:
    """GET /report/result (auth-gated shape, HTML output) -- returns
    (status_code, content_type, body)."""
    err_status, doc = load_owned_scan(
        authorization_header, scan_id, jwks_client, issuer, audience, cosmos_container
    )
    if err_status is not None:
        return err_status, "application/json", json.dumps({"error": _ERROR_MESSAGES[err_status]})

    status = derive_status(doc)
    if status != "Complete":
        return 409, "application/json", json.dumps({"error": "scan not complete", "status": status})

    return 200, "text/html", build_html(doc)
