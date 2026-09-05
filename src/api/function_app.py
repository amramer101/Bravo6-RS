#!/usr/bin/env python3
"""
Bravo6 API Gateway
=====================================================================
The four responsibilities the paper commits to (component table,
System Architecture; "API Gateway Resilience", Reliability) -- nothing
broader:
    1. JWT validation (Microsoft Entra External ID)          -> 401
    2. Blocklist enforcement (immutable, in-code)             -> 403
    3. Per-user quota enforcement (closes the Denial-of-Wallet
       gap ONLY once this is deployed and observed working)   -> 429
    4. Cosmos DB write, then Service Bus enqueue               -> 202
       (transient Service Bus errors retry internally before   -> 503
       falling back to an error response)

handle_scan_request() below is the entire decision path, deliberately
decoupled from func.HttpRequest/HttpResponse so it's directly
unit-testable with plain Python values and mocks (see
test_api_gateway.py) -- the same "pure function wrapped by a thin
Functions entry point" shape main_scanner.py's run_scout() and the
scouts' run(ctx) already use elsewhere in this project.
"""
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, ContextManager, Dict, Optional, Tuple
from urllib.parse import urlparse

import azure.functions as func
from azure.cosmos import CosmosClient
from azure.cosmos.container import ContainerProxy
from azure.identity import DefaultAzureCredential
from azure.servicebus import ServiceBusClient, ServiceBusSender
from jwt import PyJWKClient

from auth import AuthError, build_jwks_client, extract_bearer_token, validate_jwt
from blocklist import is_blocklisted
from quota import check_quota
from scan_job import (
    ScanJobWriteError,
    count_recent_scans_for_user,
    new_scan_job,
    write_scan_job,
)
from servicebus_queue import EnqueueError, enqueue_scan_job

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Bravo6-Gateway")

# Optional, secondary defense-in-depth SSRF check (Step 5 -- NOT the
# primary control; the Worker's SSRFSafeResolver/SSRFSafeConnector on
# every outbound scout request is what actually closes that gap, added
# in the previous hardening pass). Best-effort only: main_scanner.py
# lives in the Worker's OWN Function App package (src/worker/), a
# separate deployment unit from this one, so this cross-package import
# only succeeds in this repo checkout / local testing -- it will not
# resolve in a real deployed API Gateway package unless
# is_target_address_safe() (or a copy of it) is vendored into src/api/'s
# own deployment package. Failing to import is NOT an error: the
# secondary layer is simply inactive, and the Worker's own check still
# runs regardless.
try:
    sys.path.insert(0, str(Path(__file__).parent.parent / "worker"))
    from main_scanner import is_target_address_safe as _ssrf_secondary_check
except Exception:
    _ssrf_secondary_check = None


def _hostname_from_url(url: str) -> str:
    normalized = url if "://" in url else f"https://{url}"
    return urlparse(normalized).hostname or url


def handle_scan_request(
    authorization_header: Optional[str],
    url: str,
    jwks_client: PyJWKClient,
    issuer: str,
    audience: str,
    cosmos_container: ContainerProxy,
    get_service_bus_sender: Callable[[], ContextManager[ServiceBusSender]],
    ssrf_check: Optional[Callable[[str], bool]] = None,
) -> Tuple[int, Dict[str, Any]]:
    """Returns (status_code, response_body). get_service_bus_sender is a
    zero-arg callable returning a context manager yielding a
    ServiceBusSender -- called ONLY if a request reaches step 4, so a
    401/403/429 never pays for opening an AMQP link. In tests this is
    typically `lambda: contextlib.nullcontext(mock_sender)`.
    """
    # Step 1 -- JWT validation. Any failure: 401, stop immediately.
    try:
        token = extract_bearer_token(authorization_header)
        user = validate_jwt(token, jwks_client, issuer, audience)
    except AuthError as e:
        logger.info(f"401 unauthorized: {e}")
        return 401, {"error": "unauthorized"}

    hostname = _hostname_from_url(url)

    # Step 2 -- Blocklist enforcement. Runs before quota AND before any
    # Cosmos DB write / Service Bus enqueue, exactly as specified: a
    # blocked target must never consume quota or leave a trace in either
    # downstream system.
    if is_blocklisted(hostname):
        logger.info(f"403 blocklisted target: {hostname}")
        return 403, {"error": "target domain is not permitted"}

    # Step 5 (optional, secondary) -- SSRF defense-in-depth. Not the
    # primary control (see module docstring). A failure IN the check
    # itself (e.g. the cross-package import above didn't resolve, or a
    # transient DNS hiccup) does not block the request -- only an actual
    # unsafe-address verdict does.
    active_ssrf_check = ssrf_check if ssrf_check is not None else _ssrf_secondary_check
    if active_ssrf_check is not None:
        try:
            if not active_ssrf_check(hostname):
                logger.info(f"403 secondary SSRF check blocked target: {hostname}")
                return 403, {"error": "target address is not permitted"}
        except Exception as e:
            logger.warning(f"secondary SSRF check errored (not blocking on it): {e}")

    # Step 3 -- Per-user quota enforcement.
    def _count(uid: str, window_start: datetime) -> int:
        return count_recent_scans_for_user(uid, window_start, cosmos_container)

    decision = check_quota(user.subject, _count)
    if not decision.allowed:
        logger.info(
            f"429 quota exceeded: user={user.subject} "
            f"count={decision.count_in_window}/{decision.limit}"
        )
        return 429, {
            "error": "quota exceeded",
            "limit": decision.limit,
            "count_in_window": decision.count_in_window,
        }

    # Step 4 -- Cosmos DB write, then Service Bus enqueue.
    job = new_scan_job(user.subject, url)
    try:
        write_scan_job(job, cosmos_container)
    except ScanJobWriteError as e:
        logger.error(f"503 scan-job persistence failed: {e}")
        return 503, {"error": "could not persist scan job"}

    # NOTE (known limitation, not fixed here): the Cosmos write and the
    # Service Bus enqueue are not atomic. If the enqueue below fails
    # permanently after the write above succeeded, the scan-job record
    # is left in Cosmos DB with status "queued" but nothing will ever
    # process it -- an orphaned record, not a duplicate or lost request.
    # A reconciliation job (e.g. sweep "queued" records older than N
    # minutes with no matching result) would close this; out of this
    # pass's scope (the paper doesn't currently claim this is handled).
    try:
        with get_service_bus_sender() as sender:
            enqueue_scan_job(job, sender)
    except EnqueueError as e:
        logger.error(f"503 enqueue failed: {e}")
        return 503, {"error": "could not enqueue scan job"}

    logger.info(f"202 accepted: job_id={job.id} user={user.subject} url={job.url}")
    return 202, {"job_id": job.id, "status": job.status}


# ------------------------------------------------------------------------------
# Azure Functions HTTP entry point -- thin wrapper around handle_scan_request()
# ------------------------------------------------------------------------------
app = func.FunctionApp()

_credential = None
_jwks_client = None
_cosmos_container = None
_sb_client = None


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


def _get_service_bus_client() -> ServiceBusClient:
    global _sb_client
    if _sb_client is None:
        namespace = os.environ["ServiceBusConnection__fullyQualifiedNamespace"]
        _sb_client = ServiceBusClient(namespace, credential=_get_credential())
    return _sb_client


@app.route(route="scan", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def submit_scan(req: func.HttpRequest) -> func.HttpResponse:
    # auth_level=ANONYMOUS is deliberate, not a bypass of Step 1: this
    # disables the Azure Functions *host-level* function-key gate (a
    # separate, coarser mechanism from the actual per-user JWT check
    # this Gateway performs itself). The real authentication is Step 1
    # inside handle_scan_request(), which runs unconditionally.
    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "invalid JSON body"}), status_code=400, mimetype="application/json"
        )

    url = body.get("url") if isinstance(body, dict) else None
    if not url:
        return func.HttpResponse(
            json.dumps({"error": "missing 'url'"}), status_code=400, mimetype="application/json"
        )

    queue_name = os.environ.get("SERVICE_BUS_QUEUE_NAME", "bravo6-queue")

    def _get_sender() -> ContextManager[ServiceBusSender]:
        return _get_service_bus_client().get_queue_sender(queue_name=queue_name)

    status_code, response_body = handle_scan_request(
        authorization_header=req.headers.get("Authorization"),
        url=url,
        jwks_client=_get_jwks_client(),
        issuer=os.environ["ENTRA_ISSUER"],
        audience=os.environ["ENTRA_AUDIENCE"],
        cosmos_container=_get_cosmos_container(),
        get_service_bus_sender=_get_sender,
    )
    return func.HttpResponse(json.dumps(response_body), status_code=status_code, mimetype="application/json")
