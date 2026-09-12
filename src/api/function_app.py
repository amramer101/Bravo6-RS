#!/usr/bin/env python3
"""
Bravo6 API Gateway
=====================================================================
DEFERRED-AUTH NOTE (2026-09-12, see future-work/auth/README.md): this
Gateway previously did JWT validation, per-user quota enforcement, and a
Cosmos DB "scan-job" write, in that order, before enqueueing. All three
came out together -- quota and the Cosmos record are both keyed on the
JWT's `sub` claim, so neither has anything to key on without auth. The
active pipeline is now three steps, not four:
    1. Blocklist enforcement (immutable, in-code)               -> 403
    2. (optional, secondary) SSRF defense-in-depth               -> 403
    3. Service Bus enqueue                                        -> 202
       (transient Service Bus errors retry internally before     -> 503
       falling back to an error response)
There is currently NO authentication check on this endpoint at all --
auth.py, quota.py, and scan_job.py are fully written and tested, just not
wired in; see future-work/auth/ to bring them back.

CONSEQUENCE FOR REPORT FUNCTION (not fixed here, src/report/ is a
separate deployment unit and out of this pass's scope): src/report/
still validates JWTs, and its ENTRA_ISSUER/ENTRA_JWKS_URI/ENTRA_AUDIENCE
app settings depend on Terraform's entra_external_id module, which this
pass also removed from the live stack (see terraform/main.tf). Report
Function's /report/status and /report/result routes have no way to
receive a valid token anymore and will 401 on every request until that's
addressed on its own.

ALSO NOT FIXED HERE: with no Cosmos write in this Gateway anymore, there
is no "queued" record for Report Function to observe a Pending status
against -- the Worker's own finished-result write (main_scanner.py's
persist_scan_result()) is now the ONLY document that will ever exist in
Cosmos DB for a given scanId. Gap 3's scanId correlation
(DEPLOYMENT_NOTES.md) is unaffected by this -- job_id is still generated
here and threaded through to the Worker via Service Bus -- but a caller
polling Report Function before the Worker finishes would see "not found"
where it previously would have seen "Pending".

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
import uuid
from pathlib import Path
from typing import Any, Callable, ContextManager, Dict, Optional, Tuple
from urllib.parse import urlparse

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.servicebus import ServiceBusClient, ServiceBusSender

from blocklist import is_blocklisted
from servicebus_queue import EnqueueError, build_scan_message, enqueue_scan_job

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
    url: str,
    get_service_bus_sender: Callable[[], ContextManager[ServiceBusSender]],
    ssrf_check: Optional[Callable[[str], bool]] = None,
) -> Tuple[int, Dict[str, Any]]:
    """Returns (status_code, response_body). get_service_bus_sender is a
    zero-arg callable returning a context manager yielding a
    ServiceBusSender -- called ONLY if a request reaches the enqueue
    step, so a 403 never pays for opening an AMQP link. In tests this is
    typically `lambda: contextlib.nullcontext(mock_sender)`.
    """
    hostname = _hostname_from_url(url)

    # Step 1 -- Blocklist enforcement. Runs before anything else: a
    # blocked target must never leave a trace downstream.
    if is_blocklisted(hostname):
        logger.info(f"403 blocklisted target: {hostname}")
        return 403, {"error": "target domain is not permitted"}

    # Step 2 (optional, secondary) -- SSRF defense-in-depth. Not the
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

    # Step 3 -- Service Bus enqueue. job_id is the only identity this
    # request gets: no authenticated user, no Cosmos DB record. Still
    # threaded through to the Worker (Gap 3's correlation fix,
    # DEPLOYMENT_NOTES.md) and returned to the caller so they have
    # something to reference, even though nothing in Cosmos DB
    # acknowledges it as "queued" the way it used to.
    job_id = str(uuid.uuid4())
    message = build_scan_message(url=url, job_id=job_id, config=None)
    try:
        with get_service_bus_sender() as sender:
            enqueue_scan_job(message, sender, job_id)
    except EnqueueError as e:
        logger.error(f"503 enqueue failed: {e}")
        return 503, {"error": "could not enqueue scan job"}

    logger.info(f"202 accepted: job_id={job_id} url={url}")
    return 202, {"job_id": job_id, "status": "queued"}


# ------------------------------------------------------------------------------
# Azure Functions HTTP entry point -- thin wrapper around handle_scan_request()
# ------------------------------------------------------------------------------
app = func.FunctionApp()

_credential = None
_sb_client = None


def _get_credential() -> DefaultAzureCredential:
    global _credential
    if _credential is None:
        _credential = DefaultAzureCredential()
    return _credential


def _get_service_bus_client() -> ServiceBusClient:
    global _sb_client
    if _sb_client is None:
        namespace = os.environ["ServiceBusConnection__fullyQualifiedNamespace"]
        _sb_client = ServiceBusClient(namespace, credential=_get_credential())
    return _sb_client


@app.route(route="scan", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def submit_scan(req: func.HttpRequest) -> func.HttpResponse:
    # auth_level=ANONYMOUS disables the Azure Functions *host-level*
    # function-key gate (a separate, coarser mechanism from application
    # auth). There is currently no application-level auth either -- see
    # this module's docstring.
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
        url=url,
        get_service_bus_sender=_get_sender,
    )
    return func.HttpResponse(json.dumps(response_body), status_code=status_code, mimetype="application/json")
