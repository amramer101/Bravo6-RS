#!/usr/bin/env python3
"""
Bravo6 API Gateway -- Service Bus Enqueue
=====================================================================
Matches the EXACT message schema src/worker/function_app.py's
process_scan() expects -- read directly from that file for this pass:

    body = msg.get_body().decode('utf-8')
    data = json.loads(body)
    target_url = data.get("url")
    job_id = data.get("job_id")
    ...
    config = data.get("config") if isinstance(data.get("config"), dict) else None
    result = await run_scout(target_url, scan_id=job_id, config=config)

So the message body MUST be a JSON object with a required "url" string,
a required "job_id" string, and an optional "config" dict.

DEFERRED-AUTH NOTE (2026-09-12, see future-work/auth/README.md): this
module previously took a ScanJob instance (scan_job.py, now moved out of
the active package) and read job.url/job.id off it. Since there's no
more authenticated user to build a ScanJob record for, build_scan_message()
below takes url/job_id/config directly instead -- the wire format sent to
the Worker is UNCHANGED, only the caller-side shape that produces it is
simpler. job_id is still what makes the finished result document the
Worker writes identifiable to whoever holds it (Gap 3's fix,
DEPLOYMENT_NOTES.md), even though nothing in Cosmos DB records it as
"queued" first anymore -- see function_app.py's module docstring.
"""
import json
import logging
import time
from typing import Any, Dict, Optional

from azure.servicebus import ServiceBusMessage, ServiceBusSender
from azure.servicebus.exceptions import ServiceBusError

logger = logging.getLogger("Bravo6-Gateway.servicebus_queue")

ENQUEUE_MAX_ATTEMPTS = 3
ENQUEUE_RETRY_BACKOFF_SECONDS = 1.0


class EnqueueError(Exception):
    """All retry attempts to enqueue exhausted -- caller must return 503."""


def build_scan_message(url: str, job_id: str, config: Optional[Dict[str, Any]] = None) -> ServiceBusMessage:
    body: Dict[str, Any] = {"url": url, "config": config, "job_id": job_id}
    return ServiceBusMessage(json.dumps(body))


def enqueue_scan_job(message: ServiceBusMessage, sender: ServiceBusSender, job_id: str) -> None:
    """sender is an already-open ServiceBusSender (the caller manages its
    lifecycle via `with client.get_queue_sender(...) as sender:`),
    injected here so tests can supply a mock instead of a real Service
    Bus connection. Retries ENQUEUE_MAX_ATTEMPTS times on a transient
    ServiceBusError before raising EnqueueError. job_id is only used for
    logging -- it's already baked into `message`."""
    last_error: Optional[Exception] = None
    for attempt in range(1, ENQUEUE_MAX_ATTEMPTS + 1):
        try:
            sender.send_messages(message)
            return
        except ServiceBusError as e:
            last_error = e
            logger.warning(
                f"Service Bus enqueue attempt {attempt}/{ENQUEUE_MAX_ATTEMPTS} "
                f"failed for job {job_id}: {e}"
            )
            if attempt < ENQUEUE_MAX_ATTEMPTS:
                time.sleep(ENQUEUE_RETRY_BACKOFF_SECONDS * attempt)

    raise EnqueueError(
        f"Service Bus enqueue failed after {ENQUEUE_MAX_ATTEMPTS} attempts "
        f"for job {job_id}: {last_error}"
    )
