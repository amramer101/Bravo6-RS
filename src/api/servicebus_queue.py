#!/usr/bin/env python3
"""
Bravo6 API Gateway -- Service Bus Enqueue
=====================================================================
Matches the EXACT message schema src/worker/function_app.py's
process_scan() expects -- read directly from that file for this pass:

    body = msg.get_body().decode('utf-8')
    data = json.loads(body)
    target_url = data.get("url")
    ...
    config = data.get("config") if isinstance(data.get("config"), dict) else None
    result = await run_scout(target_url, config=config)

So the message body MUST be a JSON object with a required "url" string,
a required "job_id" string, and an optional "config" dict.
build_scan_message() below sets "job_id" to this job's own id
(job.id) -- process_scan() reads it and threads it through to
run_scout() as the scanId used for the finished result, so the queued
job document this API writes and the finished result document the
Worker writes end up sharing an id (DEPLOYMENT_NOTES.md's Gap 3 fix).
"""
import json
import logging
import time
from typing import Any, Dict, Optional

from azure.servicebus import ServiceBusMessage, ServiceBusSender
from azure.servicebus.exceptions import ServiceBusError

from scan_job import ScanJob

logger = logging.getLogger("Bravo6-Gateway.servicebus_queue")

ENQUEUE_MAX_ATTEMPTS = 3
ENQUEUE_RETRY_BACKOFF_SECONDS = 1.0


class EnqueueError(Exception):
    """All retry attempts to enqueue exhausted -- caller must return 503."""


def build_scan_message(job: ScanJob) -> ServiceBusMessage:
    body: Dict[str, Any] = {"url": job.url, "config": None, "job_id": job.id}
    return ServiceBusMessage(json.dumps(body))


def enqueue_scan_job(job: ScanJob, sender: ServiceBusSender) -> None:
    """sender is an already-open ServiceBusSender (the caller manages its
    lifecycle via `with client.get_queue_sender(...) as sender:`),
    injected here so tests can supply a mock instead of a real Service
    Bus connection. Retries ENQUEUE_MAX_ATTEMPTS times on a transient
    ServiceBusError before raising EnqueueError."""
    message = build_scan_message(job)
    last_error: Optional[Exception] = None
    for attempt in range(1, ENQUEUE_MAX_ATTEMPTS + 1):
        try:
            sender.send_messages(message)
            return
        except ServiceBusError as e:
            last_error = e
            logger.warning(
                f"Service Bus enqueue attempt {attempt}/{ENQUEUE_MAX_ATTEMPTS} "
                f"failed for job {job.id}: {e}"
            )
            if attempt < ENQUEUE_MAX_ATTEMPTS:
                time.sleep(ENQUEUE_RETRY_BACKOFF_SECONDS * attempt)

    raise EnqueueError(
        f"Service Bus enqueue failed after {ENQUEUE_MAX_ATTEMPTS} attempts "
        f"for job {job.id}: {last_error}"
    )
