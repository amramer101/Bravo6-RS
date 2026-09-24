# Request lifecycle

## 1. Submit a target

The caller sends a JSON object containing `url` to the Gateway's `scan` route. The handler checks JSON and the presence of the URL, applies a hostname blocklist, and optionally invokes a secondary address check. The secondary check can be unavailable or fail without rejecting the request; the Worker applies its own target checks later.

The Gateway creates a UUID job identifier, constructs a Service Bus message, and attempts enqueueing. It returns `202` with `job_id` and `status: queued` only after the enqueue helper succeeds. No initial queued document is written to Cosmos by this active handler.

## 2. Consume and execute

The Worker queue trigger expects a message containing `url` and `job_id`; `config` is accepted when it is a dictionary. Missing required fields or invalid JSON are logged and returned from the handler. Other unhandled exceptions are re-raised to the host for retry behavior. Do not describe every malformed message as automatically dead-lettered by the application.

The handler calls `run_scout(url, scan_id=job_id, config=config)`. Scouts are discovered from Worker filenames and scheduled concurrently within a scan. This per-scan concurrency is different from concurrent submission of many scan jobs.

## 3. Normalize and persist

The orchestrator records module status, combines findings, deduplicates them, and computes a score with coverage flags. Persistence attempts a Cosmos write when configured. A local JSON fallback can retain a result if cloud persistence fails, but an ephemeral local file is not durable delivery or an automatic replay system.

## 4. Retrieve a report

The caller uses the same identifier as the `scanId` query parameter on the Report service. `report/status` derives a state from the saved document; `report/result` returns the stored document only when the derived state is Complete.

| Observation | Interpretation |
| --- | --- |
| Gateway 202 | Enqueue acknowledged |
| Report 404 | No matching stored document at read time; potentially still pending |
| Report status Pending / Running | A stored document has the corresponding shape/status |
| Report status Failed | A stored failure status was recognized |
| Report result 409 | A document exists but is not derived as Complete |
| Report result 200 | Result document returned; inspect coverage and errors |

The read service supports more status shapes than the current write path necessarily emits. There is no demonstrated continuous `Pending → Running → Complete` record for every job.

## Correlation and timing

Use `job_id`/`scanId` to connect a request with its output. Do not treat the hash of a file as a request trace or proof of acquisition time. Harness wall-clock timing includes polling and inter-request delays. The saved Cosmos timestamps differ from harness completion times, so cross-service latency is not inferred.

[Exact HTTP examples](api-reference.md) · [Schema and scores](scoring.md)


## Implementation and evidence

- [src/api/function_app.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/api/function_app.py)
- [src/api/servicebus_queue.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/api/servicebus_queue.py)
- [src/worker/function_app.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/function_app.py)
- [src/worker/main_scanner.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/main_scanner.py)
- [src/report/function_app.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/report/function_app.py)

Source links follow `main`. They describe the inspectable implementation, not a verified digest of the historical deployment.
