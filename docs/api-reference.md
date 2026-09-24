# API reference

This reference describes the inspected Python handlers. It is not an OpenAPI conformance claim or a promise that an endpoint is currently deployed. All examples use invented identifiers and reserved example hostnames; no request was sent to produce them.

## Route map

The default Azure Functions `/api` prefix is used below. Gateway and Report are separate Function Apps.

| Service | Method | Path | Active caller authentication |
| --- | --- | --- | --- |
| Gateway | POST | `/api/scan` | None |
| Report | GET | `/api/report/status?scanId=…` | None |
| Report | GET | `/api/report/result?scanId=…` | None |

## Submit

Illustrative HTTP exchange, not a command to run:

```http
POST /api/scan HTTP/1.1
Host: gateway.example.invalid
Content-Type: application/json

{"url": "https://example.com"}
```

```json
{"job_id": "00000000-0000-4000-8000-000000000001", "status": "queued"}
```

| Status | Documented handler condition |
| --- | --- |
| 202 | Message enqueued |
| 400 | Invalid JSON body or missing/falsy `url` |
| 403 | Hostname policy or an explicit unsafe-address verdict |
| 503 | Enqueue helper exhausted its attempt policy |

These are handled responses, not an exhaustive guarantee for arbitrary malformed types or infrastructure failures. The active handler does not establish a complete request-schema validation layer. There is no active 401/429 authentication/quota contract, and callers cannot enable scanner configuration through this route: it constructs the message with `config=None`.

## Status

```http
GET /api/report/status?scanId=00000000-0000-4000-8000-000000000001 HTTP/1.1
Host: report.example.invalid
```

```json
{"scanId": "00000000-0000-4000-8000-000000000001", "status": "Complete"}
```

Missing scan ID yields 400; a missing document yields 404. Recognized failed statuses take precedence over result-shaped fields. Normal scanner documents can be classified Complete by the presence of result fields even without an explicit top-level Complete status.

## Result

The result route returns the stored document with 200 when Complete. If the document exists but is not complete, it returns 409 with `error: scan not complete` and the derived status. Missing ID and missing document use 400 and 404 respectively.

The result may include Cosmos metadata. It is not a sanitized public-data endpoint. There is no ownership check, and the service does not redact a saved document on retrieval. See [finding schema](scoring.md) and [data handling](ethics.md).

## Client interpretation

Retain the returned `job_id` and pass it as `scanId`; these names differ. Bound polling duration and treat timeouts as an unknown terminal outcome, not proof of zero findings. Inspect module completion, page classification, and errors before interpreting a score. A successful HTTP response does not validate an emitted finding.


## Implementation and evidence

- [src/api/function_app.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/api/function_app.py)
- [src/report/function_app.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/report/function_app.py)
- [src/api/host.json](https://github.com/amramer101/Bravo6-RS/blob/main/src/api/host.json)
- [src/report/host.json](https://github.com/amramer101/Bravo6-RS/blob/main/src/report/host.json)

Source links follow `main`. They describe the inspectable implementation, not a verified digest of the historical deployment.
