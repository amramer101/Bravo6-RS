# Architecture overview

BRAVO6 separates scan intake, execution, persistence, and retrieval. The active logical backend has five components. Identity, networking, and telemetry support those components; a proposed frontend is outside the evaluated implementation.

![BRAVO6 architecture](assets/architecture.svg)

## Component boundaries

| Component | Responsibility | Important boundary |
| --- | --- | --- |
| Gateway | Accept URL, apply intake checks, create a job identifier, enqueue | No authenticated caller; no initial queued document in Cosmos |
| Service Bus | Decouple intake from Worker execution | Delivery can be repeated; final result counts do not reveal retries |
| Worker | Discover scouts, gather observations, normalize and score, persist | Module completion is distinct from subcheck coverage |
| Cosmos DB | Store scan documents keyed by scan identifier | Source configuration and observed metadata do not provide per-hop traces |
| Report Function | Return status or stored JSON through HTTP | Anonymous access; knowing an ID is not proof of ownership |

## What is implemented

Three Azure Function applications have source entry points: API, Worker, and Report. The Worker also contains scheduled advisory synchronization. A manual advisory snapshot generator exists separately. Both are documented under [advisory data](advisory-data.md).

Terraform contains a Static Web App resource definition. This is infrastructure scaffolding, not evidence of a working frontend application. Deferred authentication, quota handling, and HTML rendering remain under `future-work/`.

## Execution and persistence

A submitted job carries `job_id`, which the Worker passes as `scan_id`. A persisted normal result has `scanId`, with Cosmos `id` and the partition key associated with that identifier. The Report service performs a point read.

The Gateway does not synchronously wait for a scan. A 202 acknowledges enqueueing; it does not certify completion, database persistence, or the quality of observations. Before the Worker saves a document, Report may return 404.

## What the experiment supports

The archive contains correlated submission/result identifiers and Cosmos metadata. This supports the cloud API execution path. It does not establish exact retry counts, every internal request, a byte-identical deployed build, or sustained concurrent throughput. The evaluated batch submitted targets serially.

## Reading paths

- [Request lifecycle](data-flow.md): state transitions and failure behavior.
- [Worker and scouts](software-architecture.md): observation and normalization.
- [Infrastructure](infrastructure.md): resources and configuration.
- [Security boundaries](security-identity.md): caller access, identities, network controls.


## Implementation and evidence

- [src/api/function_app.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/api/function_app.py)
- [src/worker/function_app.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/function_app.py)
- [src/worker/main_scanner.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/main_scanner.py)
- [src/report/function_app.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/report/function_app.py)
- [terraform/main.tf](https://github.com/amramer101/Bravo6-RS/blob/main/terraform/main.tf)

Source links follow `main`. They describe the inspectable implementation, not a verified digest of the historical deployment.
