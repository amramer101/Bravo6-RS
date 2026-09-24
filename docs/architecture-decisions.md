# Design decisions and tradeoffs

This page summarizes the inspected design without treating historical ADR prose as proof of today's deployment. These are explanatory decisions, not newly executed experiments.

| Decision | Benefit | Cost or limitation |
| --- | --- | --- |
| Queue-backed execution | Intake need not wait for a scan | Retry behavior and absent intermediate records complicate status interpretation |
| Separate Report service | Read path independent of execution | Requires ownership controls for a production multi-user service |
| Shared scan context | Reuse initial content and cached resources | No isolated cache-speedup experiment in the preserved evidence |
| Plugin discovery by filename | Simple scout integration | Renaming/moving files can alter runtime discovery |
| JSON result representation | Structured findings and audit fields | Raw evidence may contain sensitive data |
| Heuristic score with hardening cap | Compact summary with bounded hardening contribution | Not a calibrated risk model; floor hides score differences |
| Managed identities | Avoid manually supplied credentials on selected Azure paths | Does not authenticate callers or remove all secret-handling concerns |
| Static and scheduled advisory paths | Support fixed snapshots and freshness | Historical data-source provenance must be recorded explicitly |

## Deferred choices

Frontend implementation, caller JWT validation, quotas, report ownership, and HTML rendering are outside the active scope. They are not evidence-backed product features simply because code or Terraform scaffolding exists.

## Revisiting a decision

A future revision should record the concrete problem, changed behavior, validation performed, compatibility consequences, and deployment version. Preserve original experiment artifacts when comparing versions. A later detector fix cannot be represented as a fix already applied to the archived run.

[Architecture](architecture-overview.md) · [Roadmap and limitations](limitations.md)
