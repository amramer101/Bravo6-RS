# Deferred authentication and quota work

These files are outside the active Gateway/Report path. They are retained for inspection, not presented as deployed controls.

| File | Intended role |
| --- | --- |
| `auth.py`, `report_auth.py` | JWT-related authentication helpers |
| `quota.py` | Per-user request quota logic |
| `scan_job.py` | User-associated job persistence |
| `report_function_auth_gate.py` | Authenticated report access/ownership handling |
| `test_*_deferred.py` | Deferred-feature tests |
| `terraform/entra_external_id/` | Identity-provider infrastructure prototype |

The current Gateway only checks intake and enqueues; it does not write a queued Cosmos job. The current Report routes are anonymous. Managed identities between services do not restore caller authentication.

Restoring these features requires an explicit integration design, privilege/ownership review, dependency review, and controlled validation. No such integration or test execution is performed by this documentation update.

[Security boundaries](../../docs/security-identity.md)
