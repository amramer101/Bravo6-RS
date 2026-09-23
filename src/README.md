# Implementation map

| Directory | Role | Entry point |
| --- | --- | --- |
| [api](api/README.md) | Validate intake and enqueue scan jobs | `api/function_app.py` |
| [worker](worker/README.md) | Execute scouts and produce saved reports | `worker/function_app.py`, `worker/main_scanner.py` |
| [report](report/README.md) | Read stored status and JSON results | `report/function_app.py` |
| [cve-pipeline](cve-pipeline/README.md) | Generate a manual advisory snapshot | `cve-pipeline/cve_etl.py` |

The Gateway and Report routes in the inspected source use anonymous Azure Function authentication. Deferred application authentication is under `future-work/auth/`. Managed identities used by services do not authenticate the person submitting a target.

Source inspection does not establish the exact build deployed for a historical run. See [repository audit](../maintenance/REPOSITORY_AUDIT.md) before interpreting older deployment or test claims.
