# Deferred: API Gateway authentication, quota, and per-user job persistence

Everything in this directory was **removed from the API Gateway's active code path**
(`src/api/`) on 2026-09-12, not deleted. It's fully-written, previously-tested code — kept here
so the work isn't lost, and so it can be dropped back into `src/api/` largely as-is once auth
work resumes.

## Why these three files specifically

The Gateway's JWT validation, per-user quota enforcement, and the Cosmos DB "scan-job" record
are one bundle, not three independent features: quota and the scan-job record are both keyed on
the JWT's `sub` claim (the authenticated user's stable identifier). Remove authentication and
neither has an identity to key on — so all three came out together, not just `auth.py`.

| File | What it did | Why it can't run without auth |
|---|---|---|
| `auth.py` | Validated real JWTs issued by the project's Entra External ID (CIAM) tenant (signature, expiry, issuer, audience) | This *is* the auth being deferred |
| `quota.py` | Capped scan submissions to 10/hour per user | "Per user" requires a user identity |
| `scan_job.py` | Wrote a queued job record to Cosmos DB under `user_id`, and counted a user's recent jobs for quota | `user_id` comes from the JWT `sub` claim |

`test_api_gateway.py`'s test classes for these three (`TestAuth`, `TestQuota`, `TestScanJobWrite`)
moved with them — see `test_auth_deferred.py` in this directory. They still pass unmodified
except for import paths; run `python3 test_auth_deferred.py --test` from here.

## What changed in the active Gateway as a result

`src/api/function_app.py`'s `handle_scan_request()` is now three steps, not the original four:
accept the request → blocklist check → enqueue to Service Bus. No JWT check, no quota check, no
Cosmos write. `job_id` is now generated directly with `uuid.uuid4()` in `function_app.py` itself
(previously `scan_job.py`'s `new_scan_job()` did this as a side effect of building the full
`ScanJob` record) — it's still returned in the `202` response and still threaded through to the
Worker via Service Bus, so Gap 3's scanId-correlation fix (`DEPLOYMENT_NOTES.md`) is unaffected
by this change: the Worker still gets a real id to write its result under. What's gone is the
*queued* Cosmos record that Gap 3 was originally about correlating against — see the note in
`src/api/function_app.py`'s module docstring on what this means for Report Function's `Pending`
status (there's no seed record for it to observe a Pending → Complete transition from anymore).

`src/api/servicebus_queue.py` stayed in the active package (enqueueing is still part of the job)
but was decoupled from `ScanJob` — `build_scan_message()` now takes `url`/`job_id`/`config`
directly instead of a `ScanJob` dataclass instance.

## Terraform

`terraform/modules/entra_external_id/` moved here wholesale (see `terraform/entra_external_id/`
in this directory) — the Entra External ID (CIAM) app registration + service principal
Terraform. The root module (`terraform/main.tf`) no longer references it.

**Important, not fixed here**: `src/report/function_app.py` (a separate Function App, out of
this task's stated scope) still validates JWTs against `ENTRA_ISSUER`/`ENTRA_JWKS_URI`/
`ENTRA_AUDIENCE`. Those app settings are still wired in `terraform/modules/report_function/`
from root variables `entra_issuer`/`entra_jwks_uri` — which still exist in
`terraform/variables.tf` and `terraform.tfvars(.example)` for exactly this reason: Report
Function's own auth was explicitly out of scope for this pass and was left untouched. If you
ever remove those root variables too, Report Function's `/report/status` and `/report/result`
routes will need their own explicit no-auth decision first, matching what happened to the
Gateway here — don't just delete the variables and let it break silently.

## Resuming this work

1. Move these three `.py` files back into `src/api/`.
2. Move `terraform/entra_external_id/` back into `terraform/modules/entra_external_id/` and
   re-add the `module "entra_external_id"` block to `terraform/main.tf` (see git history around
   2026-09-12 for the exact block that was removed).
3. Re-wire `handle_scan_request()` back to the four-step version (see git history for the
   pre-2026-09-12 shape), or design a new one informed by however the Gateway evolved meanwhile.
4. Move `test_auth_deferred.py`'s classes back into `test_api_gateway.py`.
