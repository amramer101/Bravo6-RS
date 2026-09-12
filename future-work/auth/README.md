# Deferred: authentication, quota, and per-user job persistence

Everything in this directory was **removed from the active code path** (`src/api/` on
2026-09-12, `src/report/` in a follow-up cleanup pass the same day) — not deleted. It's
fully-written, previously-tested code — kept here so the work isn't lost, and so it can be
dropped back in largely as-is once auth work resumes across the platform.

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

## Report Function's auth (added in the follow-up cleanup pass, same day)

`src/report/function_app.py`'s JWT validation and ownership check (JWT `sub` claim vs. a scan
document's `user_id` field) were removed the same way, in a follow-up pass the same day —
**not** left in place as originally planned in this pass's first draft (an earlier version of
this README said Report Function's auth was out of scope and untouched; that's no longer true).

| File | What it did |
|---|---|
| `report_auth.py` | Report's own copy of JWT validation (deliberately vendored, not imported, from `auth.py` above — see its own docstring) |
| `report_function_auth_gate.py` | The JWT-validate → point-read → ownership-check gate that wrapped both `/report/status` and `/report/result`, plus both routes in their last auth-gated shape (including the HTML output `/report/result` still had at that moment — see `future-work/report-html/README.md`, a separate, independent decision) |

`test_report_function.py`'s auth/ownership-specific test cases moved with them — see
`test_report_function_auth_deferred.py` in this directory (6 tests, still pass unmodified
except for import paths and the target module).

**Consequence**: both routes are now genuinely anonymous — any caller who knows or guesses a
scanId can read its status/result. This is the same read-path enumeration concern the original
JWT-gating comment named explicitly; noted, not re-litigated, since restoring it is exactly
what this directory is for.

## Terraform

`terraform/modules/entra_external_id/` moved here wholesale (see `terraform/entra_external_id/`
in this directory) — the Entra External ID (CIAM) app registration + service principal
Terraform. The root module (`terraform/main.tf`) no longer references it. `entra_issuer`/
`entra_jwks_uri`/`external_tenant_id`/`app_display_name` are gone from
`terraform/variables.tf` and `terraform.tfvars(.example)` too, and from both `api_function`
and `report_function` modules' `variables.tf`/`main.tf` — there's no Entra app registration
left for either Function App to point at.

## Resuming this work

1. Move `auth.py`/`quota.py`/`scan_job.py` back into `src/api/`, and `report_auth.py`/
   `report_function_auth_gate.py` back into `src/report/` (the latter splits back into
   `auth.py` and the gate logic inlined into `function_app.py`, matching how it was laid out
   before — see git history around 2026-09-12 for the exact prior shape of each).
2. Move `terraform/entra_external_id/` back into `terraform/modules/entra_external_id/`,
   re-add the `module "entra_external_id"` block to `terraform/main.tf`, and restore
   `entra_issuer`/`entra_jwks_uri`/`external_tenant_id`/`app_display_name` to
   `terraform/variables.tf`, `terraform.tfvars(.example)`, and both function modules (see git
   history for the exact blocks removed).
3. Re-wire `src/api/function_app.py`'s `handle_scan_request()` back to the four-step version,
   and `src/report/function_app.py`'s two routes back to auth-gated (see git history for the
   pre-2026-09-12 / pre-cleanup-pass shapes), or design new ones informed by however each
   Function App evolved meanwhile.
4. Move `test_auth_deferred.py`'s classes back into `test_api_gateway.py`, and
   `test_report_function_auth_deferred.py`'s classes back into `test_report_function.py`.
