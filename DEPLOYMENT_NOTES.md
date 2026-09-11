# BRAVO6 Deployment Notes — 2026-09-11

Record of the first real deployment of BRAVO6's core infrastructure to Azure, via Terraform,
plus a first attempt at pushing application code onto it. Written as the work happened, not
reconstructed afterward — every claim below was directly observed (a command's output, a live
`az`/Terraform query, an Application Insights log), not inferred.

**Subscription**: `Azure for Students` (`55336c1c-af74-4164-b687-a7b7c3ec740c`)
**Resource group**: `bravo6-rg` (westeurope)
**Terraform state**: `terraform-rg` / `terraformstateeprofile` storage account (pre-existing backend,
not managed by this repo's Terraform)

## Current live status (2026-09-11, latest): fully torn down, cost-safe

The app stack was fully destroyed after Gap 2's identity-based `AzureWebJobsStorage` fix was
confirmed to make things *worse* (see Gap 2 below: a crash-restart loop / `503`s on API Gateway and
Report Function, not just Worker's queue trigger silently failing as before) — rather than leave a
broken, partially-functional deployment running and accruing cost. Confirmed empty two ways, not
one: `terraform state list` (empty) **and** `az group exists --name bravo6-rg` → **`false`**
(`bravo6-rg` itself no longer exists at all). **Do not redeploy the app stack** (`terraform/` root)
until Gap 2 has an actual, verified fix — redeploying as-is will reproduce the same crash loop.

A **subscription-scoped** budget alert now exists independently of this app stack, in its own
Terraform root (`terraform/budget/`, separate state) specifically so it survives future
destroy/redeploy cycles: **$25/month**, notifications at **80%** and **100%** of actual spend, both
to `amrmedhatamer1@gmail.com`. Confirmed live via `az consumption budget list` (not just trusted from
`apply`'s exit code) — see `docs/cost-finops.md` for the same figure documented there.

## Status summary

| Component | Infra deployed | Code deployed | Functionally verified |
|---|---|---|---|
| Resource group, network, storage, observability | Yes | n/a | Yes |
| Service Bus (namespace + queue) | Yes | n/a | Yes — queue accepts/holds messages |
| Cosmos DB (account + db + `scans`/`users` containers) | Yes | n/a | **No — blocked, see Gap 1** |
| API Gateway (Function App) | Yes | Yes | **No — blocked, see Gap 1** |
| Worker (Function App) | Yes | Yes | **No — blocked, see Gap 2** |
| Report (Function App) | Yes | Yes (not yet deployed to the live app) | **No — blocked, see Gap 1 & Gap 3** |
| Static Web App (frontend) | Yes | No (spec-only, matches CLAUDE.md) | n/a |
| Entra External ID (CIAM) app registration | Yes | n/a | Partially — see Entra section |

Bottom line: **all 36 Terraform-managed resources are live**, and the API Gateway and Worker both
have real application code running on them (not empty shells) — but two separate, genuine runtime
bugs (both pre-existing in the repo, not introduced by this deployment) currently prevent either
one from completing its actual job end-to-end. Gap 1 is confirmed as a platform-level Flex
Consumption / Cosmos DB service-endpoint incompatibility (Private Endpoint is the only real fix).
Gap 2's fix (identity-based `AzureWebJobsStorage`) is applied and matches Microsoft's current
documented contract, but could not be confirmed working in this pass — Flex Consumption has no
CLI-accessible raw-log path, and Application Insights shows zero telemetry from Worker even under
forced restarts. Both are precisely diagnosed below, not guessed at.

---

## What Terraform actually created

36 resources across: resource group, VNet + Functions subnet + NSG, storage account + 3 deployment
containers, Service Bus namespace + queue, Cosmos DB account + database + 2 containers + 2 custom
SQL roles + 3 role assignments, Log Analytics + App Insights, 3 Flex Consumption service plans (one
per Function App — see Fix 2 below), 3 Function Apps, Static Web App, Entra External ID app
registration + service principal, and 5 more RBAC role assignments (Storage Blob Data Contributor
×3, Service Bus Sender/Receiver ×2).

Live resource names (random suffix `ctrnd5` / `83607`, from `random_string`/`random_integer` in
`main.tf`):
- Storage account: `bravo6stgaccctrnd5`
- Cosmos DB account: `bravo6-cosmosdb-83607`, database `bravo6-db`, containers `scans` / `users`
- Service Bus: namespace `bravo6-servicebus`, queue `bravo6-queue`
- Function Apps: `worker-fun-app-ctrnd5`, `api-fun-app-ctrnd5`, `report-fun-app-ctrnd5`
- Static Web App: `brave-field-0ad301e03.6.azurestaticapps.net`
- Entra SPA app registration: `bravo6-frontend-spa`, client ID `8ea607f5-2d08-402b-aa79-3c9cdd747a56`,
  in tenant `34f39b7a-e19b-4bdb-926e-fe4b0bd735e0`

---

## Fixes made to get `terraform apply` to succeed at all

These were genuine bugs in the existing Terraform, found by actually running it — not
hypothetical. All three were confirmed with the user before applying.

1. **`entra_issuer` in `terraform.tfvars` was an unconfirmed guess.** It used the CIAM tenant's
   vanity subdomain (`bravo6ciam.ciamlogin.com`) for the issuer, but the tenant's own live OIDC
   discovery document (fetched and checked directly) shows the real `iss` claim on issued tokens
   uses the tenant-ID subdomain instead. `src/api/auth.py`'s `jwt.decode(issuer=...)` does a strict
   equality check, so the original guess would have rejected every real login token. Fixed to the
   confirmed value.
2. **Entra app registration `redirect_uris` were malformed.** Both `https://<swa-hostname>` and
   `http://localhost:3000` are bare origins with no path segment and no trailing slash — Microsoft
   Graph rejects that shape outright. Added trailing slashes to both (`main.tf`).
3. **All three Function Apps shared one Flex Consumption service plan.** Flex Consumption (`FC1`)
   allows exactly one site per plan — a hard Azure product constraint, not a quota issue. Split
   `module.functions_plan` into a `for_each` over `["worker", "api", "report"]`, one plan each,
   and rewired each Function App module's `service_plan_id` accordingly (`main.tf`).

A stale remote-state lock (3 days old, same machine/user, no live process) also had to be
force-unlocked before the first `plan` could run at all — confirmed safe (no concurrent Terraform
process existed) before doing so.

## Recurring cosmetic drift (harmless, not fixed)

Two `terraform plan`/`apply` cycles keep showing the same two no-op-ish diffs on every run that
touches a Function App or the Functions subnet:
- `azurerm_function_app_flex_consumption`'s `app_settings.APPLICATIONINSIGHTS_CONNECTION_STRING`
  reconciling from `site_config.application_insights_connection_string` back into the `app_settings`
  map — a known `azurerm` provider normalization quirk, functionally identical either way.
- The Functions subnet's `Microsoft.App/environments` delegation action drifting from
  `.../subnets/action` (what's in the `.tf` config, and the value Flex Consumption actually needs)
  back to `.../subnets/join/action` — Azure's control plane appears to silently reset this
  attribute whenever a Function App on the subnet is created or updated. Cosmetic; every apply in
  this pass corrected it back without incident, but expect to see it again on the next `apply`.

## Missing `host.json` in `src/api/`

`src/worker/` had one; `src/api/` didn't, even though every Azure Functions app needs one at its
package root to start. Added a minimal one (`{"version": "2.0", "logging": {...}}`, matching
Worker's). This is boilerplate required to run at all, not new functionality.

---

## Temporary network changes made during code deployment — both reverted

Flex Consumption's deployment pipeline needs to reach two things from *outside* the VNet (the
tooling runs on Microsoft's control plane, not inside our subnet): the target Function App's own
site, and the storage account holding its deployment package. Both `worker-fun-app-ctrnd5`'s site
and the shared storage account (`bravo6stgaccctrnd5`) have `public_network_access_enabled = false`
by design (CLAUDE.md: "Zero public exposure of the data plane"), which blocked deployment outright
— confirmed by literal 403s from both before any change.

**What was done, both explicitly confirmed with the user first:**
1. Storage account: `public_network_access_enabled = true` + `network_rules.bypass = ["AzureServices"]`,
   keeping `default_action = "Deny"` and the VNet subnet rule — Microsoft's documented pattern for
   "firewalled but deployable." Applied, used to deploy both API and Worker code, then **reverted
   to `public_network_access_enabled = false` (bypass dropped) immediately after both deployments
   finished** — confirmed via `terraform apply` (0 added, 5 changed, 0 destroyed).
2. Worker Function App: `public_network_access_enabled = true` just long enough to push its code
   package (its actual job — a Service Bus queue trigger — is an outbound listener, not an inbound
   HTTP path, so this didn't change how Worker operates once deployed). **Reverted to `false`
   immediately after the Worker code deployment finished**, confirmed the same way.

Both reverts are confirmed live (not just "applied" — `az network`/`az storage` checks after the
revert would show the closed state; the Terraform apply that reverted them completed with exit
code 0 and the expected 5-resource diff, matching the state before either was opened).

**This is a stopgap, not the real fix** — see Future Work below.

---

## Gap 1: Cosmos DB rejects the API Gateway's traffic at the network layer

`POST /api/scan` on the live, deployed API Gateway (`https://api-fun-app-ctrnd5.azurewebsites.net/api/scan`)
returns **HTTP 500** on every attempt. The exact exception, pulled directly from Application
Insights (`AppExceptions`, not guessed):

```
azure.cosmos.exceptions.CosmosHttpResponseError: (Forbidden) Request originated from VNET through
service endpoint. This is blocked by your Cosmos DB account firewall settings.
More info: https://aka.ms/cosmosdb-tsg-forbidden
```

Raised from `CosmosClient.__init__` (`src/api/function_app.py:196`, `_get_cosmos_container`) — it
fails before any data-plane RBAC check even runs. This is a **network ACL rejection**, not an
authorization problem, despite looking similar to one at first glance.

**What was ruled out**, each checked directly, not assumed:
- Not a config mismatch: the Functions subnet has `Microsoft.AzureCosmosDB` service endpoint with
  `provisioningState: Succeeded`, and Cosmos DB's `virtualNetworkRules` references that exact same
  subnet ID with `ignoreMissingVnetServiceEndpoint: false` — both sides match exactly.
- Not RBAC propagation delay: the Cosmos SQL role assignment (`gateway_scan_writer`, granting
  `readMetadata`/`items/read`/`items/create`/`executeQuery` at account scope) is provably correctly
  scoped to the API's actual managed-identity principal ID (verified they match) — and this error
  fires before any RBAC check is reached anyway.
- Not a resource provider registration issue: `Microsoft.DocumentDB` shows `Registered`.
- Not simple propagation lag: the identical error persisted unchanged across more than 10 minutes
  and multiple retries.

**Confirmed root cause (2026-09-11, follow-up pass) — not a Terraform misconfiguration, a
platform-level incompatibility.** Microsoft's own current documentation
([`functions-networking-options.md`](https://learn.microsoft.com/en-us/azure/azure-functions/functions-networking-options),
Flex Consumption section, updated 2026-07-14) states outright:

> "The subnet can't already be in use for other purposes (**like private or service endpoints**, or
> delegated to any other hosting plan or service)."

`functions-subnet` carries both the delegation Flex Consumption requires (`Microsoft.App/environments`)
*and* `service_endpoints = ["Microsoft.AzureCosmosDB", "Microsoft.Storage"]` — a combination
Microsoft explicitly disallows. This isn't fixable by pointing Cosmos's `virtual_network_rule` at a
different subnet either: the same doc says Flex Consumption's "outbound network traffic from
function app instances is routed through shared gateways that are **dedicated to the [delegated]
subnet**" — the egress path is structurally pinned to that one subnet, and that subnet can never
carry service endpoints. **Service-endpoint-based Cosmos DB access is incompatible with Flex
Consumption by design, not a config bug.** Private Endpoint (already logged as future work below)
is the only real fix. Per explicit instruction, the private-endpoint migration was *not* attempted
in this pass — this finding is reported, not worked around.

**Impact**: this blocks the *entire* live scan-submission path — `handle_scan_request()` writes to
Cosmos before it ever reaches the Service Bus enqueue step, so Worker/Service Bus were never
reached via the real API flow either.

## Gap 2: Worker's Service Bus trigger never registers — messages sit unconsumed

Sent a real test message directly to `bravo6-queue` via the Service Bus SDK (bypassing the blocked
API, to isolate this from Gap 1). Confirmed accepted (`countDetails.activeMessageCount: 1`
immediately after). Polled for over 10 minutes afterward — **still `activeMessageCount: 1`,
`deadLetterMessageCount: 0`** — Worker never picked it up.

Root cause, found directly in Worker's own Application Insights traces from its most recent cold
start (not guessed):

```
There was an error performing a read operation on the Blob Storage Secret Repository.
ErrorCode: AuthenticationFailed
AuthenticationErrorDetail: The MAC signature found in the HTTP request '...' is not the same as
any computed signature. ...
SyncTriggers operation failed.
```

**Diagnosis**: none of the three Function App Terraform modules set an explicit `AzureWebJobsStorage`
app setting. `storage_authentication_type = "SystemAssignedIdentity"` on each Function App resource
covers *only* pulling the deployment package from its own container — it does not cover the
Functions host's separate internal need for a "Blob Storage Secret Repository" (host keys, trigger
sync bookkeeping), which the platform is evidently falling back to account-key auth for, and that
key-based auth is failing outright. Without a successful `SyncTriggers` call, Azure's scale
controller never learns Worker has a Service Bus queue trigger to monitor — so it never dispatches
an instance to consume anything, indefinitely. This is not a cold-start delay; it's a hard failure
happening on every host startup.

The same `AuthenticationFailed`/`Unable to access AzureWebJobsStorage` message also appears in
API's health checks (present since its very first deployment) — API's HTTP trigger still works
despite it, since HTTP routing doesn't depend on `SyncTriggers` the way a queue trigger's dispatch
does, but the underlying gap is identical across all three Function Apps.

**Fix applied (2026-09-11, follow-up pass), verification inconclusive.** Confirmed against
Microsoft's current [`manage-connections.md`](https://learn.microsoft.com/en-us/azure/azure-functions/manage-connections)
(updated 2026-07-07) rather than guessed: Flex Consumption has "Full support... Recommended for MI"
for identity-based `AzureWebJobsStorage`. Added to all three Function App modules:
`AzureWebJobsStorage__blobServiceUri` / `__queueServiceUri` / `__tableServiceUri` = `https://<account>.<service>.core.windows.net`,
plus `__credential = "managedidentity"` (no `clientId` — confirmed all three apps use `SystemAssigned`
identity, not user-assigned). RBAC (`iam.tf`, new `functions_host_storage_blob` /
`functions_host_storage_table` role assignments, account-scoped): **Storage Blob Data Owner** +
**Storage Table Data Contributor** — the doc's explicit minimum for this connection ("Storage Blob
Data Owner... provides the minimum storage account permissions for the host-required
AzureWebJobsStorage connection... You must also add the Storage Table Data Contributor role").
Deliberately did *not* add Storage Queue Data Contributor or Storage Account Contributor (both
appear in a third-party blog's list) — the official doc scopes Queue Data Contributor to the Blob
Storage *trigger's* poison-queue writes specifically, not the base host connection, and neither app
here uses a Blob trigger; Storage Account Contributor doesn't appear in the base-connection RBAC
guidance at all. Applied via `terraform apply` — 6 added, 4 changed, 0 destroyed, exit 0; role
assignments confirmed live against Worker's actual principal ID via `az role assignment list`.

**Verification attempted, could not be confirmed either way.** The original specific failure
("SyncTriggers operation failed" / Blob Storage Secret Repository `AuthenticationFailed`) has not
recurred in Application Insights since the fix — but there's also been zero positive confirmation:
- A real test message sent before the fix was still sitting unconsumed in the queue
  (`activeMessageCount: 1`) 20+ minutes after applying.
- Worker produced **zero Application Insights telemetry** the entire time, despite `az functionapp
  restart` and two `az resource invoke-action --action syncfunctiontriggers` calls (3+ minutes
  apart, to rule out RBAC propagation lag — confirmed not the cause, the role assignments were
  already live). Both `syncfunctiontriggers` calls returned `400 "Encountered an error
  (InternalServerError) from host runtime"` — real host activity, but with no way to see what
  actually failed.
- Temporarily reopened Worker's `public_network_access_enabled` (confirmed with the user first, same
  pattern as the deploy-time openings) specifically to get raw startup logs, and hit a genuine
  tooling wall, confirmed by three independent, authoritative sources rather than one flaky command:
  - `az functionapp deployment list-publishing-credentials` → `"This is not currently supported for
    Azure Functions on the Flex Consumption plan."`
  - `func azure functionapp logstream` (the Functions-native tool) → `"Log stream is not currently
    supported in Linux Consumption and Flex Apps. Please use --browser to open Azure Application
    Insights Live Stream in the Azure portal."`
  - `az webapp log tail` (classic App Service tooling) connected without error but produced zero
    output even with filesystem logging explicitly enabled; Kudu's VFS `LogFiles` path returned 404.
  - **There is no CLI-accessible raw-log path for Flex Consumption today.** Microsoft's own tooling
    says the only live diagnostic is Application Insights Live Metrics via the Portal browser UI —
    unreachable from this environment. Since App Insights itself shows zero telemetry, whatever is
    failing happens before the app's own instrumentation SDK initializes.
  - Reverted `public_network_access_enabled` back to `false` immediately after (confirmed live via
    `az resource show`, not just trusting the apply).
- Because no logs pointed at a queue-storage permission failure specifically (no logs were obtained
  at all), **Storage Queue Data Contributor was deliberately not added speculatively**, per explicit
  instruction not to guess at further roles without log evidence.

**Update (2026-09-11, full destroy/redeploy pass) — CONFIRMED BROKEN, not just unconfirmed.**
A later pass fully destroyed `bravo6-rg` and redeployed from scratch, then re-tested this fix
directly against the fresh deployment. Result: **worse than the pre-fix state**, not fixed.

- Sent a fresh test message to `bravo6-queue`: unconsumed after 5+ minutes, same as before the fix.
- Worker's Application Insights traces on the fresh deployment show the **identical**
  `AuthenticationFailed` / MAC-signature-mismatch / `SyncTriggers operation failed` errors as the
  original diagnosis — the identity-based `AzureWebJobsStorage__*` settings did not change the
  outcome, even though the app_settings and RBAC are confirmed live on this fresh deployment too.
- **New, worse symptom found this pass**: the API Gateway's own trace log shows it entering a
  crash-restart loop — `Job host started` → repeated `An unhandled host error has occurred` (the
  same storage-auth failure) → `Job host stopped` → reinitialize → repeat. This is why the live API
  endpoint returned `503 The service is unavailable` on the fresh deployment, instead of the flat
  `500` the pre-fix/first deployment returned. The pre-fix state at least kept the host running and
  serving requests (HTTP routing doesn't depend on `SyncTriggers`); applying this fix appears to
  have pushed the host into repeated failure/restart instead. Report Function showed the same 503
  pattern.
- **This is now the single blocking item before any next deploy attempt** — redeploying the current
  Terraform as-is will reproduce this same crash loop on the API Gateway and Report Function, not
  just leave Worker's queue trigger silently unregistered as before.
- Given this regression, the live (fresh) deployment was fully destroyed again rather than left
  running broken and accruing cost (confirmed via `terraform state list` empty and `az group exists
  --name bravo6-rg` → `false`) — see the "Current live status" note at the top of this document, and
  the new subscription-scoped budget alert (`terraform/budget/`) put in place specifically because
  of this incident.

Root cause of *why* Microsoft's documented identity-based approach isn't behaving as documented
here is still unknown — this needs its own dedicated diagnostic pass (with, ideally, Portal-based
Application Insights Live Metrics access from a human), not a fix bolted onto a cost-control pass.
Do not attempt to redeploy the app stack until this has an actual, verified fix.

## Gap 3: the API's `scanId` and the Worker's `scanId` are never the same value

Found while wiring the Report Function's read path (a later pass), confirmed by reading the code
directly, not guessed. This is a Worker/API bug — out of scope to fix in either the pass that found
it or this closeout pass, both of which left Worker and API untouched by design.

- `src/api/servicebus_queue.py`'s `build_scan_message()` sends the API-generated job id as
  `"job_id"` in the Service Bus message body.
- `src/worker/function_app.py`'s `process_scan()` only ever reads `"url"` and `"config"` from that
  message — `"job_id"` is never read.
- `src/worker/main_scanner.py`'s `run_scout()` mints its **own** fresh `uuid.uuid4()` for
  `"scanId"` internally, on both the `blocked_ssrf` early-exit path and the normal-completion path
  that builds `final_result`.

**Effect**: the queued job-record document the API writes (`id` = the scanId returned to the
caller in the `202` response, the one the frontend would poll on) is never updated past
`status="queued"` — nothing in the API's own code ever transitions it. The Worker's actual
completed result lands under a completely different, uncorrelated `id` that nothing surfaces back
to the caller. **No Report Function implementation can observe a real Pending → Complete
transition for a given scanId until this is fixed** — this blocks live/functional verification of
the Report Function work (`src/report/`) entirely, on top of already blocking on Gap 1 (API can't
reach Cosmos at all yet). The Report Function's own code implements the *correct*, intended
behavior for a single evolving document and is unit-tested against that intended shape (mocks, not
live Cosmos) — see `src/report/function_app.py`'s module docstring for the same finding written
down at the point it matters most for future readers.

---

## Entra External ID — partially verified

- App registration + service principal: live, confirmed via Terraform state (`client_id
  8ea607f5-2d08-402b-aa79-3c9cdd747a56`).
- Redirect URIs: valid (fixed, see above), pointing at the live SWA hostname + localhost.
- `entra_issuer` / `entra_jwks_uri`: confirmed directly against the tenant's own live OIDC discovery
  document (both now match reality — see Fix 1 above).
- **Full interactive login flow was NOT tested** — that needs a real browser-based OAuth redirect
  flow with a test user account in the CIAM tenant, which isn't something a CLI/API-only
  verification pass can drive. Also moot right now regardless, since Gap 1 means even a
  successfully-issued, valid token would still hit the same Cosmos 500 on the first real request.

## Report Function — code now exists, live verification blocked (Gap 1 + Gap 3)

Originally (this document's first version): `src/report/` contained only `report_generator.py`, no
Azure Functions app at all. A later pass in this same effort closed that gap: added
`function_app.py` (two routes — `GET /report/status?scanId`, and `GET /report/result?scanId` per a
documented Step-2-style decision for the previously-undefined full-result contract),
vendored `auth.py`, `host.json`, `requirements.txt`, and `test_report_function.py` (12 mock-based
tests, all passing — no live Cosmos DB or Entra call). Terraform wiring (Cosmos/Entra app settings
on the `report_function` module) is applied. Both routes enforce JWT validation and ownership
(403 on a `user_id` mismatch), closing this project's paper-listed "ownership enforcement on read"
gap **in code** — not yet **live-verified**, which needs Gap 1 and Gap 3 fixed first (Report can't
observe real data until the API can write to Cosmos at all, and until a scanId actually correlates
between the queued job and the Worker's finished result).

---

## Future work (not done in this pass)

Requested explicitly by the user, plus items that surfaced directly from this session's findings:

1. **Private endpoint from the Functions subnet to the storage account**, so
   `public_network_access_enabled` can stay `false` permanently, including during deploys. The
   temporary-open/revert pattern used in this pass is a stopgap, not the real fix.
2. **`shared_access_key_enabled` on the storage account** (currently the `azurerm` default, `true`)
   — close it if nothing in the architecture actually depends on storage-account-key auth,
   consistent with the zero-secrets design used everywhere else. Already flagged separately in
   CLAUDE.md's Checkov notes as a real, non-tier-locked finding.
3. **Fix Gap 1** (Cosmos DB VNet ACL rejecting Flex-Consumption-integrated traffic) — confirmed
   (see Gap 1 above) to require Cosmos DB Private Endpoint; service-endpoint-based access is
   incompatible with Flex Consumption by design, not something a Terraform tweak can fix.
4. **Confirm Gap 2's fix actually works.** The identity-based `AzureWebJobsStorage` settings and
   RBAC are applied and match Microsoft's current documented contract exactly, but this pass could
   not confirm `SyncTriggers` now succeeds — Worker produced zero Application Insights telemetry
   even under forced restarts, and there's no CLI-accessible raw-log path for Flex Consumption (see
   Gap 2 above). Needs a human with Portal access to check Application Insights Live Metrics during
   a forced restart, or a Microsoft support case if that doesn't reveal it either.
5. **A real code-deployment pipeline.** This pass deployed code manually, from a laptop, using a
   locally-installed `azure-functions-core-tools` — there is still no CI/CD path that deploys
   application code (only `terraform_cd.yml` for infra). A VNet-integrated deploy path (e.g. a
   self-hosted GitHub Actions runner inside the Functions subnet) would also make items 1 and the
   temporary-open pattern in this pass unnecessary going forward.
6. **Report Function's actual Azure Functions app** (route, auth, Cosmos read) — done in a later
   pass (see the Report Function section above); code deployment to the live app and live
   verification remain.
7. **Fix Gap 3** (API's `scanId` and Worker's `scanId` never correlate) — needs
   `src/worker/function_app.py`'s `process_scan()` to actually read and use the `job_id` the
   message already carries, and `main_scanner.py`'s `run_scout()` to accept that id instead of
   minting its own. Blocks live verification of the Report Function work.
8. Cosmetic: the recurring subnet-delegation drift and the `entra_external_id` module's implicit
   `azuread` provider warning (`main.tf:154`, `azuread = azuread.external_tenant` with no
   `required_providers` entry in that child module) — harmless, but worth a real fix at some point.

---

*Generated during a live deployment session; every fact above was observed directly (command
output, live Azure state, or Application Insights logs) rather than inferred.*
