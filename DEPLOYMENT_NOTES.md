# BRAVO6 Deployment Notes — 2026-09-11

Record of the first real deployment of BRAVO6's core infrastructure to Azure, via Terraform,
plus a first attempt at pushing application code onto it. Written as the work happened, not
reconstructed afterward — every claim below was directly observed (a command's output, a live
`az`/Terraform query, an Application Insights log), not inferred.

**Subscription**: `Azure for Students` (`55336c1c-af74-4164-b687-a7b7c3ec740c`)
**Resource group**: `bravo6-rg` (westeurope)
**Terraform state**: `terraform-rg` / `terraformstateeprofile` storage account (pre-existing backend,
not managed by this repo's Terraform)

## Current live status (2026-09-11, gap-closing pass): fully torn down, cost-safe

**Bottom line up front: this is NOT yet the first fully-verified end-to-end run.** Gap 1 (Cosmos DB
Private Endpoint) and Gap 3 (scanId correlation) are implemented and hold up well against the live
evidence gathered this pass. **Gap 2 is CONFIRMED STILL BROKEN** — a fresh, more precise diagnosis
than any prior pass, superseding the "removing `AzureWebJobsStorage__*` is the fix" claim that had
been committed to source (see Gap 2 below). The app stack was fully destroyed immediately after
gathering this evidence, per this project's standing rule not to leave a broken deployment running.
Confirmed empty two ways: `terraform state list` (empty) **and** `az group exists --name bravo6-rg`
→ **`false`**. **Do not redeploy the app stack** until Gap 2 has an actual, verified fix (see the new
lead at the end of the Gap 2 section below) — redeploying as-is will reproduce the same failure.

### This pass's changes (summary)

1. **Gap 1 fix implemented**: Cosmos DB now sits behind a Private Endpoint in a new, dedicated,
   non-delegated `private-endpoints-subnet` (`10.0.2.0/24`), with its own private DNS zone
   (`privatelink.documents.azure.com`) linked to the VNet. The `Microsoft.AzureCosmosDB` service
   endpoint and Cosmos's `virtual_network_rule` are removed entirely (see
   `terraform/modules/cosmos_db/main.tf` for the full sourced explanation, including why this does
   NOT reverse ADR-004). **Live-deployed and largely confirmed working** — see Gap 1 below.
2. **Gap 3 fix implemented**: `src/worker/function_app.py`'s `process_scan()` now reads the Service
   Bus message's `job_id` and threads it through to `main_scanner.py`'s `run_scout(url, scan_id, ...)`
   as the scanId, on both the `blocked_ssrf` and normal-completion paths; the internal `uuid.uuid4()`
   calls are removed. New unit tests (`TestScanIdThreading` in `main_scanner.py`, plus a strengthened
   assertion in `test_api_gateway.py`) cover both code paths. The evaluation harness
   (`run_evaluation.py`) generates its own local id per attempt, unrelated to any API job. **Could
   not be live-verified this pass** — blocked by Gap 2 still being broken (see below): a direct
   Service Bus test message sat unconsumed for 20+ minutes.
3. **Gap 2: NOT fixed, despite source claiming otherwise.** Live evidence (below) shows the exact
   original `AuthenticationFailed`/"Blob Storage Secret Repository" symptom recurring, repeatedly,
   across all three Function Apps, well after code deployment. A concrete, evidence-backed lead for
   the *actual* fix was found this pass (see end of Gap 2 section) but NOT implemented or tested live
   — that needs its own dedicated pass, not a bolt-on to this one.

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

**Fix implemented and deployed this pass (2026-09-11, gap-closing pass): Cosmos DB Private
Endpoint.** New dedicated `private-endpoints-subnet` (`10.0.2.0/24`, no delegation, no service
endpoints, `private_endpoint_network_policies = "Disabled"`) in the existing VNet; an
`azurerm_private_endpoint` targeting the Cosmos account's `Sql` subresource; a
`privatelink.documents.azure.com` private DNS zone linked to the VNet. The `Microsoft.AzureCosmosDB`
service endpoint and Cosmos's `virtual_network_rule` block are removed entirely — see
`terraform/modules/cosmos_db/main.tf`'s sourced comment for the full explanation and why this is
unrelated to ADR-004 (that decision was about Private Endpoints on the Function Apps' own *inbound*
path; this is Cosmos's data-plane side, reached over the Function Apps' existing, unchanged outbound
VNet integration). `Microsoft.Storage`'s service endpoint on `functions-subnet` was investigated per
instruction and deliberately left alone — no live evidence gathered this pass showed anything
depending on it, but nothing confirmed it was safe to remove either (see `modules/network/main.tf`'s
comment); flagged for a dedicated follow-up, not touched further.

**Live evidence, gathered directly (2026-09-11):**
- `terraform apply` created the private endpoint successfully (`provisioningState: Succeeded`,
  ~8 minutes — normal for Private Link). The private DNS zone got its A records auto-populated by the
  zone group (`bravo6-cosmosdb-83088.privatelink.documents.azure.com` → `10.0.2.4`, plus a
  region-specific record → `10.0.2.5`), and the VNet link shows `LinkState: Completed`,
  `ProvisioningState: Succeeded`.
- The API Gateway's *first* live request (a garbage-bearer-token `POST /api/scan`, sent minutes after
  the private endpoint finished provisioning) hit a **500**, with Application Insights showing:
  `ServiceRequestTimeoutError: (...HTTPSConnection(host='bravo6-cosmosdb-83088.documents.azure.com',
  port=443)..., 'Connection to bravo6-cosmosdb-83088.documents.azure.com timed out. (connect
  timeout=3)')`. This is a **materially different symptom than the original Gap 1 bug** — a connect
  timeout, not an explicit "Forbidden... blocked by your Cosmos DB account firewall settings"
  rejection — consistent with DNS not yet fully resolving to the private IP immediately after
  private-endpoint/DNS-zone-group provisioning finished, not a structural failure of the fix.
- **The identical request, retried ~15 minutes later, succeeded past the point of failure**: it
  reached JWT validation and correctly returned `401 {"error": "unauthorized"}` for the garbage
  token — meaning `CosmosClient` initialization (which this app appears to do eagerly, since the
  earlier attempt failed before authentication ran) no longer times out. This is strong evidence the
  Private Endpoint fix **works once fully propagated** — but it does not, by itself, prove the
  post-auth Cosmos *write* succeeds (see "What could not be verified" below).
- Could not obtain a real Entra External ID JWT this pass (see Entra section) to drive a full
  `202`-returning request through `handle_scan_request()`'s actual Cosmos-write step. The closest
  available proxy — a direct Service Bus message to test the Worker's identical-network-path Cosmos
  write — was blocked by Gap 2 still being broken (message sat unconsumed; see Gap 2 below).

**Verdict: Gap 1's core network fix (DNS + Private Endpoint reachability) is confirmed working after
a propagation delay. The full authenticated write-then-202 path through the API Gateway itself is
still NOT directly proven live** — blocked by two separate, unrelated obstacles (no real JWT
available; Gap 2 blocking the Worker-side proxy test), not by any remaining defect found in the
Private Endpoint fix itself.

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

**Update (2026-09-11, gap-closing pass) — CONFIRMED STILL BROKEN, against a fresh deploy, with the
committed source's "removal is the fix" claim now directly contradicted by live evidence.**

Between the above entry and this pass, `terraform/modules/function_app/main.tf` (and the matching
`api_function`/`report_function` modules) were changed to the *opposite* of what's described above:
instead of adding `AzureWebJobsStorage__*` identity-based app settings, they now DELIBERATELY set
none at all, reasoning (in a sourced comment) that Flex Consumption derives the host's internal
storage config entirely from `storage_container_endpoint`/`storage_authentication_type`, and that
adding `AzureWebJobsStorage__*` on top was itself the bug. This pass deployed that version fresh and
tested it directly — first time this specific variant has been live-tested.

**Result: the identical failure recurs**, on all three Function Apps, well after code was deployed
(not just during initial cold start). Pulled directly from Application Insights `exceptions`, with
timestamps:

```
2026-09-11T18:55:34Z  worker-fun-app-4q3pjj  AuthenticationFailed (MAC signature mismatch),
                       container "azure-webjobs-secrets", "SyncTriggers operation failed" /
                       "There was an error performing a read operation on the Blob Storage Secret
                       Repository."
2026-09-11T18:56:35Z  worker-fun-app-4q3pjj  same error, recurs
2026-09-11T18:58:28Z  api-fun-app-4q3pjj     same error
2026-09-11T18:59:39Z  api-fun-app-4q3pjj     same error, recurs
2026-09-11T19:01:18Z  report-fun-app-4q3pjj  same error
2026-09-11T19:02:33Z  report-fun-app-4q3pjj  same error, recurs
2026-09-11T19:17:21Z  worker-fun-app-4q3pjj  same error, recurs AGAIN (~22 min after the first)
2026-09-11T19:17:29Z  api-fun-app-4q3pjj     same error, recurs AGAIN
```

Interspersed with repeated `python exited with code 143` entries for all three apps (worker, api,
report) across the same window — consistent with the "crash-restart loop" pattern the prior pass
found with the *other* variant of this fix, though some 143 exits may be ordinary Flex Consumption
scale-to-zero rather than crashes; the recurring `AuthenticationFailed` on fresh cold starts is the
unambiguous signal.

**Live consequence, directly observed**: a real Service Bus test message, sent directly to
`bravo6-queue` (bypassing the API, same isolation technique as the original Gap 2 diagnosis), showed
`activeMessageCount: 1` unchanged for over 20 minutes — Worker never consumed it, exactly reproducing
the original symptom. This also means Gap 3's live correlation could not be observed this pass (see
Gap 3 below): with Worker's host in this state, there was no way to watch it write a result under a
matching scanId.

Despite this, `az functionapp function list` showed all three apps' triggers correctly registered
(`process_scan`, `submit_scan`, `get_result`, `get_status`) — so `SyncTriggers` succeeds *some* of the
time (apparently including whatever internal sync a `zip` deployment triggers), just not reliably on
every cold start. This is a genuinely degraded, intermittent state, not a hard permanent failure —
but it is not a working fix.

**New lead for the actual fix (found this pass, NOT implemented or tested — flagged for a dedicated
pass, not bolted onto this one).** The failing operation is specifically the Functions host's **Blob
Storage Secret Repository** (function/host *key* storage — `azure-webjobs-secrets` container), which
is a different mechanism from the deployment-storage config
(`storage_container_endpoint`/`storage_authentication_type`) that the current source's comment
assumes covers everything. Current Microsoft guidance indicates this mechanism needs its own
explicit identity-based `AzureWebJobsStorage` connection to avoid falling back to (broken)
account-key auth — specifically via `AzureWebJobsStorage__accountName` (the storage account name) +
`AzureWebJobsStorage__credential = "managedidentity"`, which is a **different shape** than the
`__blobServiceUri`/`__queueServiceUri`/`__tableServiceUri` triplet the *original* (also
confirmed-broken) fix attempt used. RBAC guidance for this specific connection commonly cites
**Storage Blob Data Owner** (already the level of a prior attempt) plus, in some sources, **Storage
Queue Data Contributor** — deliberately not added previously per an earlier pass's explicit
no-speculative-roles instruction, but worth reconsidering given this new, more specific lead. This is
a *third* distinct variant from the two already tried and found broken; it needs its own
implement-then-live-verify pass with close Application Insights monitoring, not a guess bundled into
a cost-control or gap-closing pass.

**Do not attempt to redeploy the app stack until Gap 2 has an actual, verified fix** — this is still
the single blocking item, now with a better-scoped next step than before.

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

**Fixed in code (2026-09-11, gap-closing pass).** `src/worker/function_app.py`'s `process_scan()`
now reads `job_id` from the Service Bus message and passes it to `main_scanner.py`'s
`run_scout(url, scan_id, config=None)` (now a required parameter) as the scanId, used identically on
the `blocked_ssrf` early-exit path and the normal-completion path; `run_scout()`'s internal
`uuid.uuid4()` calls are removed entirely. `run_evaluation.py` (the offline evaluation harness) now
generates its own per-attempt id explicitly, since it never correlates with a real API job — a
3-site smoke run (`--limit 3 --batch-id smoke-gap3-scanid-fix`) confirmed the harness still runs
end-to-end with the new required parameter (3/3 succeeded). New tests: `TestScanIdThreading` in
`main_scanner.py`'s own suite (asserts both code paths use the given scan_id, including what gets
passed to `persist_scan_result`), plus a strengthened assertion + docstring in
`test_api_gateway.py`'s `test_message_schema_matches_worker_expectations`. Full existing suites for
both `src/worker` and `src/api` stay green (35 + 44 tests respectively) plus the new assertions.

**Live verification: blocked, not attempted-and-failed.** A real Service Bus test message
(`job_id="gap3-live-test-<uuid>"`) was sent directly to `bravo6-queue` this pass specifically to
prove this fix live. It could not be observed being consumed — Worker's host was in the broken state
described in Gap 2 above (repeated `AuthenticationFailed`/`SyncTriggers` failures), so no scanId
correlation could be watched end-to-end. The code fix and its tests are believed correct on their own
merits (the logic is a straightforward parameter thread-through, and the unit tests exercise exactly
the mechanism in question), but **this specific pass adds no live proof** — that needs Gap 2 fixed
first, then a repeat of this same Service Bus test.

---

## Entra External ID — partially verified

- App registration + service principal: live, confirmed via Terraform state (`client_id
  8ea607f5-2d08-402b-aa79-3c9cdd747a56`).
- Redirect URIs: valid (fixed, see above), pointing at the live SWA hostname + localhost.
- `entra_issuer` / `entra_jwks_uri`: confirmed directly against the tenant's own live OIDC discovery
  document (both now match reality — see Fix 1 above).
- **Full interactive login flow was NOT tested** — that needs a real browser-based OAuth redirect
  flow with a test user account in the CIAM tenant, which isn't something a CLI/API-only
  verification pass can drive. No longer moot on Gap 1 (that's now largely fixed, see above) — this
  is the actual remaining blocker to a real end-to-end `202` proof.
- **New finding (2026-09-11, gap-closing pass): ROPC is not officially supported on Entra External
  ID (CIAM) tenants**, confirmed against current guidance — a documented product limitation, not a
  config issue on this project's side. A "native authentication API" alternative exists but needs
  the app registration configured for it and a multi-step API flow implemented; out of scope for
  this pass. Practical effect: there is currently no non-interactive way to mint a real, validly-
  signed test JWT for this tenant from a CLI/automation context — any future live verification of
  the full authenticated write path needs either a human completing a real browser OAuth flow, or a
  dedicated native-auth implementation.
- **New finding, same pass: the CIAM tenant's Security Defaults blocked Azure CLI's own first-party
  app entirely** (`AADSTS530035`), for both a plain interactive sign-in attempt AND Terraform's
  `azuread` provider (needed for the `entra_external_id` module — blocking `terraform plan` itself,
  unrelated to Gap 1/2/3). Resolved by disabling Security Defaults on the tenant via the Entra Admin
  Center (a tenant-owner action, not something scriptable from here) — worth deciding deliberately
  whether to re-enable Security Defaults now that this pass is done, versus leaving it off for future
  CLI-driven passes, since it's a real security-posture trade-off, not just a deployment nuisance.

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
   temporary-open/revert pattern used in this pass is a stopgap, not the real fix. Still open — the
   Gap 1 pass added a Cosmos DB Private Endpoint but deliberately did not build a second one for
   Storage speculatively (see Gap 1's `Microsoft.Storage` investigation above).
2. **`shared_access_key_enabled` on the storage account** (currently the `azurerm` default, `true`)
   — close it if nothing in the architecture actually depends on storage-account-key auth,
   consistent with the zero-secrets design used everywhere else. Already flagged separately in
   CLAUDE.md's Checkov notes as a real, non-tier-locked finding. Still open, and now more clearly
   relevant given Gap 2's failure is itself an account-key-auth problem on this same storage account.
3. ~~Fix Gap 1~~ **DONE this pass** — Cosmos DB Private Endpoint implemented, deployed, and largely
   confirmed live (see Gap 1 above); the authenticated write path specifically still needs a real
   JWT to fully prove (see Entra section).
4. **Fix Gap 2 for real, using the new lead found this pass.** Two variants have now been tried and
   both confirmed broken live: adding `AzureWebJobsStorage__blobServiceUri`/`__queueServiceUri`/
   `__tableServiceUri` (original pass), and removing `AzureWebJobsStorage__*` entirely (this pass's
   starting point). The new lead — explicit `AzureWebJobsStorage__accountName` +
   `__credential=managedidentity`, specifically for the Blob Storage Secret Repository mechanism,
   possibly with Storage Queue Data Contributor added to the existing Storage Blob Data Owner grant
   — has NOT been tried. This is now the single most important next step; needs its own
   implement-then-live-verify pass.
5. **A real code-deployment pipeline.** This pass deployed code manually (via
   `az functionapp deployment source config-zip --build-remote true`, since
   `azure-functions-core-tools`' own binary download stalled in this environment — noted as an
   environment-specific tooling snag, not a project finding) — there is still no CI/CD path that
   deploys application code (only `terraform_cd.yml` for infra). A VNet-integrated deploy path (e.g.
   a self-hosted GitHub Actions runner inside the Functions subnet) would also make item 1 and the
   temporary-open pattern unnecessary going forward.
6. **Report Function's actual Azure Functions app** (route, auth, Cosmos read) — code exists and
   deployed live this pass (all three routes returned correct `401`s for unauthenticated requests,
   confirming the code is running); full authenticated read-path verification still needs Gap 2
   fixed and a real JWT.
7. ~~Fix Gap 3~~ **DONE in code this pass** — see Gap 3 above. Live verification still blocked by
   Gap 2.
8. Cosmetic: the recurring subnet-delegation drift and the `entra_external_id` module's implicit
   `azuread` provider warning (`main.tf:154`, `azuread = azuread.external_tenant` with no
   `required_providers` entry in that child module) — harmless, but worth a real fix at some point.
   Both still recur (confirmed this pass).
9. **New this pass: implement CIAM native authentication, or otherwise establish a real
   non-interactive way to get a test JWT.** ROPC is confirmed unsupported on Entra External ID (see
   Entra section) — without this, no future automation-driven pass can fully verify the API
   Gateway's authenticated write path; it will always need a human's browser.
10. **New this pass: `terraform/docs/architecture-decisions.md` (ADR-003) says Service Bus Premium
    was chosen specifically because it's "the only SKU supporting VNet isolation," but the live,
    deployed namespace (`terraform/modules/service_bus/main.tf`) is actually `Standard`.** Not
    investigated further this pass (unrelated to Gap 1/2/3) — worth reconciling: either the doc is
    stale, or Service Bus's VNet-isolation story here relies on something other than SKU-gated
    VNet integration and the ADR's stated rationale needs revisiting.

---

*Generated during a live deployment session; every fact above was observed directly (command
output, live Azure state, or Application Insights logs) rather than inferred.*
