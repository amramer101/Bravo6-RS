import azure.functions as func
import logging
import json
import os

# main_scanner.py sits alongside this file at the Function App root.
from main_scanner import run_scout
from osv_cve_sync import run_sync

app = func.FunctionApp()

# queue_name must match terraform's var.service_bus_queue_name ("bravo6-queue").
# connection="ServiceBusConnection" resolves to the
# ServiceBusConnection__fullyQualifiedNamespace app setting (managed-identity
# auth, no connection string) wired in terraform/modules/function_app/main.tf.
@app.service_bus_queue_trigger(
    arg_name="msg",
    queue_name="bravo6-queue",
    connection="ServiceBusConnection"
)
async def process_scan(msg: func.ServiceBusMessage):
    logging.info("📨 Service Bus message received")
    
    try:
        # 1. Parse the URL from the message body
        body = msg.get_body().decode('utf-8')
        logging.info(f"Message body: {body}")
        data = json.loads(body)
        target_url = data.get("url")
        job_id = data.get("job_id")

        if not target_url:
            logging.error("❌ Message does not contain a 'url' field")
            return  # Do not raise an exception for malformed messages

        if not job_id:
            logging.error("❌ Message does not contain a 'job_id' field")
            return  # Do not raise an exception for malformed messages

        # 2. Execute the security scanner.
        # run_scout(url, scan_id, config=None) is the sole public entry
        # point in main_scanner.py -- it takes no verbose/min_confidence
        # kwargs. scan_id is the API's own job_id (src/api/scan_job.py),
        # passed through as-is: this is what makes the queued job document
        # the API wrote and the finished result document the Worker writes
        # share the same id (Cosmos "scans" container, partition key
        # /scanId) -- see DEPLOYMENT_NOTES.md's Gap 3.
        logging.info(f"🚀 Starting scan for: {target_url} (job_id={job_id})")

        config = data.get("config") if isinstance(data.get("config"), dict) else None
        result = await run_scout(target_url, scan_id=job_id, config=config)

        # 3. Log the scan summary
        logging.info(f"✅ Scan completed for {target_url}")
        logging.info(f"   - Total Findings: {result.get('total_findings', 0)}")
        logging.info(f"   - Security Score: {result.get('score', 'N/A')}")
        logging.info(f"   - Grade: {result.get('grade', 'N/A')}")
        logging.info(f"   - Errors Count: {result.get('errors_count', 0)}")
        
        # Uncomment the line below to log the full JSON result
        # logging.info(f"Full result: {json.dumps(result, indent=2)}")
        
        logging.info("📁 result.json written to the temporary working directory")

    except json.JSONDecodeError as e:
        logging.error(f"❌ Invalid JSON in message: {e}")
    except Exception as e:
        # Re-raise the exception so Service Bus retries the message
        logging.error(f"❌ Scan failed with exception: {e}", exc_info=True)
        raise e


# ------------------------------------------------------------------------------
# OSV CVE Sync -- Timer Function
# ------------------------------------------------------------------------------
# Runs every 12 hours (NCRONTAB: second minute hour day month day-of-week).
# See osv_cve_sync.py's module docstring for why this lives on a schedule
# instead of test_02_frontend_libs.py calling OSV live per-scan, and why
# it's added to this Function App rather than a new, separate one:
#   - This Worker already has a working Managed Identity + deployment
#     package; adding a 4th Function App would mean a 4th instance of the
#     exact "Blob Storage Secret Repository" host-storage-identity problem
#     documented as still-unresolved in DEPLOYMENT_NOTES.md's Gap 2 --
#     multiplying exposure to a known-broken mechanism instead of reusing
#     an app that (once Gap 2 is actually fixed) only needs to get this
#     right once.
#   - Azure Functions natively supports multiple trigger types (queue +
#     timer) in one app -- this is not a workaround, it's how the
#     platform expects multi-job apps to be structured.
#   - It writes to the SAME storage account already used for
#     AzureWebJobsStorage/deployment (see terraform/modules/storage_account),
#     just a different service (Table, not Blob) -- no new storage
#     account, no new deployment container.
#
# MANAGED IDENTITY, FLAGGED EXPLICITLY (see the top-level task summary):
# this uses DefaultAzureCredential() with azure-data-tables' Table Storage
# data-plane client and a "Storage Table Data Contributor" role scoped to
# ONLY this one table (terraform/modules/storage_account's cve_cache
# table + terraform/iam.tf's osv_cache_table_access role assignment).
# This is UNRELATED to Gap 2's AzureWebJobsStorage / Blob Storage Secret
# Repository mechanism -- it's the standard, documented RBAC pattern for
# a Function App's own application code reading/writing Table Storage
# data, the same shape as this Worker's existing Cosmos DB role
# assignment, not a variant of anything already tried and failed. It has
# NOT been live-tested (no terraform apply was run for this pass) and
# does not touch, fix, or depend on Gap 2 being resolved.
@app.timer_trigger(
    schedule="0 0 */12 * * *",
    arg_name="timer",
    run_on_startup=False,
)
def sync_osv_cve_cache(timer: func.TimerRequest) -> None:
    if timer.past_due:
        logging.warning("⏰ OSV CVE sync timer is past due")

    logging.info("🔄 Starting scheduled OSV CVE sync")

    try:
        import requests
        from azure.data.tables import TableServiceClient
        from azure.identity import DefaultAzureCredential

        table_endpoint = os.environ["CVE_TABLE_ENDPOINT"]
        table_name = os.environ.get("CVE_TABLE_NAME", "cveCache")

        with TableServiceClient(endpoint=table_endpoint, credential=DefaultAzureCredential()) as service:
            table_client = service.get_table_client(table_name)
            summary = run_sync(http_post=requests.post, table_client=table_client)

        logging.info(
            f"✅ OSV CVE sync complete: {summary['rows_written']} row(s) written, "
            f"{summary['rows_failed']} failed, {summary['rows_fetched']} total fetched."
        )
    except Exception as e:
        # Deliberately not re-raised: a failed sync leaves the cache at
        # its previous (still valid, just staler) state rather than
        # crashing this Timer invocation -- the next scheduled run tries
        # again. See osv_cve_sync.py's own per-package fault isolation
        # for why individual OSV/Table Storage failures inside a run
        # already don't reach here in the first place; this is the
        # outermost safety net for something unexpected (e.g. Table
        # Storage auth itself failing) taking down the whole sync.
        logging.error(f"❌ OSV CVE sync failed: {e}", exc_info=True)