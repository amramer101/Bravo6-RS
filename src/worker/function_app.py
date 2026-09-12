import azure.functions as func
import logging
import json

# main_scanner.py sits alongside this file at the Function App root.
from main_scanner import run_scout

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