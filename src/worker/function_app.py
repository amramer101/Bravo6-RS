import azure.functions as func
import logging
import asyncio
import json
import sys
import os

# Add the scanner folder to the Python path to ensure imports work correctly
sys.path.append(os.path.join(os.path.dirname(__file__), 'scanner'))

# Import the main orchestrator from main_scanner.py
from main_scanner import run_scout

app = func.FunctionApp()

@app.service_bus_queue_trigger(
    arg_name="msg",
    queue_name="test",                     # The name of your Service Bus Queue
    connection="ServiceBusConnection"      # The app setting key for the connection string
)
async def process_scan(msg: func.ServiceBusMessage):
    logging.info("📨 Service Bus message received")
    
    try:
        # 1. Parse the URL from the message body
        body = msg.get_body().decode('utf-8')
        logging.info(f"Message body: {body}")
        data = json.loads(body)
        target_url = data.get("url")
        
        if not target_url:
            logging.error("❌ Message does not contain a 'url' field")
            return  # Do not raise an exception for malformed messages

        # 2. Execute the security scanner
        logging.info(f"🚀 Starting scan for: {target_url}")
        
        result = await run_scout(
            url=target_url,
            verbose=False,        # Suppress console output
            min_confidence=50
        )
        
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