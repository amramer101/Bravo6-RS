import azure.functions as func
import logging
import json

app = func.FunctionApp()

@app.service_bus_queue_trigger(
    arg_name="msg",
    queue_name="scan-queue",
    connection="ServiceBusConnection"
)
def process_scan(msg: func.ServiceBusMessage):
    logging.info("📨 Service Bus message received")
    logging.info(f"Message: {msg.get_body().decode('utf-8')}")

@app.route(route="health", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def health(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps({"status": "healthy", "service": "Bravo6 Scanner"}),
        status_code=200,
        mimetype="application/json"
    )