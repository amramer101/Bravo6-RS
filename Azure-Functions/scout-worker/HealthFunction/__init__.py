import azure.functions as func
import json

def main(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(
        json.dumps({"status": "healthy", "service": "Bravo6 Scanner"}),
        status_code=200,
        mimetype="application/json"
    )