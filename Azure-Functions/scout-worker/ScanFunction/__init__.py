import azure.functions as func
import logging
import asyncio
import json
import time
import sys
import os

# إضافة المسار
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "Scanner"))

from test_01_secrets import run as run_01
from test_02_frontend_libs import run as run_02
# ... إلخ (كل الـ 16)

async def run_all_tests(url):
    results = await asyncio.gather(
        run_01(url),
        run_02(url),
        # ... كل الـ 16
        return_exceptions=True
    )
    return aggregate_results(results)

def aggregate_results(raw_results):
    # نفس الكود السابق
    findings = []
    scan_errors = []
    for r in raw_results:
        if isinstance(r, Exception):
            scan_errors.append(str(r))
            continue
        if not isinstance(r, dict):
            continue
        if "findings" in r and isinstance(r["findings"], list):
            for sub in r["findings"]:
                sub["test_name"] = r.get("test_name", "unknown")
                findings.append(sub)
        else:
            findings.append(r)
    return {
        "total_findings": len(findings),
        "findings": findings[:10],
        "errors": len(scan_errors)
    }

def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        req_body = req.get_json()
        url = req_body.get("url")
    except ValueError:
        return func.HttpResponse("Invalid JSON", status_code=400)
    if not url:
        return func.HttpResponse("Missing url", status_code=400)
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(run_all_tests(url))
        loop.close()
    except Exception as e:
        logging.error(f"Scan failed: {e}")
        return func.HttpResponse(str(e), status_code=500)
    return func.HttpResponse(json.dumps(result), status_code=200, mimetype="application/json")