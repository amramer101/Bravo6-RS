import azure.functions as func
import logging
import asyncio
import json
import time

# استيراد الـ 16 اختبار
from scanner import (
    test_01_secrets,
    test_02_frontend_libs,
    test_03_mixed_content,
    test_04_ssl_tls,
    test_05_security_headers,
    test_06_info_disclosure,
    test_07_cookies,
    test_08_email_security,
    test_09_subdomain_takeover,
    test_10_robots_txt,
    test_11_cors,
    test_12_http_methods,
    test_13_cms_fingerprinting,
    test_14_subresource_integrity_sri,
    test_15_hallucinated_deps,
    test_16_ai_exposure,
)

app = func.FunctionApp()

def aggregate_results(raw_results):
    """تجميع النتائج من كل الاختبارات"""
    findings = []
    scan_errors = []
    total_tests = len(raw_results)

    for r in raw_results:
        if isinstance(r, Exception):
            scan_errors.append(str(r))
            continue
        if not isinstance(r, dict):
            scan_errors.append(f"Unexpected result type: {type(r).__name__}")
            continue

        if "findings" in r and isinstance(r["findings"], list):
            test_name = r.get("test_name", "unknown")
            for sub_finding in r["findings"]:
                if "test_name" not in sub_finding:
                    sub_finding["test_name"] = test_name
                if "overall_status" in sub_finding and "status" not in sub_finding:
                    sub_finding["status"] = sub_finding["overall_status"]
                findings.append(sub_finding)
        else:
            if "test_name" not in r:
                r["test_name"] = "unknown"
            findings.append(r)

    critical = sum(1 for f in findings if f.get("severity") == "critical" and f.get("status") in ("fail", "warning"))
    high = sum(1 for f in findings if f.get("severity") == "high" and f.get("status") in ("fail", "warning"))
    medium = sum(1 for f in findings if f.get("severity") == "medium" and f.get("status") in ("fail", "warning"))
    low = sum(1 for f in findings if f.get("severity") == "low" and f.get("status") in ("fail", "warning"))

    return {
        "total_findings": len(findings),
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "errors": len(scan_errors),
        "findings": findings[:10],  # أول 10 نتائج بس عشان الـ Response ما يطولش
        "scan_errors": scan_errors,
    }


async def run_all_tests(url):
    """تشغيل الـ 16 اختبار بالتوازي"""
    logging.info(f"🔍 Starting scan for {url}")
    start = time.time()
    
    raw_results = await asyncio.gather(
        # ── HTTP Layer ──
        test_05_security_headers.run(url),
        test_11_cors.run(url),
        test_12_http_methods.run(url),
        test_07_cookies.run(url),
        test_06_info_disclosure.run(url),
        # ── Content ──
        test_01_secrets.run(url),
        test_02_frontend_libs.run(url),
        test_03_mixed_content.run(url),
        test_13_cms_fingerprinting.run(url),
        # ── DNS/Network ──
        test_04_ssl_tls.run(url),
        test_08_email_security.run(url),
        test_09_subdomain_takeover.run(url),
        test_10_robots_txt.run(url),
        # ── AI/Supply Chain ──
        test_14_subresource_integrity_sri.run(url),
        test_15_hallucinated_deps.run(url),
        test_16_ai_exposure.run(url),
        return_exceptions=True
    )
    
    elapsed = time.time() - start
    logging.info(f"✅ Scan completed in {elapsed:.2f} seconds")
    
    return aggregate_results(raw_results)


@app.route(route="scan", methods=["POST"])
def scan(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('📨 Scan request received')

    try:
        req_body = req.get_json()
        url = req_body.get('url')
    except ValueError:
        return func.HttpResponse(
            json.dumps({"error": "Invalid JSON. Send {'url': 'https://example.com'}"}),
            status_code=400,
            mimetype="application/json"
        )

    if not url:
        return func.HttpResponse(
            json.dumps({"error": "Missing 'url' parameter"}),
            status_code=400,
            mimetype="application/json"
        )

    # تشغيل الاختبارات
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(run_all_tests(url))
        loop.close()
    except Exception as e:
        logging.error(f"❌ Scan failed: {e}")
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )

    return func.HttpResponse(
        json.dumps(result, indent=2, default=str),
        status_code=200,
        mimetype="application/json"
    )


@app.route(route="health", methods=["GET"])
def health(req: func.HttpRequest) -> func.HttpResponse:
    """للتحقق من إن الـ Function شغالة"""
    return func.HttpResponse(
        json.dumps({"status": "healthy", "service": "Bravo6 Scanner"}),
        status_code=200,
        mimetype="application/json"
    )