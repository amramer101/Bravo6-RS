"""
benchmark.py — قياس زمن تنفيذ كل اختبار على حدة

يقوم بتشغيل كل اختبار من الاختبارات الـ 16 ضد هدف محدد،
ويقيس الوقت المستغرق لكل اختبار، ويعرض تقريراً بالنتائج.
"""

import asyncio
import time
import sys
from datetime import datetime

# استيراد جميع الاختبارات
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

# قائمة الاختبارات (اسم الاختبار، دالة run)
TESTS = [
    ("secrets", test_01_secrets.run),
    ("frontend_libs", test_02_frontend_libs.run),
    ("mixed_content", test_03_mixed_content.run),
    ("ssl_tls", test_04_ssl_tls.run),
    ("security_headers", test_05_security_headers.run),
    ("info_disclosure", test_06_info_disclosure.run),
    ("cookies", test_07_cookies.run),
    ("email_security", test_08_email_security.run),
    ("subdomain_takeover", test_09_subdomain_takeover.run),
    ("robots_txt", test_10_robots_txt.run),
    ("cors", test_11_cors.run),
    ("http_methods", test_12_http_methods.run),
    ("cms_fingerprinting", test_13_cms_fingerprinting.run),
    ("sri", test_14_subresource_integrity_sri.run),
    ("hallucinated_deps", test_15_hallucinated_deps.run),
    ("ai_exposure", test_16_ai_exposure.run),
]

async def run_single_test(name, coro, url):
    """تشغيل اختبار واحد وقياس زمنه."""
    start = time.time()
    try:
        result = await coro(url)
        duration = time.time() - start
        status = result.get("status", "unknown")
        return {
            "name": name,
            "duration": duration,
            "status": status,
            "error": None,
            "findings_count": len(result.get("findings", [])) if isinstance(result, dict) else 0,
        }
    except Exception as e:
        duration = time.time() - start
        return {
            "name": name,
            "duration": duration,
            "status": "error",
            "error": str(e),
            "findings_count": 0,
        }

async def benchmark(url):
    print(f"🔍 بدء قياس أداء الاختبارات على: {url}")
    print("=" * 60)
    results = []
    total_start = time.time()

    for name, coro in TESTS:
        print(f"⏳ تشغيل {name}... ", end="", flush=True)
        res = await run_single_test(name, coro, url)
        results.append(res)
        # طباعة النتيجة فوراً
        if res["error"]:
            print(f"❌ فشل ({res['duration']:.2f}s) - {res['error'][:50]}")
        else:
            print(f"✅ {res['status']} ({res['duration']:.2f}s) - {res['findings_count']} نتيجة")

    total_duration = time.time() - total_start

    # عرض ملخص
    print("\n" + "=" * 60)
    print("📊 ملخص الأداء:")
    print(f"إجمالي الوقت: {total_duration:.2f} ثانية")
    print("\nترتيب الاختبارات حسب الزمن (الأسرع أولاً):")
    sorted_results = sorted(results, key=lambda x: x["duration"])
    for i, res in enumerate(sorted_results, 1):
        print(f"  {i:2d}. {res['name']:20s} → {res['duration']:7.2f}s  [{res['status']}]")

    # حفظ النتائج في ملف CSV
    csv_file = f"benchmark_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    with open(csv_file, "w") as f:
        f.write("test_name,duration_seconds,status,findings_count,error\n")
        for res in results:
            f.write(f"{res['name']},{res['duration']:.3f},{res['status']},{res['findings_count']},\"{res['error'] or ''}\"\n")
    print(f"\n💾 تم حفظ النتائج في: {csv_file}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("الاستخدام: python benchmark.py <URL>")
        print("مثال: python benchmark.py https://example.com")
        sys.exit(1)

    target = sys.argv[1]
    asyncio.run(benchmark(target))
