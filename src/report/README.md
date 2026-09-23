# Report service

`function_app.py` defines GET routes `report/status` and `report/result`. The normal default Functions prefix is `/api`. This service reads saved results; it does not initiate a scan or render HTML.

Both routes use anonymous Function authentication in the inspected implementation. Do not describe reports as ownership-protected. The deferred renderer is in [future-work/report-html](../../future-work/report-html/README.md).

`requirements.txt` and `host.json` configure the Function App. `test_report_function.py` contains tests; cleanup does not execute them or access Cosmos DB.

[Implementation map](../README.md)
