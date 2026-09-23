# API Gateway

`function_app.py` defines the `scan` POST route (normally `/api/scan` with the default Functions prefix). It checks intake and uses `servicebus_queue.py` to enqueue a job. `blocklist.py` provides target policy checks.

The active route is anonymous. JWT validation, per-user quotas, and the deferred job-record path are not part of this active implementation. See [deferred authentication](../../future-work/auth/README.md).

`requirements.txt` and `host.json` belong to this Function App. `test_api_gateway.py` contains local test code; its presence is not a statement that tests were run during cleanup. Do not deploy or invoke live targets as part of documentation maintenance.

[Implementation map](../README.md)
