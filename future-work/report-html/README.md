# Deferred: HTML report rendering

`report_generator.py` moved out of `src/report/` on 2026-09-12, not deleted. It built a
self-contained, XSS-escaped HTML document from a finished scan result — that's what
`GET /report/result` used to return before this pass switched it to plain JSON
(`src/report/function_app.py`).

**Why**: no report frontend is planned now or later in this project's current scope, so nothing
consumes an HTML document — a browser would have been the only real client for
`text/html` here, and there isn't one. JSON is the full current scope for this endpoint.

Not connected to the auth removal in `future-work/auth/` — this is an independent decision
(output format), not a consequence of removing JWT validation. Restoring one doesn't require
restoring the other.

**To restore**: import `build_html` from here in `src/report/function_app.py`'s
`handle_result_request()`, and return `("text/html", build_html(doc))` instead of
`("application/json", json.dumps(doc))` for the Complete-status branch.
