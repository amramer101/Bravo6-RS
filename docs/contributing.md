# Contributing & Testing

There's no `CONTRIBUTING.md` in the repository yet — this page is the closest thing until one
exists. Open an issue or a PR; it'll get a response.

## Running the tests

Every scout is a standalone module with its own `unittest`-based regression suite, runnable
directly:

```bash
cd src/worker
python3 test_04_ssl_tls.py --test      # any single scout
for f in test_*.py; do python3 "$f" --test; done   # all ten
python3 main_scanner.py --test          # orchestration-level suite
```

```bash
cd src/api
python3 test_api_gateway.py             # API Gateway suite, against mocked Azure clients
```

CI (`.github/workflows/python-tests.yml`) currently runs the ten scout suites plus the
orchestration suite on every push/PR touching `src/worker/**`. It does not yet run the API Gateway
suite — that's a real gap worth closing, since the Gateway is code-complete but has no deployed
environment to catch a regression any other way.

## Adding a new scout

Plugin discovery is by filename: the Worker globs `test_*.py` in `src/worker/` at startup
(`discover_plugins()` in `main_scanner.py`). A new scout that follows the existing pattern —
implements the twelve-field finding schema described in
[Software Architecture & Scouts](software-architecture.md), and exposes a `--test` CLI flag running
its own `unittest` suite — is picked up automatically; no change to the orchestrator is needed. Two
prototype scouts already exist outside the live pipeline in `future-work/code-scan/` as a reference
for what an unwired-but-structured scout looks like.

## API Gateway surface

The Gateway (`src/api/function_app.py`) currently implements exactly one HTTP route:

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/scan` | **None currently** (see Future Work below) | Submit a URL for scanning: checks the category-based blocklist, then enqueues a message onto Service Bus for the Worker to pick up. |

Response status codes, all covered by the regression suite:

| Status | Meaning |
|---|---|
| `202 Accepted` | Job accepted and enqueued; response body carries the job ID |
| `400 Bad Request` | Missing/invalid JSON body or missing `url` field |
| `403 Forbidden` | The target URL matches the category-based blocklist |
| `503 Service Unavailable` | Service Bus enqueue failed after retries |

**Future Work — auth.** Bearer JWT validation (Entra External ID), per-user quota enforcement,
and a Cosmos DB scan-job write were all implemented, tested, and previously wired into this
route (`401`/`429` above were both real outcomes) — deferred out of the active path on
2026-09-12, not deleted. See `future-work/auth/README.md`.

**Gap worth naming explicitly:** the "Report Function" component described in the architecture
(read-side, `GET /report/{id}`) has no Azure Function entry point implemented yet —
`src/report/report_generator.py` contains only the HTML-rendering logic (`build_html(data) -> str`),
not a routed Function App. Someone picking this up next should treat wiring that route as a
concrete, scoped next step, not assume it already exists because the architecture diagram shows it.

None of this — the one real route included — has been exercised against a deployed Function App
or real Service Bus traffic. See [Deployment Guide](deployment.md) for what deploying it would
take.
