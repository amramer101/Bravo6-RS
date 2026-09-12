# Validation Benchmark

This folder provides a local synthetic benchmark for the Bravo6 worker. It intentionally avoids changing Scout logic and instead exercises the existing scan pipeline against a controlled local HTTP server with known vulnerable and secure routes.

## Purpose

The benchmark is designed to answer one question with evidence: do the shipped scouts actually identify the synthetic weaknesses they are intended to flag, without false positives on the secure control cases?

## How it works

- A Flask app exposes intentionally vulnerable and secure pages.
- The runner calls the real orchestrator (`src/worker/main_scanner.py`) against each page.
- A fixture file declares the expected truth for each route.
- The runner compares the observed findings against the declared expectation and prints precision/recall.

## Local run

By default, the benchmark exercises the real scanner logic against the live registry path. This is the expected, reportable accuracy run.

From the repository root:

```bash
python validation-benchmark/runner.py
```

### Offline-only mock mode (explicit opt-in)

If the environment has no internet access and you still want a deterministic local benchmark for the hallucinated dependency case, you may opt in to the benchmark-only mock explicitly:

```bash
python validation-benchmark/runner.py --offline-mock
```

or:

```bash
BRAVO6_VALIDATION_OFFLINE_MOCK=1 python validation-benchmark/runner.py
```

This flag intentionally bypasses the real scout's registry decision path for the hallucinated-dependency case only. It is not a clean scanner-accuracy result and must be reported as an offline/mocked benchmark result, not as the live classifier performance.

## Docker

```bash
docker build -t bravo6-validation-benchmark -f validation-benchmark/Dockerfile .
docker run --rm -p 5001:5001 bravo6-validation-benchmark
```

## Notes

- The benchmark intentionally disables SSRF protections in the runner only so that the local server can be scanned without modifying production scout logic.
- This benchmark is local-only and is not part of Terraform or Azure deployment.
