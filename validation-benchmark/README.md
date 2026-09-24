# Synthetic validation fixtures

This directory contains a controlled fixture application, case definitions, and a benchmark runner. The files support inspection of validation design; their presence is not proof of a historical executed run or broad detector accuracy.

## Contents

| File | Role |
| --- | --- |
| `app.py` | Synthetic positive/negative HTTP responses |
| `fixtures/cases.json` | Case definitions |
| `runner.py` | Scanner/fixture comparison logic |
| `test_runner.py` | Runner test code |
| `Dockerfile` | Container setup |
| `cross-tool-calibration/` | Saved external-tool comparison artifacts and scripts |

The default runner may contact a public package registry. Its explicit mock mode bypasses part of the real dependency-check path. A mocked result must be labeled as such; neither mode is run by building the documentation.

Credential-like fixture strings are synthetic examples. Do not attempt live verification. Any controlled future run should record the exact fixture version, scanner version, configuration, mode, and executed outputs.

[Validation interpretation](../docs/validation.md) · [Known limits](../docs/limitations.md)
