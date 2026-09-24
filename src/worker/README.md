# Worker and ten scouts

The Worker executes the active scouts, normalizes/deduplicates findings, applies a heuristic scoring rubric, and persists results. Read-oriented requests include HTTP resources, protocol probes, DNS and registry operations; they are not equivalent to an ordinary page load or evidence of permission to scan.

## Entry points

| File | Responsibility |
| --- | --- |
| `function_app.py` | Service Bus trigger and scheduled advisory refresh |
| `main_scanner.py` | `run_scout`, discovery, shared context, normalization, scoring, persistence |
| `test_01_secrets.py` through `test_10_hallucinated_deps.py` | Ten runtime plugins with embedded test paths |
| `osv_cve_sync.py` | Scheduled advisory synchronization |
| `cve_database_v2.csv` | Static advisory dataset |
| `evaluation/` | Historical collection and analysis tools |

`discover_plugins()` uses filenames matching `test_*.py`; do not rename these as a formatting change. The CLI accepts a positional target URL, while the cloud handler passes the queue's `job_id` as `scan_id`. No live scan command is part of the documentation quickstart.

## Interpretation and operation

- [Scout profiles](../../docs/software-architecture.md)
- [Finding schema and score](../../docs/scoring.md)
- [Coverage rules](../../docs/coverage.md)
- [Advisory paths](../../docs/advisory-data.md)
- [Known measurement limits](../../docs/limitations.md)
- [Historical evaluation](evaluation/README.md)

The default live-secret-verification setting in source does not prove the historical deployed setting. The source checkout is not proven byte-identical to that deployment. Module completion is not proof that every subcheck ran.

Local test entry points exist, but no passing-test count or execution claim is made here. Real execution requires appropriate authorization and project rights. Current scanner behavior and original results were not changed by the documentation rewrite.
