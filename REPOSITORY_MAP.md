# Repository map

BRAVO6 is a research prototype. Public visibility does not make this repository open source: see [LICENSE](LICENSE). Runtime paths and historical evidence are preserved during repository maintenance.

| Location | Responsibility | Status / publication boundary |
| --- | --- | --- |
| `src/api/` | HTTP intake and Service Bus submission | Active implementation; not a claim about current cloud availability |
| `src/worker/` | Orchestration, ten scouts, scoring, advisory synchronization | Active implementation; filenames participate in plugin discovery |
| `src/report/` | JSON status and result retrieval | Active implementation; no HTML renderer in this path |
| `src/cve-pipeline/` | Manual advisory snapshot generation | Separate from the Worker's scheduled synchronization |
| `src/worker/evaluation/` | Historical collection and analysis tools | Live runners and offline analysis must not be confused |
| `terraform/` | Infrastructure definitions and modules | Source configuration, not proof of historical deployment |
| `validation-benchmark/` | Synthetic fixtures and historical cross-tool comparison | Existence of fixtures does not establish executed validation |
| `future-work/` | Deferred authentication, HTML reports, scout prototypes | Outside the active runtime |
| `docs/` | MkDocs website source | Existing content requires the documented task-3 reconciliation |
| `maintenance/` | Audit, publication boundaries, and cleanup decisions | No raw results or credential values |
| `.github/workflows/` | Documentation, Python suites, cloud planning/deployment | Documentation publication and Terraform execution are manual |
| `output/` | Local paper, evidence audit, and reanalysis artifacts | Ignored; preserve locally, review a selected release separately |

## Start here

- [Audit and next steps](maintenance/REPOSITORY_AUDIT.md)
- [Publication policy](maintenance/PUBLICATION_POLICY.md)
- [Workflow behavior](.github/README.md)
- [Infrastructure map](terraform/README.md)
- [Component map](src/README.md)

Do not rename `src/worker/test_*.py` as cosmetic cleanup. `discover_plugins()` uses those names. Do not move saved results or rewrite their identifiers to anonymize them in place. Prepare a separate reviewed derivative if data are to be released.
