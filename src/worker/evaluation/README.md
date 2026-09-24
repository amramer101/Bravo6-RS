# Historical collection and analysis

This directory contains both networked collection tools and analysis tools. Their roles must not be confused when reproducing saved results.

| Tool family | Examples | Behavior |
| --- | --- | --- |
| Sampling / collection | `fetch_tranco_list.py`, `run_evaluation.py` | Can access external services or targets |
| Pool construction | `sample_sites.py`, `build_candidate_pool.py`, `apply_pool_exclusions.py` | Builds/selects candidate inputs; inspect each script's data requirements |
| Historical analysis | `aggregate_results.py`, `analyze_evaluation.py`, `analyze_cache_efficiency.py` | Derives outputs from saved runs; older interpretations may be superseded |
| Counterfactual analysis | `tier_fix_counterfactual.py`, `ocsp_fix_impact.py` | Specific retrospective questions, not new ground truth |

Two historical local tools, `run_gateway_batch.py` and `analyze_gateway_batch.py`, remain ignored pending publication review. They are not promised as available in a fresh clone. The former submits to cloud endpoints; the latter contains superseded analytical assumptions.

## Recorded evaluation

The principal archived batch submitted 864 targets, saved 848 results, classified 508 pages as representative, and had 497 module-complete representative results. [Research interpretation](../../../docs/research.md) and [coverage definitions](../../../docs/coverage.md) supersede older “508 fully assessed” descriptions.

## Data boundary

`results/` and raw archives stay local. The tracked `data/` directory includes identifiable candidate lists and metadata; it is not an anonymized release. Do not overwrite originals to prepare public data. The complete retrospective analysis package is local under `output/review/task2/`, with a subsequent sensitivity correction under `output/paper/task3/`; neither directory is guaranteed in a fresh clone.

The repository is not claimed to reproduce every published number without those additional preserved inputs. A new collection run would be a new experiment, not a replacement for historical evidence.
