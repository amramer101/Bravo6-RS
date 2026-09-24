# Archived experiment and reanalysis

The principal evaluation is a preserved September 19, 2026 cloud API batch. Reanalysis reads existing results; it does not re-run targets, refresh advisories, or rewrite original findings.

## Experiment accounting

| Outcome | Count |
| --- | ---: |
| Submitted unique target domains | 864 |
| Archived result documents | 848 |
| Representative-page results | 508 |
| Module-complete representative results | 497 |
| Rejected requests | 11 |
| Polling timeouts without a saved result | 5 |

The first submission and final recorded completion span 473.83 minutes. That includes serialized submission, polling, and delay; it is not scan-only execution time or a load-test throughput result.

The original cohort combines Tranco rank bands, prior candidates, and AI-builder-associated deployments. The labels describe recorded sampling/discovery criteria, not verified AI authorship or a randomized comparison.

## Score sensitivity

| Cohort | Original mean | TLS + exact Axios exclusion | Extended exclusions |
| --- | ---: | ---: | ---: |
| 508 representative results | 16.93 | 24.78 | 24.84 |
| 497 module-complete representative results | 17.07 | 25.05 | 25.11 |

For the 508 cohort, the conservative mean has a 95% bootstrap interval of 23.12–26.49; its paired increase is 7.85 points (7.17–8.53). The extended mean has an interval of 23.16–26.56. These quantify empirical resampling stability, not all measurement or sampling uncertainty.

The conservative scenario excludes 384 unsupported weak-cipher assertions and one exact unsupported Axios advisory match across the saved batch. The extended scenario also excludes two disputed parser findings. The extended total is 387 findings on 195 sites across all saved results; 295 findings on 149 sites occur within the 508 cohort. These units must not be interchanged.

### Why the exclusions differ

- TLS evidence records a TLS 1.3 cipher and does not support the asserted NULL/anonymous legacy cipher.
- The exact Axios match incorrectly treats an advisory's explicit versions as an interval.
- Two parser findings are disputed because original response context is insufficient; their names alone do not prove false positives.

Exclusions are a sensitivity analysis, not a complete repair or independent security reassessment. All original documents are retained.

## Exploratory subgroup findings

Missing CSP occurs in 146/151 eligible representative AI-builder pages and 209/291 Tranco pages, a difference of 24.87 percentage points. It describes an emitted header finding, not exploitability or a causal effect of AI generation.

After removing unsupported weak-cipher assertions, saved legacy-TLS findings are 0/151 and 87/291 respectively. There is no independent TLS calibration. HSTS comparisons apply only to the evaluated subset, and the AI dependency comparison is not estimable because no package checks occurred.

## Statistical choices

Proportions use Wilson intervals; differences use Newcombe intervals. Six metric families under two cohort definitions are retained for a conservative twelve-comparison adjustment. Score sensitivity resamples paired observations within recorded strata with 20,000 bootstrap replicates. This was a retrospective plan, not preregistration.

The comparison with an earlier saved batch contains overlapping URLs and changed measurement conditions; it is not two independent population experiments. Paired results do not isolate a causal temporal change.

## Reproducibility boundary

The audit hashed 1,626 inputs and matched all 850 archived files to their local counterparts. Hashes establish consistency with the audit snapshot, not original acquisition time or an ethical authorization record. Current source is not tied to the exact historical deployment by a preserved build digest.

The revised manuscript and complete offline package remain local under `output/` pending a separately reviewed release. This site exposes aggregate interpretation, not raw target records, and does not claim the public repository alone reconstructs every table.

[Coverage definitions](coverage.md) · [Agreement analysis](validation.md) · [Methods and source guide](references.md)
