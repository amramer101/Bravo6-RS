# Findings, scores, and coverage flags

## Normalized finding

The current normalization function emits the following fields. Confidence and remediation are detector output, not independent adjudication.

| Field | Meaning |
| --- | --- |
| `id` | Truncated hash of selected stable finding fields; not an anonymity guarantee |
| `module`, `title` | Producing scout and assertion |
| `severity`, `confidence` | Normalized severity and implementation confidence label |
| `cwe`, `owasp` | Classification metadata |
| `location`, `evidence` | Context supporting the assertion; potentially sensitive |
| `poc`, `remediation` | Guidance emitted by the detector; not evidence of executed exploitation |
| `detection_method` | Detection source/method label |
| `tier` | Baseline or hardening scoring classification |

The normalized object does not copy the entire raw finding object. That reduces duplication, but does not prove every evidence string is safe to publish.

## Result fields

A normal result includes `scanId`, `url`, timestamps, `tests_run`, `findings`, `tests`, `summary`, `errors`, `metrics`, `score`, `raw_score`, `grade`, `grade_reliable`, `coverage_note`, and `page_is_representative`. Persistence adds the identifier used by Cosmos. Exceptional/blocked result shapes can differ; consumers should not assume every field exists.

`tests_run` counts completed modules. `page_is_representative` is a response-classification flag. `grade_reliable` is a coverage gate in this implementation, not a validated guarantee that the score is correct.

## Rubric

| Severity | Deduction per finding |
| --- | ---: |
| Critical | 30 |
| High | 15 |
| Medium | 5 |
| Low | 2 |
| Informational | 0 |

Let `B` be baseline deductions and `H` hardening deductions:

```text
raw_score = 100 - B - min(H, 10)
displayed_score = round(max(0, raw_score))
```

| Grade | Displayed score |
| --- | --- |
| A | 85–100 |
| B | 75–84 |
| C | 65–74 |
| D | 55–64 |
| F | Below 55 |

The cap applies to the combined hardening deductions, not separately to every finding. Baseline deductions are not capped. Several different raw scores can collapse to a displayed zero.

## Worked arithmetic example

An illustrative baseline high finding costs 15 points. Three medium hardening findings sum to 15 but contribute only 10 after the shared cap. The resulting score is `100 - 15 - 10 = 75`, grade B. This explains arithmetic only; it is not an observed site result or a validated risk assessment.

## Interpretation

The score is a heuristic index, not exploitation probability or expected loss. Finding multiplicity, thresholds, response classification, and missing observations affect it. Retrospective exclusions change derived scores only; they do not modify the saved JSON or establish that the detector has been repaired.

[Original and sensitivity results](research.md) · [Known limitations](limitations.md)


## Implementation and evidence

- [src/worker/main_scanner.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/main_scanner.py)

Source links follow `main`. They describe the inspectable implementation, not a verified digest of the historical deployment.
