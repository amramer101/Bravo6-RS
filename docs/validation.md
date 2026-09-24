# Validation and agreement

## Distinguish three evidence types

1. **Tests in source:** fixtures and assertions that can be inspected.
2. **Recorded execution:** a run log or output showing what actually executed.
3. **Independent validity evidence:** a justified reference outcome for the same observation.

The existence of a suite does not establish that a historical deployed build passed it. Perfect results on a small synthetic fixture set do not establish accuracy on arbitrary websites.

## Saved cross-tool comparison

The stored comparison began with 25 sites; ten incomplete scans were excluded, leaving fifteen sites with paired verdict records. Each signal can have fewer comparable pairs. These are comparisons with stored Observatory outputs, not a claim that Observatory is ground truth.

| Signal | Agreement | Cohen's κ |
| --- | ---: | ---: |
| CSP | 15/15 | Undefined |
| HSTS | 3/15 | 0.022 |
| Cookies | 6/8 | 0.385 |
| CORS | 13/15 | 0.000 |
| SRI | 7/9 | -0.125 |
| X-Frame-Options | 15/15 | 1.000 |
| X-Content-Type-Options | 14/15 | 0.842 |
| Referrer-Policy | 5/6 | 0.571 |
| COOP | 3/15 | 0.000 |
| COEP | 0/15 | 0.000 |
| CORP | 1/2 | 0.000 |

CSP κ is undefined because every pair is fail/fail. It must not be replaced with 1. Agreement and κ answer different questions.

## Mapping caveat

The saved BRAVO6 mapping assigns pass when no matching failure title remains. Selected informational outputs are excluded from failure matching, so a pass can include non-observation or inapplicability. One comparable cookie pair and one comparable SRI pair contain such outputs. The mapping can also turn an inconclusive CORS title into pass, but no included case had that title.

These statistics describe agreement under the saved mapping, not independently verified successful subchecks. Sparse pair counts and degenerate bootstrap replicates limit interpretation. Confidence intervals and undefined-replicate diagnostics are retained in the local analysis package.

## What was not calibrated

There is no preserved independent TLS/testssl.sh calibration or email-security calibration in this evidence set. Do not infer those from a table listing tool capabilities. Scanner fixes in source and successful unit tests, if later executed, would still need to be distinguished from the historical deployed run.

## Fixture interpretation

`validation-benchmark/app.py` deliberately serves synthetic positive and negative examples. Credential-like strings in those fixtures are test data. Do not validate them against third-party services. The fixture application and runner are retained unchanged during documentation work.


## Implementation and evidence

- [validation-benchmark/README.md](https://github.com/amramer101/Bravo6-RS/blob/main/validation-benchmark/README.md)
- [validation-benchmark/app.py](https://github.com/amramer101/Bravo6-RS/blob/main/validation-benchmark/app.py)
- [validation-benchmark/runner.py](https://github.com/amramer101/Bravo6-RS/blob/main/validation-benchmark/runner.py)
- [validation-benchmark/cross-tool-calibration/compute_verdict_agreement.py](https://github.com/amramer101/Bravo6-RS/blob/main/validation-benchmark/cross-tool-calibration/compute_verdict_agreement.py)

Source links follow `main`. They describe the inspectable implementation, not a verified digest of the historical deployment.
