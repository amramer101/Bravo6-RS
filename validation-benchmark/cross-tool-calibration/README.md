# Saved cross-tool verdict comparison

The directory name is historical. The available outputs support agreement under a saved verdict mapping, not independent calibration of every detector.

## Files and boundaries

- `run_calibration.py`: executes scanner/external comparison activity; networked.
- `fetch_mozilla_verdicts.py`: obtains external verdicts; networked.
- `compute_verdict_agreement.py`: computes agreement under the saved mapping.
- `results.json`, `mozilla_verdicts.json`, `verdict_agreement_results.json`: historical outputs.
- `sample_sites.json`: identifiable sample, not an anonymized dataset.

The saved sample starts with 25 sites. Ten incomplete scans are excluded, leaving fifteen paired sites with signal-specific denominators. The mapping can treat selected informational or not-applicable findings as pass. Thus agreement and κ describe the mapping, not independently verified successful subchecks.

There is no independent TLS/testssl.sh or email-security comparison in these artifacts. CSP agreement of 15/15 has undefined κ because all pairs share one outcome; it is not κ=1.

Original data and mapping code are preserved. No new collection, verdict refresh, or scanner execution is needed for reading the [revised interpretation](../../docs/validation.md).
