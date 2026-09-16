# Cross-tool calibration

This folder compares the existing Bravo6 scanner against Mozilla Observatory on a small sample of live public sites.

## Purpose

- Keep the local synthetic benchmark as the canonical correctness check for the scanner itself.
- Use a separate, independent external reference to spot broad signal-level agreement and disagreements.
- Treat comparison results as calibration evidence, not as a replacement for the synthetic benchmark.

## Files

- `sample_sites.json` — the fixed sample list used for this run.
- `run_calibration.py` — fetches each site with the real scanner and the Mozilla Observatory API, then records the overlap/disagreement by security signal.
- `results.json` — generated output from a single calibration run.

## Run

From the repository root:

```bash
python validation-benchmark/cross-tool-calibration/run_calibration.py
```

## Notes

- The harness uses the real scanner as shipped (`src/worker/main_scanner.py`).
- The Observatory comparison is limited to the signal names it exposes in `tests`.
- The script reports only genuine overlap/disagreement on mapped header-related checks; it does not claim a full equivalence between the two products.
