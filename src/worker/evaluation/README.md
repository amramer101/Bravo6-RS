# Bravo6 Evaluation Harness

Reproducible pipeline for scanning a Tranco-sampled set of live sites with the
existing, unmodified `main_scanner.py`. Run the four scripts in order:

```
python3 fetch_tranco_list.py                 # freeze a citable Tranco snapshot -> data/tranco_<id>.csv, data/tranco_metadata.txt
python3 sample_sites.py                       # fixed-seed sample -> data/sample_sites.csv, data/sample_sites.txt
python3 run_evaluation.py [--limit N]         # scan the sample -> results/<batch_id>/*.json, manifest.csv, run_summary.txt
python3 aggregate_results.py results/<batch_id>   # -> results/<batch_id>/aggregate.csv (paper input)
```

## Reproducibility

- `fetch_tranco_list.py` resolves a specific Tranco **list ID** (via their documented API,
  never a guessed URL) and freezes the raw CSV locally. Every later step reads that frozen
  file — nothing re-fetches Tranco live. Cite the list as recorded in `data/tranco_metadata.txt`.
- `sample_sites.py` uses a **fixed, hardcoded seed** (`RANDOM_SEED` at the top of the file) —
  re-running it against the same frozen CSV with the same rank band/`n` reproduces a
  byte-identical sample. Do not change the seed for the paper's canonical sample.
- `run_evaluation.py` calls the scanner exactly as normally invoked
  (`run_scout(url, config={"cve_csv_url": ...})`); no scanner-side behavior differs from a
  manual CLI run.

## Known side effect

`run_scout()` (unmodified, per this task's scope) unconditionally also saves a copy of every
result into the top-level `../results/` folder as part of its own normal behavior. That's a
side effect of calling the scanner as-is, not this harness's dataset. The **canonical**
evaluation dataset is `results/<batch_id>/` (plus its `aggregate.csv`) — that's what feeds
the paper.

## Layout

```
evaluation/
  data/
    tranco_<list_id>.csv       # frozen source list (do not edit/delete once sampled)
    tranco_metadata.txt        # citation info
    sample_sites.csv           # rank,domain (sorted by rank)
    sample_sites.txt           # one https://<domain> URL per line, runner input
  results/
    <batch_id>/
      rank_<rank>_<domain>.json  # one per successfully scanned site
      manifest.csv                # rank,domain,url,status,result_file,error_type,error_message
      run_summary.txt             # attempted/succeeded/failed + wall-clock time
      aggregate.csv                # one row per site, paper input
```
