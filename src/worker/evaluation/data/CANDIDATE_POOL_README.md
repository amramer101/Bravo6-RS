# candidate_pool_n800 — big-run candidate pool

Stratified candidate list for the large evaluation run (target: 500 successfully-scanned
domains after attrition). List-building only — not itself a scanned dataset. Built by
`../build_candidate_pool.py`, then corrected by `../apply_pool_exclusions.py`.

## Files

- `candidate_pool_n800.csv` — `domain,url,stratum,rank,platform,discovery_method,source_url`
- `candidate_pool_n800.txt` — plain `https://<domain>` per line (same convention as `sample_sites.txt`)

## Final composition (864 total)

| stratum | count | source |
|---|---|---|
| `tranco-low-rank` | 50 | Tranco rank 1–1,000 |
| `tranco-mid-rank` | 250 | Tranco rank 1,000–50,000 |
| `tranco-high-rank` | 250 | Tranco rank 50,000–500,000 |
| `prior-candidate-list` | 125 | reused from `sample_sites.csv` (the already-scanned n=500 `20260903T182513Z_n500_c3_10scouts_FINAL` batch's own input) |
| `ai-generated` | 189 | Lovable/Bolt.new/v0-built public deployments |

Tranco source: the same frozen snapshot already used elsewhere in this harness —
**Tranco list ID N2Q8W**, generated 2026-08-28T22:00:01, `https://tranco-list.eu/list/N2Q8W`
(see `tranco_metadata.txt`). Re-confirmed still valid/citable via Tranco's own API before reuse
(`GET https://tranco-list.eu/api/lists/id/N2Q8W` → `"available": true, "failed": false`).
Reused rather than re-fetched: this harness's stated reproducibility convention is one frozen
Tranco CSV, read by every downstream script — re-fetching "today's" list would have produced a
second, inconsistent snapshot. Same fixed seed as the rest of this harness: `RANDOM_SEED = 20260829`
(`sample_sites.py`).

## Adult/NSFW and calibration-overlap exclusions (applied)

`apply_pool_exclusions.py` removed 20 domains from the originally-built 864-candidate pool and
replaced each with a same-stratum, same-rank-band seeded replacement, so per-stratum counts stay
exactly 50/250/250/125/189 (total unchanged: 864 → 864).

### Adult/NSFW filter (Task 1) — 14 excluded

**Source used:** [UT1 Blacklists](https://dsi.ut-capitole.fr/blacklists/), maintained by
Université Toulouse 1 Capitole (Direction du Système d'Information) — a long-running,
actively-updated, categorized domain blocklist compiled specifically for web-content
categorization/filtering research and widely cited in that literature (as opposed to a
general-purpose ad/malware hosts file repurposed for this). License: **Creative Commons
BY-SA 4.0** (confirmed on the source page), which permits reuse and redistribution with
attribution — appropriate for a paper's methodology appendix. Categories used: **`adult`**
(4,599,280 domains) and **`mixed_adult`** (149 domains), combined and deduplicated
(4,599,412 unique domains after combining). Downloaded 2026-09-16 from
`https://dsi.ut-capitole.fr/blacklists/download/adult.tar.gz` and
`https://dsi.ut-capitole.fr/blacklists/download/mixed_adult.tar.gz`.

**Known limitation, documented rather than hidden:** blocklists have imperfect recall. One of
the two domains manually spotted in the prior review (`xxxpostpic.org`) is **not** present in
UT1's `adult`/`mixed_adult` categories despite being genuinely adult content — it was excluded
via an explicit manual-confirmation override (`MANUALLY_CONFIRMED_ADULT` in
`apply_pool_exclusions.py`), not by the automated list. The other (`aznude.com`) is present in
UT1's list. Conversely, `pixiv.net` (tranco-low-rank, rank 35) *is* in UT1's `adult` category —
it is a mainstream Japanese art-sharing platform that also hosts user-submitted NSFW content, a
known over-blocking pattern for mixed-content platforms in categorized blocklists. It was excluded
anyway, mechanically, per the systematic/documented list rather than carved out as a personal
judgment call — flagged here so the trade-off is a visible, conscious methodological choice, not
a silent one.

Excluded (14): `pixiv.net` (tranco-low-rank), `aznude.com`, `xxxpostpic.org`, `redvelvet.co.za`,
`peakpx.com`, `hot-india.com`, `xvideos10.blog.br` (tranco-mid-rank), `twinkaboo.com`,
`userporn.com`, `gamesfuckgirls.com`, `freshporn.me` (tranco-high-rank), `taboodude.com`,
`3xxx.pro`, `lechetube.com` (prior-candidate-list).

### Cross-tool-calibration overlap (Task 2) — 6 excluded

Removed the 6 domains already used in
`validation-benchmark/cross-tool-calibration/sample_sites.json` (`github.com`, `paypal.com` —
both `tranco-low-rank`; `olx.pl`, `buzzoola.com`, `openweathermap.org`, `fastpanel.direct` — all
`prior-candidate-list`) so no site both fed the calibration exercise and counts toward the
big-run evaluation dataset — keeps the two pieces of evidence methodologically independent.

### Replacement method

For each stratum that lost domains, the same source pool is re-consulted (the matching Tranco
rank band for `tranco-*`; `sample_sites.csv`'s full 500 for `prior-candidate-list`; the full
361-candidate GitHub/showcase discovery pool, beyond the 189 already used, for `ai-generated`),
with already-selected-anywhere-in-the-pool domains and every excluded/blocklisted/calibration
domain removed from consideration, then
`random.Random(RANDOM_SEED).sample(remaining_eligible, k=needed)` draws the exact number of
replacements needed. This is deterministic and re-runnable (same seed, same reduced input →
same output every time), but is **not** a continuation of the original per-band
`random.sample()` call — Python's `sample()` isn't prefix-stable across different `k` values
with the same seed, so a true incremental continuation isn't well-defined; a fresh seeded draw
against the reduced eligible pool is the reproducible alternative used instead.

Replacements drawn: `tranco-low-rank` (3): `newrelic.com`, `awsglobalaccelerator.com`, `pvp.net`
· `tranco-mid-rank` (6): `musical.ly`, `jet.su`, `yu.edu`, `iodata.jp`, `routenote.com`,
`cjbgxt.com` · `tranco-high-rank` (4): `echo-usa.com`, `safholland.com`, `fiancees-ua.com`,
`newspass.jp` · `prior-candidate-list` (7): `wordunscrambler.me`, `sikayetvar.com`,
`bilendi.com`, `spintoband.com`, `i-now.com`, `whs-saas.com`, `maillist-manage.eu`.

Verified post-replacement: 864 total (unchanged), 0 duplicate domains, 0 remaining
blocklist/manual-confirmed/calibration-overlap hits, exact per-stratum counts preserved.
