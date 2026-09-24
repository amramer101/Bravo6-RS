# Coverage and missing observations

## Three nested cohorts

| Cohort | Count | Inclusion rule |
| --- | ---: | --- |
| Saved | 848 | A result document was archived |
| Representative pages | 508 | Saved `page_is_representative` is true |
| Module-complete representative | 497 | Representative, ten completed modules, and saved reliability flag |

There are 340 non-representative saved results and eleven representative results with nine completed modules. The 864 submitted targets also include eleven rejected requests and five polling timeouts without saved results.

A flag named “representative” does not make this a probability sample of the Web. The study combines ranked domains, prior candidates, and builder-associated deployments.

## Observation states

| State | Counts as an evaluated negative? |
| --- | --- |
| Eligible resource assessed, no finding | Potentially, subject to detector validity |
| Module failed or timed out | No |
| Subcheck skipped | No |
| No applicable cookie/resource/manifest | No for that subcheck |
| Informational “not applicable” output | No |
| Module complete without subcheck evidence | Insufficient by itself |

## HSTS missingness

HSTS was skipped for 113 of 151 representative AI-builder-associated pages because of the saved CDN classification. Missing HSTS appears in 3/38 evaluated AI pages and 156/291 evaluated Tranco pages. Reporting 3/151 as a full-group missing-HSTS rate would silently classify the skipped cases as passes.

The full AI-group missing-HSTS proportion could range from 3/151 to 116/151 under extreme assumptions about the skipped observations. These are identification bounds, not confidence intervals, and they do not establish a group-wide advantage.

## Dependencies

Scout 10 completed on all 508 representative pages, but only 17 selected a manifest and six produced package-check events. Thirty events were recorded. The extended parser-exclusion scenario retains four sites and 28 events; events are not necessarily distinct packages.

Ten AI-builder pages selected a manifest, but none produced a package check. A zero dependency-finding count in that subgroup therefore does not demonstrate better dependency hygiene.

## Use explicit denominators

Every rate should identify the cohort, module/subcheck eligibility, number of events, and number of affected sites. An exclusion count is not a count of dropped sites. Missingness and shared hosting remain limitations even when a confidence interval is supplied.

[Evaluation results](research.md) · [Cross-tool agreement](validation.md)
