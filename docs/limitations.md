# Known limitations and roadmap

## Measurement limitations

| Issue | Consequence | Current treatment |
| --- | --- | --- |
| Unsupported weak-cipher assertions | Inflated findings and deductions | Separate retrospective exclusion; no claim of a repaired historical run |
| Exact Axios advisory mismatch | Unsupported affected-version inference | Exclude the specific match only |
| Two disputed parser findings | Uncertain package-absence interpretation | Conservative and extended scenarios remain separate |
| HSTS skipping | Unequal, incomplete observation | Eligible denominators and bounds |
| Sparse manifest/package coverage | Zero findings can mean no evaluation | Report package-check counts |
| Saved verdict mapping | Non-observation can map to pass | κ described as agreement under that mapping |
| Shared hosting and convenience strata | Confounding and selection effects | Exploratory, noncausal subgroup interpretation |
| Missing deployment/cache digest | Historical runtime not exactly reconstructable | Explicit provenance limitation |

## Product and operational limitations

Caller authentication, quotas, result ownership, implemented frontend, and HTML reports are deferred. SSRF controls are not exhaustively validated across outbound paths. Queue use does not guarantee exactly-once execution, and local fallback is not a durable recovery system. There is no supported production availability, cost, or throughput claim.

## Priorities for future work

1. Establish a controlled and appropriately authorized validation protocol.
2. Repair and locally test detector semantics with independent fixtures.
3. Make observation states explicit in schemas and scoring eligibility.
4. Add authenticated intake and report ownership before multi-user exposure.
5. Record build and advisory digests plus per-hop telemetry for future runs.
6. Revisit live comparisons only as a separately planned experiment.

These are future priorities, not features implemented by documentation edits. The preserved experiment and its original outputs remain unchanged.
