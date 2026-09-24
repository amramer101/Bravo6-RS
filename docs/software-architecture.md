# Worker and scout reference

## Orchestration

`discover_plugins()` loads `test_*.py` modules from the Worker directory. The ten active scouts share an initial HTTP context and execute concurrently with module-level limits. Renaming these files is a runtime change, not cosmetic organization.

The shared context holds response content, parsed HTML, cache state, and counters. A shared initial page can avoid duplicate retrieval, but TLS, DNS, CORS origins, additional paths, registry requests, and other observations still require separate operations. The experiment does not isolate speedup against an uncached control.

## The ten scouts

| Scout | Observation | Prerequisite / interpretation limit |
| --- | --- | --- |
| 01 · Secrets | Credential-like patterns in served content | A matched string is not a verified live credential; optional live verification is a separate setting |
| 02 · Frontend libraries | Fingerprints and advisory matching | Version identification and advisory semantics must both be correct |
| 03 · Cookies | Attributes of observed cookies | No cookies observed is not proof of secure cookies |
| 04 · TLS | Certificate and protocol/cipher observations | Negotiation must establish the actual protocol/cipher asserted; see known weak-cipher issue |
| 05 · Headers | CSP, HSTS, and other response headers | Saved CDN classification can cause HSTS to be skipped |
| 06 · Information disclosure | Additional paths and response checks | Soft errors and response classification affect specificity |
| 07 · Email DNS | Mail-related DNS/configuration signals | No independent email calibration is preserved |
| 08 · CORS | Synthetic-origin response behavior | An inconclusive request differs from a safe CORS policy |
| 09 · SRI | Eligible cross-origin resource integrity attributes | No eligible resource is not a successful SRI assessment |
| 10 · Dependencies | Manifest parsing and registry presence | Requires actual package checks; absence does not prove AI origin or exploitation |

## 01 — Secret patterns

Findings are detector assertions based on patterns and context. The inspected source defaults optional live verification off; this is not proof of the historical cloud setting. Saved counts must not be called counts of working keys. Do not copy evidence values into issues or the public documentation.

## 02 — Library advisories

Fingerprinting and advisory matching are separate evidence steps. The Worker has a Table Storage path and a static dataset path. An enumerated affected-version list must not be treated as a continuous range. The reanalysis removes one exact unsupported Axios/advisory match; it does not clear that version of all other vulnerabilities.

## 03–05 — Cookies, TLS, and headers

Record whether an observable resource exists before turning “no finding” into a pass. For TLS, a connection negotiated with `TLS_AES_128_GCM_SHA256` does not support an assertion that a NULL or anonymous cipher was negotiated. For HSTS, saved skipped observations remain not evaluated; they must not enter the denominator as successful checks.

## 06–09 — Paths, DNS, CORS, and integrity

These checks have distinct traffic and eligibility rules. Path requests can resemble a successful response even when a file is absent. DNS records describe mail configuration rather than web-page source. CORS probes require contextual interpretation of origin and credentials. SRI is meaningful only for applicable external resources. A single shared “completed” flag does not resolve those differences.

## 10 — Manifest and registry coverage

A module can finish without finding a manifest. Even a fetched manifest can produce no usable package checks. The saved representative cohort has 508 completed dependency modules, 17 selected manifests, and six sites with package-check events. In the extended sensitivity scenario, four sites remain after excluding two disputed parser cases. No AI-builder page in the saved subgroup had a package check.

The uppercase token and IP-shaped name in the disputed cases are not proven invalid Python names merely by their appearance. A later parser heuristic is not independent ground truth.

## Error and coverage states

Per-module records can include completion state, fatal errors, and durations. These are execution observations. Module timeouts, absent resources, inapplicability, and a clean evaluated result should not be merged into one “safe” outcome. The [coverage guide](coverage.md) defines the analysis denominators.

## Deferred scouts

Mixed-content and AI-exposure prototypes under `future-work/code-scan/` are not part of the active ten-scout runtime. Their existence is not experimental validation.


## Implementation and evidence

- [src/worker/main_scanner.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/main_scanner.py)
- [src/worker/test_01_secrets.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/test_01_secrets.py)
- [src/worker/test_02_frontend_libs.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/test_02_frontend_libs.py)
- [src/worker/test_03_cookies.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/test_03_cookies.py)
- [src/worker/test_04_ssl_tls.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/test_04_ssl_tls.py)
- [src/worker/test_05_security_headers.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/test_05_security_headers.py)
- [src/worker/test_06_info_disclosure.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/test_06_info_disclosure.py)
- [src/worker/test_07_email_security.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/test_07_email_security.py)
- [src/worker/test_08_cors.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/test_08_cors.py)
- [src/worker/test_09_sri.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/test_09_sri.py)
- [src/worker/test_10_hallucinated_deps.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/test_10_hallucinated_deps.py)

Source links follow `main`. They describe the inspectable implementation, not a verified digest of the historical deployment.
