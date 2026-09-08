# Software Architecture & Scouts

This page covers the scanning engine itself — the part of BRAVO6 that actually runs — as opposed to
the Azure infrastructure it runs on (see [Architecture Overview](architecture-overview.md)).

## The pipeline

Every scan reduces to the same four stages regardless of which scouts are installed:

1. **Plugin discovery** — the Worker globs `test_*.py` in `src/worker/` at startup
   (`discover_plugins()`), so a future scout joins the pipeline just by matching that filename
   pattern; nothing else needs to change.
2. **Concurrent execution** — every discovered scout runs against the same target via
   `asyncio.gather(..., return_exceptions=True)`. No scout depends on another's output, which is
   what makes per-scout fault isolation possible: an exception inside one scout's coroutine doesn't
   crash the scan, it fills that scout's result slot with an error and the rest complete normally.
3. **Normalize + deduplicate** — every finding, from any scout, is normalized into the same
   twelve-field schema (`title`, `severity`, `confidence`, `cwe`, `owasp`, `location`, `evidence`,
   `poc`, `remediation`, `detection_method`, plus a `raw_data` block carrying at minimum a `tier`).
4. **Score + grade** — findings are scored against one consistent rubric regardless of which scout
   produced them.

## The scan-time cache

Every scan issues exactly one pre-flight `GET` to the target's base URL
(`fetch_main_page_and_analyze()`), caching the response — HTML, parsed soup, and headers — on the
shared `ScannerContext` object passed to every scout. Six of the ten scouts (Secrets Hunter,
Frontend Library Detection, Cookie Security, Security Headers, Information Disclosure's initial
page read, and Subresource Integrity) read from that cache instead of re-fetching. The other four
have I/O the cache can't satisfy: SSL/TLS Health opens its own TLS socket; Email Security is
DNS-only; CORS Misconfiguration needs a synthetic `Origin` header a passive page load could never
produce; Hallucinated Dependency Detection fetches manifest/registry endpoints that aren't the page
itself.

## Finding tiers

Every finding carries a `tier`:

- **`baseline`** — a directly exploitable condition, scored uncapped.
- **`hardening`** — a defense-in-depth absence that only matters if something else is separately
  compromised (e.g. missing OCSP stapling, missing DNS CAA record). Hardening-tier penalties are
  pooled across the whole scan and capped at a combined 10 points, so a site missing five unrelated
  hardening controls isn't scored as if it had five separate baseline vulnerabilities.

## Cross-cutting false-positive mitigation

A few techniques recur across scouts rather than being reinvented per check:

- **Entropy-based filtering** (Secrets Hunter) — separates real secrets from high-entropy-looking
  noise before flagging anything.
- **CVE signature verification against a version string** (Frontend Library Detection) — a bare
  library-name match isn't enough to flag a CVE; the version has to actually be in the affected
  range.
- **Baseline-response comparison** (Information Disclosure) — probes a random, definitely-nonexistent
  path first and compares a candidate path's response against that baseline, to tell a true hit from
  a soft-404 (a server that returns HTTP 200 for everything).
- **Three-way result modeling instead of a boolean** (SSL/TLS Health, Hallucinated Dependency
  Detection) — a failed network probe is classified `inconclusive`, never silently treated as a
  confirmed-negative or confirmed-positive result. This exists because it was a real bug once: a
  failed TLS-tooling subprocess was, on an earlier pass, misread as a confirmed-negative finding.

## The ten scouts

| # | Scout | Focus | Tier | Network behavior |
|---|---|---|---|---|
| 01 | Secrets Hunter | Exposed credentials/keys in served content | mixed | cached page + shared JS fetches |
| 02 | Frontend Library Detection | Known-vulnerable JS libraries (CVE matching against a local dataset, not a live feed) | mixed | cached page + shared JS fetches |
| 03 | Cookie Security | Missing `HttpOnly`/`Secure`/`SameSite` | hardening | zero — cached headers only |
| 04 | SSL/TLS Health | Certificate, protocol, TLS configuration, OCSP stapling | mixed | TLS socket to `:443` + `openssl`/`dig` |
| 05 | Security Headers | Missing CSP, HSTS, Referrer-Policy, etc. | mixed | zero — cached headers only |
| 06 | Information Disclosure | Exposed sensitive paths, soft-404-aware | mixed | ~23 GETs (baseline probe + well-known paths + `robots.txt`) |
| 07 | Email Security | SPF, DKIM, DMARC, MTA-STS, BIMI | baseline | zero HTTP — DNS lookups only |
| 08 | CORS Misconfiguration | Wildcard-plus-credentials, origin reflection | baseline | 1 cross-origin OPTIONS/GET with a synthetic `Origin` header |
| 09 | Subresource Integrity | Missing/unenforced SRI on cross-origin tags | hardening | zero — second pass over the already-cached page |
| 10 | Hallucinated Dependency Detection | Declared package absent from its public registry | baseline | 0–5 GETs (manifest paths) + one registry lookup per package |

**Scout 09 (Subresource Integrity)** is a pure second pass over HTML the orchestrator already
fetched for Scout 02 — no network request of its own. Beyond the baseline missing-integrity check,
it distinguishes a same-registrable-domain cross-origin resource (a sibling subdomain, almost
certainly the same operator — low severity) from a genuine third party (a CDN or analytics host —
medium for a script, low for a stylesheet), and separately flags an `integrity` attribute present
without a valid `crossorigin` attribute — under which browsers silently skip the integrity check
entirely, which is worse than not having `integrity` at all because it looks protected and isn't.

**Scout 10 (Hallucinated Dependency Detection)** is the check most directly tied to the project's
motivating problem: an AI coding assistant emits an import or manifest entry for a package name
that was never published, and an attacker who registers that exact name on the real public registry
gets it pulled into any environment that installs from the manifest verbatim. Because BRAVO6 has no
source access, this is scoped to the one path where it can act with real evidence: a manifest
(`package.json`, `requirements.txt`, related lock files) that's itself exposed on the public web
server. Each declared package name is checked against its registry (npm or PyPI) and classified into
exactly three states — `present`, `confirmed-absent`, or `lookup-inconclusive` — specifically so a
failed registry request is never misread as a confirmed-hallucinated finding.

## Current test coverage

Run any scout's own suite directly — the numbers below are what this repository's tests report
right now, reproduce them yourself rather than trusting this table indefinitely:

```bash
cd src/worker
for f in test_*.py; do python3 "$f" --test; done   # each prints its own "Ran N tests"
python3 main_scanner.py --test                      # orchestration-level suite
cd ../api
python3 test_api_gateway.py                          # API Gateway suite (mocked Azure clients)
```

As of this page's last update: 190 scout-level test methods across the ten scouts, 33 in the
Worker's orchestration suite, and 44 in the API Gateway's suite covering every status-code path
(401/403/429/202/503) — the API Gateway suite runs against mocked Azure clients only; it has not
been exercised against a deployed Function App or real Entra tokens.
