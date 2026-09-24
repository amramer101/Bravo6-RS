# BRAVO6

**A serverless web-security research prototype with coverage-aware evaluation.**

![Research prototype](docs/assets/badge-research.svg) ![Ten scouts](docs/assets/badge-scouts.svg) ![All rights reserved](docs/assets/badge-rights.svg)

BRAVO6 combines ten scouts behind an asynchronous Azure pipeline. It collects externally observable HTTP, TLS, DNS, library, and dependency signals, then produces structured findings and a heuristic score. Results must be interpreted alongside observation coverage and known measurement limitations.

[Documentation source](docs/index.md) · [Architecture](docs/architecture-overview.md) · [Research results](docs/research.md) · [Repository map](REPOSITORY_MAP.md)

The configured Pages address is https://amramer101.github.io/Bravo6-RS/. Local documentation edits do not update that site until the manual publication workflow runs.

## System at a glance

![Architecture: Gateway to queue to Worker; Worker writes Cosmos and Report reads results.](docs/assets/architecture.svg)

| Component | Active responsibility |
| --- | --- |
| Gateway | URL intake, policy checks, job ID, Service Bus enqueue |
| Worker | Scout execution, normalization, deduplication, score, persistence |
| Cosmos DB | Stored result documents |
| Report | JSON status/result reads |

Service Bus decouples Gateway and Worker. Frontend implementation, caller authentication, quotas, ownership enforcement, and HTML reports are deferred. The active HTTP routes are anonymous; this is not an authenticated production multitenant service.

## What the saved experiment shows

| Submitted targets | Saved results | Representative pages | Module-complete representative results |
| ---: | ---: | ---: | ---: |
| 864 | 848 | 508 | 497 |

The September 19, 2026 cloud batch is preserved. Offline analysis separates these cohorts and reports sensitivity to unsupported findings. The representative mean is 16.93 originally, 24.78 after conservative TLS/Axios exclusions, and 24.84 when two disputed parser findings are additionally excluded. These are derived analyses, not new scans or proof that the original scanner was repaired.

[Coverage](docs/coverage.md) · [Scores](docs/scoring.md) · [Agreement and validation](docs/validation.md) · [Known limitations](docs/limitations.md)

## Explore the implementation

- [Source components](src/README.md): API, Worker, Report, advisory tooling.
- [API reference](docs/api-reference.md): routes and synthetic examples.
- [Scout reference](docs/software-architecture.md): prerequisites and interpretation limits.
- [Infrastructure](terraform/README.md): source configuration and manual cloud workflows.
- [Deferred work](future-work/README.md): features outside the active pipeline.

## Preview the documentation

For the owner or an authorized maintainer:

```bash
python3 -m venv .venv-docs
.venv-docs/bin/python -m pip install -r requirements-docs.txt
.venv-docs/bin/mkdocs build --strict
.venv-docs/bin/mkdocs serve --dev-addr 127.0.0.1:8000
```

This builds documentation only. It does not run scanners, deploy Azure resources, or publish Pages. Existing scanner CI has soft-failing steps; no passing-test claim is made by these badges.

## Research and ethical boundaries

Read-oriented probing still generates traffic and requires an appropriate authorization boundary. The author reports that the historical study had no site-owner permissions, institutional ethical approval, disclosure notifications, or manual review. Automated findings are not confirmed exploitable vulnerabilities. Historical live-verification settings remain unestablished. [Full disclosure and data handling](docs/ethics.md).

Raw experiment archives and local paper/reanalysis packages are retained outside normal Git additions. The public repository alone is not claimed to reproduce every research output. A separate data-release review remains necessary.

## Rights and citation

Copyright © 2026 Amr Medhat Amer. **All Rights Reserved.** Public visibility is not an open-source license. See [LICENSE](LICENSE) and [citation guidance](docs/rights.md). Third-party materials retain their own rights.
