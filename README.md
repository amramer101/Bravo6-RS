# Bravo6

**A passive security scanning platform for the AI-coding era.**

AI-assisted development has collapsed the time it takes to ship an application from weeks to hours — but the security layer hasn't kept pace. Secrets get hardcoded into auto-generated code, dependencies get pulled from stale training data, and API responses go out with missing headers and misconfigured CORS policies that look fine until someone exploits them. This gap is what Bravo6 was built to close.

Bravo6 performs stealth reconnaissance against live targets: 7 concurrent, passive security checks that behave exactly like a browser — no payloads, no brute-forcing, no intrusion attempts, no alarms triggered. It reads what's already publicly exposed and reports what an attacker would see, before they see it.

This is not a weekend script. It's a production-grade, cloud-native system, architected end-to-end with the same rigor expected of a real platform in production: serverless and event-driven for cost efficiency, fully async for throughput, and secured with a zero-trust network model on Azure.

---

## Capabilities

- **7 passive security checks, executed concurrently** — secrets exposure, vulnerable frontend libraries, cookie security, SSL/TLS posture, security headers, information disclosure, and email security (SPF/DMARC/DKIM). See [`src/worker/README.md`](src/worker/README.md) for what each check covers and how to run a scan.
- **Read-only reconnaissance** — no exploitation, no destructive traffic, safe to run against production and inside CI/CD pipelines
- **Serverless, event-driven architecture** — scales to zero at idle, scales out automatically under load
- **Reproducible evaluation harness** (`src/worker/evaluation/`) — samples a citable Tranco snapshot with a fixed random seed and batch-runs the scanner across it for the project's evaluation dataset

Additional checks (subdomain takeover, robots.txt analysis, CORS, HTTP methods, CMS fingerprinting, and others) are prototyped but not yet wired into the live scanner — see `future-work/`.

## Project Structure

```
src/
  worker/       # the scanner itself: main_scanner.py + 7 scout plugins (test_0N_*.py) + evaluation/
  api/          # API function app (not yet implemented)
  report/       # report generation function app
  cve-pipeline/ # offline OSV.dev -> cve_database_v2.csv ETL, run separately from the live scanner
terraform/      # infrastructure as code (Azure)
docs/           # architecture, infra, security, and cost documentation (served via mkdocs)
future-work/    # prototyped-but-unwired scout checks for later phases
```

## Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python · `aiohttp` (fully async) |
| **Frontend** | React |
| **Compute** | Azure Functions (Flex Consumption) |
| **Messaging** | Azure Service Bus (Premium, VNet-isolated) |
| **Database** | Azure Cosmos DB |
| **Infrastructure as Code** | Terraform |
| **Auth** | JWT |

## Documentation

Architecture decisions, infrastructure-as-code, data flow, security model, and cost analysis are documented in full here:

📖 **[Bravo6 Documentation](https://bravo6.amrmedhatamer100.workers.dev/)**

## Status

Actively in development, built as part of a final-year graduation project.

## License

**Proprietary — All Rights Reserved.**
This is a private repository. No part of this codebase may be copied, modified, or distributed without explicit written permission from the author.

---

**Amr Medhat**
Cloud Platform Engineer — DevSecOps
AWS Certified Solutions Architect (SAA-C03) · Microsoft Certified: Azure Administrator (AZ-104)