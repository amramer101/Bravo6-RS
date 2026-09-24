# Cost and operational accounting

The project does not have an evidence-backed monthly cost estimate in the preserved evaluation. The archived scan duration is not a billing record. Consumption-based compute does not make the entire architecture free at idle.

## Cost categories

| Category | What must be measured or selected |
| --- | --- |
| Functions | Execution count, duration, memory, plan settings |
| Service Bus | Tier, namespace provisioning, operations |
| Cosmos DB | Throughput mode, storage, requests, account eligibility |
| Storage | Capacity, operations, transfer, advisory refreshes |
| Networking | Private endpoints, DNS, transfer and regional effects |
| Observability | Ingestion, retention, query/export usage |
| Frontend scaffolding | Chosen hosting plan and whether it is actually used |

Free grants, student credits, and promotional eligibility differ from the underlying resource cost. Do not assert $0–$1 per persistent month or compare savings without a dated region/configuration baseline and billing evidence.

## Available configuration

The repository contains a separate budget configuration and telemetry resources. A budget notification is not proof of a hard spending cap or automatic teardown. The existence of deployment notes does not prove resources were deleted after the September 19 experiment.

## Future cost evaluation

Capture a dated resource inventory, region, SKU choices, billing export, workload window, and any credits separately. Attribute shared costs transparently. A cost experiment is future work; no infrastructure is restarted to populate this page.

Official price references: [Azure Service Bus](https://azure.microsoft.com/en-us/pricing/details/service-bus/), [Azure Private Link](https://azure.microsoft.com/en-us/pricing/details/private-link/). These are reference links, not fixed price quotations.


## Implementation and evidence

- [terraform/budget/main.tf](https://github.com/amramer101/Bravo6-RS/blob/main/terraform/budget/main.tf)
- [terraform/modules/observability/main.tf](https://github.com/amramer101/Bravo6-RS/blob/main/terraform/modules/observability/main.tf)
- [terraform/variables.tf](https://github.com/amramer101/Bravo6-RS/blob/main/terraform/variables.tf)

Source links follow `main`. They describe the inspectable implementation, not a verified digest of the historical deployment.
