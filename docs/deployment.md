# Deployment Guide

**Status: infrastructure-provisioned via Terraform, but not currently applied to a live Azure
environment.** The state file this project's backend points at is empty. Everything below is
accurate against the current Terraform source and produces a valid, internally-consistent plan —
it has not been independently verified by watching real resources come up in the Azure portal.
Treat this page as "how to deploy it," not "confirmation that it's deployed."

## Prerequisites

- An Azure subscription you control, and the Azure CLI (`az`) authenticated against it.
- [Terraform](https://developer.hashicorp.com/terraform) 1.9.x (the CI/CD workflows pin `1.9.8`).

**No Entra External ID (CIAM) tenant is needed as of 2026-09-12** — both the API Gateway's and
Report Function's JWT auth were deferred out of the active deployment (see Future Work /
`future-work/auth/README.md`). Both are currently fully unauthenticated — see
[Security & Identity](security-identity.md).

## Local, manual deploy

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` and fill in real values for your own subscription: resource group name,
region, and the resource-naming variables. `terraform.tfvars` is gitignored — never commit it
with real values in it.

```bash
terraform init
terraform validate
terraform plan -out=tfplan.binary
terraform apply tfplan.binary
```

The remote state backend (`terraform/backend.tf`) points at an Azure Storage-backed backend
(`resource_group_name = "terraform-rg"`, container `tfstate`, key `bravo_terraform.tfstate`) — that
resource group and storage account need to exist and be reachable with your credentials before
`terraform init` will succeed, or you'll need to change `backend.tf` to point at your own state
storage.

## CI/CD-driven deploy

Two workflows exist for this already:

- **`terraform_ci.yml`** — runs on pushes/PRs touching `terraform/`: `terraform fmt -check`,
  `terraform validate`, and `terraform plan`, uploading the plan as a build artifact.
- **`terraform_cd.yml`** — manually triggered (`workflow_dispatch`) with a commit SHA input;
  downloads that commit's plan artifact from `terraform_ci.yml` and runs
  `terraform apply -auto-approve tfplan.binary` against it.

Both authenticate to Azure via `azure/login@v2` using OIDC federated credentials
(`ARM_USE_OIDC: "true"`), not a stored client secret — the three GitHub Actions secrets they need
are `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and `AZURE_SUBSCRIPTION_ID`, which must be configured as
repository secrets by whoever runs this project's CD, and must correspond to an app registration
with a federated credential trusting this repository's GitHub Actions OIDC issuer. Setting that up
is an Azure Portal / `az ad app federated-credential` step outside this repository's own files, and
is not automated by anything checked in here.

## What Terraform provisions

Independently-scalable components, one Terraform module each, under `terraform/modules/`:
`resource_group`, `network`, `storage_account`, `service_bus`, `cosmos_db`, `functions_plan`,
`function_app` (parameterized per Function App — worker/API/report), `frontend_swa`,
and `observability` (Application Insights + Log Analytics). (`entra_external_id` moved to
`future-work/auth/terraform/` on 2026-09-12 — see Prerequisites above.) See
[Infrastructure as Code](infrastructure.md) for the full resource inventory and
[Architecture Overview](architecture-overview.md) for how they fit together.

## Verifying a deploy

There's no automated post-deploy smoke test in this repository yet. After `terraform apply`
succeeds, the practical check is: hit the Worker's HTTP trigger directly (or run
`python3 src/worker/main_scanner.py --url <target>` against a target you're authorized to scan) and
confirm a result lands in Cosmos DB, then check Application Insights for a matching trace. Building
an actual automated smoke test is a reasonable next step — see
[Contributing & Testing](contributing.md).
