# Infrastructure source

The root Terraform configuration references modules under `modules/`. `budget/` is a separate configuration. Review `main.tf`, `variables.tf`, and `outputs.tf` to understand the actual wiring. Module existence is not evidence that a resource was deployed or used in an experiment.

- `backend.tf`: remote state configuration; initialization may contact Azure.
- `terraform.tfvars.example`: tracked example inputs.
- Real `.tfvars`, state, plans, and provider working directories remain local and ignored.
- `.github/workflows/terraform_ci.yml`: manually dispatched historical cloud planning.
- `.github/workflows/terraform_cd.yml`: manually dispatched application of a saved plan; has real cloud side effects.

Repository cleanup does not run Terraform, change resource definitions, or assert current infrastructure status. Historical deployment notes describe their recorded dates, not today's environment.

[Repository map](../REPOSITORY_MAP.md)
