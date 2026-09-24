# Infrastructure reference

Terraform describes intended resources; it is not a live inventory. No Azure state query or deployment is performed by this documentation build.

## Module map

| Module directory | Purpose |
| --- | --- |
| `resource_group` | Resource grouping and location |
| `storage_account` | Deployment containers and advisory table |
| `network` | VNet, Function subnet, private-endpoint subnet, network security group |
| `service_bus` | Namespace and queue |
| `cosmos_db` | Account, databases/containers, private endpoint and DNS |
| `observability` | Log Analytics and Application Insights |
| `functions_plan` | Separate plan instance for Worker, API, and Report |
| `function_app` | Worker Function App |
| `api_function` | Gateway Function App |
| `report_function` | Report Function App |
| `frontend_swa` | Static Web App infrastructure scaffolding |

`terraform/iam.tf` defines identity grants. `terraform/budget/` is a separate budget configuration. The root `outputs.tf` exposes a Static Web App hostname; it is not a complete application endpoint catalog.

## Queue settings

The queue definition sets `max_delivery_count = 3` and enables dead-lettering on expiration. Delivery attempts and expiration are different mechanisms. Application behavior also matters: malformed messages are logged and returned from the Worker rather than necessarily raising an error.

## Configuration and state

Real `.tfvars`, saved plans, state, and provider directories are excluded from normal Git additions. Existing remote backend configuration must be reviewed before initialization; `terraform init` is not guaranteed offline. Historical backend identifiers must not be copied into a new deployment unexamined.

Changing a module name, resource address, or file location can have deployment consequences. Documentation maintenance preserves those definitions. See [deployment guidance](deployment.md) for the operational boundary.

## Observability limits

Application Insights and Log Analytics configuration supplies telemetry destinations. The saved research dataset is not a complete distributed trace. Absence of a preserved span cannot establish that a hop failed, and configured telemetry cannot retroactively supply missing execution evidence.


## Implementation and evidence

- [terraform/main.tf](https://github.com/amramer101/Bravo6-RS/blob/main/terraform/main.tf)
- [terraform/iam.tf](https://github.com/amramer101/Bravo6-RS/blob/main/terraform/iam.tf)
- [terraform/backend.tf](https://github.com/amramer101/Bravo6-RS/blob/main/terraform/backend.tf)
- [terraform/outputs.tf](https://github.com/amramer101/Bravo6-RS/blob/main/terraform/outputs.tf)
- [terraform/modules/service_bus/main.tf](https://github.com/amramer101/Bravo6-RS/blob/main/terraform/modules/service_bus/main.tf)

Source links follow `main`. They describe the inspectable implementation, not a verified digest of the historical deployment.
