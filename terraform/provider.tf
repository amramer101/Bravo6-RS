terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.21"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0.0"
    }
    # azuread REMOVED (2026-09-12, see future-work/auth/README.md) -- it
    # only backed the entra_external_id module, which moved to
    # future-work/auth/terraform/ along with the API Gateway's JWT
    # validation it supported.
  }

}

provider "azurerm" {
  # Auth method is deliberately NOT hardcoded here (no use_oidc/use_cli):
  # a local developer's own `az login` is a User account and needs CLI
  # auth (the provider's default fallback when no other auth env vars are
  # set); CI (terraform_ci.yml / terraform_cd.yml) authenticates as a
  # Service Principal via OIDC and needs the opposite. Both are selected
  # by environment variables (ARM_USE_OIDC + ARM_CLIENT_ID/ARM_TENANT_ID/
  # ARM_SUBSCRIPTION_ID, set only in the CI workflows) rather than by a
  # static setting here, so neither path breaks the other. See the CI
  # workflow files for why this is needed: azurerm explicitly refuses
  # CLI-based auth for a Service Principal session ("Authenticating using
  # the Azure CLI is only supported as a User, not a Service Principal"),
  # which is why every CI run's plan/apply failed before this fix.
  features {
    # Application Insights auto-creates an "Application Insights Smart
    # Detection" action group as a side effect the instant the AI resource
    # is created -- Azure does this itself, it's never in Terraform's
    # state, and Terraform never asked for it. The default
    # (prevent_deletion_if_contains_resources = true) live-checks the
    # resource group for ANY resource still inside it before deleting it
    # directly, specifically to stop an accidental destroy of something
    # unrelated -- but that default also means `terraform destroy` fails
    # on the final resource-group deletion step every single time,
    # because this auto-created action group is always still there. Given
    # this project is deliberately destroy/redeploy cycled to control
    # cost, that would mean a manual `az group delete` workaround on every
    # cycle -- so this is turned off here, deliberately, not an
    # accidental safety bypass.
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}
