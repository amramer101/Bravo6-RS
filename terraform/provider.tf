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
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.50"
    }
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
  }
}

provider "azuread" {
  alias     = "external_tenant"
  tenant_id = var.external_tenant_id
}