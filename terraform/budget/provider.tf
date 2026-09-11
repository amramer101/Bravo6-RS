terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.21"
    }
  }
}

provider "azurerm" {
  # Auth method deliberately not hardcoded, same reasoning as ../provider.tf:
  # a local developer's own `az login` needs CLI auth; CI would need OIDC.
  # Both are selected by environment variables, not a static setting here.
  features {}
}
