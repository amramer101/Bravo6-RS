terraform {
  backend "azurerm" {
    resource_group_name  = "terraform-rg"
    storage_account_name = "terraformstateeprofile"
    container_name       = "tfstate"
    # Deliberately a DIFFERENT key from the app stack's ../backend.tf
    # (bravo_terraform.tfstate) -- this is a separate state file in the
    # same pre-existing backend storage account, never touched by
    # `terraform destroy` run from the ../ root. See main.tf's header
    # comment for why this directory exists as its own root at all.
    key = "bravo_budget_terraform.tfstate"
  }
}
