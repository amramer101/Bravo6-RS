terraform {
  backend "azurerm" {
    resource_group_name  = "terraform-rg"
    storage_account_name = "terraformstateeprofile"
    container_name       = "tfstate"
    key                  = "bravo_terraform.tfstate"
  }
}