resource "azurerm_storage_account" "functions_app" {
  name                     = var.storage_account_name
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = var.storage_account_tier
  account_replication_type = var.replication_type
  
  tags = {
    source = "terraform"
  }
}

resource "azurerm_storage_container" "app_container" {
  name                  = var.storage_account_container_name
  storage_account_name  = var.storage_account_name
  container_access_type = "private"
}
