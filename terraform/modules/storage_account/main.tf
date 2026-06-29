resource "azurerm_storage_account" "functions_app" {
  name                     = var.storage_account_name
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = var.storage_account_tier
  account_replication_type = var.replication_type
}

resource "azurerm_storage_container" "app_container" {
  name                  = var.storage_account_container_name
  storage_account_name  = azurerm_storage_account.functions_app.name
  container_access_type = "private"
}
