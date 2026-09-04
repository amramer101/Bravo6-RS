resource "azurerm_storage_account" "functions_stg" {
  name                          = var.storage_account_name
  resource_group_name           = var.resource_group_name
  location                      = var.location
  account_tier                  = var.storage_account_tier
  account_replication_type      = var.replication_type
  public_network_access_enabled = false
  min_tls_version               = "TLS1_2"

  network_rules {
    default_action             = "Deny"
    virtual_network_subnet_ids = [var.functions_subnet_id]
  }

  tags = {
    source = "terraform"
  }
}
# ------------------------------------------------------------------- containers -------------------------------------------------------------------


resource "azurerm_storage_container" "worker_deploy" {
  name                  = var.worker_deployment_container_name
  storage_account_id    = azurerm_storage_account.functions_stg.id
  container_access_type = "private"
}

resource "azurerm_storage_container" "api_deploy" {
  name                  = var.api_deployment_container_name
  storage_account_id    = azurerm_storage_account.functions_stg.id
  container_access_type = "private"
}

resource "azurerm_storage_container" "report_deploy" {
  name                  = var.report_deployment_container_name
  storage_account_id    = azurerm_storage_account.functions_stg.id
  container_access_type = "private"
}