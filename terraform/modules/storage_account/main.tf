resource "azurerm_storage_account" "functions_stg" {
  name                     = var.storage_account_name
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = var.storage_account_tier
  account_replication_type = var.replication_type
  # TEMPORARY: reopened for code deployment (see DEPLOYMENT_NOTES.md) --
  # revert to false immediately after api/worker/report package deploys
  # finish.
  public_network_access_enabled = true
  min_tls_version               = "TLS1_2"

  network_rules {
    default_action             = "Deny"
    bypass                     = ["AzureServices"]
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