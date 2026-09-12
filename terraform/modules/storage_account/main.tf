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

# ------------------------------------------------------------------------------
# OSV CVE cache (Table Storage) -- populated on a schedule by the Worker's
# sync_osv_cve_cache Timer Function (src/worker/function_app.py,
# src/worker/osv_cve_sync.py), read per-scan by test_02_frontend_libs.py's
# fetch_cve_dataset_from_table() instead of a live per-scan OSV.dev call.
# Same storage account as the deployment containers above -- no new
# storage account needed, just a different service (Table, not Blob) on
# the existing one. Managed Identity access is a table-scoped "Storage
# Table Data Contributor" role assignment in terraform/iam.tf, NOT
# related to the AzureWebJobsStorage/Blob Storage Secret Repository
# mechanism documented as still-broken in DEPLOYMENT_NOTES.md's Gap 2.
resource "azurerm_storage_table" "cve_cache" {
  name               = var.cve_cache_table_name
  storage_account_id = azurerm_storage_account.functions_stg.id
}