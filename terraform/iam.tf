resource "azurerm_role_assignment" "worker_storage_access" {
  scope                = module.storage_account.stg_id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = module.function_app.worker_principal_id
}