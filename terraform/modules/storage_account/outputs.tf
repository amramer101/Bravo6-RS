output "stg_name" {
  value       = azurerm_storage_account.functions_stg.name
  description = "The name of the storage account"
}

output "stg_id" {
  value       = azurerm_storage_account.functions_stg.id
  description = "The name of the storage account"
}

output "primary_blob_endpoint" {
  value = azurerm_storage_account.functions_stg.primary_blob_endpoint
}

# Per-container IDs so iam.tf can grant each Function App's identity access
# scoped to only its own deployment container, instead of the whole storage
# account.
output "worker_deploy_container_id" {
  value       = azurerm_storage_container.worker_deploy.id
  description = "Resource ID of the worker Function App's deployment container"
}

output "api_deploy_container_id" {
  value       = azurerm_storage_container.api_deploy.id
  description = "Resource ID of the API Function App's deployment container"
}

output "report_deploy_container_id" {
  value       = azurerm_storage_container.report_deploy.id
  description = "Resource ID of the Report Function App's deployment container"
}

# OSV CVE cache table (Task 2 -- see osv_cve_sync.py). resource_manager_id
# (not the plain `id`, which is a Table-endpoint-shaped string, not a
# valid ARM scope) is what iam.tf's role assignment scopes to.
output "cve_cache_table_resource_manager_id" {
  value       = azurerm_storage_table.cve_cache.resource_manager_id
  description = "ARM resource ID of the OSV CVE cache table, for RBAC scoping"
}

output "table_endpoint" {
  value       = azurerm_storage_account.functions_stg.primary_table_endpoint
  description = "Primary Table Storage endpoint, for the Worker's Timer Function (CVE_TABLE_ENDPOINT app setting)"
}
