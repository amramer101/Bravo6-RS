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
