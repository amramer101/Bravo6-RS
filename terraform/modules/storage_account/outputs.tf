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

output "worker_container_name" {
  value = azurerm_storage_container.worker_deploy.name
}

output "api_container_name" {
  value = azurerm_storage_container.api_deploy.name
}

output "report_container_name" {
  value = azurerm_storage_container.report_deploy.name
}