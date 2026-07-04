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