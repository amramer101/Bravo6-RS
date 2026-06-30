output "stg_name" {
  value       = azurerm_storage_account.functions_app_stg.name
  description = "The name of the storage account"
}

output "stg_id" {
  value       = azurerm_storage_account.functions_app_stg.id
  description = "The name of the storage account"
}
