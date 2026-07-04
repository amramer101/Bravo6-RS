output "worker_principal_id" {
  value = azurerm_function_app_flex_consumption.worker_function.identity[0].principal_id
}

