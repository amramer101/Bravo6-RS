output "worker_principal_id" {
  value       = azurerm_linux_function_app.worker_function.identity[0].principal_id
  description = "The Principal ID of the Worker Function App"
}