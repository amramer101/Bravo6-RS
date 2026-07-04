# For Managed Identity of the Report Function App
output "report_principal_id" {
  value       = azurerm_function_app_flex_consumption.report_function.identity[0].principal_id
  description = "The Principal ID of the Report Function App"
}