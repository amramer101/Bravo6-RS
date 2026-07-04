output "plan_id" {
  value       = azurerm_service_plan.functions_plan.id
  description = "The ID of the App Service Plan to be used by the Functions"
}