output "connection_string" {
  value       = azurerm_application_insights.appi.connection_string
  sensitive   = true
  description = "Application Insights connection string -- wired into each Function App's APPLICATIONINSIGHTS_CONNECTION_STRING app setting"
}

output "instrumentation_key" {
  value     = azurerm_application_insights.appi.instrumentation_key
  sensitive = true
}

output "app_insights_id" {
  value = azurerm_application_insights.appi.id
}

output "workspace_id" {
  value = azurerm_log_analytics_workspace.law.id
}
