output "static_web_app_id" {
  value       = azurerm_static_web_app.frontend.id
  description = "The ID of the Static Web App"
}

output "frontend_url" {
  description = "The default URL of the Static Web App"
  value       = azurerm_static_web_app.frontend.default_host_name
}
