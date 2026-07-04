output "static_web_app_id" {
  value       = azurerm_linux_web_app.frontend_app.id
  description = "The ID of the Static Web App"
}

output "frontend_url" {
  description = "The default URL of the Static Web App"
  value       = azurerm_linux_web_app.frontend_app.default_site_hostname
}
