output "app_service_id" {
  value       = azurerm_linux_web_app.frontend_app.id
  description = "The ID of the app service"
}

output "frontend_url" {
  description = "The default URL of the Static Web App"
  value       = azurerm_linux_web_app.frontend_app.app_settings["WEBSITE_URL"]
}
