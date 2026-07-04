output "storage_website_url" {
  description = "The primary web endpoint of the storage account"
  value       = azurerm_storage_account.frontend_storage.primary_web_endpoint
}

output "cdn_endpoint_url" {
  description = "The URL of the CDN Endpoint to access the React app globally"
  value       = "https://${azurerm_cdn_endpoint.frontend_cdn_endpoint.name}.azureedge.net"
}