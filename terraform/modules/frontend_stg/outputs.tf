output "frontdoor_endpoint_url" {
  description = "The URL of the Front Door Endpoint to access the React app globally"
  value       = "https://${azurerm_cdn_frontdoor_endpoint.frontend_fd_endpoint.host_name}"
}