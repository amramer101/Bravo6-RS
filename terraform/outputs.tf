output "frontdoor_endpoint_url" {
  description = "The URL of the Front Door Endpoint to access the React app globally"
  value       = module.frontend_stg.frontdoor_endpoint_url
}