# terraform/outputs.tf

output "function_app_name" {
  value = module.function_app.name
}

output "cosmos_db_endpoint" {
  value = module.cosmos_db.endpoint
}

output "service_bus_namespace" {
  value = module.service_bus.namespace_name
}

output "static_website_url" {
  value = module.static_website.website_url
}
