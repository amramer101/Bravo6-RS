# ---------------------------------------------------------
# 1. Frontend URL
# ---------------------------------------------------------
output "frontend_url" {
  description = "The default URL of the Static Web App"
  value       = module.app_services.frontend_url
}

