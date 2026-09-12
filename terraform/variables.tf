# terraform/variables.tf

variable "location" {
  description = "Azure region"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "project_name" {
  description = "Project name"
  type        = string
}

#---------------------------------------------- RG Variables

variable "resource_group_name" {
  type        = string
  description = "The name of the resource group"
}

# --------------------------------------------- Storage Account Variables 

variable "storage_account_name" {
  type        = string
  description = "The name of the Storage Account"
}

variable "storage_account_tier" {
  type        = string
  description = "The tier of the Storage Account"
}

variable "replication_type" {
  type        = string
  description = "The replication type for the Storage Account"
}

# --------------------------------------------- Service Bus Variables

variable "service_bus_name" {
  description = "The name of the service bus"
  type        = string
}

variable "service_bus_sku" {
  type        = string
  description = "service bus sku"
}

variable "service_bus_queue_name" {
  type        = string
  description = "service bus queue name"
}

# --------------------------------------------- App Functions Variables

variable "function_app_name" {
  type = string
}

variable "function_api_name" {
  type = string
}

variable "function_report_name" {
  type = string
}

variable "api_deployment_container_name" {
  type        = string
  description = "Name of the blob container holding the deployed package"
}

variable "worker_deployment_container_name" {
  type        = string
  description = "Name of the blob container holding the deployed package"
}

variable "report_deployment_container_name" {
  type        = string
  description = "Name of the blob container holding the deployed package"
}

variable "cve_cache_table_name" {
  type        = string
  description = "Name of the Table Storage table holding the OSV CVE cache (Task 2, src/worker/osv_cve_sync.py)"
}

variable "plan_name" {
  type        = string
  description = "The name of the App Service Plan"
}

variable "sku_name" {
  type        = string
  description = "The SKU for the plan (e.g., Y1 for Consumption, S1 for Standard)"
}

variable "os_type" {
  type        = string
  description = "The O/S type for the App Services to be hosted in this plan (Linux or Windows)"
}

# --------------------------------------------- DB Variables

variable "cosmosdb_name" {
  type = string
}

variable "db_name" {
  type = string
}

# --------------------------------------------- Network Variables

variable "vnet_name" {
  type        = string
  description = "The name of the virtual network"
}


# --------------------------------------------- Frontend SWA Variables

variable "static_web_app_name" {
  description = "The name of the static web app"
  type        = string
}

variable "static_web_app_tier" {
  type        = string
  description = "static web app tier"
}

variable "static_web_app_size" {
  type        = string
  description = "static web app size"
}

# --------------------------------------------- Observability Variables

variable "log_analytics_workspace_name" {
  type        = string
  description = "Name of the Log Analytics workspace backing Application Insights"
}

variable "app_insights_name" {
  type        = string
  description = "Name of the Application Insights resource"
}

# --------------------------------------------- API Gateway / Entra Auth Variables
#
# DEFERRED (2026-09-12, see future-work/auth/README.md): entra_issuer /
# entra_jwks_uri / external_tenant_id / app_display_name removed -- the
# API Gateway no longer validates JWTs, and the entra_external_id module
# they configured moved to future-work/auth/terraform/. NOT FIXED HERE:
# src/report/function_app.py still reads ENTRA_ISSUER/ENTRA_JWKS_URI/
# ENTRA_AUDIENCE and will 401 every request now that nothing sets them --
# see terraform/main.tf's report_function module block.
