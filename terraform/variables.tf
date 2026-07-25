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

# --------------------------------------------- external tenant id Variables

variable "external_tenant_id" {
  type        = string
  description = "Tenant ID of the Entra External ID (CIAM) tenant"
}

variable "app_display_name" {
  type = string
}

variable "redirect_uris" {
  type = list(string)
}