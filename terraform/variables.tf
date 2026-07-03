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

variable "storage_account_container_name" {
  type        = string
  description = "The name of the Storage Account Container"
}

variable "storage_account_tier" {
  type        = string
  description = "The tier of the Storage Account"
}

variable "replication_type" {
  type        = string
  description = "The replication type for the Storage Account"
}

# --------------------------------------------- Key Vault Variables

variable "key_vault_name" {
  description = "The name of the Key Vault"
  type        = string
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

variable "plan_name" {
  type        = string
  description = "The name of the App Service Plan"
}

variable "sku_name" {
  type        = string
  description = "The SKU for the plan (e.g., Y1 for Consumption, S1 for Standard)"
  default     = "Y1" # Serverless (Consumption)
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


# --------------------------------------------- DB Variables

variable "cosmosdb_name" {
  type = string
}

variable "db_name" {
  type = string
}


# --------------------------------------------- Static Web App  Variables

variable "static_web_app_name" {
  description = "The name of the static web app"
  type        = string
}


variable "static_web_app_sku" {
  type        = string
  description = "static web app sku"
}


# --------------------------------------------- Network Variables

variable "vnet_name" {
  type        = string
  description = "The name of the virtual network"
}