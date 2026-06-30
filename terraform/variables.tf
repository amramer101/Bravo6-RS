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

#---------------------------------------------- Secret Variables

variable "subscription_id" {
  type        = string
  description = "The Azure Subscription ID"
}

variable "client_id" {
  type        = string
  description = "The Azure Service Principal Client ID"
}

variable "client_secret" {
  type        = string
  description = "The Azure Service Principal Client Secret"
  sensitive   = true
}

variable "tenant_id" {
  type        = string
  description = "The Azure Tenant ID"
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