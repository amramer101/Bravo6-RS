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

#----------------------------------------------

variable "resource_group_name" {
  type        = string
  description = "The name of the resource group"
}

# ---------------------------------------------

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
