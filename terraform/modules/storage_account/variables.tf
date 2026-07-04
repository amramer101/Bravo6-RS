variable "storage_account_name" {
  description = "The name of the Storage Account"
  type        = string
}

variable "storage_account_tier" {
  description = "The tier of the Storage Account"
  type        = string
}

variable "replication_type" {
  description = "The replication type for the Storage Account"
  type        = string
}


variable "resource_group_name" {
  description = "The name of the Resource Group"
  type        = string
}

variable "location" {
  type        = string
  description = "Azure region"
}

variable "functions_subnet_id" {
  type        = string
  description = "The ID of the Subnet"
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