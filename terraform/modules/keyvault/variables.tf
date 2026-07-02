variable "key_vault_name" {
  description = "The name of the Key Vault"
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

variable "service_endpoint_subnet_id" {
  type        = string
  description = "The ID of the Subnet"
}
