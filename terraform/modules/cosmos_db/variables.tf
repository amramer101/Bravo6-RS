variable "cosmosdb_name" {
  type        = string
  description = "The name of the Cosmos DB account (must be globally unique)"
}

variable "db_name" {
  type        = string
  description = "The name of the DB name"
}

variable "location" {
  type        = string
  description = "The Azure Region"
}

variable "resource_group_name" {
  type        = string
  description = "The name of the Resource Group"
}

variable "service_endpoint_subnet_id" {
  type        = string
  description = "The ID of the Subnet"
}
