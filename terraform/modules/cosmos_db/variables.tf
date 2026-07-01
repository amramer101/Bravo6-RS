variable "cosmosdb_name" {
  type        = string
  description = "The name of the Cosmos DB account (must be globally unique)"
}

variable "location" {
  type        = string
  description = "The Azure Region"
}

variable "resource_group_name" {
  type        = string
  description = "The name of the Resource Group"
}