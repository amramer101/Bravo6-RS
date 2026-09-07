variable "function_app_name" {
  type = string
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "service_plan_id" {
  type = string
}

variable "storage_account_name" {
  type = string
}

variable "service_bus_namespace" {
  type        = string
  description = "The namespace of the Service Bus (passed from root)"
}

variable "service_endpoint_subnet_id" {
  type        = string
  description = "The ID of the Subnet"
}

variable "storage_primary_blob_endpoint" {
  type        = string
  description = "Primary blob endpoint of the storage account used for Flex Consumption deployment"
}

variable "worker_deployment_container_name" {
  type        = string
  description = "Name of the blob container holding the deployed package"
}

variable "app_insights_connection_string" {
  type        = string
  sensitive   = true
  description = "Application Insights connection string, set as APPLICATIONINSIGHTS_CONNECTION_STRING"
}

# --- Cosmos DB target for the Worker's scan-result writes ---
# Mirrors the same three variables already on the API Gateway module
# (modules/api_function/variables.tf). The Worker's main_scanner.py has always
# read COSMOS_URL / COSMOS_DATABASE / COSMOS_CONTAINER, but nothing in
# Terraform ever set them, so its Cosmos write path was unreachable in the
# deployed configuration and every scan result fell to a local JSON file on an
# ephemeral Flex Consumption instance.
variable "cosmosdb_endpoint" {
  type        = string
  description = "Cosmos DB account endpoint URL, set as COSMOS_URL"
}

variable "cosmosdb_database_name" {
  type        = string
  description = "Cosmos SQL database name, set as COSMOS_DATABASE"
}

variable "cosmosdb_container_name" {
  type        = string
  description = "Cosmos SQL container name for scan results, set as COSMOS_CONTAINER"
}
