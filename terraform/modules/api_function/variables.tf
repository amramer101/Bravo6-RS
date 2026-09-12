variable "function_api_name" {
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

variable "api_deployment_container_name" {
  type        = string
  description = "Name of the blob container holding the deployed package"
}

variable "app_insights_connection_string" {
  type        = string
  sensitive   = true
  description = "Application Insights connection string, set as APPLICATIONINSIGHTS_CONNECTION_STRING"
}

variable "service_bus_queue_name" {
  type        = string
  description = "Name of the Service Bus queue the Gateway enqueues scan jobs onto, set as SERVICE_BUS_QUEUE_NAME"
}

variable "cosmosdb_endpoint" {
  type        = string
  description = "Cosmos DB account endpoint URL, set as COSMOS_URL"
}

variable "cosmosdb_database_name" {
  type        = string
  description = "Cosmos DB database name, set as COSMOS_DATABASE"
}

variable "cosmosdb_container_name" {
  type        = string
  description = "Cosmos DB container the Gateway writes scan-job records to and queries for quota counts, set as COSMOS_CONTAINER"
}

# entra_issuer / entra_jwks_uri / entra_audience variables REMOVED
# (2026-09-12, see future-work/auth/README.md) -- the API Gateway no
# longer validates JWTs at all.