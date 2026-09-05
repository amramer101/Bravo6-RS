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

variable "entra_issuer" {
  type        = string
  description = "Expected JWT 'iss' claim for the Entra External ID (CIAM) tenant, set as ENTRA_ISSUER"
}

variable "entra_jwks_uri" {
  type        = string
  description = "JWKS endpoint URL for the Entra External ID (CIAM) tenant, set as ENTRA_JWKS_URI"
}

variable "entra_audience" {
  type        = string
  description = "Expected JWT 'aud' claim (the SPA app registration's client ID), set as ENTRA_AUDIENCE"
}