variable "function_report_name" {
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

variable "report_deployment_container_name" {
  type        = string
  description = "Name of the blob container holding the deployed package"
}

variable "app_insights_connection_string" {
  type        = string
  sensitive   = true
  description = "Application Insights connection string, set as APPLICATIONINSIGHTS_CONNECTION_STRING"
}

# --- Cosmos DB target for the Report Function's read-only status/result
# routes (src/report/function_app.py) ---
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
  description = "Cosmos SQL container name holding scan job/result documents, set as COSMOS_CONTAINER"
}

# --- API Gateway / Entra External ID (CIAM) auth values -- same tenant
# and audience the API Gateway validates against, so a token issued for
# the frontend SPA works against both. ---
variable "entra_issuer" {
  type        = string
  description = "Expected JWT 'iss' claim the Report Function validates tokens against, set as ENTRA_ISSUER"
}

variable "entra_jwks_uri" {
  type        = string
  description = "JWKS endpoint URL the Report Function fetches Entra External ID (CIAM) signing keys from, set as ENTRA_JWKS_URI"
}

variable "entra_audience" {
  type        = string
  description = "Expected JWT 'aud' claim (the SPA app registration's client ID), set as ENTRA_AUDIENCE"
}