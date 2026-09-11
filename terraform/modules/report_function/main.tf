
resource "azurerm_function_app_flex_consumption" "report_function" {
  name                = var.function_report_name
  resource_group_name = var.resource_group_name
  location            = var.location
  service_plan_id     = var.service_plan_id

  storage_container_type      = "blobContainer"
  storage_container_endpoint  = "${var.storage_primary_blob_endpoint}${var.report_deployment_container_name}"
  storage_authentication_type = "SystemAssignedIdentity"

  runtime_name    = "python"
  runtime_version = "3.11"

  virtual_network_subnet_id     = var.service_endpoint_subnet_id
  public_network_access_enabled = true
  https_only                    = true

  instance_memory_in_mb  = 512
  maximum_instance_count = 10

  identity {
    type = "SystemAssigned"
  }

  site_config {
    vnet_route_all_enabled = true
  }

  app_settings = {
    "APPLICATIONINSIGHTS_CONNECTION_STRING" = var.app_insights_connection_string

    # Identity-based AzureWebJobsStorage (host-internal storage) -- see the
    # matching block in modules/function_app/main.tf for why this is needed
    # and what it fixes. RBAC granted in terraform/iam.tf.
    "AzureWebJobsStorage__blobServiceUri"  = "https://${var.storage_account_name}.blob.core.windows.net"
    "AzureWebJobsStorage__queueServiceUri" = "https://${var.storage_account_name}.queue.core.windows.net"
    "AzureWebJobsStorage__tableServiceUri" = "https://${var.storage_account_name}.table.core.windows.net"
    "AzureWebJobsStorage__credential"      = "managedidentity"

    # Read-only Cosmos DB target for src/report/function_app.py's
    # /report/status and /report/result routes. No COSMOS_KEY, deliberately:
    # this Function App authenticates via its system-assigned identity
    # (DefaultAzureCredential -> Managed Identity), backed by the
    # read-only report_reader Cosmos SQL role assignment in
    # terraform/iam.tf -- no write action is granted, matching the
    # Report Function's read-only-end-to-end design.
    "COSMOS_URL"       = var.cosmosdb_endpoint
    "COSMOS_DATABASE"  = var.cosmosdb_database_name
    "COSMOS_CONTAINER" = var.cosmosdb_container_name

    # Microsoft Entra External ID (CIAM) values the JWT validator checks
    # every token against -- same tenant/audience as the API Gateway
    # (modules/api_function/main.tf), so a token issued for the frontend
    # SPA is valid against both.
    "ENTRA_ISSUER"   = var.entra_issuer
    "ENTRA_JWKS_URI" = var.entra_jwks_uri
    "ENTRA_AUDIENCE" = var.entra_audience
  }

  tags = {
    source = "terraform"
  }
}