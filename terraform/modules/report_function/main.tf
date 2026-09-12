
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

    # DELIBERATELY no AzureWebJobsStorage__* app settings -- see the
    # matching comment in modules/function_app/main.tf for the sourced
    # reason (Flex Consumption derives AzureWebJobsStorage automatically
    # from storage_container_endpoint/storage_authentication_type above;
    # manually setting it too was the confirmed root cause of the
    # crash-restart-loop documented in DEPLOYMENT_NOTES.md's Gap 2).

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

    # ENTRA_ISSUER / ENTRA_JWKS_URI / ENTRA_AUDIENCE REMOVED (2026-09-12,
    # see future-work/auth/README.md and terraform/main.tf's
    # report_function module block) -- Report Function's own JWT
    # validation and ownership check were removed too, in a follow-up
    # cleanup pass the same day (future-work/auth/report_auth.py,
    # future-work/auth/report_function_auth_gate.py), not left reading
    # these now-nonexistent env vars. Both routes are unauthenticated.
  }

  tags = {
    source = "terraform"
  }
}