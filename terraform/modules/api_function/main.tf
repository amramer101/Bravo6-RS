resource "azurerm_function_app_flex_consumption" "api_function" {
  name                = var.function_api_name
  resource_group_name = var.resource_group_name
  location            = var.location
  service_plan_id     = var.service_plan_id

  storage_container_type      = "blobContainer"
  storage_container_endpoint  = "${var.storage_primary_blob_endpoint}${var.api_deployment_container_name}"
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
    "ServiceBusConnection__fullyQualifiedNamespace" = "${var.service_bus_namespace}.servicebus.windows.net"
    "APPLICATIONINSIGHTS_CONNECTION_STRING"         = var.app_insights_connection_string

    # Identity-based AzureWebJobsStorage (host-internal storage) -- see the
    # matching block in modules/function_app/main.tf for why this is needed
    # and what it fixes. RBAC granted in terraform/iam.tf.
    "AzureWebJobsStorage__blobServiceUri"  = "https://${var.storage_account_name}.blob.core.windows.net"
    "AzureWebJobsStorage__queueServiceUri" = "https://${var.storage_account_name}.queue.core.windows.net"
    "AzureWebJobsStorage__tableServiceUri" = "https://${var.storage_account_name}.table.core.windows.net"
    "AzureWebJobsStorage__credential"      = "managedidentity"

    # Wired for the API Gateway's own code (src/api/function_app.py),
    # which authenticates to both via the identity block above
    # (DefaultAzureCredential -- Managed Identity in Azure), not a
    # connection string or account key. NOTE: neither the Worker's nor
    # the Report Function's app_settings set any COSMOS_* values today
    # (confirmed by grepping the whole terraform/ tree during this pass)
    # -- that's a pre-existing gap in those two modules, out of scope for
    # this pass, not something introduced here.
    "SERVICE_BUS_QUEUE_NAME" = var.service_bus_queue_name
    "COSMOS_URL"             = var.cosmosdb_endpoint
    "COSMOS_DATABASE"        = var.cosmosdb_database_name
    "COSMOS_CONTAINER"       = var.cosmosdb_container_name

    # Microsoft Entra External ID (CIAM) values the JWT validator checks
    # every token against. Concrete values live in terraform.tfvars,
    # NOT hardcoded here or in Python -- see that file's comments for
    # how they were derived and what still needs confirming against the
    # live tenant before deploy.
    "ENTRA_ISSUER"   = var.entra_issuer
    "ENTRA_JWKS_URI" = var.entra_jwks_uri
    "ENTRA_AUDIENCE" = var.entra_audience
  }

  tags = {
    source = "terraform"
  }
}