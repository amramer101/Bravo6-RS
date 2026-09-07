resource "azurerm_function_app_flex_consumption" "worker_function" {
  name                = var.function_app_name
  resource_group_name = var.resource_group_name
  location            = var.location
  service_plan_id     = var.service_plan_id

  storage_container_type      = "blobContainer"
  storage_container_endpoint  = "${var.storage_primary_blob_endpoint}${var.worker_deployment_container_name}"
  storage_authentication_type = "SystemAssignedIdentity"

  runtime_name    = "python"
  runtime_version = "3.11"

  virtual_network_subnet_id     = var.service_endpoint_subnet_id
  public_network_access_enabled = false
  https_only                    = true

  instance_memory_in_mb  = 2048
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

    # Cosmos DB target for main_scanner.py's persist_scan_result(). Same
    # account / database / container the API Gateway already writes scan-job
    # records to (see modules/api_function/main.tf) -- one "scans" container
    # holds both the queued job and the finished result, keyed by the same
    # scanId, so there is nothing to join across containers later.
    #
    # No COSMOS_KEY here, deliberately: the Worker authenticates with the
    # system-assigned identity declared above (DefaultAzureCredential ->
    # Managed Identity in Azure), backed by its Cosmos SQL data-plane role
    # assignment in terraform/iam.tf. Only the endpoint URL is configuration;
    # there is no secret to set.
    "COSMOS_URL"       = var.cosmosdb_endpoint
    "COSMOS_DATABASE"  = var.cosmosdb_database_name
    "COSMOS_CONTAINER" = var.cosmosdb_container_name
  }

  tags = {
    source = "terraform"
  }
}