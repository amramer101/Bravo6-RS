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

  virtual_network_subnet_id = var.service_endpoint_subnet_id
  # TEMPORARY: reopened for code deployment (see DEPLOYMENT_NOTES.md) --
  # revert to false immediately after the worker package deploy finishes.
  public_network_access_enabled = true
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

    # DELIBERATELY no AzureWebJobsStorage__* app settings here. An earlier
    # pass added them, reasoning from Azure Functions' GENERIC
    # identity-based-connections docs (manage-connections.md) -- which
    # describe classic Consumption/Premium, where AzureWebJobsStorage is a
    # separate concept from deployment storage. That reasoning doesn't
    # transfer to Flex Consumption: per
    # https://learn.microsoft.com/en-us/azure/azure-functions/flex-consumption-plan
    # (Deployment section, live-checked 2026-09-11): "You no longer need
    # app settings to influence deployment behavior... By default, the
    # same storage account used to store internal host metadata
    # (AzureWebJobsStorage) also serves as the deployment container." On
    # Flex Consumption, storage_container_endpoint +
    # storage_authentication_type above (functionAppConfig.deployment.storage
    # under the hood) IS the host's internal storage config too -- there is
    # no separate thing to configure. Manually adding AzureWebJobsStorage__*
    # on top didn't add coverage; it competed with the platform's own
    # automatic derivation. Confirmed root cause of the crash-restart-loop /
    # AuthenticationFailed MAC-signature-mismatch failures documented in
    # DEPLOYMENT_NOTES.md's Gap 2 -- removing these settings is the fix, not
    # a variant of them. RBAC for this (Storage Blob Data Contributor,
    # scoped to this app's own deployment container) is already covered by
    # functions_storage_access in terraform/iam.tf -- see that file for why
    # no additional account-scoped roles are needed either.

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

    # Task 2: OSV CVE cache (Table Storage). Read by
    # sync_osv_cve_cache (Timer Function, writes) and
    # fetch_cve_dataset_from_table() (per-scan, reads) -- both
    # authenticate via the SystemAssigned identity above
    # (DefaultAzureCredential), backed by the table-scoped "Storage
    # Table Data Contributor" role assignment in terraform/iam.tf. No
    # account key here, same zero-secrets pattern as COSMOS_URL above.
    "CVE_TABLE_ENDPOINT" = var.cve_table_endpoint
    "CVE_TABLE_NAME"     = var.cve_table_name
  }

  tags = {
    source = "terraform"
  }
}