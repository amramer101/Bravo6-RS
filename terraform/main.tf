# terraform/main.tf

resource "random_string" "random_suffix" {
  length  = 6
  special = false
  upper   = false
}
resource "random_integer" "ri" {
  min = 10000
  max = 99999
}

# ---------------------------------------------- Modules ----------------------------------------------

module "resource_group" {
  source   = "./modules/resource_group"
  rg_name  = var.resource_group_name
  location = var.location
}

module "storage_account" {
  source                           = "./modules/storage_account"
  storage_account_name             = "${var.storage_account_name}${random_string.random_suffix.result}"
  resource_group_name              = module.resource_group.name
  location                         = module.resource_group.location
  storage_account_tier             = var.storage_account_tier
  replication_type                 = var.replication_type
  functions_subnet_id              = module.network.functions_subnet_id
  worker_deployment_container_name = var.worker_deployment_container_name
  api_deployment_container_name    = var.api_deployment_container_name
  report_deployment_container_name = var.report_deployment_container_name

}

module "service_bus" {
  source                 = "./modules/service_bus"
  service_bus_name       = var.service_bus_name
  service_bus_sku        = var.service_bus_sku
  resource_group_name    = module.resource_group.name
  location               = module.resource_group.location
  service_bus_queue_name = var.service_bus_queue_name
}

module "cosmos_db" {
  source                     = "./modules/cosmos_db"
  resource_group_name        = module.resource_group.name
  location                   = module.resource_group.location
  cosmosdb_name              = "bravo6-cosmosdb-${random_integer.ri.result}"
  db_name                    = var.db_name
  service_endpoint_subnet_id = module.network.functions_subnet_id
}

module "observability" {
  source                       = "./modules/observability"
  resource_group_name          = module.resource_group.name
  location                     = module.resource_group.location
  log_analytics_workspace_name = var.log_analytics_workspace_name
  app_insights_name            = var.app_insights_name
}

module "functions_plan" {
  source              = "./modules/functions_plan"
  plan_name           = var.plan_name
  sku_name            = var.sku_name
  os_type             = var.os_type
  resource_group_name = module.resource_group.name
  location            = module.resource_group.location
}

module "function_app" {
  source                           = "./modules/function_app"
  function_app_name                = "${var.function_app_name}-${random_string.random_suffix.result}"
  resource_group_name              = module.resource_group.name
  location                         = module.resource_group.location
  service_plan_id                  = module.functions_plan.plan_id
  storage_account_name             = module.storage_account.stg_name
  service_bus_namespace            = module.service_bus.service_bus_namespace
  service_endpoint_subnet_id       = module.network.functions_subnet_id
  storage_primary_blob_endpoint    = module.storage_account.primary_blob_endpoint
  worker_deployment_container_name = var.worker_deployment_container_name
  app_insights_connection_string   = module.observability.connection_string
}

module "api_function" {
  source                         = "./modules/api_function"
  function_api_name              = "${var.function_api_name}-${random_string.random_suffix.result}"
  resource_group_name            = module.resource_group.name
  location                       = module.resource_group.location
  service_plan_id                = module.functions_plan.plan_id
  storage_account_name           = module.storage_account.stg_name
  service_endpoint_subnet_id     = module.network.functions_subnet_id
  service_bus_namespace          = module.service_bus.service_bus_namespace
  storage_primary_blob_endpoint  = module.storage_account.primary_blob_endpoint
  api_deployment_container_name  = var.api_deployment_container_name
  app_insights_connection_string = module.observability.connection_string

  service_bus_queue_name = var.service_bus_queue_name

  # Reuses the "scans" container already provisioned in
  # modules/cosmos_db/main.tf (partition key /scanId) for scan-job
  # records -- see src/api/scan_job.py for why no new container was
  # added.
  cosmosdb_endpoint       = module.cosmos_db.cosmosdb_endpoint
  cosmosdb_database_name  = var.db_name
  cosmosdb_container_name = "scans"

  entra_issuer   = var.entra_issuer
  entra_jwks_uri = var.entra_jwks_uri
  entra_audience = module.entra_external_id.client_id
}

module "report_function" {
  source                           = "./modules/report_function"
  function_report_name             = "${var.function_report_name}-${random_string.random_suffix.result}"
  resource_group_name              = module.resource_group.name
  location                         = module.resource_group.location
  service_plan_id                  = module.functions_plan.plan_id
  storage_account_name             = module.storage_account.stg_name
  service_endpoint_subnet_id       = module.network.functions_subnet_id
  service_bus_namespace            = module.service_bus.service_bus_namespace
  storage_primary_blob_endpoint    = module.storage_account.primary_blob_endpoint
  report_deployment_container_name = var.report_deployment_container_name
  app_insights_connection_string   = module.observability.connection_string
}

module "network" {
  source              = "./modules/network"
  vnet_name           = var.vnet_name
  location            = module.resource_group.location
  resource_group_name = module.resource_group.name
}


module "frontend_swa" {
  source              = "./modules/frontend_swa"
  static_web_app_name = var.static_web_app_name
  resource_group_name = module.resource_group.name
  location            = module.resource_group.location
  static_web_app_size = var.static_web_app_size
  static_web_app_tier = var.static_web_app_tier
}

module "entra_external_id" {
  source = "./modules/entra_external_id"
  providers = {
    azuread = azuread.external_tenant
  }
  app_display_name = var.app_display_name
  redirect_uris = [
    "https://${module.frontend_swa.static_web_app_default_hostname}",
    "http://localhost:3000"
  ]
}