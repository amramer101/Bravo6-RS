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
  cve_cache_table_name             = var.cve_cache_table_name

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
  private_endpoint_subnet_id = module.network.private_endpoints_subnet_id
  vnet_id                    = module.network.vnet_id
}

module "observability" {
  source                       = "./modules/observability"
  resource_group_name          = module.resource_group.name
  location                     = module.resource_group.location
  log_analytics_workspace_name = var.log_analytics_workspace_name
  app_insights_name            = var.app_insights_name
}

module "functions_plan" {
  # Flex Consumption (FC1) allows exactly one Function App per service plan,
  # so each of the three Function Apps below needs its own plan instance
  # instead of sharing one.
  for_each            = toset(["worker", "api", "report"])
  source              = "./modules/functions_plan"
  plan_name           = "${var.plan_name}-${each.key}"
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
  service_plan_id                  = module.functions_plan["worker"].plan_id
  storage_account_name             = module.storage_account.stg_name
  service_bus_namespace            = module.service_bus.service_bus_namespace
  service_endpoint_subnet_id       = module.network.functions_subnet_id
  storage_primary_blob_endpoint    = module.storage_account.primary_blob_endpoint
  worker_deployment_container_name = var.worker_deployment_container_name
  app_insights_connection_string   = module.observability.connection_string

  # Same Cosmos account / database / container the API Gateway writes scan-job
  # records to, above: the Worker writes the finished scan RESULT for the same
  # scanId into that same "scans" container (partition key /scanId). See
  # src/worker/main_scanner.py's persist_scan_result().
  cosmosdb_endpoint       = module.cosmos_db.cosmosdb_endpoint
  cosmosdb_database_name  = var.db_name
  cosmosdb_container_name = "scans"

  # Task 2: the OSV CVE cache osv_cve_sync.py's Timer Function (this same
  # Function App, see src/worker/function_app.py's sync_osv_cve_cache)
  # writes to, and test_02_frontend_libs.py's fetch_cve_dataset_from_table()
  # reads from -- both in this same deployment package.
  cve_table_endpoint = module.storage_account.table_endpoint
  cve_table_name     = var.cve_cache_table_name
}

module "api_function" {
  source                         = "./modules/api_function"
  function_api_name              = "${var.function_api_name}-${random_string.random_suffix.result}"
  resource_group_name            = module.resource_group.name
  location                       = module.resource_group.location
  service_plan_id                = module.functions_plan["api"].plan_id
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
  #
  # DEFERRED-AUTH NOTE (2026-09-12, see future-work/auth/README.md):
  # entra_issuer/entra_jwks_uri/entra_audience wiring removed -- the API
  # Gateway no longer validates JWTs at all (src/api/function_app.py no
  # longer even imports auth.py, which moved to future-work/auth/). This
  # container is still passed through for parity with the Worker/Report
  # modules, but note the Gateway's active code no longer writes to it
  # either (see function_app.py's module docstring) -- it's currently
  # unused by the deployed API Gateway.
  cosmosdb_endpoint       = module.cosmos_db.cosmosdb_endpoint
  cosmosdb_database_name  = var.db_name
  cosmosdb_container_name = "scans"
}

module "report_function" {
  source                           = "./modules/report_function"
  function_report_name             = "${var.function_report_name}-${random_string.random_suffix.result}"
  resource_group_name              = module.resource_group.name
  location                         = module.resource_group.location
  service_plan_id                  = module.functions_plan["report"].plan_id
  storage_account_name             = module.storage_account.stg_name
  service_endpoint_subnet_id       = module.network.functions_subnet_id
  service_bus_namespace            = module.service_bus.service_bus_namespace
  storage_primary_blob_endpoint    = module.storage_account.primary_blob_endpoint
  report_deployment_container_name = var.report_deployment_container_name
  app_insights_connection_string   = module.observability.connection_string

  # Same Cosmos account / database / container the API Gateway and Worker
  # already read/write -- Report only ever reads from it (report_reader
  # role in terraform/iam.tf), never writes.
  cosmosdb_endpoint       = module.cosmos_db.cosmosdb_endpoint
  cosmosdb_database_name  = var.db_name
  cosmosdb_container_name = "scans"

  # DEFERRED-AUTH NOTE (2026-09-12, see future-work/auth/README.md):
  # entra_issuer/entra_jwks_uri/entra_audience wiring removed along with
  # the entra_external_id module below (this task's scope was the API
  # Gateway, but that module's removal takes this reference down with
  # it -- there's no Entra app registration left to point at). NOT FIXED
  # HERE: src/report/function_app.py's own JWT validation code is
  # untouched and still runs -- with ENTRA_ISSUER/ENTRA_JWKS_URI/
  # ENTRA_AUDIENCE now unset, every /report/status and /report/result
  # request will 401. Report Function's own auth needs its own explicit
  # decision (drop it to match the Gateway, or restore Entra) -- flagged,
  # not silently left broken.
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

# DEFERRED-AUTH (2026-09-12, see future-work/auth/README.md): the
# entra_external_id module moved to future-work/auth/terraform/ -- the
# API Gateway no longer validates JWTs, so there's no app registration
# to maintain. The frontend (untouched, out of this task's scope) is not
# affected by this removal since it has no implementation yet.