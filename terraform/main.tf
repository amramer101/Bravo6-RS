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
  source                         = "./modules/storage_account"
  storage_account_name           = "${var.storage_account_name}${random_string.random_suffix.result}"
  resource_group_name            = module.resource_group.name
  location                       = module.resource_group.location
  storage_account_tier           = var.storage_account_tier
  replication_type               = var.replication_type
  storage_account_container_name = var.storage_account_container_name
  functions_subnet_id            = module.network.functions_subnet_id
}

module "service_bus" {
  source                     = "./modules/service_bus"
  service_bus_name           = var.service_bus_name
  service_bus_sku            = var.service_bus_sku
  resource_group_name        = module.resource_group.name
  location                   = module.resource_group.location
  service_bus_queue_name     = var.service_bus_queue_name
  service_endpoint_subnet_id = module.network.functions_subnet_id
}

module "cosmos_db" {
  source                     = "./modules/cosmos_db"
  resource_group_name        = module.resource_group.name
  location                   = module.resource_group.location
  cosmosdb_name              = "bravo6-cosmosdb-${random_integer.ri.result}"
  db_name                    = var.db_name
  service_endpoint_subnet_id = module.network.functions_subnet_id
}

module "app_service_plan" {
  source              = "./modules/app_service_plan"
  plan_name           = var.plan_name
  sku_name            = var.sku_name
  os_type             = var.os_type
  resource_group_name = module.resource_group.name
  location            = module.resource_group.location
}

module "function_app" {
  source                     = "./modules/function_app"
  function_app_name          = "${var.function_app_name}-${random_string.random_suffix.result}"
  resource_group_name        = module.resource_group.name
  location                   = module.resource_group.location
  service_plan_id            = module.app_service_plan.plan_id
  storage_account_name       = module.storage_account.stg_name
  service_bus_namespace      = module.service_bus.service_bus_namespace
  service_endpoint_subnet_id = module.network.functions_subnet_id
}

module "keyvault" {
  source                     = "./modules/keyvault"
  key_vault_name             = "${var.key_vault_name}-${random_string.random_suffix.result}"
  resource_group_name        = module.resource_group.name
  location                   = module.resource_group.location
  service_endpoint_subnet_id = module.network.functions_subnet_id
}

module "api_function" {
  source                     = "./modules/api_function"
  function_api_name          = "${var.function_api_name}-${random_string.random_suffix.result}"
  resource_group_name        = module.resource_group.name
  location                   = module.resource_group.location
  service_plan_id            = module.app_service_plan.plan_id
  storage_account_name       = module.storage_account.stg_name
  service_endpoint_subnet_id = module.network.functions_subnet_id
  service_bus_namespace      = module.service_bus.service_bus_namespace
}

module "report_function" {
  source                     = "./modules/report_function"
  function_report_name       = "${var.function_report_name}-${random_string.random_suffix.result}"
  resource_group_name        = module.resource_group.name
  location                   = module.resource_group.location
  service_plan_id            = module.app_service_plan.plan_id
  storage_account_name       = module.storage_account.stg_name
  service_endpoint_subnet_id = module.network.functions_subnet_id
  service_bus_namespace      = module.service_bus.service_bus_namespace
}

module "static_website" {
  source              = "./modules/static_website"
  static_web_app_name = var.static_web_app_name
  static_web_app_sku  = var.static_web_app_sku
  resource_group_name = module.resource_group.name
  location            = module.resource_group.location
}

module "network" {
  source              = "./modules/network"
  vnet_name           = var.vnet_name
  location            = module.resource_group.location
  resource_group_name = module.resource_group.name
}


