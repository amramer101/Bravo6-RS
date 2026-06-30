# terraform/main.tf

module "resource_group" {
  source   = "./modules/resource_group"
  rg_name  = var.resource_group_name
  location = var.location
}

module "storage_account" {
  source                         = "./modules/storage_account"
  storage_account_name           = var.storage_account_name
  resource_group_name            = module.resource_group.name
  location                       = module.resource_group.location
  storage_account_tier           = var.storage_account_tier
  replication_type               = var.replication_type
  storage_account_container_name = var.storage_account_container_name
}

module "service_bus" {
  source = "./modules/service_bus"
  # variables...
}

module "cosmos_db" {
  source = "./modules/cosmos_db"
  # variables...
}

module "function_app" {
  source = "./modules/function_app"
  # variables...
}

module "keyvault" {
  source = "./modules/keyvault"
  # variables...
}

module "api_function" {
  source = "./modules/api_function"
  # variables...
}

module "report_function" {
  source = "./modules/report_function"
  # variables...
}

module "static_website" {
  source = "./modules/static_website"
  # variables...
}
