# terraform/main.tf

module "resource_group" {
  source = "./modules/resource_group"
  # variables...
}

module "storage_account" {
  source = "./modules/storage_account"
  # variables...
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
