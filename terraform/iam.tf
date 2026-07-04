locals {
  function_identities = {
    "worker" = module.function_app.worker_principal_id
    "api"    = module.api_function.api_principal_id
    "report" = module.report_function.report_principal_id
  }
}

# ---------------------------------------------- 
# Function App Role Assignments For Storage Account 
# ----------------------------------------------
resource "azurerm_role_assignment" "functions_storage_access" {
  for_each = local.function_identities

  scope                = module.storage_account.stg_id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = each.value
}

# ---------------------------------------------- 
# Function App Role Assignments For Database (Data Plane)
# ----------------------------------------------
resource "azurerm_cosmosdb_sql_role_assignment" "functions_db_access" {
  for_each = local.function_identities

  resource_group_name = module.resource_group.name
  account_name        = module.cosmos_db.cosmosdb_name

  # Built-in Data Contributor 
  role_definition_id = "${module.cosmos_db.cosmosdb_id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"

  principal_id = each.value
  scope        = module.cosmos_db.cosmosdb_id
}

# ----------------------------------------------
# API Function Role Assignments For Service Bus
# ----------------------------------------------
resource "azurerm_role_assignment" "api_sb_sender" {
  scope                = module.service_bus.service_bus_id
  role_definition_name = "Azure Service Bus Data Sender"
  principal_id         = module.api_function.api_principal_id
}


# ----------------------------------------------
# Worker (Receiver)
# ----------------------------------------------
resource "azurerm_role_assignment" "worker_sb_receiver" {
  scope                = module.service_bus.service_bus_id
  role_definition_name = "Azure Service Bus Data Receiver"
  principal_id         = module.function_app.worker_principal_id
}
