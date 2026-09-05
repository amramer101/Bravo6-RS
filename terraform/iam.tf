locals {
  # Report's identity is deliberately excluded here -- its application code
  # only ever reads Cosmos DB, so it gets the read-only role below instead
  # of Data Contributor. API is also excluded -- see the custom
  # gateway_scan_writer role below: it only ever needs to read (quota
  # count query) and create (new scan-job record) documents, never
  # replace or delete one, so blanket Data Contributor is broader than
  # its application code (src/api/scan_job.py, src/api/quota.py) needs.
  function_identities = {
    "worker" = module.function_app.worker_principal_id
  }

  # Each identity's Storage Blob Data Contributor grant is scoped to ONLY
  # its own deployment container (needed for Flex Consumption's
  # identity-based package pull -- storage_authentication_type =
  # "SystemAssignedIdentity" in each function_app module), not the whole
  # storage account. Previously all three identities were granted at
  # account scope, so e.g. the Report Function's identity could read/write
  # the Worker's and API's deployment containers too, with no legitimate
  # reason to. Same role/permission level as before -- only the scope
  # narrows, so this should not change what the Flex Consumption deployment
  # mechanism itself is able to do.
  function_deploy_containers = {
    "worker" = {
      principal_id = module.function_app.worker_principal_id
      container_id = module.storage_account.worker_deploy_container_id
    }
    "api" = {
      principal_id = module.api_function.api_principal_id
      container_id = module.storage_account.api_deploy_container_id
    }
    "report" = {
      principal_id = module.report_function.report_principal_id
      container_id = module.storage_account.report_deploy_container_id
    }
  }
}

# ----------------------------------------------
# Function App Role Assignments For Storage Account
# ----------------------------------------------
resource "azurerm_role_assignment" "functions_storage_access" {
  for_each = local.function_deploy_containers

  scope                = each.value.container_id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = each.value.principal_id
}

# ---------------------------------------------- 
# Function App Role Assignments For Database (Data Plane)
# ----------------------------------------------
resource "azurerm_cosmosdb_sql_role_assignment" "functions_db_access" {
  for_each = local.function_identities

  resource_group_name = module.resource_group.name
  account_name        = module.cosmos_db.cosmosdb_name

  # Built-in Data Contributor (read+write) -- Worker and API both need to
  # write scan results / enqueue-tracking data, not just read them.
  role_definition_id = "${module.cosmos_db.cosmosdb_id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000002"

  principal_id = each.value
  scope        = module.cosmos_db.cosmosdb_id
}

# ----------------------------------------------
# Report Function Role Assignment For Database (Data Plane) -- read-only.
# Report's application code never writes to Cosmos DB, so it gets the
# built-in Data Reader role instead of Data Contributor. These role
# definition IDs are fixed, built-in Cosmos DB SQL API role definitions
# (documented by Microsoft as 000...001 = Data Reader, 000...002 = Data
# Contributor) -- the same well-known IDs already relied on above, not
# something specific to this subscription that "az cosmosdb sql role
# definition list" would show differently.
# ----------------------------------------------
resource "azurerm_cosmosdb_sql_role_assignment" "report_db_read_access" {
  resource_group_name = module.resource_group.name
  account_name        = module.cosmos_db.cosmosdb_name

  # Built-in Data Reader
  role_definition_id = "${module.cosmos_db.cosmosdb_id}/sqlRoleDefinitions/00000000-0000-0000-0000-000000000001"

  principal_id = module.report_function.report_principal_id
  scope        = module.cosmos_db.cosmosdb_id
}

# ----------------------------------------------
# API Gateway Custom Role For Database (Data Plane) -- read + create only.
# The Gateway's application code (src/api/scan_job.py, src/api/quota.py)
# only ever reads (quota count query via executeQuery) and creates (new
# scan-job record) documents -- it never replaces or deletes one, so
# neither built-in role fits: Data Reader (...001) can't write at all,
# and Data Contributor (...002) also grants replace/upsert/delete/
# container- and database-level management actions it has no legitimate
# reason to hold. No built-in "reader + create-only" role exists, so this
# defines one -- the same least-privilege reasoning already applied to
# Report's identity above, extended to a case that needs a genuinely
# custom role rather than picking the closer of the two built-ins.
# ----------------------------------------------
resource "azurerm_cosmosdb_sql_role_definition" "gateway_scan_writer" {
  name                = "Bravo6 Gateway Scan Writer"
  resource_group_name = module.resource_group.name
  account_name        = module.cosmos_db.cosmosdb_name
  type                = "CustomRole"
  assignable_scopes   = [module.cosmos_db.cosmosdb_id]

  permissions {
    data_actions = [
      "Microsoft.DocumentDB/databaseAccounts/readMetadata",
      "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/read",
      "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/items/create",
      "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/executeQuery",
      "Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers/readChangeFeed",
    ]
  }
}

resource "azurerm_cosmosdb_sql_role_assignment" "api_db_scan_writer" {
  resource_group_name = module.resource_group.name
  account_name        = module.cosmos_db.cosmosdb_name

  role_definition_id = azurerm_cosmosdb_sql_role_definition.gateway_scan_writer.id

  principal_id = module.api_function.api_principal_id
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
