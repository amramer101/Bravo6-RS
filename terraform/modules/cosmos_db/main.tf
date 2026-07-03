resource "azurerm_cosmosdb_account" "db" {
  name                = var.cosmosdb_name
  location            = var.location
  resource_group_name = var.resource_group_name
  offer_type          = "Standard"

  kind = "GlobalDocumentDB"

  free_tier_enabled                 = true
  automatic_failover_enabled        = false
  is_virtual_network_filter_enabled = true
  public_network_access_enabled     = false
  local_authentication_disabled     = true

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = var.location
    failover_priority = 0
  }

  virtual_network_rule {
    id                                   = var.service_endpoint_subnet_id
    ignore_missing_vnet_service_endpoint = false
  }

  tags = {
    source = "terraform"
  }
}

# ----------------------------- Database -----------------------------

resource "azurerm_cosmosdb_sql_database" "main_db" {
  name                = var.db_name
  resource_group_name = var.resource_group_name
  account_name        = azurerm_cosmosdb_account.db.name
}

# (Users container)
resource "azurerm_cosmosdb_sql_container" "users_container" {
  name                = "users"
  resource_group_name = var.resource_group_name
  account_name        = azurerm_cosmosdb_account.db.name
  database_name       = azurerm_cosmosdb_sql_database.main_db.name

  partition_key_paths = ["/userId"]

  throughput = 400
}

# (Scans container)
resource "azurerm_cosmosdb_sql_container" "scans_container" {
  name                = "scans"
  resource_group_name = var.resource_group_name
  account_name        = azurerm_cosmosdb_account.db.name
  database_name       = azurerm_cosmosdb_sql_database.main_db.name

  partition_key_paths = ["/scanId"]

  throughput = 400
}