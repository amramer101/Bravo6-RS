resource "azurerm_cosmosdb_account" "db" {
  name                = var.cosmosdb_name
  location            = var.location
  resource_group_name = var.resource_group_name
  offer_type          = "Standard"
  
  kind                = "GlobalDocumentDB"

  free_tier_enabled          = true 
  automatic_failover_enabled = false

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = var.location
    failover_priority = 0
  }
  tags = {
    source = "terraform"
  } 
}