output "cosmosdb_id" {
  value = azurerm_cosmosdb_account.db.id
}

output "cosmosdb_endpoint" {
  value = azurerm_cosmosdb_account.db.endpoint
}
