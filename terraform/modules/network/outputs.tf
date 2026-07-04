output "functions_subnet_id" {
  value = azurerm_subnet.functions_subnet.id
}

output "appservice_subnet_id" {
  value = azurerm_subnet.appservice_subnet.id
}
