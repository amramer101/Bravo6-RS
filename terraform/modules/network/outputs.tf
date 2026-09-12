output "functions_subnet_id" {
  value = azurerm_subnet.functions_subnet.id
}

output "private_endpoints_subnet_id" {
  value = azurerm_subnet.private_endpoints_subnet.id
}

output "vnet_id" {
  value = azurerm_virtual_network.vnet_bravo6.id
}

