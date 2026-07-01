output "service_bus_id" {
  value = azurerm_servicebus_namespace.service_bus.id
}

output "service_bus_namespace" {
  value = azurerm_servicebus_namespace.service_bus.name
}
