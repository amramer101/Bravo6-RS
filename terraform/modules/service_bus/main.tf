resource "azurerm_servicebus_namespace" "service_bus" {
  name                = var.service_bus_name
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = var.service_bus_sku

  tags = {
    source = "terraform"
  }
  
}

resource "azurerm_servicebus_namespace_network_rule_set" "sb_network_rules" {
  namespace_id   = azurerm_servicebus_namespace.service_bus.id
  default_action = "Deny"

  network_rules {
    subnet_id                            = var.service_endpoint_subnet_id
    ignore_missing_vnet_service_endpoint = false
  }
}


resource "azurerm_servicebus_queue" "service_bus_queue" {
  name         = var.service_bus_queue_name
  namespace_id = azurerm_servicebus_namespace.service_bus.id
  partitioning_enabled = false
}