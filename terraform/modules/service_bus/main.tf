resource "azurerm_servicebus_namespace" "service_bus" {
  name                = var.service_bus_name
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = var.service_bus_sku

  tags = {
    source = "terraform"
  }
}