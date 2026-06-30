resource "azurerm_service_plan" "functions_plan" {
  name                = var.plan_name
  resource_group_name = var.resource_group_name
  location            = var.location
  os_type             = var.os_type
  sku_name            = var.sku_name
  tags = {
    source = "terraform"
  }
}
