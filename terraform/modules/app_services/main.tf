resource "azurerm_service_plan" "frontend_plan" {
  name                = var.frontend_plan_name
  location            = var.location
  resource_group_name = var.resource_group_name
  os_type             = "Linux"

  sku_name = var.frontend_plan_sku
}

resource "azurerm_linux_web_app" "frontend_app" {
  name                = var.frontend_app_name
  location            = var.location
  resource_group_name = var.resource_group_name
  service_plan_id     = azurerm_service_plan.frontend_plan.id

  site_config {
    application_stack {
      node_version = "18-lts"
    }

    # VNet Integration
    virtual_network_subnet_id = var.service_endpoint_subnet_id
    vnet_route_all_enabled    = true
  }

  tags = {
    source = "terraform"
  }
}