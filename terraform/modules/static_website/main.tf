resource "azurerm_static_web_app" "frontend" {
  name                = "bravo6-frontend"
  resource_group_name = var.resource_group_name

  location = var.location

  sku_tier = var.static_web_app_sku
  sku_size = var.static_web_app_sku

  identity {
    type = "SystemAssigned"
  }

  tags = {
    source = "terraform"
  }
}