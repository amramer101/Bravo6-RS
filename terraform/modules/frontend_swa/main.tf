resource "azurerm_static_web_app" "frontend" {
  name                = var.static_web_app_name
  resource_group_name = var.resource_group_name
  location            = var.location
  sku_tier            = var.static_web_app_tier
  sku_size            = var.static_web_app_size

  tags = {
    source = "terraform"
    tier   = "frontend"
  }
}