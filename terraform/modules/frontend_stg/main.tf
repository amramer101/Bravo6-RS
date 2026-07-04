# 1. إنشاء الـ Storage Account (سادة من غير بلوك الـ Website)
resource "azurerm_storage_account" "frontend_storage" {
  name                     = var.storage_account_name
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = var.storage_account_tier
  account_replication_type = var.replication_type

  tags = {
    source = "terraform"
    tier   = "frontend"
  }
}

resource "azurerm_storage_account_static_website" "frontend_website" {
  storage_account_id = azurerm_storage_account.frontend_storage.id

  index_document     = "index.html"
  error_404_document = "index.html"
}

resource "azurerm_cdn_profile" "frontend_cdn_profile" {
  name                = var.cdn_profile_name
  location            = "global"
  resource_group_name = var.resource_group_name
  sku                 = "Standard_Microsoft"
}

# CDN Endpoint
resource "azurerm_cdn_endpoint" "frontend_cdn_endpoint" {
  name                = var.cdn_endpoint_name
  profile_name        = azurerm_cdn_profile.frontend_cdn_profile.name
  location            = "global"
  resource_group_name = var.resource_group_name

  origin {
    name      = "frontend-origin"
    host_name = azurerm_storage_account.frontend_storage.primary_web_host
  }

  origin_host_header = azurerm_storage_account.frontend_storage.primary_web_host
}