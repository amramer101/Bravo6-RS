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

# Azure Front Door Profile
resource "azurerm_cdn_frontdoor_profile" "frontend_fd_profile" {
  name                = var.cdn_profile_name
  resource_group_name = var.resource_group_name
  sku_name            = "Standard_AzureFrontDoor"
}

# Endpoint
resource "azurerm_cdn_frontdoor_endpoint" "frontend_fd_endpoint" {
  name                     = var.cdn_endpoint_name
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.frontend_fd_profile.id
}

# Origin Group
resource "azurerm_cdn_frontdoor_origin_group" "frontend_fd_origin_group" {
  name                     = "frontend-origin-group"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.frontend_fd_profile.id
  session_affinity_enabled = false

  load_balancing {
    sample_size                 = 4
    successful_samples_required = 3
  }

  health_probe {
    path                = "/"
    protocol            = "Https"
    interval_in_seconds = 100
  }
}


resource "azurerm_cdn_frontdoor_origin" "frontend_fd_origin" {
  name                          = "frontend-origin"
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.frontend_fd_origin_group.id

  enabled                        = true
  host_name                      = azurerm_storage_account.frontend_storage.primary_web_host
  origin_host_header             = azurerm_storage_account.frontend_storage.primary_web_host
  certificate_name_check_enabled = true
}

resource "azurerm_cdn_frontdoor_route" "frontend_fd_route" {
  name                          = "frontend-route"
  cdn_frontdoor_endpoint_id     = azurerm_cdn_frontdoor_endpoint.frontend_fd_endpoint.id
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.frontend_fd_origin_group.id
  cdn_frontdoor_origin_ids      = [azurerm_cdn_frontdoor_origin.frontend_fd_origin.id]

  supported_protocols    = ["Http", "Https"]
  patterns_to_match      = ["/*"]
  forwarding_protocol    = "HttpsOnly"
  link_to_default_domain = true
  https_redirect_enabled = true
}