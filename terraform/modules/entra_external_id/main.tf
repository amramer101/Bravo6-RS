resource "azuread_application" "bravo6_spa" {
  display_name = var.app_display_name

  single_page_application {
    redirect_uris = var.redirect_uris
  }

  api {
    requested_access_token_version = 2
  }
}

resource "azuread_service_principal" "bravo6_spa_sp" {
  client_id = azuread_application.bravo6_spa.client_id
}