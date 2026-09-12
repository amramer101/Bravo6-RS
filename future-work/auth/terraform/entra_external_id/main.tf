# DEFERRED (2026-09-12): moved out of terraform/modules/ -- not part of
# the live app stack. See future-work/auth/README.md for why and how to
# bring it back (re-add the "entra_external_id" module block to
# terraform/main.tf, and the azuread provider block it needs to
# terraform/provider.tf). Code below is unmodified from its last live
# version.

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