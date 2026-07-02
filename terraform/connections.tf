# ----------------------------------------------
# API Function and Static Web App (Linked Backend)
# ----------------------------------------------
resource "azurerm_static_web_app_function_app_registration" "api_registration" {
  static_web_app_id = module.static_website.static_web_app_id
  function_app_id   = module.api_function.api_id
}

