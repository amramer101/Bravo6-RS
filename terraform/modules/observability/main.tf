resource "azurerm_log_analytics_workspace" "law" {
  name                = var.log_analytics_workspace_name
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = {
    source = "terraform"
  }
}

# Workspace-based Application Insights (the current recommended mode --
# classic/non-workspace App Insights is being retired). Every Function App's
# APPLICATIONINSIGHTS_CONNECTION_STRING app setting points here, so a scan
# run produces queryable traces/logs/exceptions/dependencies in this one
# workspace instead of only the transient, non-aggregated default Function
# host logs.
resource "azurerm_application_insights" "appi" {
  name                = var.app_insights_name
  resource_group_name = var.resource_group_name
  location            = var.location
  workspace_id        = azurerm_log_analytics_workspace.law.id
  application_type    = "web"

  tags = {
    source = "terraform"
  }
}
