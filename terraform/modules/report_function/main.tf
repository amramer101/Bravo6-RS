resource "azurerm_linux_function_app" "report_function" {
  name                = var.function_report_name
  resource_group_name = var.resource_group_name
  location            = var.location
  virtual_network_subnet_id  = var.service_endpoint_subnet_id

  service_plan_id        = var.service_plan_id
  storage_account_name   = var.storage_account_name
  
  storage_uses_managed_identity = true

  https_only                 = true
  
  identity {
    type = "SystemAssigned"
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }
    vnet_route_all_enabled = true
  }

  app_settings = {
    "FUNCTIONS_WORKER_RUNTIME" = "python"
    "AzureWebJobsStorage__accountName" = var.storage_account_name
    "ServiceBusConnection__fullyQualifiedNamespace" = "${var.service_bus_namespace}.servicebus.windows.net"
    "WEBSITE_RUN_FROM_PACKAGE" = "1"

  }


  tags = {
    source = "terraform"
  }
}