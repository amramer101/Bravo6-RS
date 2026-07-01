resource "azurerm_linux_function_app" "worker_function" {
  name                = var.function_app_name
  resource_group_name = var.resource_group_name
  location            = var.location

  service_plan_id        = var.service_plan_id
  storage_account_name   = var.storage_account_name

  identity {
    type = "SystemAssigned"
  }

  site_config {
    application_stack {
      python_version = "3.11"
    }
  }

  app_settings = {
    "FUNCTIONS_WORKER_RUNTIME" = "python"
    "AzureWebJobsStorage__accountName" = var.storage_account_name
    "ServiceBusConnection__fullyQualifiedNamespace" = "${var.service_bus_namespace}.servicebus.windows.net"  
  }

  tags = {
    source = "terraform"
  }
}