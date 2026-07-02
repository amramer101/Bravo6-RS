resource "azurerm_virtual_network" "vnet_bravo6" {
  name                = var.vnet_name
  location            = var.location
  resource_group_name = var.resource_group_name
  address_space       = ["10.0.0.0/16"]
  
  tags = {
    source = "terraform"
  }
}

resource "azurerm_subnet" "functions_subnet" {
  name                 = "functions-subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.vnet_bravo6.name
  address_prefixes     = ["10.0.1.0/24"]

  service_endpoints = [
    "Microsoft.AzureCosmosDB",
    "Microsoft.KeyVault",
    "Microsoft.Storage",
    "Microsoft.ServiceBus"
  ]

  delegation {
    name = "functions-delegation"
    service_delegation {
      name    = "Microsoft.Web/serverFarms"
      actions = ["Microsoft.Network/virtualNetworks/subnets/action"]
    }
  }
}