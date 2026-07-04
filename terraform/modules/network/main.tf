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
      name    = "Microsoft.App/environments" # ✅ اتصلحت من serverFarms
      actions = ["Microsoft.Network/virtualNetworks/subnets/action"]
    }
  }
}

# ----------------------------------------------------
# NSG لتطبيق مبدأ Zero Trust على الـ subnet
resource "azurerm_network_security_group" "nsg" {
  name                = "${var.resource_group_name}-nsg"
  location            = var.location
  resource_group_name = var.resource_group_name

  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 1000
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowServiceEndpoints"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "VirtualNetwork"
  }
}

resource "azurerm_subnet_network_security_group_association" "nsg_association" {
  subnet_id                 = azurerm_subnet.functions_subnet.id
  network_security_group_id = azurerm_network_security_group.nsg.id
}