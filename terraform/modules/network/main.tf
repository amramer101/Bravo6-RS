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

  # Microsoft.AzureCosmosDB service endpoint REMOVED (Gap 1 fix, see
  # modules/cosmos_db/main.tf's private endpoint block for the full
  # explanation). Microsoft's current Flex Consumption networking docs
  # (functions-networking-options.md, updated 2026-07-14) state this
  # subnet "can't already be in use for other purposes (like private or
  # service endpoints...)" alongside the Microsoft.App/environments
  # delegation below -- service-endpoint-based Cosmos DB access was
  # structurally incompatible with this subnet, not a firewall-rule bug
  # (confirmed live: DEPLOYMENT_NOTES.md's Gap 1). Cosmos DB access now
  # goes through a Private Endpoint in a separate, non-delegated subnet
  # (private-endpoints-subnet, below) instead.
  #
  # Microsoft.Storage is DELIBERATELY still here. It's under the same
  # documented incompatibility in principle, but unlike Cosmos DB's
  # virtual_network_rule (which produced a live, confirmed VNet-firewall
  # rejection), no live evidence was gathered this pass that anything
  # actually depends on this specific service endpoint at runtime -- the
  # storage account's own network_rules.bypass = ["AzureServices"] may be
  # what actually allows Functions-platform traffic through regardless of
  # whether this service endpoint even resolves correctly. Removing it
  # without a live test to confirm nothing regresses would be guessing, so
  # it's left in place and flagged for a dedicated follow-up pass (see
  # DEPLOYMENT_NOTES.md).
  service_endpoints = [
    "Microsoft.Storage"
  ]

  delegation {
    name = "functions-delegation"
    service_delegation {
      name    = "Microsoft.App/environments"
      actions = ["Microsoft.Network/virtualNetworks/subnets/action"]
    }
  }
}

# ----------------------------------------------------
# Gap 1 fix: dedicated subnet for Private Endpoints (Cosmos DB today; any
# future private-linked service belongs here too). Deliberately separate
# from functions-subnet: Flex Consumption's delegated subnet "can't
# already be in use for other purposes (like private or service
# endpoints...)" per Microsoft's current docs -- so a Private Endpoint
# cannot live in functions-subnet, it needs its own, non-delegated one.
# 10.0.2.0/24 does not overlap functions-subnet's 10.0.1.0/24 within the
# VNet's 10.0.0.0/16 address space.
resource "azurerm_subnet" "private_endpoints_subnet" {
  name                 = "private-endpoints-subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.vnet_bravo6.name
  address_prefixes     = ["10.0.2.0/24"]

  # Required so Private Endpoint NICs can be created in this subnet
  # without the subnet's own NSG/route-table policies interfering with
  # Private Link's own traffic handling -- Microsoft's documented private
  # endpoint setup (az network vnet subnet update
  # --disable-private-endpoint-network-policies true) does the same thing.
  private_endpoint_network_policies = "Disabled"
}

# ----------------------------------------------------
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