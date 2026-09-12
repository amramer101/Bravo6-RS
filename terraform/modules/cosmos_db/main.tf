resource "azurerm_cosmosdb_account" "db" {
  name                = var.cosmosdb_name
  location            = var.location
  resource_group_name = var.resource_group_name
  offer_type          = "Standard"

  kind = "GlobalDocumentDB"

  free_tier_enabled          = true
  automatic_failover_enabled = false
  # Was true, backing the virtual_network_rule below -- that whole
  # service-endpoint-based ACL mechanism is replaced by the Private
  # Endpoint below (Gap 1 fix), so there's no VNet rule left to enable.
  is_virtual_network_filter_enabled = false
  public_network_access_enabled     = false

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = var.location
    failover_priority = 0
  }

  tags = {
    source = "terraform"
  }
}

# ============================================================================
# Gap 1 fix: Cosmos DB Private Endpoint
#
# `POST /api/scan` on the live API Gateway returned a flat 500, root-caused
# (DEPLOYMENT_NOTES.md, Gap 1) directly from Application Insights to:
#   azure.cosmos.exceptions.CosmosHttpResponseError: (Forbidden) Request
#   originated from VNET through service endpoint. This is blocked by your
#   Cosmos DB account firewall settings.
# Confirmed root cause against Microsoft's current Flex Consumption
# networking docs (functions-networking-options.md, updated 2026-07-14):
# the Flex-Consumption-delegated functions-subnet "can't already be in use
# for other purposes (like private or service endpoints...)" -- so the
# `Microsoft.AzureCosmosDB` service endpoint + the `virtual_network_rule`
# block that used to live on the account above were never able to work
# correctly on that subnet. This isn't a firewall-rule tweak; the
# service-endpoint ACL mechanism itself can't function on a subnet
# delegated to Microsoft.App/environments. A Private Endpoint is the
# documented alternative (learn.microsoft.com/azure/cosmos-db/
# how-to-configure-private-endpoints, updated 2026-04-27): it puts a
# private IP for this Cosmos account into a SEPARATE, non-delegated
# subnet (private-endpoints-subnet, modules/network/main.tf), which the
# Function Apps can still reach because Flex Consumption's outbound
# `vnet_route_all_enabled = true` routes ALL egress through the VNet, not
# just the delegated subnet's own address range -- the delegated subnet's
# constraint is about what can be layered ONTO it, not about what other
# subnets in the same VNet it can reach.
#
# NOT a reversal of ADR-004 (docs/architecture-decisions.md). ADR-004
# rejected Private Endpoints on the *inbound* HTTP path of the API/Report
# Function Apps themselves, specifically because combining that with
# Flex Consumption's *outbound* VNet integration hits a documented
# platform bug (GitHub issue #2635) and needs a reverse-proxy layer to
# stay browser-reachable. This is a Private Endpoint on Cosmos DB's data
# plane instead -- the Function Apps' own inbound path (still public +
# JWT, per ADR-004) is completely unchanged; they simply resolve Cosmos's
# hostname to a private IP over their existing outbound VNet integration.
# Issue #2635 doesn't apply here: it's specifically about a Function App's
# *own* inbound Private Endpoint, not a downstream dependency's.
#
# DNS: Cosmos SQL API's private zone name (confirmed current, same doc)
# is privatelink.documents.azure.com. Linking it to the VNet is what lets
# vnet_route_all_enabled resolve the account's hostname to the private IP
# instead of its public one -- without this link, the Function Apps would
# still resolve to the public endpoint and get the same firewall
# rejection, private endpoint or not.
# ============================================================================

resource "azurerm_private_dns_zone" "cosmos" {
  name                = "privatelink.documents.azure.com"
  resource_group_name = var.resource_group_name

  tags = {
    source = "terraform"
  }
}

resource "azurerm_private_dns_zone_virtual_network_link" "cosmos" {
  name                  = "cosmos-privatelink-link"
  resource_group_name   = var.resource_group_name
  private_dns_zone_name = azurerm_private_dns_zone.cosmos.name
  virtual_network_id    = var.vnet_id
  registration_enabled  = false

  tags = {
    source = "terraform"
  }
}

resource "azurerm_private_endpoint" "cosmos" {
  name                = "${var.cosmosdb_name}-pe"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint_subnet_id

  private_service_connection {
    name                           = "${var.cosmosdb_name}-psc"
    private_connection_resource_id = azurerm_cosmosdb_account.db.id
    # "Sql" is the correct subresource/group ID for Cosmos DB's API for
    # NoSQL (this account's kind = "GlobalDocumentDB") -- confirmed
    # current against Microsoft's subresource table, which also maps it
    # to the privatelink.documents.azure.com zone above.
    subresource_names    = ["Sql"]
    is_manual_connection = false
  }

  private_dns_zone_group {
    name                 = "cosmos-dns-zone-group"
    private_dns_zone_ids = [azurerm_private_dns_zone.cosmos.id]
  }

  tags = {
    source = "terraform"
  }
}

# ----------------------------- Database -----------------------------

resource "azurerm_cosmosdb_sql_database" "main_db" {
  name                = var.db_name
  resource_group_name = var.resource_group_name
  account_name        = azurerm_cosmosdb_account.db.name
}

# (Users container)
resource "azurerm_cosmosdb_sql_container" "users_container" {
  name                = "users"
  resource_group_name = var.resource_group_name
  account_name        = azurerm_cosmosdb_account.db.name
  database_name       = azurerm_cosmosdb_sql_database.main_db.name

  partition_key_paths = ["/userId"]

  throughput = 400
}

# (Scans container)
resource "azurerm_cosmosdb_sql_container" "scans_container" {
  name                = "scans"
  resource_group_name = var.resource_group_name
  account_name        = azurerm_cosmosdb_account.db.name
  database_name       = azurerm_cosmosdb_sql_database.main_db.name

  partition_key_paths = ["/scanId"]

  throughput = 400
}