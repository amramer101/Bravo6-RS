resource "azurerm_servicebus_namespace" "service_bus" {
  name                = var.service_bus_name
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = var.service_bus_sku


  tags = {
    source = "terraform"
  }
}

resource "azurerm_servicebus_queue" "service_bus_queue" {
  name                 = var.service_bus_queue_name
  namespace_id         = azurerm_servicebus_namespace.service_bus.id
  partitioning_enabled = false

  # Design specifies 3 delivery attempts before dead-lettering. Left unset,
  # the deployed queue silently takes Azure's platform default of 10.
  max_delivery_count = 3

  # A message that exceeds max_delivery_count is already dead-lettered
  # automatically by the service regardless of this setting -- that part is
  # not this flag's job. This flag covers the OTHER way a message can stop
  # being retried without a trace: TTL expiration. No default_message_ttl
  # is set on this queue today (so messages effectively never expire on
  # their own), but if one is added later, an expired message would
  # otherwise just be silently deleted instead of landing somewhere an
  # operator can inspect it. Setting this now means that stays true by
  # default rather than depending on remembering to set it alongside a
  # future TTL.
  dead_lettering_on_message_expiration = true
}