variable "service_bus_name" {
  description = "The name of the service bus"
  type        = string
}

variable "resource_group_name" {
  description = "The name of the Resource Group"
  type        = string
}

variable "location" {
  type        = string
  description = "Azure region"
}

variable "service_bus_sku" {
  type        = string
  description = "service bus sku"
}

variable "service_bus_queue_name" {
  type        = string
  description = "service bus queue name"
}

