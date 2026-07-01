variable "function_app_name" {
  type        = string
}

variable "location" {
  type        = string
}

variable "resource_group_name" {
  type        = string
}

variable "service_plan_id" {
  type        = string
}

variable "storage_account_name" {
  type        = string
}

variable "service_bus_namespace" {
  type        = string
  description = "The namespace of the Service Bus (passed from root)"
}