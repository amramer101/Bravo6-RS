variable "plan_name" {
  type        = string
  description = "The name of the App Service Plan"
}

variable "resource_group_name" {
  type        = string
  description = "The name of the Resource Group (Passed from RG module)"
}

variable "location" {
  type        = string
  description = "The location of the App Service Plan (Passed from RG module)"
}

variable "os_type" {
  type        = string
  description = "The O/S type for the App Services to be hosted in this plan (Linux or Windows)"
}

variable "sku_name" {
  type        = string
  description = "The SKU for the plan (e.g., Y1 for Consumption, S1 for Standard)"
}
