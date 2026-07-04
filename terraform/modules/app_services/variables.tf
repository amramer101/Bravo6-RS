variable "resource_group_name" {
  description = "The name of the Resource Group"
  type        = string
}

variable "location" {
  type        = string
  description = "Azure region"
}

variable "frontend_plan_name" {
  description = "The name of the frontend service plan"
  type        = string
}

variable "frontend_plan_sku" {
  type        = string
  description = "frontend service plan sku"
}


variable "frontend_app_name" {
  description = "The name of the frontend web app"
  type        = string
}

variable "service_endpoint_subnet_id" {
  type        = string
  description = "The ID of the Subnet"
}

