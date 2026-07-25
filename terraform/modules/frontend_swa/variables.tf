
variable "static_web_app_name" {
  description = "The name of the static web app"
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

variable "static_web_app_tier" {
  type        = string
  description = "static web app tier"
}

variable "static_web_app_size" {
  type        = string
  description = "static web app size"
}
