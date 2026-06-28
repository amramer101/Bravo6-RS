# terraform/variables.tf

variable "location" {
  description = "Azure region"
  type        = string
  default     = "uaenorth"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "project_name" {
  description = "Project name"
  type        = string
  default     = "bravo6"
}

variable "subscription_id" {
  description = "Azure Subscription ID"
  type        = string
  default     = "55336c1c-af74-4164-b687-a7b7c3ec740c"
}
