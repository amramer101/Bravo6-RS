variable "log_analytics_workspace_name" {
  type        = string
  description = "Name of the Log Analytics workspace backing Application Insights"
}

variable "app_insights_name" {
  type        = string
  description = "Name of the Application Insights resource"
}

variable "resource_group_name" {
  type = string
}

variable "location" {
  type = string
}
