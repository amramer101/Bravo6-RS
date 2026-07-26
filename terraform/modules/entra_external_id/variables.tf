
variable "external_tenant_id" {
  type        = string
  description = "Tenant ID of the Entra External ID (CIAM) tenant"
}

variable "app_display_name" {
  type = string
}

variable "redirect_uris" {
  type = list(string)
}