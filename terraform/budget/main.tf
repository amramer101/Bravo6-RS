# terraform/budget/main.tf
#
# Deliberately its own Terraform root, with its own state (see backend.tf)
# -- NOT part of ../ (the app stack's root module). The app stack is
# routinely destroyed and redeployed to control cost (see
# DEPLOYMENT_NOTES.md); a `terraform destroy` run from ../ must never be
# able to take this budget alert down with it, since the alert's entire
# purpose is to catch exactly the kind of silent cost accrual that a
# broken or forgotten deployment causes. Concretely, this means:
#   - a subscription-scoped budget (azurerm_consumption_budget_subscription),
#     not resource-group-scoped -- a bravo6-rg-scoped budget would be
#     destroyed along with bravo6-rg every cycle, which defeats the point.
#   - its own state file (backend.tf's key), so `terraform destroy` in ../
#     has no way to see or touch this resource at all.
#
# Run from THIS directory only: `terraform init && terraform apply`.
# Never run `terraform destroy` here as part of routine app teardown --
# this budget alert is meant to persist across every future
# destroy/redeploy cycle of the app stack.

data "azurerm_subscription" "current" {}

resource "azurerm_consumption_budget_subscription" "bravo6_monthly_budget" {
  name            = "bravo6-monthly-budget"
  subscription_id = data.azurerm_subscription.current.id

  amount     = 25
  time_grain = "Monthly"

  time_period {
    # First of the current month -- azurerm requires a UTC-midnight,
    # first-of-month start_date. No end_date set: the provider defaults
    # to a multi-year window, which is what we want for a standing alert
    # rather than a one-off budget for a fixed project window.
    start_date = "2026-09-01T00:00:00Z"
  }

  notification {
    enabled        = true
    threshold      = 80
    threshold_type = "Actual"
    operator       = "GreaterThanOrEqualTo"
    contact_emails = [
      "amrmedhatamer1@gmail.com",
    ]
  }

  notification {
    enabled        = true
    threshold      = 100
    threshold_type = "Actual"
    operator       = "GreaterThanOrEqualTo"
    contact_emails = [
      "amrmedhatamer1@gmail.com",
    ]
  }
}
