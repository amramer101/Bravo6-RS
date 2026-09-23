# Automation boundaries

| Workflow | Trigger | Effect |
| --- | --- | --- |
| `docs.yml` | Documentation PR/push, or manual dispatch | Strict documentation build; Pages publication only for manual `publish=true` on `main` |
| `python-tests.yml` | Worker Python/runtime dependency/config changes, or manual dispatch | Existing scanner suites; not triggered by README-only edits |
| `terraform_ci.yml` | Manual dispatch only | Azure login, Terraform initialization/planning and policy checks |
| `terraform_cd.yml` | Manual dispatch only | Applies a saved Terraform plan to Azure |

Documentation builds need no Azure credentials. Build artifacts contain only MkDocs `site/`, not the repository root or local `output/`. A manual publication remains a public release: review the content before selecting it.

The historical Python and Terraform workflows contain `continue-on-error` / soft-fail steps. A green overall status must not be advertised as proof that all scanner or infrastructure checks passed. This cleanup preserves their test and deployment behavior and does not run them. Detailed CI hardening is separate work.

No repository visibility setting, GitHub environment protection, or existing published site is changed by editing these files locally.
