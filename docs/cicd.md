# CI/CD Pipeline

Four GitHub Actions workflows live in `.github/workflows/`.

## `python-tests.yml` — scanner regression suites

Triggers on push/PR to `main` touching `src/worker/**`, plus manual dispatch. Runs every scout's
own `test_NN_*.py --test` suite individually (not through a shared runner), so a failure names
exactly which scout broke — matching how these suites are already run locally and cited in the
accompanying paper. Then runs the Worker's own orchestration-level suite
(`main_scanner.py --test`).

This workflow does **not** currently run the API Gateway's suite (`src/api/test_api_gateway.py`) —
worth adding, since that's 44 assertions covering a component that's code-complete but not yet
deployed and therefore has no other verification running against it in CI.

## `terraform_ci.yml` — infrastructure plan on every push

Triggers on push to `main` touching `terraform/**`, plus manual dispatch. Authenticates to Azure via
OIDC (`azure/login@v2` + `ARM_USE_OIDC: "true"`, no stored client secret), then runs
`terraform fmt -check`, `terraform validate`, a soft-fail Checkov security scan (see the workflow's
own comments for exactly which findings are accepted as tier-locked cost trade-offs versus real
follow-up items), and `terraform plan`, uploading the plan binary as a build artifact keyed to the
commit SHA.

## `terraform_cd.yml` — manual apply

`workflow_dispatch`-only, takes a commit SHA as input, downloads that commit's plan artifact from
`terraform_ci.yml`, and runs `terraform apply -auto-approve` against it. Deliberately not automatic
on every push — applying infrastructure changes is a human-triggered action here, not a merge-to-main
side effect.

## `docs.yml` — documentation site

Builds this MkDocs site and deploys it to GitHub Pages on push to `main` (paths touching
`docs/**`, `mkdocs.yml`, or the workflow itself), plus manual dispatch. Uses the official
`actions/deploy-pages` flow (build → `actions/upload-pages-artifact` → `actions/deploy-pages`),
which requires the repository's **Settings → Pages → Build and deployment → Source** set to
"GitHub Actions."

## Required repository secrets

| Secret | Used by | Purpose |
|---|---|---|
| `AZURE_CLIENT_ID` | `terraform_ci.yml`, `terraform_cd.yml` | OIDC federated identity client ID |
| `AZURE_TENANT_ID` | same | Azure AD tenant for the federated credential |
| `AZURE_SUBSCRIPTION_ID` | same | Target subscription for `terraform plan`/`apply` |

None of the four workflows require a stored Azure credential secret beyond the OIDC identity above
— consistent with the rest of this platform's Managed-Identity-first design.
