# Automation and documentation builds

## Workflow contract

| Workflow | Trigger | Side effects |
| --- | --- | --- |
| Documentation | Docs/config PR or push; manual dispatch | Build static site; publish only on manual `publish=true` from `main` |
| Python Tests | Worker Python/dependency/host changes; manual dispatch | Runs existing suites; README-only changes do not trigger them |
| Terraform CI | Manual dispatch | Azure login, initialization, planning, policy checks |
| Terraform CD | Manual dispatch | Apply an existing saved plan to Azure |

Documentation build permissions are read-only. Pages and identity-token permissions are granted to the deployment job. The upload contains the generated `site/` directory, not the repository root or ignored research output.

## Build versus publish

A successful build checks that MkDocs can construct the site. It does not certify factual claims, scanner correctness, accessibility, or research validity. Publication is a separate explicit action. Local previews and this documentation task do not publish or change GitHub visibility.

The documentation requirements pin direct dependency versions. They are not a complete transitive lockfile. The current build removes external font and Mermaid CDN dependencies by using local SVG assets and system fonts.

## Interpreting CI badges

Historical Python and Terraform workflows retain soft-failing steps. A green workflow can coexist with a failed internal check. This site therefore uses static scope/rights badges and does not advertise “all tests passing.” A future CI hardening change must make the relevant checks blocking before such a badge is meaningful.

## Review-only work

For documentation changes, run the strict build, verify generated links, inspect desktop/mobile rendering, and preserve protected source/data hashes. Scanner tests and cloud plans are separate activities and were not run for this rewrite.


## Implementation and evidence

- [.github/workflows/docs.yml](https://github.com/amramer101/Bravo6-RS/blob/main/.github/workflows/docs.yml)
- [.github/workflows/python-tests.yml](https://github.com/amramer101/Bravo6-RS/blob/main/.github/workflows/python-tests.yml)
- [.github/workflows/terraform_ci.yml](https://github.com/amramer101/Bravo6-RS/blob/main/.github/workflows/terraform_ci.yml)
- [.github/workflows/terraform_cd.yml](https://github.com/amramer101/Bravo6-RS/blob/main/.github/workflows/terraform_cd.yml)
- [requirements-docs.txt](https://github.com/amramer101/Bravo6-RS/blob/main/requirements-docs.txt)

Source links follow `main`. They describe the inspectable implementation, not a verified digest of the historical deployment.
