# Maintainer guide

BRAVO6 is publicly inspectable under an All Rights Reserved notice. This page documents maintenance practice; it is not an open-source contribution or reuse license. Arrange permission with the owner before contributing or reusing project material.

## Choose the right scope

| Work | Location | Validation boundary |
| --- | --- | --- |
| Documentation | `docs/`, `README.md`, component READMEs | Build, links, source consistency, visual review |
| Scanner changes | `src/worker/` | Relevant local fixtures and explicit measurement impact |
| API/Report changes | `src/api/`, `src/report/` | Handler contracts and controlled tests |
| Infrastructure | `terraform/` | Plan/review in an authorized environment |
| Saved-data analysis | Separate analysis package | Preserve original files; record formulas, denominators, exclusions |

## Preserve runtime paths

Worker filenames are used for plugin discovery. Keep deferred prototypes outside that directory. A directory reorganization must consider imports, package layouts, analysis paths, and Terraform addresses before changing them.

## Tests in the repository

Scout files expose their own `--test` paths; the orchestrator has a separate suite, and API/Report have handler tests. The benchmark contains a synthetic app and runner. Inspect fixture isolation before executing a suite; its presence alone is not evidence of current success. No scanner tests were executed as part of this documentation work.

## Documentation workflow

1. Read the actual source path and distinguish implementation from historical evidence.
2. Update the relevant page and cross-references together.
3. Build with `mkdocs build --strict` using the documented environment.
4. Review tables, code blocks, navigation, search, light/dark themes, and mobile widths.
5. Keep raw evidence and generated output out of the site source.
6. Review the diff before committing; publication is a separate manual operation.

## Reporting a concern

Describe the component, revision, expected behavior, and a minimal sanitized example. Do not put real keys, third-party response bodies, or identifiable vulnerability evidence into a public issue. No private disclosure inbox or response-time commitment is invented by this documentation.

[Rights](rights.md) · [Publication and research ethics](ethics.md)
