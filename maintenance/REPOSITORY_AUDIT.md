# Repository audit and cleanup — tasks 1 and 2

## Scope

Read-only source/history review followed by repository metadata, navigation, ignore-rule, and automation edits. No scanner code edits, scanner tests, target requests, Azure commands, Git commits, pushes, index changes, or history rewriting. The initial local snapshot contained 142 tracked files and 178 commits reachable from local refs; 939 historical blobs were examined using a small credential-pattern scan. Remote refs were not refreshed, and remote settings, PR attachments, Actions artifacts, and unreachable objects were not audited.

## Findings

| Finding | Evidence | Disposition |
| --- | --- | --- |
| Existing proprietary rights notice | `LICENSE` | Preserved; Public does not mean open source |
| Existing MkDocs site and automatic publication | `mkdocs.yml`, `.github/workflows/docs.yml` | Reuse site; build separated from manual publication |
| Outdated architecture/security claims | `README.md`, `docs/architecture-overview.md`, `docs/security-identity.md` | Entry-point notice added; full reconciliation in task 3 |
| Cost and deployment statements conflict across docs | `docs/cost-finops.md`, `DEPLOYMENT_NOTES.md` | Retained as historical material pending rewrite |
| Worker discovery depends on filenames | `src/worker/main_scanner.py`, `discover_plugins()` | Runtime files and locations preserved |
| Soft-failing CI can yield misleading badges | Python and Terraform workflow steps | Explicitly documented; no test-success badge approved |
| Terraform CI previously triggered cloud access on Terraform pushes | `.github/workflows/terraform_ci.yml` | Manual dispatch only |
| Raw archive and generated outputs were untracked but not excluded | Initial `git status` | Explicit ignore rules; retained on disk |
| Two untracked historical evaluation tools | `src/worker/evaluation/run_gateway_batch.py`, `analyze_gateway_batch.py` | Preserved and ignored pending review; runner embeds endpoints, analysis has superseded claims |
| Broad worker JSON ignores also matched future source configuration | `.gitignore` | Narrowed to generated directories |
| Stale ignore comments claimed unavailable committed experiment outputs | `.gitignore`, initial tracked inventory | Replaced with explicit local-evidence policy |
| Site-level records and target lists are already tracked | `src/worker/evaluation/data/`, `validation-benchmark/cross-tool-calibration/` | Kept unchanged; separate data-release review required |

## Credential-pattern review

Six historical blobs were flagged. Manual context review identified AWS example keys in tests, synthetic benchmark strings across three app versions, a quoted example in an advisory cache, and one old `local.settings.json` containing emulator/runtime/namespace configuration. No active credential was established by these findings. No candidate was tested against a service. Pattern matching cannot prove that a repository or its history is free of secrets.

The audit also found operational identifiers in historical documentation. Such identifiers are not automatically secrets, but should not be repeated in public examples. Detailed findings, paths, and original-file hashes remain under ignored `output/repository-audit/`; no credential values are reproduced in this public report.

Dependency requirements are listed in `dependency_inventory.csv`; versions of runtime dependencies are ranges, so a complete resolved SBOM and license notice review cannot be inferred from these declarations. No external dependency code was vendored or relicensed.

## Organization decisions

Keep `src/`, `terraform/`, `validation-benchmark/`, and `future-work/` stable. Add concise component READMEs and a root `REPOSITORY_MAP.md`. Keep maintenance decisions outside the website source; keep raw experiments and generated manuscript packages local. This avoids path breakage and does not pretend to fix detector behavior through rearrangement.

## Verification and remaining scope

Local validation covers Git diff whitespace, workflow/config syntax and publication guards, ignore-rule behavior, documentation build and new local links, and SHA-256 preservation of the 1,725 pre-existing protected source/evidence files. Detailed results are retained in the local audit report. Scanner tests and infrastructure checks are intentionally outside this task.

Task 3 must rewrite the existing README and website claims against the revised paper; task 4 handles complete visual/site review; task 5 selects release artifacts and publishes. Existing site-level data, third-party provenance, and obsolete deployment examples remain explicit release-review items. These tasks are not silently treated as complete by repository cleanup.

## Documentation follow-up — tasks 3 and 4

The root README, active/deferred component READMEs, and twenty-one MkDocs pages have been rewritten against source and reviewed research results. Older deployment notes remain an explicitly labeled historical record. New local SVG assets, responsive styling, search, light/dark themes, and manual-publication boundaries replace the former presentation. Local build, link, content, and browser verification are recorded in ignored `output/docs-review/`.

The author subsequently confirmed no historical permissions, institutional approval, notifications, or manual review; the website now states that explicitly. The already-built paper PDF still requires the corresponding final ethics wording update before submission. No original paper artifacts are silently regenerated in this documentation task. Task 5 (selected release artifacts, final paper links and publication) remains outstanding.
