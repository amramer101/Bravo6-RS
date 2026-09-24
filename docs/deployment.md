# Configuration and deployment boundary

This is a source-oriented guide for the owner or an authorized operator. It does not assert that the current checkout was live-deployed, and documentation access does not grant a license to operate the software.

## Package boundaries

The API, Worker, and Report directories each contain their Function entry point, `host.json`, and runtime requirements. The Worker expects its scout modules alongside the orchestrator. Deferred code is not part of these packages.

## Application settings

| Setting | Consumer | Meaning |
| --- | --- | --- |
| `ServiceBusConnection__fullyQualifiedNamespace` | Gateway, Worker trigger | Namespace FQDN for identity-based Service Bus access |
| `SERVICE_BUS_QUEUE_NAME` | Gateway | Queue name; defaults to `bravo6-queue` |
| `COSMOS_URL` | Worker, Report | Cosmos endpoint |
| `COSMOS_DATABASE` | Worker, Report | Database; default `bravo6-db` |
| `COSMOS_CONTAINER` | Worker, Report | Container; default `scans` |
| `CVE_TABLE_ENDPOINT` | Advisory synchronization/cache | Table service endpoint |
| `CVE_TABLE_NAME` | Advisory synchronization/cache | Table selection; default `cveCache` |

The Worker trigger literally names `bravo6-queue`. Changing only the Gateway/Terraform queue setting can therefore break alignment. The Gateway also receives Cosmos settings in Terraform even though the active intake handler does not use that database path.

Use placeholders when documenting settings. Do not commit account credentials, real local settings, state, or plans. Function host storage and deployment-container identity must be reviewed for the selected hosting configuration; earlier deployment notes contain troubleshooting history, not universal setup instructions.

## Before an authorized deployment

1. Select the intended source revision and record its digest.
2. Review caller authentication, report access, network boundaries, traffic scope, and rights.
3. Review backend state ownership and environment-specific Terraform inputs.
4. Align queue naming, identities, resource endpoints, and advisory selection.
5. Inspect a plan in the authorized environment and review its side effects.
6. Deploy and validate in a controlled environment, preserving actual logs and versions.

These steps are guidance, not a record of actions performed here. The repository's manual Terraform workflows contact Azure; applying a saved plan changes resources. No deployment commands are part of the documentation quickstart.

## Documentation-only local setup

```bash
python3 -m venv .venv-docs
.venv-docs/bin/python -m pip install -r requirements-docs.txt
.venv-docs/bin/mkdocs build --strict
.venv-docs/bin/mkdocs serve --dev-addr 127.0.0.1:8000
```

Dependency installation requires package access. The site build uses local assets and does not need scanner dependencies, Azure credentials, or target traffic. Preview is a local documentation server, not a scanner endpoint.


## Implementation and evidence

- [src/api/function_app.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/api/function_app.py)
- [src/worker/function_app.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/function_app.py)
- [src/report/function_app.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/report/function_app.py)
- [terraform/modules/api_function/main.tf](https://github.com/amramer101/Bravo6-RS/blob/main/terraform/modules/api_function/main.tf)
- [terraform/modules/function_app/main.tf](https://github.com/amramer101/Bravo6-RS/blob/main/terraform/modules/function_app/main.tf)

Source links follow `main`. They describe the inspectable implementation, not a verified digest of the historical deployment.
