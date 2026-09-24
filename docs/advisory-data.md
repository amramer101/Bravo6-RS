# Advisory data paths

BRAVO6 contains two advisory-data workflows. Their presence does not prove which snapshot was used by a historical cloud run.

| Path | Producer | Intended use |
| --- | --- | --- |
| Manual snapshot | `src/cve-pipeline/cve_etl.py` | Produce a static dataset for an explicitly selected baseline |
| Scheduled cache | `src/worker/osv_cve_sync.py`, Worker timer | Refresh Table Storage data for configured runtime reads |

The Worker timer is configured for a twelve-hour schedule. `CVE_TABLE_ENDPOINT` identifies the table service endpoint and `CVE_TABLE_NAME` selects the table. The frontend-library scout contains cache and snapshot loading logic. Inspect that selection logic before describing a particular run's source.

## Version semantics

OSV affected-version enumerations and version-range events are different structures. An enumeration of two affected releases does not imply that all intermediate releases are affected. The exact unsupported Axios match in the archived experiment is treated separately in [sensitivity analysis](research.md).

## Provenance for future experiments

Record the selected data path, source retrieval time, snapshot digest, schema/parser version, and deployed build identifier. Preserve the actual dataset when rights and storage policy permit. Refreshing data now cannot retrospectively establish a historical snapshot.

## Rights and scope

Advisory records have external provenance; they are not made exclusively owned by the project's rights notice. The repository's dependency inventory is a list of requirements, not a resolved software bill of materials or a completed license review. Do not regenerate the dataset as part of reproducing the saved analysis.

[OSV schema](https://ossf.github.io/osv-schema/) describes the external record format.


## Implementation and evidence

- [src/cve-pipeline/cve_etl.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/cve-pipeline/cve_etl.py)
- [src/worker/osv_cve_sync.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/osv_cve_sync.py)
- [src/worker/test_02_frontend_libs.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/test_02_frontend_libs.py)
- [src/worker/function_app.py](https://github.com/amramer101/Bravo6-RS/blob/main/src/worker/function_app.py)

Source links follow `main`. They describe the inspectable implementation, not a verified digest of the historical deployment.
