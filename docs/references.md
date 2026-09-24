# Evidence and reading guide

## Internal evidence hierarchy

| Question | Most relevant source |
| --- | --- |
| What does the current handler do? | Source implementation and configuration |
| What happened in the recorded batch? | Preserved manifest, result documents, and run log |
| How was an aggregate derived? | Offline analysis code, inputs, exclusion ledger, and denominator rules |
| Was a historical build identical to current source? | Requires a deployment artifact/digest; not currently established |
| Were sites authorized or manually reviewed? | Author's historical disclosure, not scan output or file hashes |

The local review packages contain a claim register, integrity inventory, per-site analytical index, and bootstrap/coverage outputs. They are not linked as public downloads because they have not been released. This site's aggregate numbers are transcribed from those reviewed artifacts; current repository source links alone are insufficient to regenerate all historical outputs.

## Primary references

- [OSV schema](https://ossf.github.io/osv-schema/): affected versions and range structures.
- [OpenSSL s_client](https://docs.openssl.org/3.0/man1/openssl-s_client/): distinct TLS 1.3 ciphersuite configuration.
- [PyPA name normalization](https://packaging.python.org/en/latest/specifications/name-normalization/): valid package-name syntax.
- [ZAP passive scanning](https://www.zaproxy.org/docs/desktop/start/features/pscan/): passive analysis within a broader security tool.
- [MDN HTTP Observatory](https://developer.mozilla.org/en-US/observatory): HTTP configuration assessment.
- [Tranco](https://tranco-list.eu/): ranked sampling frames.
- [Wilson, 1927](https://doi.org/10.1080/01621459.1927.10502953): interval estimation for proportions.
- [Cohen, 1960](https://doi.org/10.1177/001316446002000104): agreement beyond chance.

External methods and specifications explain interpretation; they do not independently validate the archived BRAVO6 outputs.
