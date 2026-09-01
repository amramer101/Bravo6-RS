# Bravo6 Scanner (`src/worker/`)

The scanner itself: an async orchestrator (`main_scanner.py`) plus ten auto-discovered scout
plugins. Every request the scanner makes is passive (GET/HEAD/OPTIONS/DNS — the same traffic a
normal page load or DNS lookup produces).

## Scouts

| Module | Checks |
|---|---|
| `test_01_secrets.py` | Hardcoded secrets/API keys in inline and external JS, referenced config files |
| `test_02_frontend_libs.py` | Outdated/vulnerable frontend libraries (SCA), CVE correlation via `cve_database_v2.csv` |
| `test_03_cookies.py` | Cookie security: `HttpOnly`/`Secure`/`SameSite`, `__Host-`/`__Secure-` prefix validation, long-lived session cookies |
| `test_04_ssl_tls.py` | TLS/certificate posture: protocol/cipher support, cert expiry, chain trust, mixed content |
| `test_05_security_headers.py` | HTTP security headers: CSP, HSTS, clickjacking protection, and hardening headers |
| `test_06_info_disclosure.py` | Exposed sensitive files/paths, HTML comments, tech fingerprinting, robots.txt |
| `test_07_email_security.py` | SPF/DMARC/DKIM (pure DNS — does not contact the target's web server) |
| `test_08_cors.py` | CORS misconfiguration: wildcard-with-credentials, arbitrary-origin reflection (one synthetic cross-origin preflight probe) |
| `test_09_sri.py` | Subresource Integrity: cross-origin `<script>`/`<link rel="stylesheet">` missing `integrity`, or `integrity` present without a valid `crossorigin` (zero new requests — reparses the cached HTML) |
| `test_10_hallucinated_deps.py` | AI-introduced supply-chain risk: if a dependency manifest (`package.json`/`requirements.txt`/lockfiles) is exposed on the web root, cross-checks each declared package name against npm/PyPI — a confirmed registry 404 is a "hallucinated" (slopsquattable) dependency |

There is no `test_03` collision with anything named "mixed content" — that check lives, unwired,
in `../../future-work/code-scan/`.

## Running a scan

```bash
python3 main_scanner.py https://example.com
python3 main_scanner.py https://example.com --cve-csv-url ./cve_database_v2.csv   # enable CVE correlation
```

Results are saved as JSON under `results/` (gitignored — ad-hoc/manual runs only; see
`evaluation/` below for the reproducible dataset).

## Running the test suites

Every scout (and `main_scanner.py` itself) bundles its own regression suite:

```bash
python3 main_scanner.py --test
python3 test_01_secrets.py --test
python3 test_02_frontend_libs.py --test
python3 test_03_cookies.py --test
python3 test_04_ssl_tls.py --test
python3 test_05_security_headers.py --test
python3 test_06_info_disclosure.py --test
python3 test_07_email_security.py --test
python3 test_08_cors.py --test
python3 test_09_sri.py --test
python3 test_10_hallucinated_deps.py --test
```

## Running the evaluation harness

See [`evaluation/README.md`](evaluation/README.md) for the full reproducible pipeline (Tranco
sampling, batch scanning, aggregation) that produces the project's evaluation dataset.

## Dependencies

```bash
pip install -r requirements.txt
```
