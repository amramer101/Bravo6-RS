# Bravo6 — Scout Worker: 13 Script Prompts

> **Instructions:** كل prompt مستقل — ابعته لـ AI وهو هيعمل الـ script كاملة.
> بعد ما تعمل الـ 13 script، اجمعهم في `scout_worker.py` واحدة باستخدام `asyncio.gather()`.

---

## الـ Shared Context (ابعته مع كل prompt)

```
You are writing a Python security scanning module for a platform called Bravo6.

Rules:
- All functions must be async (use aiohttp, not requests)
- Function signature: async def run(url: str) -> dict
- Return format MUST be exactly:
  {
    "test_name": "...",
    "status": "pass" | "fail" | "warning" | "error",
    "severity": "critical" | "high" | "medium" | "low" | "info",
    "title": "...",
    "description": "...",
    "evidence": "...",   # actual proof found
    "remediation": "..."
  }
- Handle ALL exceptions — never let the script crash
- Timeout: 10 seconds max per request
- User-Agent header: "Bravo6-Scanner/1.0"
- Input is always a clean domain or URL (e.g. "example.com")
- Normalize the URL at the start: if no scheme, add https://
- Test on real websites — write production-quality code
```

---

## Script 01 — Security Headers

```
[SHARED CONTEXT ABOVE]

Write a Python async module: test_security_headers.py

Task: Check the HTTP response headers of the target URL for missing or misconfigured security headers.

Check ALL of these headers:
1. Strict-Transport-Security (HSTS)
   - Must exist
   - Must include max-age >= 31536000
   - Bonus check: includeSubDomains present?

2. X-Frame-Options
   - Must be DENY or SAMEORIGIN
   - If ALLOWALL → critical

3. Content-Security-Policy (CSP)
   - Must exist
   - If exists but contains "unsafe-inline" or "unsafe-eval" → warning
   - If missing entirely → high severity

4. X-Content-Type-Options
   - Must be "nosniff"

5. Referrer-Policy
   - Must exist
   - Acceptable values: no-referrer, strict-origin, strict-origin-when-cross-origin
   - If "unsafe-url" → high

6. Permissions-Policy
   - Must exist (informational if missing)

Logic:
- Make one GET request, check all headers from the response
- For each missing/misconfigured header, create a finding
- Calculate overall status: if any critical/high → "fail", if only medium → "warning", all good → "pass"
- Evidence field: show the actual header value found (or "Header not present")

Return a list of findings, one per header issue found.
Final return wraps them:
{
  "test_name": "security_headers",
  "findings": [...],  # list of individual header findings
  "overall_status": "pass|fail|warning",
  "headers_checked": 6,
  "headers_failed": N
}
```

---

## Script 02 — SSL/TLS Health Check

```
[SHARED CONTEXT ABOVE]

Write a Python async module: test_ssl.py

Task: Analyze the SSL/TLS configuration of the target domain.

Use Python's built-in ssl module + socket (not aiohttp for this one — use asyncio with executor for blocking ssl calls).

Check ALL of the following:

1. Certificate Validity
   - Is the certificate expired? → critical
   - Expires in < 30 days? → high
   - Expires in < 90 days? → medium
   - Show exact expiry date in evidence

2. Certificate Chain
   - Is it self-signed? → high
   - Is the CN/SAN matching the domain? → critical if mismatch

3. TLS Protocol Versions
   - Connect and check what protocol is negotiated
   - If SSLv3 supported → critical
   - If TLS 1.0 supported → high
   - If TLS 1.1 supported → medium
   - TLS 1.2 only → warning (recommend 1.3)
   - TLS 1.3 → pass

4. Cipher Suite
   - If NULL cipher → critical
   - If RC4 → critical
   - If DES/3DES → high
   - If SHA1 signed → medium

Implementation notes:
- Use asyncio.get_event_loop().run_in_executor() for blocking ssl calls
- Try to connect with different ssl versions to detect what's supported
- Handle connection refused, timeout, certificate errors gracefully

Return format:
{
  "test_name": "ssl_tls",
  "status": "pass|fail|warning|error",
  "severity": "...",
  "title": "...",
  "description": "...",
  "evidence": {
    "cert_expiry": "...",
    "tls_version": "...",
    "issuer": "...",
    "subject": "..."
  },
  "remediation": "..."
}
```

---

## Script 03 — Secrets Detection (Vibe Check)

```
[SHARED CONTEXT ABOVE]

Write a Python async module: test_secrets.py

Task: Fetch the target page HTML, find all linked JavaScript files, download them, and scan for hardcoded secrets and sensitive data.

Step 1: Fetch the HTML of the target URL
Step 2: Parse HTML with BeautifulSoup to find all <script src="..."> tags
Step 3: Download each JS file (max 10 files, skip files > 500KB)
Step 4: Run regex patterns on the combined JS content

Regex patterns to detect (compile these):

AWS_ACCESS_KEY = r'AKIA[0-9A-Z]{16}'
AWS_SECRET_KEY = r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']'
GOOGLE_API_KEY = r'AIza[0-9A-Za-z\-_]{35}'
FIREBASE_KEY = r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'
PRIVATE_KEY = r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'
DB_CONN_STRING = r'(?i)(mongodb|mysql|postgresql|redis):\/\/[^\s"\'<>]+'
GENERIC_SECRET = r'(?i)(secret|password|passwd|api_key|apikey|token|auth)[\s]*[=:]["\'`]([^\s"\'`]{8,})'
GITHUB_TOKEN = r'ghp_[A-Za-z0-9]{36}'
SLACK_TOKEN = r'xox[baprs]-([0-9a-zA-Z]{10,48})'
JWT_TOKEN = r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*'
STRIPE_KEY = r'(?:r|s)k_live_[0-9a-zA-Z]{24}'

For each match found:
- Record: pattern name, matched value (truncate to first 20 chars + "..."), which file it was found in, line number
- Severity: critical for AWS/Private Keys/Stripe live keys, high for everything else

Entropy check (bonus):
- Any string > 20 chars that looks random (high Shannon entropy > 4.5) near words like "key", "token", "secret" → flag as "Potential Secret (High Entropy)"

Return:
{
  "test_name": "secrets_detection",
  "status": "fail" if any found else "pass",
  "severity": "critical" if critical found else "high" if high found else "info",
  "title": "Hardcoded Secrets Detected" or "No Secrets Found",
  "description": "...",
  "evidence": [
    {"type": "AWS Access Key", "file": "app.js", "preview": "AKIAIOSFODNN7..."},
    ...
  ],
  "remediation": "Move all secrets to environment variables. Use Azure Key Vault or AWS Secrets Manager. Rotate all exposed credentials immediately.",
  "js_files_scanned": N,
  "secrets_found": N
}
```

---

## Script 04 — Frontend Library Audit

```
[SHARED CONTEXT ABOVE]

Write a Python async module: test_js_libraries.py

Task: Identify JavaScript libraries used on the target page and check for known vulnerable versions.

Step 1: Fetch the HTML
Step 2: Parse all <script src> tags and inline <script> content
Step 3: Identify libraries from:
  - File names (jquery-3.2.1.min.js → jQuery 3.2.1)
  - Script content patterns (look for version strings like jQuery v3.2.1)
  - Known CDN URL patterns

Step 4: Check detected versions against this known vulnerable versions database (hardcode this):

VULNERABLE_LIBS = {
    "jquery": {
        "vulnerable_below": "3.5.0",
        "cve": "CVE-2020-11022, CVE-2020-11023",
        "description": "XSS via HTML passed to manipulation methods",
        "severity": "high"
    },
    "bootstrap": {
        "vulnerable_below": "4.3.1",
        "cve": "CVE-2019-8331",
        "description": "XSS in tooltip/popover data-template attribute",
        "severity": "medium"
    },
    "angular": {
        "vulnerable_below": "1.8.0",
        "cve": "CVE-2019-14863",
        "description": "XSS via ng-attr-* directives",
        "severity": "high"
    },
    "lodash": {
        "vulnerable_below": "4.17.21",
        "cve": "CVE-2021-23337",
        "description": "Command injection via template function",
        "severity": "high"
    },
    "moment": {
        "vulnerable_below": "2.29.4",
        "cve": "CVE-2022-24785",
        "description": "Path traversal vulnerability",
        "severity": "high"
    },
    "axios": {
        "vulnerable_below": "0.21.2",
        "cve": "CVE-2021-3749",
        "description": "ReDoS via crafted HTTP response",
        "severity": "medium"
    }
}

Version comparison: use packaging.version for accurate semver comparison

Return:
{
  "test_name": "js_library_audit",
  "status": "fail|pass|warning",
  "severity": "...",
  "title": "...",
  "description": "...",
  "evidence": [
    {
      "library": "jQuery",
      "version_detected": "3.2.1",
      "vulnerable": true,
      "cve": "CVE-2020-11022",
      "severity": "high"
    }
  ],
  "libraries_detected": N,
  "vulnerable_count": N,
  "remediation": "Update all libraries to latest stable versions."
}
```

---

## Script 05 — Mixed Content Detection

```
[SHARED CONTEXT ABOVE]

Write a Python async module: test_mixed_content.py

Task: Check if an HTTPS page loads any resources over insecure HTTP.

Step 1: Fetch the HTML of the target (ensure it's HTTPS)
Step 2: If target is HTTP → return warning "Site not using HTTPS, mixed content irrelevant"
Step 3: Parse HTML with BeautifulSoup and find ALL of these:
  - <img src="http://...">
  - <script src="http://...">
  - <link href="http://..."> (stylesheets)
  - <iframe src="http://...">
  - <audio src="http://...">
  - <video src="http://...">
  - <source src="http://...">
  - CSS url() references in <style> tags with http://

Step 4: Categorize findings:
  - Active mixed content (scripts, iframes) → critical: these CAN be used to attack the user
  - Passive mixed content (images, audio, video) → medium: these downgrade connection

Step 5: Check for Content-Security-Policy header:
  - If CSP has "block-all-mixed-content" or "upgrade-insecure-requests" → note this as mitigation

Return:
{
  "test_name": "mixed_content",
  "status": "fail|pass",
  "severity": "critical|medium|pass",
  "title": "...",
  "description": "...",
  "evidence": [
    {"type": "script", "url": "http://cdn.example.com/jquery.js", "severity": "critical"},
    {"type": "image", "url": "http://img.example.com/logo.png", "severity": "medium"}
  ],
  "active_mixed_count": N,
  "passive_mixed_count": N,
  "remediation": "Replace all http:// resource URLs with https://. Add 'upgrade-insecure-requests' to Content-Security-Policy."
}
```

---

## Script 06 — Information Disclosure

```
[SHARED CONTEXT ABOVE]

Write a Python async module: test_info_disclosure.py

Task: Find server/technology information that is unnecessarily exposed.

Check ALL of the following in one GET request:

1. Response Headers (check for version numbers):
   - Server: header → "Apache/2.4.49" exposes version → high
   - X-Powered-By: header → "PHP/7.2.0" → high
   - X-AspNet-Version → medium
   - X-Generator → medium
   - Via header with internal IPs → medium

2. HTML Source Code:
   - HTML comments containing: version numbers, internal paths, developer notes, server names, TODO/FIXME
   - Meta generator tags: <meta name="generator" content="WordPress 5.8">
   - Hidden form fields with internal data

3. Error Page Detection:
   - Request a non-existent page (/bravo6-test-404-xyz)
   - If error page shows: stack trace, file paths, framework version, database errors → critical
   - If custom 404 page → good

4. Directory Listing Check:
   - Request /images/ or /assets/ or /static/
   - If response shows directory listing (contains "Index of /") → high

Pattern for version detection in headers:
VERSION_PATTERN = r'\d+\.\d+\.?\d*'

Return:
{
  "test_name": "information_disclosure",
  "status": "fail|pass|warning",
  "severity": "...",
  "title": "...",
  "description": "...",
  "evidence": [
    {"location": "Server header", "value": "Apache/2.4.49", "risk": "Version exposed"},
    {"location": "HTML comment", "value": "<!-- built with WordPress 5.8 -->", "risk": "CMS version exposed"}
  ],
  "remediation": "Remove version information from all HTTP headers. Configure custom error pages. Disable directory listing."
}
```

---

## Script 07 — Cookie Security Flags

```
[SHARED CONTEXT ABOVE]

Write a Python async module: test_cookies.py

Task: Analyze all cookies set by the target website for missing security flags.

Step 1: Make a GET request and capture Set-Cookie headers
Step 2: Also follow redirects and capture cookies at each step
Step 3: For each cookie found, check:

  A. HttpOnly flag
     - Missing → high (JavaScript can read the cookie → XSS can steal sessions)

  B. Secure flag
     - Missing on HTTPS site → high (cookie can be sent over HTTP)

  C. SameSite attribute
     - Missing → medium (CSRF risk)
     - SameSite=None without Secure → high
     - SameSite=Lax → acceptable
     - SameSite=Strict → best

  D. Cookie Name Analysis
     - If cookie name contains "session", "auth", "token", "jwt", "user" → it's sensitive → elevate severity for missing flags

  E. Secure Cookie over HTTP
     - If Secure flag set but site is HTTP → flag as misconfiguration

Step 4: Use http.cookiejar or manually parse Set-Cookie headers
Parse with regex: r'Set-Cookie:\s*([^;]+)(.*)'

Return:
{
  "test_name": "cookie_security",
  "status": "fail|pass|warning",
  "severity": "...",
  "title": "...",
  "description": "...",
  "evidence": [
    {
      "cookie_name": "sessionid",
      "issues": ["Missing HttpOnly", "Missing SameSite"],
      "severity": "high",
      "is_sensitive": true
    }
  ],
  "cookies_analyzed": N,
  "cookies_with_issues": N,
  "remediation": "Set HttpOnly, Secure, and SameSite=Strict flags on all cookies. Especially critical for session and authentication cookies."
}
```

---

## Script 08 — Email Security (SPF / DMARC / DKIM)

```
[SHARED CONTEXT ABOVE]

Write a Python async module: test_email_security.py

Task: Check DNS records for email authentication mechanisms to prevent domain spoofing.

Use dnspython library (dns.resolver). Run DNS queries in asyncio executor.

Extract the root domain from the input URL first.
Example: "https://blog.example.com/page" → "example.com"

Check ALL THREE:

1. SPF Record
   - Query TXT records for the domain
   - Look for record starting with "v=spf1"
   - If missing → high (anyone can send email as this domain)
   - If exists but has "+all" → critical (allows all servers to send)
   - If has "?all" → medium (neutral, not recommended)
   - If has "~all" (softfail) → low
   - If has "-all" (fail) → pass (best)
   - Evidence: show the actual SPF record

2. DMARC Record
   - Query TXT records for _dmarc.example.com
   - If missing → high
   - If exists, check p= value:
     - p=none → medium (monitoring only, no enforcement)
     - p=quarantine → low (good)
     - p=reject → pass (best)
   - Also check: rua= (reporting address) present?
   - Evidence: show full DMARC record

3. DKIM
   - Try common selectors: default, google, mail, dkim, k1, selector1, selector2
   - Query TXT records for {selector}._domainkey.{domain}
   - If at least one found → pass
   - If none found → info (DKIM might exist with unknown selector)
   - Evidence: which selector found and key type

Return:
{
  "test_name": "email_security",
  "status": "fail|pass|warning",
  "overall_severity": "...",
  "findings": {
    "spf": {"status": "pass|fail|warning", "record": "...", "severity": "...", "issue": "..."},
    "dmarc": {"status": "pass|fail|warning", "record": "...", "severity": "...", "policy": "..."},
    "dkim": {"status": "pass|not_found", "selector_found": "...", "severity": "info"}
  },
  "title": "...",
  "description": "...",
  "remediation": "Add SPF record with -all. Set DMARC with p=reject. Configure DKIM signing."
}
```

---

## Script 09 — Subdomain Takeover Check

```
[SHARED CONTEXT ABOVE]

Write a Python async module: test_subdomain_takeover.py

Task: Check DNS CNAME records for the target domain and common subdomains to identify potential subdomain takeover vulnerabilities.

Step 1: Extract root domain from URL
Step 2: Check these common subdomains:
  SUBDOMAINS = ["www", "mail", "blog", "dev", "staging", "api", "cdn", "static", "assets", "media", "help", "support", "docs", "app", "dashboard"]

Step 3: For each subdomain, query CNAME records using dnspython

Step 4: If CNAME points to a known cloud service, check if it's unclaimed:

TAKEOVER_FINGERPRINTS = {
    "amazonaws.com": {
        "error_pattern": "NoSuchBucket|The specified bucket does not exist",
        "service": "AWS S3",
        "severity": "critical"
    },
    "github.io": {
        "error_pattern": "There isn't a GitHub Pages site here",
        "service": "GitHub Pages",
        "severity": "critical"
    },
    "herokuapp.com": {
        "error_pattern": "No such app|There is no app configured at that hostname",
        "service": "Heroku",
        "severity": "critical"
    },
    "azurewebsites.net": {
        "error_pattern": "404 Web Site not found",
        "service": "Azure Web Apps",
        "severity": "critical"
    },
    "netlify.app": {
        "error_pattern": "Not Found - Request ID",
        "service": "Netlify",
        "severity": "high"
    },
    "readthedocs.io": {
        "error_pattern": "unknown to Read the Docs",
        "service": "ReadTheDocs",
        "severity": "medium"
    }
}

Step 5: For each CNAME that matches a cloud service:
  - Make HTTP request to the subdomain
  - Check if response body contains the error_pattern
  - If yes → potential takeover vulnerability

Step 6: DNS NXDOMAIN check:
  - If subdomain returns NXDOMAIN but has dangling reference → flag it

Return:
{
  "test_name": "subdomain_takeover",
  "status": "fail|pass|warning",
  "severity": "...",
  "title": "...",
  "description": "...",
  "evidence": [
    {
      "subdomain": "blog.example.com",
      "cname": "example.github.io",
      "service": "GitHub Pages",
      "vulnerable": true,
      "severity": "critical"
    }
  ],
  "subdomains_checked": N,
  "vulnerable_count": N,
  "remediation": "Remove DNS records pointing to unclaimed cloud resources. Claim the resource or delete the CNAME record."
}
```

---

## Script 10 — Robots.txt Analysis

```
[SHARED CONTEXT ABOVE]

Write a Python async module: test_robots.py

Task: Fetch and analyze robots.txt to find sensitive paths that are intentionally hidden from crawlers.

Step 1: Fetch /robots.txt from the target domain
Step 2: If 404 → return info finding (no robots.txt)
Step 3: Parse all Disallow: directives

Step 4: Flag sensitive paths based on these patterns:

SENSITIVE_PATTERNS = {
    r'/(admin|administrator|wp-admin|dashboard|control)': ("Admin Panel", "high"),
    r'/backup|/bak|/\.backup': ("Backup Directory", "critical"),
    r'/config|/configuration|/settings': ("Config Directory", "high"),
    r'/\.env|/env': ("Environment File", "critical"),
    r'/api/|/api$': ("API Endpoint", "medium"),
    r'/private|/secret|/hidden|/internal': ("Private Directory", "high"),
    r'/db|/database|/sql': ("Database Directory", "critical"),
    r'/upload|/uploads|/files': ("Upload Directory", "medium"),
    r'/phpmyadmin|/pma|/mysqladmin': ("Database Admin Panel", "critical"),
    r'/\.git|/\.svn|/\.hg': ("Version Control Directory", "critical"),
    r'/tmp|/temp|/cache': ("Temporary Directory", "medium"),
    r'/logs?|/log': ("Log Directory", "high"),
    r'/wp-content|/wp-includes': ("WordPress Core Directory", "medium"),
    r'/jenkins|/jira|/confluence': ("Internal Tool", "high"),
}

Step 5: Also check:
  - Is robots.txt exposing the full sitemap location? (informational)
  - Does it list /sitemap.xml? (good practice — informational)
  - Are there wildcard blocks (*) or specific bot blocks?

Step 6: For each sensitive Disallow path found:
  - Make a request to that path
  - If it returns 200 → escalate severity (path is actually accessible)
  - If 403 → exists but blocked (still flag, lower severity)
  - If 404 → path mentioned but doesn't exist

Return:
{
  "test_name": "robots_txt",
  "status": "fail|pass|info",
  "severity": "...",
  "title": "...",
  "description": "...",
  "evidence": [
    {
      "path": "/admin",
      "pattern_matched": "Admin Panel",
      "http_status": 200,
      "severity": "high",
      "note": "Path is publicly accessible"
    }
  ],
  "total_disallow_rules": N,
  "sensitive_paths_found": N,
  "remediation": "Remove sensitive paths from robots.txt. Robots.txt is public — listing paths here reveals your site structure to attackers."
}
```

---

## Script 11 — CORS Misconfiguration

```
[SHARED CONTEXT ABOVE]

Write a Python async module: test_cors.py

Task: Test the CORS configuration of the target to find misconfigurations that allow unauthorized cross-origin requests.

CORS works by the browser sending an Origin header and checking if the server's response allows it.

Step 1: Make a request with a malicious origin:
  Headers: {"Origin": "https://evil-attacker.com"}

Step 2: Check response headers:
  - Access-Control-Allow-Origin (ACAO)
  - Access-Control-Allow-Credentials (ACAC)

Step 3: Analyze the response:

CASE 1 — ACAO: * (wildcard)
  - Without credentials → medium (any site can read responses)
  - Cannot be used with ACAC: true (browser blocks it)

CASE 2 — ACAO: https://evil-attacker.com (reflects our origin)
  - Without ACAC → medium
  - WITH ACAC: true → CRITICAL (any site can make authenticated requests)

CASE 3 — ACAO: null
  - If ACAC: true → high (sandbox iframes can exploit this)

CASE 4 — No ACAO header → pass

Step 4: Test with additional origins:
  - "null" (for sandbox exploit)
  - "https://example.com.evil.com" (subdomain bypass attempt)
  - "https://notexample.com" (simple wrong domain)

Step 5: Check preflight (OPTIONS request):
  - Send OPTIONS with:
    Origin: https://evil-attacker.com
    Access-Control-Request-Method: POST
    Access-Control-Request-Headers: Authorization
  - Check if Access-Control-Allow-Methods includes dangerous methods

Return:
{
  "test_name": "cors",
  "status": "fail|pass|warning",
  "severity": "critical|high|medium|info",
  "title": "...",
  "description": "...",
  "evidence": {
    "tested_origin": "https://evil-attacker.com",
    "acao_header": "https://evil-attacker.com",
    "acac_header": "true",
    "verdict": "Origin reflected with credentials — critical CORS misconfiguration"
  },
  "remediation": "Maintain an explicit allowlist of trusted origins. Never reflect the Origin header directly. Never combine wildcard with credentials."
}
```

---

## Script 12 — HTTP Methods Check

```
[SHARED CONTEXT ABOVE]

Write a Python async module: test_http_methods.py

Task: Discover which HTTP methods the server supports and flag dangerous ones.

Step 1: Send OPTIONS request to the target URL
Step 2: Check Allow and Access-Control-Allow-Methods headers

Step 3: Also try sending each dangerous method directly and check response:

DANGEROUS_METHODS = {
    "TRACE": {
        "severity": "medium",
        "reason": "TRACE enables Cross-Site Tracing (XST) attacks. Combined with XSS, it can steal HttpOnly cookies."
    },
    "PUT": {
        "severity": "high",
        "reason": "PUT method may allow uploading arbitrary files to the server."
    },
    "DELETE": {
        "severity": "high",
        "reason": "DELETE method may allow deleting server resources."
    },
    "CONNECT": {
        "severity": "medium",
        "reason": "CONNECT can be used for proxy tunneling attacks."
    },
    "DEBUG": {
        "severity": "critical",
        "reason": "DEBUG is a Microsoft IIS method that can enable remote debugging and expose sensitive info."
    }
}

SAFE_METHODS = ["GET", "POST", "HEAD", "OPTIONS"]

Step 4: For TRACE specifically:
  - Send actual TRACE request
  - If response body contains your original headers (echo) → confirmed vulnerable
  - Evidence: show the echoed response

Step 5: For PUT:
  - Try PUT /bravo6-test-file.txt with body "test"
  - If 200 or 201 → critical (file upload possible)
  - If 405 or 403 → not allowed (good)

Return:
{
  "test_name": "http_methods",
  "status": "fail|pass|warning",
  "severity": "...",
  "title": "...",
  "description": "...",
  "evidence": {
    "methods_allowed": ["GET", "POST", "OPTIONS", "TRACE", "PUT"],
    "dangerous_methods_found": [
      {"method": "TRACE", "severity": "medium", "confirmed": true},
      {"method": "PUT", "severity": "high", "confirmed": false}
    ]
  },
  "remediation": "Disable TRACE, PUT, DELETE, DEBUG methods unless explicitly required. Configure web server to only allow GET, POST, HEAD, OPTIONS."
}
```

---

## Script 13 — CMS & Vibe Code Detection

```
[SHARED CONTEXT ABOVE]

Write a Python async module: test_cms_vibecheck.py

Task: Detect the CMS/framework used, check for known misconfigurations, and analyze if the site shows patterns of AI-generated (vibe-coded) development.

--- PART A: CMS Detection ---

Step 1: Fetch HTML and response headers
Step 2: Detect CMS from these signals:

CMS_SIGNATURES = {
    "WordPress": {
        "patterns": ["/wp-content/", "/wp-includes/", 'name="generator" content="WordPress'],
        "check_paths": ["/wp-login.php", "/xmlrpc.php", "/wp-json/"],
        "risks": {
            "/wp-login.php": ("Login page exposed", "info"),
            "/xmlrpc.php": ("XML-RPC enabled — brute force and DDoS risk", "high"),
            "/wp-json/": ("REST API exposed — user enumeration possible", "medium")
        }
    },
    "Joomla": {
        "patterns": ["/components/com_", "/media/jui/", "Joomla!"],
        "check_paths": ["/administrator/", "/configuration.php"],
        "risks": {
            "/administrator/": ("Admin panel exposed", "medium")
        }
    },
    "Drupal": {
        "patterns": ["Drupal.settings", "/sites/default/files/", 'name="Generator" content="Drupal'],
        "check_paths": ["/user/login", "/admin/"],
        "risks": {
            "/user/login": ("Default login page exposed", "info")
        }
    },
    "Laravel": {
        "patterns": ["laravel_session", "XSRF-TOKEN", "Laravel"],
        "check_paths": ["/.env", "/telescope", "/horizon"],
        "risks": {
            "/.env": ("Environment file may be exposed", "critical"),
            "/telescope": ("Laravel Telescope debugger may be exposed", "high")
        }
    },
    "Django": {
        "patterns": ["csrfmiddlewaretoken", "django", "__django"],
        "check_paths": ["/admin/", "/static/admin/"],
        "risks": {
            "/admin/": ("Django admin panel exposed", "medium")
        }
    },
    "Next.js": {
        "patterns": ["__NEXT_DATA__", "_next/static", "next/dist"],
        "check_paths": ["/_next/", "/api/"],
        "risks": {}
    },
    "React (Vite/CRA)": {
        "patterns": ["react-dom", "__react", "data-reactroot", "/assets/index-"],
        "check_paths": [],
        "risks": {}
    }
}

For detected CMS: check all risk paths and report findings.

--- PART B: Vibe Code Detection ---

Step 3: Analyze HTML + JS for AI-generated code patterns

Calculate a "Vibe Score" (0-100) based on signals:

VIBE_SIGNALS = [
    # Each signal adds points to vibe_score
    {
        "name": "AI Generator Meta Tag",
        "patterns": [r'content="v0|lovable|bolt\.new|cursor|replit'],
        "points": 30,
        "severity": "info"
    },
    {
        "name": "Generic Tailwind Class Structure",
        "patterns": [r'className="(flex|grid) (flex-col|items-center) (justify-center|gap-\d)'],
        "points": 10,
        "severity": "info"
    },
    {
        "name": "Console.log in Production",
        "patterns": [r'console\.log\(["\']'],
        "points": 15,
        "severity": "low"
    },
    {
        "name": "Empty Catch Blocks",
        "patterns": [r'catch\s*\(\s*\w+\s*\)\s*\{\s*\}'],
        "points": 15,
        "severity": "low"
    },
    {
        "name": "TODO/FIXME in Production",
        "patterns": [r'//\s*(TODO|FIXME|HACK|XXX)'],
        "points": 10,
        "severity": "info"
    },
    {
        "name": "Placeholder Text",
        "patterns": [r'Lorem ipsum|placeholder text|Your Name Here|email@example'],
        "points": 20,
        "severity": "info"
    },
    {
        "name": "Generic CSS Variable Names",
        "patterns": [r'--primary-color|--secondary-color|--accent-color'],
        "points": 10,
        "severity": "info"
    },
    {
        "name": "AI Comment Patterns",
        "patterns": [r'//\s*(Add your|Insert your|Replace with|Update this)'],
        "points": 20,
        "severity": "info"
    }
]

Vibe Score interpretation:
  0-20   → "Likely Human-Written"
  21-40  → "Some AI Assistance Detected"
  41-60  → "Significant AI Assistance"
  61-80  → "Likely AI-Generated"
  81-100 → "Almost Certainly Vibe Coded"

Return:
{
  "test_name": "cms_vibe_detection",
  "status": "info",
  "cms_detected": "WordPress",
  "cms_findings": [
    {"path": "/xmlrpc.php", "issue": "XML-RPC enabled", "severity": "high"}
  ],
  "vibe_score": 73,
  "vibe_label": "Likely AI-Generated",
  "vibe_signals": [
    {"signal": "Console.log in Production", "occurrences": 14},
    {"signal": "AI Generator Meta Tag", "occurrences": 1, "value": "v0"}
  ],
  "severity": "info",
  "title": "WordPress Detected — Vibe Score: 73%",
  "description": "...",
  "remediation": "Review AI-generated code carefully for security issues. Disable xmlrpc.php. Vibe-coded sites have higher risk of security misconfigurations."
}
```

---

## ملاحظات للـ Integration

بعد ما تخلص الـ 13 script، الـ `scout_worker.py` النهائية هتبقى:

```python
import asyncio
from tests import (
    test_security_headers,
    test_ssl,
    test_secrets,
    test_js_libraries,
    test_mixed_content,
    test_info_disclosure,
    test_cookies,
    test_email_security,
    test_subdomain_takeover,
    test_robots,
    test_cors,
    test_http_methods,
    test_cms_vibecheck
)

async def run_scout(url: str) -> dict:
    results = await asyncio.gather(
        # Group A: HTTP
        test_security_headers.run(url),
        test_cors.run(url),
        test_http_methods.run(url),
        test_cookies.run(url),
        test_info_disclosure.run(url),
        # Group B: Content
        test_secrets.run(url),
        test_js_libraries.run(url),
        test_mixed_content.run(url),
        test_cms_vibecheck.run(url),
        # Group C: DNS/Network
        test_ssl.run(url),
        test_email_security.run(url),
        test_subdomain_takeover.run(url),
        test_robots.run(url),
        return_exceptions=True  # مهم: لو واحدة crash مش هتوقف الباقيين
    )
    return aggregate_results(results)
```
