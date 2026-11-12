# TV-EYE v1.0.0 - Assessment Report

**Author:** Mr_TV  |  **Telegram:** @Mr_TV_ir  |  **GitHub:** https://github.com/TV-CENTER

**Generated:** 2026-11-12 09:19:43 UTC

## Summary

| Severity | Count |
|----------|-------|
| critical | 1 |
| high | 5 |
| medium | 5 |
| low | 3 |
| info | 2 |

**Targets:** -

## Findings

### #16 [CRITICAL] Valid credentials found: tveyeowner / labpass

- **Target:** `http://127.0.0.1:65156/login`
- **Time:** 2026-11-12 09:19:39 UTC
- **CWE:** CWE-521
- **Module:** login_brute

**Evidence:**

```
Login succeeded (HTTP 200) with tveyeowner:labpass
```

**Remediation tip:** Report per program policy; suggest MFA + lockout.

### #5 [HIGH] Environment file exposed: /.env

- **Target:** `http://127.0.0.1:65156/.env`
- **Time:** 2026-11-12 09:19:10 UTC
- **CWE:** CWE-200
- **Module:** sensitive_files

**Evidence:**

```
DB_HOST=127.0.0.1
DB_USER=fakeuser
DB_PASS=fakepassword123
API_KEY=FAKE-not-a-real-key

```

**Remediation tip:** Secrets in .env can leak API keys and DB passwords.

### #6 [HIGH] Possible secret in JavaScript: AWS Key

- **Target:** `http://127.0.0.1:65156/app.js`
- **Time:** 2026-11-12 09:19:10 UTC
- **CWE:** CWE-798
- **Module:** js_secrets

**Evidence:**

```
Match: AKIAIOSFODNN7EXAMPLE
```

**Remediation tip:** Verify key is live and report with minimal redaction.

### #12 [HIGH] SQL injection (error-based) in parameter 'id' (MySQL)

- **Target:** `http://127.0.0.1:65156/item?id=%27`
- **Time:** 2026-11-12 09:19:30 UTC
- **CWE:** CWE-89
- **Module:** sqli_scan

**Evidence:**

```
Database error triggered by 6 payload(s).
Param: id
Payloads: '; "; 1 OR 1=1; 1' OR '1'='1; 1) OR 1=1--; 1 UNION SELECT NULL--
Response snippet: <html><body>Warning: mysql error: you have an error in your SQL syntax near '''</body></html>
```

**Remediation tip:** Confirm with sqlmap; determine DBMS and enumerate safely.

### #13 [HIGH] File inclusion/traversal in parameter 'page'

- **Target:** `http://127.0.0.1:65156/view?page=..%2F..%2F..%2Fetc%2Fpasswd`
- **Time:** 2026-11-12 09:19:32 UTC
- **CWE:** CWE-98
- **Module:** lfi_scan

**Evidence:**

```
Signature-bearing responses for 6 payload(s).
Payloads: ../../../etc/passwd; ....//....//....//etc/passwd; /etc/passwd; file:///etc/passwd; ../../../windows/win.ini; ..\..\..\windows\win.ini
HTTP status: 200
```

**Remediation tip:** Verify manually; try reading known files; check RFI/filter chains.

### #14 [HIGH] Template injection (SSTI) in parameter 'name'

- **Target:** `http://127.0.0.1:65156/template?name=%7B%7B7%2A7%7D%7D`
- **Time:** 2026-11-12 09:19:33 UTC
- **CWE:** CWE-1336
- **Module:** ssti_scan

**Evidence:**

```
Math probe '{{7*7}}' evaluated to '49' in the response (HTTP 200). Baseline did not contain the result.
```

**Remediation tip:** Confirm engine type (Jinja2/Twig/Freemarker...) and escalate carefully with proof-of-impact.

### #7 [MEDIUM] Possible secret in JavaScript: Generic secret

- **Target:** `http://127.0.0.1:65156/app.js`
- **Time:** 2026-11-12 09:19:10 UTC
- **CWE:** CWE-798
- **Module:** js_secrets

**Evidence:**

```
Match: AKIAIOSFODNN7EXAMPLE
```

**Remediation tip:** Verify key is live and report with minimal redaction.

### #8 [MEDIUM] Possible secret in JavaScript: Generic secret

- **Target:** `http://127.0.0.1:65156/app.js`
- **Time:** 2026-11-12 09:19:10 UTC
- **CWE:** CWE-798
- **Module:** js_secrets

**Evidence:**

```
Match: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Remediation tip:** Verify key is live and report with minimal redaction.

### #9 [MEDIUM] Possible secret in JavaScript: Generic secret

- **Target:** `http://127.0.0.1:65156/app.js`
- **Time:** 2026-11-12 09:19:10 UTC
- **CWE:** CWE-798
- **Module:** js_secrets

**Evidence:**

```
Match: SuperSecretLabValue123
```

**Remediation tip:** Verify key is live and report with minimal redaction.

### #11 [MEDIUM] Possible reflected XSS in parameter 'q'

- **Target:** `http://127.0.0.1:65156/search?q=%22%27%3E%3Ctveyealert%3Ealert%281%29%3C%2Ftveyealert%3E`
- **Time:** 2026-11-12 09:19:29 UTC
- **CWE:** CWE-79
- **Module:** xss_scan

**Evidence:**

```
Canary payload(s) reflected raw into the response body.
Parameter: q
Reflected payload examples: <tveyealert>; <svg/onload; </script; <img src=x onerror; href="javascript:; <details open ontoggle
Response: HTTP 200, 75 bytes
```

**Remediation tip:** Manually verify with a browser and prove execution; check encoding context (attribute/JS/HTML).

### #15 [MEDIUM] GraphQL introspection enabled: http://127.0.0.1:65156/graphql

- **Target:** `http://127.0.0.1:65156/graphql`
- **Time:** 2026-11-12 09:19:36 UTC
- **CWE:** CWE-200
- **Module:** graphql_scan

**Evidence:**

```
Introspection query returned schema metadata:
{"data": {"__schema": {"queryType": {"name": "Query"}}}}
```

**Remediation tip:** Introspection discloses the full API surface; disable in prod.

### #2 [LOW] Permissive CORS: Access-Control-Allow-Origin: *

- **Target:** `http://127.0.0.1:65156`
- **Time:** 2026-11-12 09:18:55 UTC
- **CWE:** CWE-942
- **Module:** security_headers

**Evidence:**

```
ACA-O: *
```

**Remediation tip:** Wildcard CORS on credentialed APIs leaks data.

### #3 [LOW] Insecure cookie flags (HttpOnly missing, Secure missing, SameSite missing)

- **Target:** `http://127.0.0.1:65156`
- **Time:** 2026-11-12 09:18:55 UTC
- **CWE:** CWE-1004
- **Module:** security_headers

**Evidence:**

```
Set-Cookie: labsession=abc123
```

**Remediation tip:** Set HttpOnly; Secure; SameSite=Lax on session cookies.

### #4 [LOW] Clickjacking possible (no frame protection)

- **Target:** `http://127.0.0.1:65156`
- **Time:** 2026-11-12 09:18:55 UTC
- **CWE:** CWE-1021
- **Module:** security_headers

**Evidence:**

```
no X-Frame-Options and no CSP frame-ancestors
```

**Remediation tip:** Add frame-ancestors 'none' or X-Frame-Options: DENY.

### #1 [INFO] Server version disclosed in Server header (1.0)

- **Target:** `http://127.0.0.1:65156`
- **Time:** 2026-11-12 09:18:54 UTC
- **CWE:** CWE-200
- **Module:** tech_fingerprint

**Evidence:**

```
Server: TV-EYE-Lab/1.0 (Python)
```

**Remediation tip:** Banner disclosure assists attackers; suppress versions.

### #10 [INFO] Possible secret in JavaScript: Internal URL

- **Target:** `http://127.0.0.1:65156/app.js`
- **Time:** 2026-11-12 09:19:10 UTC
- **CWE:** CWE-200
- **Module:** js_secrets

**Evidence:**

```
Match: http://10.0.0.42:8080/internal
```

**Remediation tip:** Verify key is live and report with minimal redaction.
