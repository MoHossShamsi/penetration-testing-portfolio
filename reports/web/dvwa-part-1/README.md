# DVWA Web Application Security Assessment — Part 1

> **Application:** Damn Vulnerable Web Application (DVWA)  
> **Assessment type:** Authorized web-application security training assessment  
> **Environment:** Local, intentionally vulnerable lab instance  
> **Assessor:** Mohamed Hossam Elshamsi  
> **Assessment date:** 2026  

> **Authorization disclaimer:** This assessment was performed exclusively against DVWA, an intentionally vulnerable training application running in an authorized local lab. No production systems, real user accounts, or third-party applications were tested. The content is shared for educational and defensive purposes only.

## Executive summary

This assessment identified weaknesses in request-integrity controls, output handling, file inclusion, and database query construction. The most significant risks are stored cross-site scripting, local file inclusion, and SQL injection, which can lead to unauthorized actions, disclosure of server-side data, account compromise, and—in certain configurations—further server compromise.

The findings below describe the tested DVWA lab behavior. Severity is an assessment estimate for the lab scenario; production severity depends on authentication requirements, exposed data, deployment architecture, and compensating controls.

## Scope and methodology

### Scope

- DVWA CSRF, XSS, file-inclusion, and SQL-injection training modules
- Local lab endpoint: `http://127.0.0.1:42000/`

### Methodology

1. Mapped the affected application functionality.
2. Identified user-controlled parameters and input/output contexts.
3. Tested each module using harmless proof-of-concept payloads.
4. Confirmed findings through observable application behavior.
5. Documented root cause, practical impact, remediation, and retest criteria.

## Findings summary

| ID | Finding | CWE | Severity | CVSS v3.1 estimate |
|---|---|---|---|---:|
| DVWA-01 | Password-change CSRF | CWE-352 | High | 8.8 |
| DVWA-02 | DOM-based cross-site scripting | CWE-79 | Medium | 6.1 |
| DVWA-03 | Reflected cross-site scripting | CWE-79 | Medium | 6.1 |
| DVWA-04 | Stored cross-site scripting | CWE-79 | High | 8.1 |
| DVWA-05 | Local file inclusion / file disclosure | CWE-98 | High | 7.5 |
| DVWA-06 | SQL injection | CWE-89 | Critical | 9.8 |

---

## DVWA-01: Password-change CSRF

| Attribute | Detail |
|---|---|
| **Severity** | High |
| **CVSS v3.1** | 8.8 — `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` |
| **CWE** | CWE-352: Cross-Site Request Forgery |
| **Affected area** | DVWA CSRF module / password-change functionality |

### Description and root cause

The password-change feature accepts a state-changing request through `GET` without an anti-CSRF token or other request-origin validation. A victim who is authenticated to the application can be induced to load a crafted URL, causing the browser to submit the password-change request with the victim's session cookie.

### Evidence and reproduction in the authorized lab

1. Authenticate to the local DVWA lab.
2. Open the CSRF module.
3. Submit a password-change request using the application.
4. Observe that the request does not contain an unpredictable, session-bound CSRF token.
5. Confirm that a crafted request in the following format changes the password while the victim session is active:

```text
/vulnerabilities/csrf/?password_new=[TEST_PASSWORD]&password_conf=[TEST_PASSWORD]&Change=Change
```

### Impact

An attacker could change the password of a logged-in victim, potentially locking the victim out. If the victim has elevated privileges, this may lead to takeover of that privileged account.

### Remediation

- Use `POST` for state-changing requests; do not rely on `GET` for password changes.
- Generate a cryptographically strong CSRF token per session or request and validate it server-side.
- Verify the current password or require recent reauthentication before sensitive account changes.
- Set session cookies with appropriate `Secure`, `HttpOnly`, and `SameSite` attributes.
- Validate `Origin` or `Referer` as a defense-in-depth control where appropriate.

### Retest criteria

A request without a valid session-bound CSRF token must fail, and a password change must require the current password or recent reauthentication.

---

## DVWA-02: DOM-based cross-site scripting

| Attribute | Detail |
|---|---|
| **Severity** | Medium |
| **CVSS v3.1** | 6.1 — `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| **CWE** | CWE-79: Improper Neutralization of Input During Web Page Generation |
| **Affected area** | DVWA DOM XSS module / `default` URL parameter |

### Description and root cause

Client-side JavaScript reads attacker-controlled data from the URL and passes it to an unsafe DOM sink such as `document.write()` without context-appropriate encoding. This allows attacker-supplied markup to be interpreted by the browser.

### Evidence and reproduction in the authorized lab

1. Open the DOM XSS module.
2. Append a harmless proof-of-concept value to the `default` parameter.
3. Confirm that the browser executes the benign test payload when the page uses the value in the DOM.

Example lab payload:

```text
?default=</select><img src=x onerror=alert(1)>
```

### Impact

In a production application, DOM XSS can enable page manipulation, phishing content, actions in the victim's session context, or theft of data accessible to JavaScript. Cookie theft depends on whether sensitive cookies lack the `HttpOnly` attribute.

### Remediation

- Replace `document.write()` and similar HTML-parsing sinks with `textContent` or safe DOM APIs where possible.
- Apply context-aware output encoding before writing untrusted values to HTML, JavaScript, CSS, or URL contexts.
- Use a restrictive Content Security Policy as defense in depth.

### Retest criteria

Attacker-controlled URL values must render as text or be rejected; they must not execute JavaScript or create HTML elements.

---

## DVWA-03: Reflected cross-site scripting

| Attribute | Detail |
|---|---|
| **Severity** | Medium |
| **CVSS v3.1** | 6.1 — `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| **CWE** | CWE-79: Improper Neutralization of Input During Web Page Generation |
| **Affected area** | `/vulnerabilities/xss_r/` / `name` parameter |

### Description and root cause

The server reflects the `name` parameter into the HTML response without context-aware output encoding. A partial blacklist that blocks selected tags is insufficient because alternative HTML contexts and event handlers can still execute JavaScript.

### Evidence and reproduction in the authorized lab

1. Open the reflected XSS module.
2. Supply a harmless markup-based proof of concept in `name`.
3. Confirm that the page reflects and executes the benign payload.

Example lab payload:

```text
/vulnerabilities/xss_r/?name=<img src=x onerror=alert(1)>
```

### Impact

An attacker could send a crafted link to a victim. If opened while authenticated, the payload may execute in the trusted site's origin and perform actions or access data available to the victim's browser session.

### Remediation

- Encode all untrusted output for its exact rendering context.
- Do not rely on blacklist filtering of `<script>` or selected keywords.
- Add a restrictive CSP as a secondary protection, not as the primary XSS fix.

### Retest criteria

The supplied input must be displayed as literal text and must not create executable browser content.

---

## DVWA-04: Stored cross-site scripting

| Attribute | Detail |
|---|---|
| **Severity** | High |
| **CVSS v3.1** | 8.1 — `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N` |
| **CWE** | CWE-79: Improper Neutralization of Input During Web Page Generation |
| **Affected area** | DVWA guestbook / `txtName` and `mtxMessage` fields |

### Description and root cause

The guestbook stores attacker-controlled input and later renders it to other visitors without context-aware output encoding. Because the payload persists in the database, all users who view the affected content can be exposed.

### Evidence and reproduction in the authorized lab

1. Navigate to the stored XSS/guestbook module.
2. Submit harmless proof-of-concept markup in a guestbook field.
3. Reload the page or access it in another authenticated lab session.
4. Confirm that the stored payload executes when the entry is rendered.

Example lab payload:

```html
<script>alert(1)</script>
```

### Impact

Stored XSS has broader reach than reflected XSS because multiple users may trigger the stored payload. It can enable persistent defacement, phishing, unauthorized requests in victim sessions, and exposure of JavaScript-accessible data.

### Remediation

- Apply context-aware output encoding on every rendering path.
- Treat rich HTML as untrusted unless a tightly scoped, trusted sanitization library and allowlist are required.
- Add CSP, `HttpOnly` cookies, and secure session management as defense in depth.

### Retest criteria

Stored input must render harmlessly as text for every viewer and must not execute browser code.

---

## DVWA-05: Local file inclusion / file disclosure

| Attribute | Detail |
|---|---|
| **Severity** | High |
| **CVSS v3.1** | 7.5 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **CWE** | CWE-98: Improper Control of Filename for Include/Require Statement in PHP Program |
| **Affected area** | DVWA file-inclusion module / user-controlled page parameter |

### Description and root cause

The application passes a user-controlled file/path value to a server-side include mechanism without a strict allowlist. Directory-traversal sequences can therefore cause the application to access local files outside the intended template directory.

### Evidence and reproduction in the authorized lab

1. Open the DVWA file-inclusion module.
2. Identify the parameter that selects the included page.
3. Replace the expected page name with a traversal sequence targeting a non-sensitive lab file.
4. Confirm that the application returns the selected local file content.

Representative training-lab request format:

```text
/vulnerabilities/fi/?page=../../../../etc/passwd
```

Where source-code disclosure is being verified in a local PHP training environment, a filter wrapper may demonstrate that PHP source can be read rather than executed:

```text
/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=include.php
```

### Impact

An attacker may read sensitive operating-system files, application configuration, source code, database credentials, private keys, or session-related files. Some PHP configurations can allow escalation beyond disclosure, but that must be separately validated rather than assumed.

### Remediation

- Do not pass raw user input to `include`, `require`, or file-loading functions.
- Replace dynamic paths with a server-side allowlist mapping, for example `home` → `home.php`.
- Resolve paths with `realpath()` and enforce that the final path remains within a dedicated approved directory.
- Disable unnecessary PHP URL wrappers and keep `allow_url_include` disabled.
- Do not expose sensitive configuration/source files to the web process.

### Retest criteria

Traversal sequences, URL-encoded variants, and PHP wrappers must be rejected. Only explicitly allowed page identifiers must be accepted.

---

## DVWA-06: SQL injection

| Attribute | Detail |
|---|---|
| **Severity** | Critical |
| **CVSS v3.1** | 9.8 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **CWE** | CWE-89: Improper Neutralization of Special Elements used in an SQL Command |
| **Affected area** | DVWA SQL injection modules / user-controlled query parameter |

### Description and root cause

User-controlled data is concatenated into an SQL statement rather than being passed as a bound parameter. This allows crafted input to alter the query's syntax and logic.

### Evidence and reproduction in the authorized lab

1. Open the SQL injection module in the local DVWA lab.
2. Submit an input containing a quote to identify behavior changes or database errors.
3. Use the lab to demonstrate boolean, UNION-based, or blind SQL injection behavior at the configured security level.
4. Confirm only the minimum evidence required to prove the issue; do not access unrelated data.

Representative lab indicators include:

```text
' OR '1'='1' -- 
```

and, where the response exposes compatible columns, a controlled UNION test such as:

```text
' UNION SELECT user, password FROM users -- 
```

### Impact

Depending on database privileges and application design, SQL injection can permit authentication bypass, disclosure of confidential data, unauthorized changes/deletion, and sometimes deeper server compromise. The exact impact must be validated against the database account's actual privileges.

### Remediation

- Use parameterized queries/prepared statements for every database operation.
- Do not build SQL with string concatenation, even if input validation is present.
- Use a least-privileged database account; the web application should not connect as a database administrator.
- Handle database errors safely without exposing query details.
- Use allowlist validation for constrained values such as sort fields, but never as a replacement for parameterization.
- Consider a WAF only as secondary protection, never as the primary fix.

### Retest criteria

Inputs containing SQL syntax must be handled as literal data. Parameterized queries must be confirmed in code review and functional testing.

## General recommendations

1. Establish server-side validation and authorization for every sensitive operation.
2. Use secure-by-default frameworks and standard libraries for CSRF defenses, output encoding, and database access.
3. Apply least privilege to web-server and database accounts.
4. Implement secure session-cookie attributes and a restrictive Content Security Policy.
5. Add security tests to the development lifecycle, including regression tests for CSRF, XSS, file access, and injection flaws.

## References

- OWASP Cross-Site Request Forgery Prevention Cheat Sheet
- OWASP Cross Site Scripting Prevention Cheat Sheet
- OWASP SQL Injection Prevention Cheat Sheet
- OWASP File Inclusion guidance
- CWE-352: Cross-Site Request Forgery
- CWE-79: Improper Neutralization of Input During Web Page Generation
- CWE-98: Improper Control of Filename for Include/Require Statement
- CWE-89: SQL Injection
