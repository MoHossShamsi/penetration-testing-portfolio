# DVWA Web Application Security Assessment — Part 2

> **Application:** Damn Vulnerable Web Application (DVWA)  
> **Assessment type:** Authorized web-application security training assessment  
> **Environment:** Local, intentionally vulnerable lab instance  
> **Assessor:** Mohamed Hossam Elshamsi  
> **Assessment date:** 2026  

## Executive summary

This assessment identified weaknesses in CAPTCHA/workflow validation, unvalidated redirects, cryptographic token design, API mass assignment, authentication controls, OS command handling, file-upload validation, session-token generation, Content Security Policy configuration, client-side security logic, and object-level authorization.

The most significant lab risks are command injection, unsafe file upload, weak session identifiers, mass assignment, and broken object-level authorization. Severity estimates describe the demonstrated lab behavior and should be recalculated for a production deployment using the exact asset, privileges, exposure, and business impact.

## Scope and methodology

### Scope

- DVWA CAPTCHA, open redirect, cryptography, API, brute-force, command-injection, file-upload, weak-session-ID, CSP, JavaScript, and authorization modules
- Local lab endpoint: `http://127.0.0.1:42000/`

### Methodology

1. Mapped the relevant application workflows and endpoints.
2. Captured requests in Burp Suite where request modification was required.
3. Tested whether security decisions were enforced server-side.
4. Used harmless lab proof-of-concept actions and minimal post-validation.
5. Documented root cause, impact, remediation, and retest criteria.

## Findings summary

| ID | Finding | CWE | Severity | CVSS v3.1 estimate |
|---|---|---|---|---:|
| DVWA-07 | CAPTCHA/workflow validation bypass | CWE-602 / CWE-620 | High | 8.8 |
| DVWA-08 | Open redirect | CWE-601 | Medium | 6.1 |
| DVWA-09 | ECB token manipulation / missing integrity protection | CWE-327 / CWE-345 | High* | 8.8* |
| DVWA-10 | API mass assignment / privilege escalation | CWE-915 | High | 8.8 |
| DVWA-11 | Brute-force protection failure | CWE-307 | High | 8.1* |
| DVWA-12 | OS command injection | CWE-78 | Critical | 9.8 |
| DVWA-13 | Unrestricted file upload | CWE-434 | Critical | 9.8 |
| DVWA-14 | Weak/predictable session identifiers | CWE-330 | High | 8.2 |
| DVWA-15 | CSP nonce/policy weakness | CWE-693 / CWE-1021 | Medium* | 5.4* |
| DVWA-16 | Client-side security control bypass | CWE-602 | Medium* | 6.1* |
| DVWA-17 | Broken object-level authorization | CWE-639 | High | 8.1 |

`*` Recalculate the score for the exact production context. Some original estimates treated confidentiality, integrity, and availability as fully impacted without documenting the necessary prerequisites.

---

## DVWA-07: CAPTCHA and workflow validation bypass

| Attribute | Detail |
|---|---|
| **Severity** | High |
| **CVSS v3.1 estimate** | 8.8 — `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` |
| **CWE** | CWE-602: Client-Side Enforcement of Server-Side Security; CWE-620: Unverified Password Change |
| **Affected area** | CAPTCHA/password-change workflow |

### Description and root cause

The application trusts a client-controlled parameter such as `passed_captcha=true` and a workflow indicator such as `step=2` instead of independently verifying the CAPTCHA and enforcing the required sequence server-side. A browser or proxy user can modify these values.

### Evidence and reproduction in the authorized lab

1. Open the local CAPTCHA/password-change module.
2. Submit the workflow normally and capture the request in Burp Suite.
3. Inspect the second-step request and identify the client-controlled CAPTCHA status parameter.
4. In the local lab, resend the second-step request with the CAPTCHA-status value changed to the accepted value, without completing the first step.
5. Confirm the result only with a disposable lab account and test password.

Illustrative lab parameters:

```text
step=2&passed_captcha=true
```

### Impact

An attacker may bypass a CAPTCHA or workflow gate. If the password-change function also lacks current-password verification and CSRF protection, the weakness may contribute to account takeover. The CAPTCHA bypass alone should not automatically be described as CSRF; those are separate controls that may be chained.

### Remediation

- Verify CAPTCHA responses server-to-server with the provider’s secret key.
- Bind the challenge to the session, action, and short expiration window.
- Do not trust `step`, `passed`, or similar client-provided flags.
- Require the current password or recent reauthentication for password changes.
- Add CSRF protection to the password-change request.
- Invalidate challenge tokens after one use.

### Retest criteria

Changing or omitting the client-side CAPTCHA fields must not bypass server-side verification, and the password change must fail without valid reauthentication/CSRF controls.

---

## DVWA-08: Open redirect

| Attribute | Detail |
|---|---|
| **Severity** | Medium |
| **CVSS v3.1 estimate** | 6.1 — `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` |
| **CWE** | CWE-601: URL Redirection to Untrusted Site |
| **Affected area** | Redirect parameter in the open-redirect module |

### Description and root cause

The application accepts a user-controlled redirect destination and attempts to block selected strings such as `http://` or `https://`. This blacklist can be bypassed with alternate URL representations, including protocol-relative destinations.

### Evidence and reproduction in the authorized lab

1. Open the redirect module in DVWA.
2. Capture the redirect request in Burp Suite.
3. Identify the destination parameter.
4. Replace the destination with a controlled, harmless external test domain or protocol-relative value.

Example lab value:

```text
//example.invalid/
```

### Impact

Users may trust a link containing the legitimate application’s domain and then be redirected to a phishing or malicious site. Open redirects can also contribute to OAuth or token-flow attacks when other validation weaknesses exist.

### Remediation

- Prefer relative internal paths rather than accepting arbitrary URLs.
- Use a strict allowlist of approved destinations.
- Parse and validate the final URL server-side; do not rely on substring filtering.
- Display an interstitial warning when an external redirect is genuinely required.

### Retest criteria

External destinations and alternate URL forms must be rejected unless explicitly approved.

---

## DVWA-09: ECB token manipulation and missing integrity protection

| Attribute | Detail |
|---|---|
| **Severity** | High in the demonstrated lab scenario; do not automatically label Critical |
| **CVSS** | Recalculate based on whether authentication/authorization is bypassed and whether the endpoint is remotely reachable |
| **CWE** | CWE-327: Use of a Broken or Risky Cryptographic Algorithm; CWE-345: Insufficient Verification of Data Authenticity |
| **Affected area** | Encrypted token containing authorization attributes |

### Description and root cause

The application encrypts structured token data using AES-ECB and does not provide authenticated integrity protection. ECB encrypts each block independently, allowing block patterns to remain meaningful. More importantly, encrypted authorization claims are trusted without a secure authenticity mechanism.

### Evidence and reproduction in the authorized lab

1. Inspect the lab documentation and token format.
2. Capture two authorized test tokens with different non-sensitive roles or values.
3. Divide the ciphertext into blocks according to the documented block size.
4. Demonstrate, using disposable lab accounts only, that modifying or recombining blocks changes the decrypted claims and is accepted by the application.
5. Record the exact prerequisite: whether a valid token, known plaintext, or privileged token is required.

Do not publish real secrets or reusable tokens; redact them in the public report.

### Impact

An attacker may forge or alter authorization claims, identity, or expiration data if the server accepts manipulated ciphertext. The exact impact depends on whether the attacker can obtain suitable tokens and whether the server performs additional integrity and authorization checks.

### Remediation

- Use an authenticated encryption mode such as AES-GCM with a securely generated nonce.
- Alternatively, use a standard signed token design with secure key management and strict claim validation.
- Never treat encryption alone as proof that data is authentic.
- Keep authorization decisions server-side and validate role/identity claims against trusted server state.
- Rotate keys and invalidate affected tokens after remediation.

### Retest criteria

Any modified, reordered, replayed, expired, or invalidly authenticated token must be rejected before authorization decisions are made.

---

## DVWA-10: API mass assignment and privilege escalation

| Attribute | Detail |
|---|---|
| **Severity** | High |
| **CVSS v3.1** | 8.8 — `AV:N/AC:L/PR:L/S:U/C:H/I:H/A:H` |
| **CWE** | CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes |
| **Affected area** | Profile-update API |

### Description and root cause

The API updates a user object from the complete JSON request body instead of allowing only explicitly approved fields. A user can add a privileged field such as `level` to the request and alter their own authorization state.

### Evidence and reproduction in the authorized lab

1. Authenticate as a normal disposable lab user.
2. Capture the profile-update request.
3. Confirm which fields are legitimately editable, such as `name`.
4. Add an unauthorized field such as `level` to the JSON body.
5. Confirm in the lab that the server changes the user’s privilege state.

Illustrative request body:

```json
{
  "name": "Test User",
  "level": 0
}
```

### Impact

A normal user may obtain administrative privileges, access sensitive functions, modify other users, or alter application data.

### Remediation

- Define an explicit server-side allowlist of editable fields.
- Ignore or reject privileged fields supplied by the client.
- Enforce authorization on every privileged endpoint.
- Validate role changes through a separate administrator-only workflow.

Example safe update concept:

```text
update_user(name=request.json["name"])
```

### Retest criteria

Adding `level`, `role`, `is_admin`, or similar fields must not change authorization state, and unauthorized fields should be rejected or ignored.

---

## DVWA-11: Brute-force protection failure

| Attribute | Detail |
|---|---|
| **Severity** | High; exact score depends on account value and exposure |
| **CVSS** | Recalculate for the lab and target context; avoid automatically using 9.8 |
| **CWE** | CWE-307: Improper Restriction of Excessive Authentication Attempts |
| **Affected area** | Login endpoint |

### Description and root cause

The login endpoint lacks effective rate limiting, lockout/backoff, strong anomaly detection, or MFA. Distinct responses or response lengths may also help identify valid credentials.

### Evidence and reproduction in the authorized lab

1. Use only disposable lab credentials and a very small test wordlist.
2. Capture one login request.
3. Submit a limited number of invalid attempts under the lab rules.
4. Compare status codes, response lengths, and timing.
5. Confirm whether the endpoint applies throttling, backoff, lockout, or generic error messages.

### Impact

Attackers may perform password guessing, credential stuffing, or account enumeration, potentially compromising weak or reused passwords.

### Remediation

- Apply adaptive rate limits per account, IP, device, and risk signal.
- Use exponential backoff rather than relying only on permanent lockouts.
- Use MFA for sensitive accounts.
- Return generic authentication errors and avoid distinguishable responses.
- Monitor and alert on distributed or anomalous login attempts.
- Avoid publishing high-volume brute-force commands or real credential lists.

### Retest criteria

Repeated failed attempts must trigger throttling or an appropriate defensive response without creating an easy denial-of-service lockout against victims.

---

## DVWA-12: OS command injection

| Attribute | Detail |
|---|---|
| **Severity** | Critical in the demonstrated lab scenario |
| **CVSS v3.1** | 9.8 — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **CWE** | CWE-78: Improper Neutralization of Special Elements used in an OS Command |
| **Affected area** | Network utility/ping function |

### Description and root cause

The application places user-controlled input into a shell command without safe argument handling. Shell metacharacters or encoded line breaks cause additional commands to execute.

### Evidence and reproduction in the authorized lab

1. Submit a normal test IP address.
2. Capture the request in Burp Suite.
3. In the local lab, add a harmless identity command using a shell separator or encoded newline.
4. Confirm that the response contains the expected identity output, proving command execution.

Illustrative lab-only input pattern:

```text
8.8.8.8%0aid
```

### Impact

The web-server account may execute arbitrary commands. Depending on its privileges and network access, this can lead to data theft, application compromise, credential exposure, or lateral movement.

### Remediation

- Avoid shell invocation; use a library/API for the required network operation.
- If a subprocess is unavoidable, pass a fixed executable and argument array without invoking a shell.
- Strictly validate input against the required format, such as a parsed IP address.
- Run the application with a least-privileged OS account and isolate it from sensitive systems.

### Retest criteria

Shell metacharacters and encoded separators must be rejected or treated as data, and the application must not execute arbitrary commands.

---

## DVWA-13: Unrestricted file upload

| Attribute | Detail |
|---|---|
| **Severity** | Critical if server-side code execution is confirmed; otherwise lower |
| **CVSS** | Score based on whether the uploaded file executes, is publicly retrievable, and requires authentication |
| **CWE** | CWE-434: Unrestricted Upload of File with Dangerous Type |
| **Affected area** | File-upload module |

### Description and root cause

The upload control relies on client-controlled metadata, such as a filename or `Content-Type`, without robust content validation, safe storage, and execution prevention. In the lab, changing a file’s declared content type allows an otherwise rejected upload.

### Evidence and reproduction in the authorized lab

1. Upload a harmless non-executable test file with an allowed extension.
2. Capture the multipart request.
3. Change only the declared content type in the authorized lab and observe whether validation relies on that header.
4. Confirm whether the file is stored outside the web root, renamed, retrievable, and executable.
5. Do not upload a real web shell to any non-lab system.

### Impact

A dangerous upload may enable stored XSS, malicious content hosting, overwrite of files, denial of service, or remote code execution if executable files are stored in an executable web directory.

### Remediation

- Validate extension, MIME type, and magic bytes server-side.
- Generate random filenames and ignore user-supplied names.
- Store uploads outside the web root or on a separate non-executable host.
- Disable script execution in upload directories.
- Enforce authorization, size limits, quotas, malware scanning, and safe download headers.

### Retest criteria

Spoofing filename or MIME type must not bypass validation; uploaded files must not execute as server-side code.

---

## DVWA-14: Weak or predictable session identifiers

| Attribute | Detail |
|---|---|
| **Severity** | High if token prediction leads to session takeover |
| **CVSS v3.1 estimate** | 8.2 — validate against the exact observed prerequisites |
| **CWE** | CWE-330: Use of Insufficiently Random Values; CWE-384: Session Fixation where applicable |
| **Affected area** | Session-token generation |

### Description and root cause

Session identifiers appear predictable or insufficiently random. A token that follows a sequential, timestamp-based, or otherwise low-entropy pattern may be guessed or enumerated.

### Evidence and reproduction in the authorized lab

1. Create multiple disposable lab sessions.
2. Record only redacted/hashed token observations.
3. Compare token length, character set, repetition, and changes across sessions.
4. In the local lab only, determine whether predicting the next token grants access to another disposable test session.

Never publish reusable tokens.

### Impact

Successful prediction may enable session hijacking without knowing the user’s password.

### Remediation

- Generate tokens with a CSPRNG and at least 128 bits of unpredictable entropy.
- Rotate the session ID after login and privilege changes.
- Invalidate sessions on logout/password reset.
- Set `Secure`, `HttpOnly`, and appropriate `SameSite` attributes.
- Store only a hash of the session token server-side when appropriate.

### Retest criteria

Repeated sessions must show no predictable relationship, and old tokens must be invalidated after authentication-state changes.

---

## DVWA-15: CSP policy/nonce weakness

| Attribute | Detail |
|---|---|
| **Severity** | Medium as a defense-in-depth weakness; severity depends on the underlying XSS |
| **CVSS** | Recalculate for the exact XSS chain; do not treat CSP bypass alone as full code execution |
| **CWE** | CWE-693: Protection Mechanism Failure; CWE-1021: Improper Restriction of Rendered UI Layers or Frames |
| **Affected area** | Content-Security-Policy response header |

### Description and root cause

The CSP is configured with unsafe directives, overly broad sources, predictable/reusable nonces, or an implementation that allows attacker-controlled script execution. CSP should reduce XSS impact, not replace output encoding.

### Evidence and reproduction in the authorized lab

1. Inspect the response `Content-Security-Policy` header.
2. Determine whether it includes `unsafe-inline`, `unsafe-eval`, wildcard sources, or a nonce that is predictable/reused.
3. In the local lab, use a harmless script proof of concept to determine whether the policy blocks or permits execution.
4. Document the exact directive that permits the behavior.

### Impact

A weak CSP may fail to reduce the impact of an existing XSS vulnerability, allowing script execution, data access, or unauthorized actions in the victim’s browser context.

### Remediation

- Remove `unsafe-inline` and `unsafe-eval` where feasible.
- Use unpredictable, per-response nonces or hashes.
- Use strict allowlists and avoid wildcards.
- Apply `frame-ancestors`, `object-src 'none'`, and other relevant directives.
- Fix the underlying XSS with context-aware output encoding.

### Retest criteria

The policy should block unauthorized script sources and inline scripts while allowing only the application’s intended resources.

---

## DVWA-16: Client-side security-control bypass

| Attribute | Detail |
|---|---|
| **Severity** | Medium as a client-trust weakness; higher only when it bypasses a server-side control |
| **CVSS** | Recalculate based on confirmed server-side impact |
| **CWE** | CWE-602: Client-Side Enforcement of Server-Side Security |
| **Affected area** | JavaScript validation and token construction |

### Description and root cause

The application performs security-sensitive validation in JavaScript. The expected value can be derived from the page source or changed through browser developer tools, allowing a user to bypass the intended client-side control.

### Evidence and reproduction in the authorized lab

1. Review the JavaScript function responsible for constructing or validating the token.
2. Identify the transformation applied to the input.
3. In the local lab, modify the input or call the function from developer tools.
4. Confirm whether the server accepts the result and whether the control has any server-side enforcement.

### Impact

If the server trusts the client-generated value, an attacker may bypass validation, unlock restricted functionality, or manipulate role/permission-related behavior.

### Remediation

- Enforce all authorization and validation server-side.
- Do not trust client-generated role, permission, price, or completion flags.
- Sign server-issued values and validate them server-side when state must be returned to the client.
- Treat browser JavaScript as fully controlled by the attacker.

### Retest criteria

Changing JavaScript, DOM values, or client-generated tokens must not bypass server-side authorization or validation.

---

## DVWA-17: Broken object-level authorization

| Attribute | Detail |
|---|---|
| **Severity** | High |
| **CVSS v3.1** | 8.1 — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| **CWE** | CWE-639: Authorization Bypass Through User-Controlled Key |
| **Affected area** | Object update/profile endpoint |

### Description and root cause

The server does not verify that the authenticated user owns the object referenced by the request. A normal user can modify an object identifier or request body and change another user’s data.

### Evidence and reproduction in the authorized lab

1. Create two disposable lab users with distinct records.
2. Capture an authorized update request as one user.
3. Change the object/user identifier or relevant fields while remaining authenticated as the lower-privileged user.
4. Confirm the other user’s record changes by checking with the separate lab account.

### Impact

An attacker may read, modify, or delete other users’ information. This can cause unauthorized data access, account/profile manipulation, privacy violations, and privilege escalation depending on the object.

### Remediation

- Enforce server-side ownership/authorization checks on every object request.
- Derive the user identity from the authenticated session rather than trusting a client-supplied owner ID.
- Use policy-based authorization and test horizontal and vertical access-control paths.
- UUIDs can reduce enumeration but do not replace authorization checks.

### Retest criteria

Changing object IDs or user fields must not permit access to another user’s object, regardless of whether the identifier is sequential or random.

## General recommendations

1. Enforce all security decisions on the server.
2. Use prepared statements for database access.
3. Use allowlists for redirect destinations, editable API fields, and upload types.
4. Use secure session management with high-entropy tokens and cookie protections.
5. Apply CSRF tokens to state-changing browser requests.
6. Use secure cryptographic designs with authenticated encryption and key management.
7. Use least privilege for database and operating-system accounts.
8. Add regression tests for every confirmed finding.

## References

- OWASP Authentication Cheat Sheet
- OWASP CSRF Prevention Cheat Sheet
- OWASP File Upload Cheat Sheet
- OWASP OS Command Injection Defense Cheat Sheet
- OWASP Session Management Cheat Sheet
- OWASP Content Security Policy Cheat Sheet
- CWE-78, CWE-307, CWE-330, CWE-434, CWE-601, CWE-602, CWE-639, CWE-915
