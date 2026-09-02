

> **Application:** AllSafe v1.0  
> **Platform:** Android  
> **Package:** `infosecadventures.allsafe`  
> **Assessment Type:** Mobile Application Penetration Testing  
> **Assessor:** Mohamed Hossam Elshamsi  
> **Tools Used:** ADB (Android Debug Bridge), JADX Decompiler, Frida, Objection, Hex Editor

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Vulnerability Findings](#vulnerability-findings)
   - [AllSafe-01: Insecure Logging]
   - [AllSafe-02: Hardcoded Credentials]
   - [AllSafe-03: Insecure Shared Preferences]
   - [AllSafe-04: SQL Injection Bypass]
   - [AllSafe-05: Firebase Data Exposure]
   - [AllSafe-06: Deep Link Exploitation]
   - [AllSafe-07: XSS-Based WebView Attacks]
   - [AllSafe-08: PIN Bypass]
   - [AllSafe-09: Insecure Object Serialization]
   - [AllSafe-10: Certificate Pinning]
   - [AllSafe-11: Insecure Broadcast Receiver]
   - [AllSafe-12: Native Library Challenge]
   - [AllSafe-13: Smali Patch Challenge (Firewall)]
   - [AllSafe-14: Weak Cryptography]
   - [AllSafe-15: Bypass Root Check]
   - [AllSafe-16: Insecure Providers]
   - [AllSafe-17: Secure Flag Bypass]
   - [AllSafe-18: Insecure Service]
1. [Risk Summary Matrix](#risk-summary-matrix)
2. [Conclusion](#conclusion)
3. [References](#references)

---

## Executive Summary

This report presents the findings of a comprehensive security assessment conducted on the **AllSafe** Android application. AllSafe is an intentionally vulnerable application designed to teach developers and security professionals about common Android security flaws.

During the assessment, **18 vulnerabilities** were identified and exploited across multiple categories:

| Category | Count | Max Severity |
|----------|-------|-------------|
| Insecure Data Storage / Cryptography | 5 | High |
| Client Code Quality / Injection | 3 | Critical |
| Authentication & Authorization | 3 | High |
| Insecure Components (IPC) | 3 | Critical |
| Reverse Engineering & Tampering | 2 | Low |

The vulnerabilities range in severity from **Low to Critical**, with CVSS v3.1 scores between **3.3 and 9.8**. The most critical findings involve SQL injection (AllSafe-04) and exported, insecure background services capable of silent audio recording (AllSafe-16).

---

## Vulnerability Findings

---

### AllSafe-01: Insecure Logging [Challenge 01]

| Attribute               | Detail                                                    |
| ----------------------- | --------------------------------------------------------- |
| **Challenge**           | 1. Insecure Logging                                       |
| **CWE**                 | CWE-532: Insertion of Sensitive Information into Log File |
| **OWASP Mobile Top 10** | M2: Insecure Data Storage                                 |
| **Severity**            | 🟠 **High**                                               |
| **CVSS v3.1 Score**     | **7.5** (High)                                            |
| **CVSS Vector**         | `AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`                     |
| **Affected Component**  | `infosecadventures.allsafe` Logging Mechanism             |

#### Description

The application logs sensitive information, such as the flag, directly to the system log (logcat), which can be accessed by other applications or via ADB.

#### Impact

- **Confidentiality:** Sensitive data is exposed in system logs.
- **Privacy:** Any co-installed application with `READ_LOGS` or a user with ADB access can harvest the data.

#### Proof of Concept

**Step 1:** Open the Insecure Logging challenge.

**Step 2:** Monitor logcat output using `adb logcat | grep infosecadventures`.

The flag is exposed in plain text in the logs.

#### Mitigation

1. **Remove all logging statements** in production builds.
2. Use tools like ProGuard to strip `Log` calls, or implement a custom logging wrapper that disables output in release mode.

#### References

- [OWASP Mobile Top 10 — M2: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage)

---

### AllSafe-02: Hardcoded Credentials [Challenge 02]

| Attribute               | Detail                                       |
| ----------------------- | -------------------------------------------- |
| **Challenge**           | 2. Hardcoded Credentials                     |
| **CWE**                 | CWE-798: Use of Hard-coded Credentials       |
| **OWASP Mobile Top 10** | M9: Reverse Engineering                      |
| **Severity**            | 🟠 **High**                                  |
| **CVSS v3.1 Score**     | **7.5** (High)                               |
| **CVSS Vector**         | `AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`        |
| **Affected Component**  | `infosecadventures.allsafe` Application Code |

#### Description

The application stores sensitive information (a password/flag) as hardcoded strings within the application's source code.

#### Impact

- **Credential Exposure:** Attackers can decompile the application and retrieve the hardcoded credentials.
- **Authentication Bypass:** The retrieved credentials can be used to bypass security controls.

#### Proof of Concept

**Step 1:** Open the Hardcoded Credentials challenge.
![Challenge 02 Briefing](screenshot-01.png)

**Step 2:** Decompile the APK using tools like JADX and locate the hardcoded string `SuperSecretPassword`.
![Jadx Hardcoded String](screenshot-02.png)

#### Mitigation

1. **Never hardcode secrets** in the source code.
2. Use secure storage mechanisms such as the Android Keystore, or fetch them dynamically from a secure backend.

#### References

- [OWASP Mobile Top 10 — M9: Reverse Engineering](https://owasp.org/www-project-mobile-top-10/2016-risks/m9-reverse-engineering)

---

### AllSafe-03: Insecure Shared Preferences [Challenge 03]

| Attribute               | Detail                                              |
| ----------------------- | --------------------------------------------------- |
| **Challenge**           | 3. Insecure Shared Preferences                      |
| **CWE**                 | CWE-312: Cleartext Storage of Sensitive Information |
| **OWASP Mobile Top 10** | M2: Insecure Data Storage                           |
| **Severity**            | 🟡 **Medium**                                       |
| **CVSS v3.1 Score**     | **5.5** (Medium)                                    |
| **CVSS Vector**         | `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N`               |
| **Affected Component**  | `SharedPreferences` Data                            |

#### Description

The application stores sensitive data in cleartext within Android Shared Preferences.

#### Impact

- **Data Exposure:** Any attacker with device access or root privileges can read the data.

#### Proof of Concept

**Step 1:** Open the Insecure Shared Preferences challenge and save credentials.
![Challenge 03 Briefing](screenshot-03.png)

**Step 2:** Access the application's data directory via ADB and read the file:
`cat /data/data/infosecadventures.allsafe/shared_prefs/...`
![Shared Preferences Data](screenshot-04.png)

#### Mitigation

1. Encrypt sensitive data before storing it in Shared Preferences.
2. Consider using `EncryptedSharedPreferences` provided by Android Jetpack Security.

#### References

- [OWASP Mobile Top 10 — M2: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage)

---

### AllSafe-04: SQL Injection Bypass [Challenge 04]

| Attribute | Detail |
|-----------|--------|
| **Challenge** | 4. SQL Injection Bypass |
| **CWE** | CWE-89: Improper Neutralization of Special Elements used in an SQL Command |
| **OWASP Mobile Top 10** | M7: Client Code Quality |
| **Severity** | 🔴 **Critical** |
| **CVSS v3.1 Score** | **9.8** (Critical) |
| **CVSS Vector** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Affected Component** | SQLite Database Query |

#### Description

The application is vulnerable to SQL Injection, allowing an attacker to bypass authentication or access restricted data by manipulating input queries.

#### Impact

- **Authentication Bypass:** Attackers can bypass login checks.
- **Data Leakage:** Full access to the application's local database.

#### Proof of Concept

**Step 1:** Open the SQL Injection Bypass challenge.
![Challenge 04 Briefing](screenshot-05.png)

**Step 2:** In the input field, enter the payload: `' OR '1'='1`

**Step 3:** The query evaluates to true, bypassing the intended authentication check.
![SQL Injection Success](screenshot-06.png)

#### Mitigation

1. Use parameterized queries (Prepared Statements) for all database operations.
2. Avoid concatenating user input directly into SQL queries.

#### References

- [OWASP Mobile Top 10 — M7: Client Code Quality](https://owasp.org/www-project-mobile-top-10/2016-risks/m7-client-code-quality)

---

### AllSafe-05: Firebase Data Exposure [Challenge 05]

| Attribute | Detail |
|-----------|--------|
| **Challenge** | 5. Firebase Data Exposure |
| **CWE** | CWE-922: Insecure Storage of Sensitive Information |
| **OWASP Mobile Top 10** | M2: Insecure Data Storage |
| **Severity** | 🟠 **High** |
| **CVSS v3.1 Score** | **7.5** (High) |
| **CVSS Vector** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Affected Component** | Firebase Realtime Database |

#### Description

The application exposes its Firebase database URL in the `strings.xml` file and lacks proper security rules, allowing unauthenticated read access to the database.

#### Impact

- **Data Breach:** Any internet user can access sensitive data stored in the Firebase database.

#### Proof of Concept

**Step 1:** Read the briefing for the challenge.
![Challenge 05 Briefing](screenshot-07.png)

**Step 2:** Extract `strings.xml` and locate the Firebase database URL.
![strings.xml Firebase URL](screenshot-08.png)

**Step 3:** Access the database URL via a browser, appending `.json`.
![Firebase Console Access](screenshot-09.png)

**Step 4:** The database returns the flag without requiring authentication.
![Exposed Data](screenshot-10.png)

#### Mitigation

1. Implement robust Firebase Security Rules to restrict access based on authentication and authorization.
2. Ensure sensitive endpoints are not publicly accessible.

#### References

- [OWASP Mobile Top 10 — M2: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage)

---

### AllSafe-06: Deep Link Exploitation [Challenge 06]

| Attribute | Detail |
|-----------|--------|
| **Challenge** | 6. Deep Link Exploitation |
| **CWE** | CWE-939: Improper Authorization in Handler for Custom URL Scheme |
| **OWASP Mobile Top 10** | M1: Improper Platform Usage |
| **Severity** | 🟡 **Medium** |
| **CVSS v3.1 Score** | **6.5** (Medium) |
| **CVSS Vector** | `AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N` |
| **Affected Component** | Custom Intent Filter |

#### Description

The application uses insecure deep links to perform actions without sufficient validation, allowing arbitrary external intent invocation.

#### Impact

- **Unauthorized Action Execution:** Malicious apps or websites can force the app to perform unintended actions.

#### Proof of Concept

**Step 1:** Open the Deep Link Exploitation challenge.
![Challenge 06 Briefing](screenshot-11.png)

**Step 2:** Identify the deep link scheme (`allsafe://infosecadventures/congrats?key=ebfb...`) from the app's manifest/strings.
![strings.xml Deep Link Key](screenshot-12.png)

**Step 3:** Trigger the deep link using ADB: `adb shell am start -a "android.intent.action.VIEW" -d "allsafe://infosecadventures/congrats?key=..."`
![ADB Intent Execution](Screenshot%202026-05-28%20202547.png)

**Step 4:** The deep link is executed successfully.
![Deep Link Executed](screenshot-13.png)

#### Mitigation

1. Validate the source and contents of all incoming deep links.
2. Avoid using deep links for sensitive state-changing operations without secondary authentication.

#### References

- [OWASP Mobile Top 10 — M1: Improper Platform Usage](https://owasp.org/www-project-mobile-top-10/2016-risks/m1-improper-platform-usage)

---

### AllSafe-07: XSS-Based WebView Attacks [Challenge 07]

| Attribute | Detail |
|-----------|--------|
| **Challenge** | 7. XSS-Based WebView Attacks |
| **CWE** | CWE-79: Improper Neutralization of Input During Web Page Generation |
| **OWASP Mobile Top 10** | M7: Client Code Quality |
| **Severity** | 🟠 **High** |
| **CVSS v3.1 Score** | **7.5** (High) |
| **CVSS Vector** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Affected Component** | `WebView` Component |

#### Description

The application's WebView is vulnerable to Cross-Site Scripting (XSS) and allows arbitrary local file access via malicious URLs.

#### Impact

- **Local File Read:** Attackers can read sensitive internal application files using `file://` schemes.

#### Proof of Concept

**Step 1:** Open the WebView challenge.
![Challenge 07 Briefing](screenshot-14.png)

**Step 2:** Input `file:///etc/hosts` into the WebView URL prompt.
![Payload Entry](screenshot-15.png)

**Step 3:** The WebView fetches and displays the contents of the local file.

#### Mitigation

1. Disable file access in WebViews (`setAllowFileAccess(false)`).
2. Sanitize all inputs rendered within the WebView to prevent XSS.

#### References

- [OWASP Mobile Top 10 — M7: Client Code Quality](https://owasp.org/www-project-mobile-top-10/2016-risks/m7-client-code-quality)

---

### AllSafe-08: PIN Bypass [Challenge 08]

| Attribute | Detail |
|-----------|--------|
| **Challenge** | 8. PIN Bypass |
| **CWE** | CWE-287: Improper Authentication |
| **OWASP Mobile Top 10** | M8: Code Tampering |
| **Severity** | 🟠 **High** |
| **CVSS v3.1 Score** | **7.5** (High) |
| **CVSS Vector** | `AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Affected Component** | PIN Authentication Logic |

#### Description

The application implements PIN verification locally, which can be bypassed using runtime manipulation tools like Frida.

#### Impact

- **Authentication Bypass:** Attackers can bypass the PIN screen to access protected features.

#### Proof of Concept

**Step 1:** Navigate to the challenge.
![Challenge 08 Briefing](screenshot-16.png)

**Step 2:** Identify the `checkPin` method in the application source code using JADX.
![Jadx checkPin Method](screenshot-17.png)

**Step 3:** Write a Frida script to hook and bypass this method by forcing it to return `true`. The PIN prompt is successfully bypassed.
![Frida Bypass Execution](screenshot-18.png)

#### Mitigation

1. Rely on server-side validation for PINs.
2. Implement robust anti-tampering and anti-hooking mechanisms to detect runtime manipulation.

#### References

- [OWASP Mobile Top 10 — M8: Code Tampering](https://owasp.org/www-project-mobile-top-10/2016-risks/m8-code-tampering)

---

### AllSafe-09: Insecure Object Serialization [Challenge 09]

| Attribute | Detail |
|-----------|--------|
| **Challenge** | 9. Insecure Object Serialization |
| **CWE** | CWE-502: Deserialization of Untrusted Data |
| **OWASP Mobile Top 10** | M8: Code Tampering |
| **Severity** | 🟠 **High** |
| **CVSS v3.1 Score** | **7.5** (High) |
| **CVSS Vector** | `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` |
| **Affected Component** | Native Java Serialization (`user.dat`) |

#### Description

The application insecurely serializes user data and stores it in `user.dat`. Deserialization of this data without validation allows attackers to modify object properties, such as escalating privileges.

#### Impact

- **Privilege Escalation:** By modifying serialized data, an attacker can alter internal state logic and bypass role checks.

#### Proof of Concept

**Step 1:** Open the challenge.
![Challenge 09 Briefing](screenshot-19.png)

**Step 2:** Pull the serialized file `user.dat` from the device.
![ADB Pull Command](screenshot-20.png)

**Step 3:** Open it in a Hex Editor and find the `ROLE_USER` string.
![Hex Editor ROLE_USER](screenshot-21.png)

**Step 4:** Modify it to `ROLE_EDITOR`.
![Hex Editor ROLE_EDITOR](screenshot-22.png)

**Step 5:** Push the modified file back to the device.
![ADB Push Command](screenshot-23.png)

**Step 6:** The application deserializes the tampered object and grants the escalated privileges.
![Success Toast](screenshot-24.png)

#### Mitigation

1. Do not use native Java serialization for sensitive data.
2. Use safer formats like JSON and cryptographically sign serialized objects to detect tampering.

#### References

- [OWASP Mobile Top 10 — M8: Code Tampering](https://owasp.org/www-project-mobile-top-10/2016-risks/m8-code-tampering)

---

### AllSafe-10: Certificate Pinning [Challenge 10]

| Attribute | Detail |
|-----------|--------|
| **Challenge** | 10. Certificate Pinning |
| **CWE** | CWE-295: Improper Certificate Validation |
| **OWASP Mobile Top 10** | M3: Insecure Communication |
| **Severity** | 🟡 **Medium** |
| **CVSS v3.1 Score** | **5.9** (Medium) |
| **CVSS Vector** | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Affected Component** | Network Configuration |

#### Description

The application attempts to pin its SSL certificates, but the implementation is vulnerable to being bypassed using tools like Frida or Objection.

#### Impact

- **MITM Attack:** Attackers can intercept network traffic and view sensitive data in transit.

#### Proof of Concept

**Step 1:** Access the Certificate Pinning challenge.
![Challenge 10 Briefing](screenshot-25.png)

**Step 2:** The application rejects MITM proxies by default.
**Step 3:** Run a Frida pinning bypass script during runtime to bypass the checks.

#### Mitigation

1. Implement robust certificate pinning utilizing frameworks like TrustKit.
2. Implement anti-hooking protections to make dynamic bypass harder.

#### References

- [OWASP Mobile Top 10 — M3: Insecure Communication](https://owasp.org/www-project-mobile-top-10/2016-risks/m3-insecure-communication)

---

### AllSafe-11: Insecure Broadcast Receiver [Challenge 11]

| Attribute | Detail |
|-----------|--------|
| **Challenge** | 11. Insecure Broadcast Receiver |
| **CWE** | CWE-926: Improper Export of Android Application Components |
| **OWASP Mobile Top 10** | M1: Improper Platform Usage |
| **Severity** | 🟡 **Medium** |
| **CVSS v3.1 Score** | **5.3** (Medium) |
| **CVSS Vector** | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` |
| **Affected Component** | `NoteReceiver` |

#### Description

The application exports a broadcast receiver (`NoteReceiver`) without any permissions, allowing external applications to trigger it and potentially perform sensitive actions.

#### Impact

- **Component Hijacking:** Other apps can trigger internal app logic without authorization.

#### Proof of Concept

**Step 1:** Review the challenge briefing.
![Challenge Briefing](screenshot-26.png)

**Step 2:** Locate the exported receiver in the Manifest and its source code.
![NoteReceiver Source Code](screenshot-27.png)

**Step 3:** Trigger the broadcast using ADB: `adb shell am broadcast -a <action>`.
![ADB Broadcast Trigger](screenshot-28.png)

#### Mitigation

1. Set `android:exported="false"` in the Manifest for the receiver.
2. If it must be exported, protect it with custom signature-level permissions.

#### References

- [OWASP Mobile Top 10 — M1: Improper Platform Usage](https://owasp.org/www-project-mobile-top-10/2016-risks/m1-improper-platform-usage)

---

### AllSafe-12: Native Library Challenge

| Attribute | Detail |
|-----------|--------|
| **Challenge** | Native Library Challenge |
| **CWE** | CWE-798: Use of Hard-coded Credentials |
| **OWASP Mobile Top 10** | M9: Reverse Engineering |
| **Severity** | 🟠 **High** |
| **CVSS v3.1 Score** | **7.4** (High) |
| **CVSS Vector** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Affected Component** | `libnative_library.so` / `NativeLibrary.checkPassword()` |

#### Description

This challenge uses JNI to call a native C/C++ library function for password validation. The password check is implemented in compiled code (`libnative_library.so`), making it harder to bypass than Java code. 

#### Impact

- **Authentication Bypass:** Attackers can dynamically hook the native wrapper function in Java using tools like Frida and bypass the password check by forcing it to return true.

#### Proof of Concept

**Step 1:** The user enters a password in EditText, which calls `NativeLibrary.checkPassword(String password)`.
**Step 2:** JNI invokes the native function in `libnative_library.so`.
**Step 3:** To bypass this, a Frida script is created (`native_java_bypass.js`) to hook the Java wrapper:
```javascript
Java.perform(function() {
    console.log("[*] Hooking NativeLibrary.checkPassword");
    try {
        var NativeLib = Java.use("infosecadventures.allsafe.challenges.NativeLibrary");
        NativeLib.checkPassword.implementation = function(password) {
            console.log("[+] checkPassword() called with input: " + password);
            console.log("[+] BYPASSING - returning true regardless of input");
            return true; // Always accept any password
        };
        console.log("[+] Native library bypass installed");
    } catch (e) {
        console.log("[-] Error: " + e);
    }
});
```
**Step 4:** Run Frida with: `frida -U -f infosecadventures.allsafe -l native_java_bypass.js --no-pause`
![[screenshot-29.png]]
**Step 5:** Enter any password and bypass the check successfully.
![[Screenshot 2026-01-01 160857.png]]
#### Mitigation

1. Never rely entirely on client-side security checks, especially for authentication.
2. If client-side checks are required, implement runtime integrity protections and obfuscate the native code.

#### References

- [OWASP Mobile Top 10 — M9: Reverse Engineering](https://owasp.org/www-project-mobile-top-10/2016-risks/m9-reverse-engineering)

---

### AllSafe-13: Smali Patch Challenge (Firewall) [Challenge 14]

| Attribute | Detail |
|-----------|--------|
| **Challenge** | 14. Smali Patch Challenge (Firewall) |
| **CWE** | CWE-693: Protection Mechanism Failure |
| **OWASP Mobile Top 10** | M8: Code Tampering |
| **Severity** | 🟡 **Medium** |
| **CVSS v3.1 Score** | **5.5** (Medium) |
| **CVSS Vector** | `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N` |
| **Affected Component** | `SmaliPatch.smali` / Static APK code |

#### Description

The application initializes an enum value to `INACTIVE`, but the success check requires `ACTIVE`. The challenge involves patching the smali bytecode statically to change this value to bypass the firewall check.

#### Impact

- **Code Tampering:** Attackers can bypass client-side restrictions permanently by modifying the APK file and repackaging it.

#### Proof of Concept
![[screenshot-30.png]]

![[screenshot-31.png]]

**Step 1:** Decompile the APK using apktool: `apktool d allsafe.apk -o allsafe_decompiled`.
![[screenshot-32.png]]
**Step 2:** Locate the `SmaliPatch.smali` file (e.g. `allsafe_decompiled\smali\infosecadventures\allsafe\challenges\SmaliPatch.smali`).
**Step 3:** Open the file and search for the `INACTIVE` enum reference:
```smali
sget-object v0, Linfosecadventures/allsafe/challenges/SmaliPatch$Firewall;->INACTIVE:Linfosecadventures/allsafe/challenges/SmaliPatch$Firewall;
```
**Step 4:** Replace `INACTIVE` with `ACTIVE`:
```smali
sget-object v0, Linfosecadventures/allsafe/challenges/SmaliPatch$Firewall;->ACTIVE:Linfosecadventures/allsafe/challenges/SmaliPatch$Firewall;
```
**Step 5:** Save the file and rebuild the APK: `apktool b allsafe_decompiled -o allsafe-patched.apk`.
![[Screenshot 2026-01-02 121545.png]]
![[screenshot-33.png]]
**Step 6:** Sign the APK using `uber-apk-signer.jar` or `apksigner`.
![[screenshot-34.png]]
**Step 7:** Uninstall the original app and install the patched APK.

`adb uninstall infosecadventures.allsafe`
`adb install allsafe-patched-aligned-debugSigned.apk`

**Step 8:** Test the firewall check, which now evaluates to true.
![[screenshot-35.png]]
#### Mitigation

1. Implement runtime integrity checks (such as SafetyNet or Play Integrity API).
2. Validate the application signature at runtime to detect repackaging.

#### References

- [OWASP Mobile Top 10 — M8: Code Tampering](https://owasp.org/www-project-mobile-top-10/2016-risks/m8-code-tampering)

---

### AllSafe-14: Weak Cryptography [Challenge 15]

| Attribute | Detail |
|-----------|--------|
| **Challenge** | 15. Weak Cryptography |
| **CWE** | CWE-327: Use of a Broken or Risky Cryptographic Algorithm |
| **OWASP Mobile Top 10** | M5: Insufficient Cryptography |
| **Severity** | 🟠 **High** |
| **CVSS v3.1 Score** | **7.5** (High) |
| **CVSS Vector** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Affected Component** | Encryption Implementation |

#### Description

The application uses weak cryptographic algorithms (like AES in ECB mode) or hardcoded encryption keys, compromising the confidentiality of encrypted data.

#### Impact

- **Data Decryption:** Attackers can decrypt ciphertext due to weak algorithmic patterns or known keys.

#### Proof of Concept

**Step 1:** Navigate to the cryptography challenge.
![Challenge 15 Briefing](screenshot-36.png)

**Step 2:** Examine the crypto implementation and observe the usage of ECB mode or hardcoded keys.

#### Mitigation

1. Use strong algorithms (e.g., AES-GCM).
2. Securely manage cryptographic keys utilizing the Android Keystore system.

#### References

- [OWASP Mobile Top 10 — M5: Insufficient Cryptography](https://owasp.org/www-project-mobile-top-10/2016-risks/m5-insufficient-cryptography)

---

### AllSafe-15: Bypass Root Check [Challenge 16]

| Attribute | Detail |
|-----------|--------|
| **Challenge** | 16. Bypass Root Check |
| **CWE** | CWE-693: Protection Mechanism Failure |
| **OWASP Mobile Top 10** | M8: Code Tampering |
| **Severity** | 🟢 **Low** |
| **CVSS v3.1 Score** | **3.3** (Low) |
| **CVSS Vector** | `AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` |
| **Affected Component** | Root Detection Logic |

#### Description

The application detects rooted devices but can be easily bypassed by hooking the root detection methods using a dynamic instrumentation tool.

#### Impact

- **Defense Bypass:** Enables attackers to run the app in hostile, rooted environments.

#### Proof of Concept

**Step 1:** Launch the app and identify the root detection challenge and try to capture a screenshot.![[screenshot-37.png]]


**Step 2:** Write a Frida script to hook `isRooted()` and force it to return false.
![Frida Script Execution](Screenshot%202026-05-28%20152256.png)

**Step 3:** The root check is successfully bypassed.![[screenshot-38.png]]


#### Mitigation

1. Use advanced root detection mechanisms.
2. Combine them with obfuscation and anti-tampering (e.g., SafetyNet API / Play Integrity API).

#### References

- [OWASP Mobile Top 10 — M8: Code Tampering](https://owasp.org/www-project-mobile-top-10/2016-risks/m8-code-tampering)

---

### AllSafe-16: Insecure Providers [Challenge 17]

| Attribute | Detail |
|-----------|--------|
| **Challenge** | 17. Insecure Providers |
| **CWE** | CWE-926: Improper Export of Android Application Components |
| **OWASP Mobile Top 10** | M2: Insecure Data Storage |
| **Severity** | 🟠 **High** |
| **CVSS v3.1 Score** | **7.5** (High) |
| **CVSS Vector** | `AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |
| **Affected Component** | `infosecadventures.allsafe.dataprovider` |

#### Description

The application exports a Content Provider (`infosecadventures.allsafe.dataprovider`) without requiring any permissions, exposing sensitive database contents to any application installed on the device.

#### Impact

- **Data Exfiltration:** Any application on the device can query and steal sensitive data.

#### Proof of Concept

**Step 1:** View the challenge prompt.
![Challenge 17 Briefing](screenshot-39.png)

**Step 2:** Identify the exported `DataProvider` in the `AndroidManifest.xml`.
![Manifest Exported Provider](screenshot-40.png)

**Step 3:** Query the provider using ADB: `adb shell content query --uri "content://infosecadventures.allsafe.dataprovider"`.
![Data Exfiltration](screenshot-41.png)

#### Mitigation

1. Set `android:exported="false"` for all sensitive content providers.
2. If sharing is required, secure them using robust custom permissions (`android:permission`).

#### References

- [OWASP Mobile Top 10 — M2: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage)

---

### AllSafe-17: Secure Flag Bypass [Challenge 18]

| Attribute | Detail |
|-----------|--------|
| **Challenge** | 18. Secure Flag Bypass |
| **CWE** | CWE-693: Protection Mechanism Failure |
| **OWASP Mobile Top 10** | M8: Code Tampering |
| **Severity** | 🟢 **Low** |
| **CVSS v3.1 Score** | **3.3** (Low) |
| **CVSS Vector** | `AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` |
| **Affected Component** | WindowManager (`FLAG_SECURE`) |

#### Description

The application relies on `FLAG_SECURE` to prevent screenshots of sensitive data. This can be bypassed by patching the Smali code or hooking the method using Frida.

#### Impact

- **Screenshot Capture:** Attackers can take screenshots of sensitive screens containing credentials or personal data.

#### Proof of Concept

**Step 1:** Access the challenge screen.
![Challenge 18 Briefing](screenshot-42.png)

**Step 2:** Alternatively, hook the method using Frida.
![Frida Script Execution](screenshot-43.png)

**Step 3:** Recompile and install or run the frida script, allowing screenshots to be taken.

#### Mitigation

1. `FLAG_SECURE` is a UI-level mechanism. Use it alongside root detection and anti-hooking mechanisms to increase difficulty, though a determined attacker with a rooted device can always bypass it.

#### References

- [OWASP Mobile Top 10 — M8: Code Tampering](https://owasp.org/www-project-mobile-top-10/2016-risks/m8-code-tampering)

---

### AllSafe-18: Insecure Service [Challenge 20]

| Attribute | Detail |
|-----------|--------|
| **Challenge** | 20. Insecure Service |
| **CWE** | CWE-926: Improper Export of Android Application Components |
| **OWASP Mobile Top 10** | M1: Improper Platform Usage |
| **Severity** | 🔴 **Critical** |
| **CVSS v3.1 Score** | **8.4** (Critical) |
| **CVSS Vector** | `AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H` |
| **Affected Component** | `RecorderService` |

#### Description

The application exports an insecure background service (`RecorderService`) without required permissions. Any application can start this service to record audio secretly.

#### Impact

- **Silent Audio Recording:** Attackers can stealthily record environmental audio, severely violating user privacy.

#### Proof of Concept

**Step 1:** Open the challenge.
![Challenge 20 Briefing](screenshot-44.png)

**Step 2:** Identify the exported `RecorderService` in the `AndroidManifest.xml`.
![Manifest Exported Service](screenshot-45.png)

**Step 3:** Start the service using ADB: `adb shell am start-foreground-service infosecadventures.allsafe/.challenges.RecorderService`.
![ADB Service Start](screenshot-46.png)

**Step 4:** The device begins recording audio without user interaction.
![Audio Recording Started](screenshot-47.png)
![Audio Recording Stopped](screenshot-48.png)

#### Mitigation

1. Ensure that background services performing sensitive actions (like recording audio) are protected by robust permissions or `android:exported="false"`.

#### References

- [OWASP Mobile Top 10 — M1: Improper Platform Usage](https://owasp.org/www-project-mobile-top-10/2016-risks/m1-improper-platform-usage)

---

## Risk Summary Matrix

| ID | Vulnerability | Severity | CVSS v3.1 | CWE | Status |
|----|--------------|----------|-----------|-----|--------|
| AllSafe-01 | Insecure Logging | 🟠 High | 7.5 | CWE-532 | ✅ Exploited |
| AllSafe-02 | Hardcoded Credentials | 🟠 High | 7.5 | CWE-798 | ✅ Exploited |
| AllSafe-03 | Insecure Shared Preferences | 🟡 Medium | 5.5 | CWE-312 | ✅ Exploited |
| AllSafe-04 | SQL Injection Bypass | 🔴 Critical | 9.8 | CWE-89 | ✅ Exploited |
| AllSafe-05 | Firebase Data Exposure | 🟠 High | 7.5 | CWE-922 | ✅ Exploited |
| AllSafe-06 | Deep Link Exploitation | 🟡 Medium | 6.5 | CWE-939 | ✅ Exploited |
| AllSafe-07 | XSS-Based WebView Attacks | 🟠 High | 7.5 | CWE-79 | ✅ Exploited |
| AllSafe-08 | PIN Bypass | 🟠 High | 7.5 | CWE-287 | ✅ Exploited |
| AllSafe-09 | Insecure Object Serialization | 🟠 High | 7.5 | CWE-502 | ✅ Exploited |
| AllSafe-10 | Certificate Pinning | 🟡 Medium | 5.9 | CWE-295 | ✅ Exploited |
| AllSafe-11 | Insecure Broadcast Receiver | 🟡 Medium | 5.3 | CWE-926 | ✅ Exploited |
| AllSafe-12 | Native Library Challenge | 🟠 High | 7.4 | CWE-798 | ✅ Exploited |
| AllSafe-13 | Smali Patch Challenge (Firewall) | 🟡 Medium | 5.5 | CWE-693 | ✅ Exploited |
| AllSafe-14 | Weak Cryptography | 🟠 High | 7.5 | CWE-327 | ✅ Exploited |
| AllSafe-15 | Bypass Root Check | 🟢 Low | 3.3 | CWE-693 | ✅ Exploited |
| AllSafe-16 | Insecure Providers | 🟠 High | 7.5 | CWE-926 | ✅ Exploited |
| AllSafe-17 | Secure Flag Bypass | 🟢 Low | 3.3 | CWE-693 | ✅ Exploited |
| AllSafe-18 | Insecure Service | 🔴 Critical | 8.4 | CWE-926 | ✅ Exploited |

### Severity Distribution

```
Critical: ████ 2 (11.1%)
High:     ██████████████████ 9 (50.0%)
Medium:   ██████████ 5 (27.8%)
Low:      ████ 2 (11.1%)
```

---

## Conclusion

The AllSafe application assessment revealed **18 vulnerabilities** across various risk categories. The most severe flaws allow complete exploitation of sensitive data, authentication bypass, and severe privacy violations.

These findings highlight common Android security pitfalls:
- ❌ **Exporting components (Services/Providers/Receivers)** without adequate permissions.
- ❌ **Client-side trust** logic for crucial checks like PIN entry and Authentication.
- ❌ **Exposing endpoints and API structures** (Firebase) with missing security rules.
- ❌ **Deserializing untrusted data** which leads to privilege escalation.

### Recommendations Summary

| Priority | Recommendation |
|----------|---------------|
| 🔴 **P0** | Parameterize all SQL queries to mitigate SQL injection completely. |
| 🔴 **P0** | Lock down Firebase instances with rigorous authentication rules. |
| 🔴 **P0** | Restrict exported services, specifically the `RecorderService`. |
| 🟠 **P1** | Implement server-side verification for authentication loops (PINs, Deep Links). |
| 🟠 **P1** | Replace local serialization logic with validated JSON objects. |
| 🟡 **P2** | Add runtime defensive techniques (obfuscation, SafetyNet/Play Integrity). |

---

## References

1. [OWASP Mobile Top 10 (2024)](https://owasp.org/www-project-mobile-top-10/)
2. [CWE — Common Weakness Enumeration](https://cwe.mitre.org/)
3. [CVSS v3.1 Calculator — FIRST](https://www.first.org/cvss/calculator/3.1)
4. [Android Security Best Practices](https://developer.android.com/topic/security/best-practices
