# AndroGoat Android Security Assessment

> **Application:** AndroGoat – Insecure App (Kotlin)  
> **Package:** `owasp.sat.agoat`  
> **Assessment type:** Authorized mobile security training assessment  
> **Environment:** Local Android emulator / test device  
> **Assessor:** Mohamed Hossam Elshamsi  
> **Assessment date:** 2026  

> **Authorization disclaimer:** This assessment was performed exclusively against AndroGoat, an intentionally vulnerable training application, in an authorized lab environment. No production apps, real user accounts, or third‑party services were tested. The content is shared for educational and defensive purposes only.

## Executive summary

This assessment identified multiple weaknesses in data storage, client‑side trust, component exposure, and resilience controls. The most significant lab risks are cleartext storage of credentials, unprotected Android components (activities, services, deep links, content providers), and client‑side enforcement of security logic.

Severity estimates describe the demonstrated lab behavior and should be recalculated for a production deployment using the exact asset, exposure, and business impact.

## Scope and methodology

### In scope

- AndroGoat challenges covering:
  - Insecure data storage (SharedPreferences, SQLite, temporary files, external storage)
  - Data tampering via Shared Preferences
  - Hardcoded secrets (promocode)
  - Unprotected components (exported activity, service, deep link, content provider)
  - Root and emulator detection weaknesses
- Local emulator / test device only

### Out of scope

- Denial‑of‑service testing
- Testing external or production applications
- Testing accounts or systems outside the local AndroGoat environment

### Methodology

1. Installed AndroGoat on an authorized emulator/test device.
2. Performed static review of the APK (manifest, resources, decompiled code).
3. Exercised each challenge and captured behavior with screenshots.
4. Validated insecure storage, component exposure, and client‑side logic using ADB and standard tooling.
5. Documented root cause, practical impact, remediation, and retest criteria.

## Findings summary

| # | Vulnerability | Severity | CVSS | OWASP Mobile Top 10 |
|---|--------------|----------|------|---------------------|
| 1 | Insecure Data Storage — Shared Preferences | High | 7.5 | M2: Insecure Data Storage |
| 2 | Insecure Data Storage — SQLite Database | High | 7.5 | M2: Insecure Data Storage |
| 3 | Insecure Data Storage — Temporary Files | High | 7.5 | M2: Insecure Data Storage |
| 4 | Insecure Data Storage — External Storage / SD Card | High | 7.5 | M2: Insecure Data Storage |
| 5 | Data Tampering — Shared Preferences | Medium | 5.5 | M8: Code Tampering |
| 6 | Hardcoded Secrets — Promocode Bypass | Medium | 5.3 | M9: Reverse Engineering |
| 7 | Unprotected Components — Direct Activity Launch | Medium | 5.3 | M1: Improper Platform Usage |
| 8 | Unprotected Components — Exported Service | Medium | 5.3 | M1: Improper Platform Usage |
| 9 | Unprotected Components — Deep Link Bypass | Medium | 5.3 | M1: Improper Platform Usage |
|10 | Unprotected Components — Exported Content Provider | Low | 3.3 | M1: Improper Platform Usage |
|11 | Inadequate Root Detection | Low | 3.3 | M8: Code Tampering |
|12 | Inadequate Emulator Detection | Low | 3.3 | M9: Reverse Engineering |

---

## 1. Insecure Data Storage — Shared Preferences (cleartext credentials)

- **Severity:** High (CVSS 3.1: 7.5 — `CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`)
- **CWE:** [CWE-312: Cleartext Storage of Sensitive Information](https://cwe.mitre.org/data/definitions/312.html)
- **Description:** The application stores highly sensitive user data, including usernames and passwords, in plain text within its `SharedPreferences` file (`users.xml`).
- **Impact:** Any malicious application that gains root access, or an attacker with physical access to the device (or device backups), can easily read these sensitive credentials, leading to full account compromise.
- **Proof of Concept:**

  **Step 1:** The user enters credentials (`test`/`test`) in the “Shared Preferences — Part 1” activity and taps SAVE:

  ![Shared Preferences Part1 – Entering Credentials](assets/screenshot-01.png)

  **Step 2:** Using ADB shell, navigating to the application’s internal data directory and listing the contents:

  ![ADB Shell – Navigating to App Data Directory](assets/screenshot-02.png)

  **Step 3:** Reading `shared_prefs/users.xml` via `cat` exposes the credentials in plain text:

  ![Cleartext Credentials in users.xml](assets/screenshot-03.png)

- **Mitigation:**
  - Utilize `EncryptedSharedPreferences` from the Jetpack Security library.
  - Use the Android Keystore system to securely generate and store cryptographic keys.
  - Never store raw passwords; use salted hashes if local validation is required.
- **References:**
  - [OWASP Mobile Top 10 — M2: Insecure Data Storage](https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage)
  - [CWE-312](https://cwe.mitre.org/data/definitions/312.html)

---

## 2. Insecure Data Storage — SQLite Database (cleartext credentials)

- **Severity:** High (CVSS 3.1: 7.5)
- **CWE:** CWE-312
- **Description:** The application stores user credentials in an unencrypted SQLite database (`aGoat`) within the app’s internal storage directory.
- **Impact:** An attacker with root access or physical access can extract the database file and read all stored user records in plain text.
- **Proof of Concept:**

  **Step 1:** The user enters credentials in the “SQLite” challenge activity and taps SAVE:

  ![SQLite Challenge – Entering Credentials](assets/screenshot-04.png)

  **Step 2:** Using the `sqlite3` command-line tool via ADB to open the database and query the `users` table reveals plain text credentials:

  ![SQLite Database Dump – Cleartext Credentials](assets/screenshot-05.png)

- **Mitigation:**
  - Use SQLCipher or a similar encrypted database solution.
  - Never store raw passwords; use salted hashes with a strong algorithm.
- **References:**
  - OWASP M2: Insecure Data Storage
  - CWE-312

---

## 3. Insecure Data Storage — Temporary Files (cleartext credentials)

- **Severity:** High (CVSS 3.1: 7.5)
- **CWE:** CWE-312
- **Description:** The application writes sensitive user information to temporary files (e.g., `users...tmp`) in its internal storage directory without any form of encryption.
- **Impact:** Temporary files can be accessed by attackers on rooted devices or through local backups, exposing sensitive credentials.
- **Proof of Concept:**

  **Step 1:** The user enters credentials in the “Temp File” challenge activity:

  ![Temp File Challenge – Entering Credentials](assets/screenshot-06.png)

  **Step 2:** Accessing the app’s internal directory via ADB reveals a `.tmp` file containing the username and password in plain text:

  ![Temp File Contents Exposed](assets/screenshot-07.png)

- **Mitigation:**
  - Avoid writing sensitive data to temporary files entirely.
  - If required, encrypt the data before writing and ensure the files are securely deleted immediately after use.
- **References:**
  - OWASP M2: Insecure Data Storage
  - CWE-312

---

## 4. Insecure Data Storage — External Storage / SD Card (world‑readable credentials)

- **Severity:** High (CVSS 3.1: 7.5)
- **CWE:** CWE-922: Insecure Storage of Sensitive Information
- **Description:** The application writes sensitive user credentials to external storage (SD card), which is world‑readable by any application with `READ_EXTERNAL_STORAGE` permission.
- **Impact:** Unlike internal app storage, external storage has no sandboxing. Any app on the device can read these files, making credential theft trivial without even requiring root access.
- **Proof of Concept:**

  **Step 1:** The application requests broad “Files and media” permissions:

  ![External Storage Permission Request](assets/screenshot-08.png)

  **Step 2:** The user enters credentials in the “External Storage – SDCard” challenge and taps SAVE:

  ![External Storage SD Card – Entering Credentials](assets/screenshot-09.png)

  **Step 3:** Navigating to external storage via ADB reveals a file containing credentials in plain text:

  ![SD Card Credentials Exposed via ADB](assets/screenshot-10.png)

- **Mitigation:**
  - Never store sensitive data on external storage.
  - Use the app’s private internal storage directory with `MODE_PRIVATE`.
  - If external storage is absolutely required, encrypt data using the Android Keystore system.
- **References:**
  - OWASP M2: Insecure Data Storage
  - CWE-922

---

## 5. Data Tampering — Shared Preferences (game logic manipulation)

- **Severity:** Medium (CVSS 3.1: 5.5)
- **CWE:** CWE-472: External Control of Assumed-Immutable Web Parameter
- **Description:** The application relies on an insecurely stored integer in `SharedPreferences` (`score.xml`) to track the user’s score in a minigame, which can be modified directly on disk.
- **Impact:** An attacker can manipulate local application state and business logic by altering data that the app trusts unconditionally.
- **Proof of Concept:**

  **Step 1:** The “Shared Preferences — Part 2” minigame requires 10,000 points to advance. Initial state shows Level 1, Score 0:

  ![Game Initial State – Level 1 Score 0](assets/screenshot-11.png)

  **Step 2:** After a few taps, the score increments normally:

  ![Game State After Interaction](assets/screenshot-12.png)

  **Step 3:** Pulling the `score.xml` file and opening it in a text editor reveals the score stored as a plain integer:

  ![score.xml in Text Editor](assets/screenshot-13.png)

  **Step 4:** The attacker modifies `score.xml` to set the score to 10000 and pushes it back:

  ![Tampering Score XML – Modified to 10000](assets/screenshot-14.png)

  **Step 5:** Upon reopening the activity, the app reads the tampered score and awards a win:

  ![Game Won – Tampering Successful](assets/screenshot-15.png)

- **Mitigation:**
  - Store sensitive state variables on a remote server with server-side validation.
  - If local storage is necessary, use cryptographic signatures (HMAC) or `EncryptedSharedPreferences` to detect tampering.
- **References:**
  - OWASP M8: Code Tampering
  - CWE-472

---

## 6. Hardcoded Secrets — Promocode Bypass

- **Severity:** Medium (CVSS 3.1: 5.3)
- **CWE:** CWE-798: Use of Hard-coded Credentials
- **Description:** The application contains a hardcoded promotional code directly within the source code.
- **Impact:** Attackers can decompile the APK, easily discover the hardcoded secret, and exploit it to gain unauthorized benefits.
- **Proof of Concept:**

  **Step 1:** Decompiling the app with jadx and inspecting the relevant activity reveals the hardcoded promo code:

  ![Decompiled Source – Hardcoded Promo Code](assets/screenshot-16.png)

  **Step 2:** Entering the discovered code in the application UI:

  ![Entering Hardcoded Promo Code](assets/screenshot-17.png)

  **Step 3:** Successfully bypasses the cost, changing the price to 0:

  ![Hardcode Exploit Success – Price 0](assets/screenshot-18.png)

  **Step 4:** Final result showing product obtained for free:

  ![Product Obtained for Free](assets/screenshot-19.png)

- **Mitigation:**
  - Never hardcode secrets, API keys, or business logic bypass codes in the source code.
  - Fetch promotional codes dynamically from a secure backend server.
  - Use code obfuscation tools as defense-in-depth.
- **References:**
  - OWASP M9: Reverse Engineering
  - CWE-798

---

## 7. Unprotected Android Components — Direct Activity Launch (Access Control Bypass)

- **Severity:** Medium (CVSS 3.1: 5.3)
- **CWE:** CWE-926: Improper Export of Android Application Components
- **Description:** A PIN-protected activity can be launched directly via ADB or by a malicious app, completely bypassing the PIN check.
- **Impact:** An attacker or malicious app can invoke protected activities directly, bypassing authentication to access restricted functionalities.
- **Proof of Concept:**

  **Step 1:** The challenge presents a PIN verification screen:

  ![Unprotected Components – PIN Verification Required](assets/screenshot-20.png)

  **Step 2:** Identifying the current activity via ADB:

  ![ADB Dumpsys – Identifying Activity](assets/screenshot-21.png)

  **Step 3:** Static analysis of `AndroidManifest.xml` reveals the activity declaration:

  ![AndroidManifest.xml – Activity Declaration](assets/screenshot-22.png)

  **Step 4:** Decompiled source code shows the PIN check and intent to launch the view activity:

  ![Decompiled Source – PIN Check and Intent](assets/screenshot-23.png)

- **Mitigation:**
  - Set `android:exported="false"` for activities that should not be accessible from external apps.
  - Implement authorization checks within the `onCreate()` method of every sensitive activity.
- **References:**
  - OWASP M1: Improper Platform Usage
  - CWE-926

---

## 8. Unprotected Android Components — Exported Service (Invoice Download Without Auth)

- **Severity:** Medium (CVSS 3.1: 5.3)
- **CWE:** CWE-926
- **Description:** A service responsible for downloading invoices is declared with `android:exported="true"`, allowing any application to start it without authentication.
- **Impact:** A malicious app can trigger the invoice download service directly, accessing sensitive business documents without any PIN verification.
- **Proof of Concept:**

  **Step 1:** Static analysis shows the service is exported:

  ![AndroidManifest – Exported DownloadInvoiceService](assets/screenshot-24.png)

  **Step 2:** Starting the service externally via ADB:

  ![ADB – Starting Exported Service](assets/screenshot-25.png)

  **Step 3:** The service is created successfully, displaying a toast:

  ![Service Created Toast](assets/screenshot-26.png)

  **Step 4:** The service triggers the invoice download:

  ![Invoice Download Triggered](assets/screenshot-27.png)

  **Step 5:** The download completes and the file is visible in the file manager:

  ![Downloaded Invoice in File Manager](assets/screenshot-28.png)

- **Mitigation:**
  - Set `android:exported="false"` for services not intended for external consumption.
  - If the service must be exported, implement a custom permission with `signature` protection level.
- **References:**
  - OWASP M1: Improper Platform Usage
  - CWE-926

---

## 9. Unprotected Android Components — Deep Link Bypass (Custom URL Scheme)

- **Severity:** Medium (CVSS 3.1: 5.3)
- **CWE:** CWE-939: Improper Authorization in Handler for Custom URL Scheme
- **Description:** A protected activity is tied to a custom URL deep link scheme via an intent filter, allowing direct invocation without PIN verification.
- **Impact:** An attacker or a malicious app can invoke the protected activity directly using the deep link, bypassing the PIN authentication entirely.
- **Proof of Concept:**

  **Step 1:** The challenge lists objectives including “Login using Custom URL Scheme”:

  ![Challenge Objectives](assets/screenshot-29.png)

  **Step 2:** Static analysis shows the intent filter for the activity:

  ![AndroidManifest – Deep Link Intent Filter](assets/screenshot-30.png)

  **Step 3:** Executing the ADB command to trigger the deep link:

  ![Triggering Deep Link via ADB](assets/screenshot-31.png)

  **Step 4:** The protected screen is rendered without authentication:

  ![Access Control Bypassed via Deep Link](assets/screenshot-32.png)

- **Mitigation:**
  - If the component does not need to be accessible from other apps, set `android:exported="false"`.
  - If deep linking is required, implement robust authorization and session validation checks within the target activity.
  - Use Android App Links (verified deep links) instead of custom URL schemes where appropriate.
- **References:**
  - OWASP M1: Improper Platform Usage
  - CWE-939

---

## 10. Unprotected Android Components — Exported Content Provider

- **Severity:** Low (CVSS 3.1: 3.3)
- **CWE:** CWE-926
- **Description:** A content provider is declared and can be accessed by other applications on the device.
- **Impact:** A malicious application on the same device could query the Content Provider to extract application data without user awareness.
- **Proof of Concept:**

  **Step 1:** The `AndroidManifest.xml` shows the content provider component:

  ![AndroidManifest – Content Provider Declaration](assets/screenshot-33.png)

  **Step 2:** The component can be launched from external applications using standard ADB intents:

  ![External Activity Launch via ADB](assets/screenshot-34.png)

- **Mitigation:**
  - Set `android:exported="false"` if the Content Provider does not need to share data with other apps.
  - Use `android:permission` attributes to define custom permissions for accessing the provider.
- **References:**
  - OWASP M1: Improper Platform Usage
  - CWE-926

---

## 11. Inadequate Root Detection

- **Severity:** Low (Defense-in-Depth) (CVSS 3.1: 3.3)
- **CWE:** CWE-919: Weaknesses in Mobile Applications
- **Description:** The application’s root detection relies on simple checks for known root binaries and paths, which are easily identifiable and bypassable.
- **Impact:** Attackers can easily bypass these checks using runtime manipulation tools, enabling them to run the app on rooted devices for advanced dynamic analysis.
- **Proof of Concept:**

  **Step 1:** The Root Detection challenge screen:

  ![Root Detection Challenge](assets/screenshot-35.png)

  **Step 2:** Root detection check is bypassed using a runtime exploration framework:

  ![Runtime Tool – Root Detection Bypass](assets/screenshot-36.png)

  **Step 3:** The app now incorrectly displays “Device is not rooted”:

  ![Root Detection Defeated](assets/screenshot-37.png)

- **Mitigation:**
  - Implement the Google Play Integrity API for reliable environment attestation.
  - Combine multiple proprietary checks, execute them using native code, and apply code obfuscation.
- **References:**
  - OWASP M8: Code Tampering
  - OWASP MSTG — Testing Root Detection

---

## 12. Inadequate Emulator Detection

- **Severity:** Low (Defense-in-Depth) (CVSS 3.1: 3.3)
- **CWE:** CWE-919
- **Description:** Emulator detection logic is weak and relies on basic checks that can be trivially bypassed using runtime hooking frameworks.
- **Impact:** Enables attackers to run the app within a controlled emulator environment, significantly lowering the barrier to entry for dynamic analysis and exploitation.
- **Proof of Concept:**

  **Step 1:** The Emulator Detection challenge screen:

  ![Emulator Detection Challenge](assets/screenshot-38.png)

  **Step 2:** Bypassed using a runtime hooking framework with a public script:

  ![Runtime Emulator Detection Bypass Script](assets/screenshot-39.png)

  **Step 3:** After the bypass, the emulator detection check returns “This is not Emulator”:

  ![Emulator Detection Defeated](assets/screenshot-40.png)

- **Mitigation:**
  - Inspect complex telephony and hardware properties that are difficult to emulate.
  - Utilize the Google Play Integrity API.
  - Implement checks in native code with obfuscation.
- **References:**
  - OWASP M9: Reverse Engineering
  - OWASP MSTG — Testing Emulator Detection

---

## General recommendations

1. Avoid storing sensitive data locally; when required, use encrypted storage backed by Android Keystore.
2. Do not trust the client for security decisions; enforce authorization and business rules server-side.
3. Minimize exported components; protect required ones with permissions and internal authorization checks.
4. Validate deep-link parameters and session state before granting access.
5. Use layered resilience controls (obfuscation, integrity checks, Play Integrity) while recognizing they are not primary protections.

## References

- OWASP Mobile Top 10  
- OWASP MASVS / MASTG  
- CWE-312, CWE-472, CWE-798, CWE-919, CWE-926, CWE-939  
- Android Developer Security Best Practices
