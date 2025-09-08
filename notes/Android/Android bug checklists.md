### Easy to Find (Low-hanging fruit but still valid)

- **Insecure WebView Usage**
    
    - `addJavascriptInterface()` without `@JavascriptInterface` or with untrusted input.
        
    - Loading remote content in `WebView` with `setAllowFileAccess(true)` or `setAllowUniversalAccessFromFileURLs(true)`.
        
- **Exported Activities/Services/Receivers**
    
    - No permission check on exported components.
        
    - Can lead to privilege escalation or data exfiltration.
        
- **Hardcoded API Keys / Secrets in APK**
    
    - Keys visible in `res/values/strings.xml`, `.so` libraries, or simply decompiled `.dex`.
        
    - Many programs pay for _leaked production credentials_.
        
- **Backup Enabled / Debuggable App**
    
    - `android:allowBackup="true"` → attacker can extract app data.
        
    - `android:debuggable="true"` → app runs in debug mode, easier to tamper.
        

---

### ⚡ Medium to Find (Require digging, but high payout if valid)

- **SQL Injection / No Input Sanitization**
    
    - Especially in content providers (`query()`, `insert()`, etc.).
        
- **Insecure Data Storage**
    
    - Sensitive info in SharedPreferences, SQLite, or logs without encryption.
        
- **Deep Link Hijacking**
    
    - Malicious app intercepting intent-filter URLs (`scheme://...`) and stealing auth tokens.
        
- **Misconfigured Permissions**
    
    - App requesting dangerous permissions unnecessarily (e.g. `READ_SMS`, `READ_CONTACTS`) that can be abused via component interaction.
        
- **Custom Cryptography**
    
    - Developers rolling their own crypto (weak AES modes like ECB, hardcoded IVs, static keys).
        

---

### 🔥 Hard to Find (High-skill, high-pay)

- **Privilege Escalation via Binder/IPC**
    
    - Abuse of custom AIDL interfaces to escalate privileges or access restricted functions.
        
- **Race Conditions / TOCTOU (Time-of-check to time-of-use)**
    
    - Example: file path checks before file operations.
        
- **RCE in Native Libraries (NDK bugs)**
    
    - Memory corruption in `.so` files, unsafe `strcpy`/`sprintf`.
        
- **Authentication / Session Bugs**
    
    - JWT token leaks, weak refresh token logic, improper OAuth flows.
        
- **Secure Hardware Misuse**
    
    - Improper use of Keystore/TEE (e.g., exporting private keys).
        
- **App ↔ Server Chain Exploits**
    
    - Bugs where Android client logic allows server-side abuse (API request tampering, bypassing root/jailbreak checks).