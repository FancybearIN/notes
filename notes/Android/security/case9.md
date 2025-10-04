# **Session Tokens Stored Insecurely**

📌 **Scenario**  
Apps persist session tokens, refresh tokens, OAuth access tokens, JWTs, or auth cookies in places that are easy to read by an attacker (plaintext in SharedPreferences, SQLite, files in internal storage, external storage, or weakly protected Key/Value stores). If these tokens are long-lived or not bound to the device/session, an attacker who extracts them can impersonate the user → full account takeover, data theft, transactions, or service abuse.

---

### **Detection**

1. **Static analysis**
    
    - Search for storage APIs and suspicious keys:
        
        ```bash
        grep -R -n -E "SharedPreferences|getSharedPreferences|PreferenceManager|openOrCreateDatabase|SQLiteDatabase|dbHelper|write\\(|putString\\(|putLong\\(" .
        grep -R -n -E "token|access[_-]?token|refresh[_-]?token|jwt|session|auth|cookie|credentials" .
        ```
        
    - Inspect code patterns:
        
        - `prefs.edit().putString("token", token).apply()`
            
        - `db.insert("sessions", ...)`
            
        - `new File(getFilesDir(), "session.txt")`
            
    - Check for use of encryption libs (e.g., AndroidX Security `EncryptedSharedPreferences`, `SQLCipher`) vs. plain APIs.
        
2. **Dynamic analysis**
    
    - Run the app, authenticate, then inspect storage:
        
        - SharedPreferences:
            
            ```bash
            adb shell run-as com.example.app cat /data/data/com.example.app/shared_prefs/<name>.xml
            ```
            
        - Internal files:
            
            ```bash
            adb shell run-as com.example.app ls -la /data/data/com.example.app/files
            adb shell run-as com.example.app cat /data/data/com.example.app/files/session.txt
            ```
            
        - SQLite:
            
            ```bash
            adb shell run-as com.example.app ls -la /data/data/com.example.app/databases
            adb shell run-as com.example.app sqlite3 /data/data/com.example.app/databases/app.db "select * from sessions;"
            ```
            
    - On non-rooted device where run-as fails, use emulator or rooted device.
        
    - Dump app storage with `adb backup` on older Android (careful, limited nowadays).
        
3. **Runtime hooking / memory inspection**
    
    - Hook prefs/file APIs with Frida to catch writes:
        
        ```js
        Java.perform(function(){
          var Pref = Java.use('android.app.SharedPreferences$Editor');
          Pref.putString.overload('java.lang.String','java.lang.String').implementation = function(k,v){
            send({k:k,v:v});
            return this.putString(k,v);
          };
        });
        ```
        
    - Hook network libraries to map tokens to storage writes (see where access token from auth response is stored).
        
4. **Token location heuristics**
    
    - Check WebView cookies (CookieManager).
        
    - Inspect exported content providers that may leak data.
        
    - Check external storage (rare but catastrophic): `/sdcard/Android/data/<pkg>/files/*`
        

---

### **Exploitation**

- **Extract & reuse tokens**
    
    - Pull token from prefs/DB → set `Authorization: Bearer <token>` in API calls → access account.
        
- **Refresh token theft**
    
    - Steal refresh token to mint new access tokens indefinitely (higher impact than short-lived access token theft).
        
- **Cookie theft**
    
    - If cookies are stored in plaintext and reused by WebView or backend, attacker can impersonate browser session.
        
- **Token replay & privileged actions**
    
    - Use stolen token to perform actions (transfer, read PII, delete data) depending on token scopes.
        
- **Escalation**
    
    - Tokens may reveal scopes, client_id, or user_id → craft targeted API abuse, find admin endpoints or pivot to backend logic flaws.
        

Attacker vectors: local malware, malicious app with ability to read files (external storage), physical device access, rooted device, or compromised CI that consumes a backup.

---

### **Test cases / Practical checklist**

- Static:
    
    - `grep -R -n "putString(\"token"`
        
    - Check `build.gradle` for inclusion of `EncryptedSharedPreferences` usage.
        
- Dynamic:
    
    - Authenticate with test account.
        
    - Enumerate storage: shared_prefs, files, databases, cache.
        
    - Look for tokens stored verbatim (`bearer`, JWT结构 `xxx.yyy.zzz`).
        
- Frida:
    
    - Hook `putString`, `write`, `FileOutputStream.write`, `SQLiteDatabase.insert/update` to capture token write moments and stack traces.
        
- Edge cases:
    
    - Tokens in WebView localStorage / IndexedDB — inspect via remote debugger (chrome://inspect).
        
    - Tokens saved in crash logs, analytics events, or uploaded to third-party SDKs.
        
    - Tokens written to external storage or world-readable files (older API flags).
        

---

### **Detection signatures (grep / regex examples)**

```bash
# Find likely token strings in storage dumps
grep -iE "access[_-]?token|refresh[_-]?token|authorization|bearer|jwt" /path/to/dump -n

# JWT regex
grep -oE "([A-Za-z0-9_-]+\.){2}[A-Za-z0-9_-]+" /path/to/dump

# Simple Authorization header like patterns
grep -iE "Authorization: Bearer [A-Za-z0-9\-\._~\+\/]+=*" /path/to/dump
```

---

### **Real Bug Bounty Examples (what pays & why)**

- **Refresh tokens stored in plaintext** → High/Critical (long-term takeover); high payouts when refresh tokens are not rotated or bound.
    
- **Access tokens with broad scopes persisted plaintext** → High (data exfiltration / actions-as-user).
    
- **Persistent session cookie in file readable by other apps or world-readable** → Critical if it maps to privileged session.
    
- **Tokens included in logs or analytics exports** → High depending on data exposure.
    

Programs prioritize token/credential storage issues because they directly enable account takeover and widespread abuse.

---

### **Mitigation (practical & defensive)**

1. **Prefer platform KeyStore for secrets**
    
    - Store cryptographic keys in Android Keystore (hardware-backed if available). Use Keystore to encrypt/decrypt tokens, not as direct storage for blobs.
        
        - Generate an AES key in Keystore, use it to encrypt tokens before persisting.
            
2. **Use `EncryptedSharedPreferences` / secure DB**
    
    - AndroidX Security `EncryptedSharedPreferences` and `EncryptedFile` wrap proper AES keys in Keystore.
        
    - For databases, use SQLCipher or encrypt values before inserting.
        
3. **Avoid plaintext persistence**
    
    - Keep access tokens in memory only; persist only refresh tokens if absolutely necessary and encrypt them.
        
4. **Minimize token scope & TTL**
    
    - Use the principle of least privilege: short-lived access tokens, minimal scopes. Refresh tokens should be short and rotated.
        
5. **Bind tokens to device/session**
    
    - Use token binding: include device identifier or proof-of-possession (mutual TLS, client-assertion, or signed requests).
        
6. **Use HttpOnly, Secure cookies for WebView**
    
    - When using WebView/embedded browser, ensure cookies are HttpOnly when appropriate and not exposed to JS or app file storage.
        
7. **Protect backups & external storage**
    
    - Avoid writing secrets to external storage; exclude sensitive files from backups.
        
8. **Secure deletion & rotation**
    
    - On logout or credential change, delete persisted tokens and revoke them server-side when possible.
        
9. **Detect jailbroken/rooted devices**
    
    - Consider additional hardening on rooted devices (e.g., refuse to run or reduce functionality), but don’t rely on it.
        
10. **Audit third-party SDKs**
    
    - Ensure SDKs don’t persist tokens insecurely or leak to analytics.
        
11. **Monitoring & anomaly detection**
    
    - On server-side, monitor unusual token usage (geo, device, simultaneous sessions) and revoke suspect tokens.
        
12. **Code hygiene**
    
    - Don’t log tokens; avoid embedding tokens in Intents or extras that may be readable by other apps.
        

---

### **Escalation paths & impact reasoning**

- **Immediate full account takeover** — stolen refresh token → mint new tokens → persistent access.
    
- **Cross-service pivot** — token or credentials used across services (dev/test environments) → wider breach.
    
- **Monetary fraud** — if tokens allow transactions.
    
- **Mass compromise** — if keys used to encrypt tokens are hardcoded or shared across installations.
    
- **Regulatory / reputational damage** — PII exposure via token access triggers legal issues.
    

Severity depends on token lifetime, scope, whether token can be exchanged for privileged access, and server-side checks (IP/device binding, rotation).

---

### **Exploitation notes & POC ideas (concise)**

- **POC A — Extract token from SharedPreferences**
    
    1. Authenticate in app.
        
    2. `adb shell run-as com.example.app cat /data/data/com.example.app/shared_prefs/app_prefs.xml`
        
    3. Copy token value; call API:
        
        ```bash
        curl -H "Authorization: Bearer <token>" https://api.target/user/me
        ```
        
    4. Show returned user info (redacted in report).
        
- **POC B — Extract refresh token from DB**
    
    1. `adb shell run-as com.example.app sqlite3 /data/data/com.example.app/databases/app.db "select refresh_token from sessions;"`
        
    2. Use refresh endpoint to obtain new access token and access protected endpoints.
        
- **POC C — Frida capture & stacktrace**
    
    - Hook `putString("refresh_token", ...)` to capture value and stack (identifies code path storing it).
        
- **POC D — WebView localStorage**
    
    - Connect Chrome remote debugger → Application tab → inspect LocalStorage / IndexedDB for tokens.
        

Always redact secrets in external reports; include reproduction steps required by the program.

---

✅ **Summary**

- Storing session/access/refresh tokens in plaintext anywhere on device is a direct path to account takeover.
    
- Hunt by grepping for storage APIs and token-named keys, dump SharedPreferences/DB/files after login, and hook runtime writes to map flow → storage.
    
- Fix by using Keystore-backed encryption (EncryptedSharedPreferences/EncryptedFile/SQLCipher), minimizing token lifetime/scope, binding tokens to device, server-side rotation/revocation, and avoiding persistence of access tokens when possible.
    

Keep token handling paranoid and ephemeral — tokens are tiny keys that open big doors.