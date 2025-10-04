# **Improper Key Management**

📌 **Scenario**  
Developers sometimes treat cryptographic keys like config — they hardcode secrets in code, store keys unencrypted in SharedPreferences/SQLite/files, embed keys in `res/values/strings.xml`, ship private keys inside native `.so` binaries, or generate keys in-app but persist them insecurely. When an attacker extracts those keys, any data encrypted with them (local DB, files, tokens, backups) becomes trivial to decrypt. Keys leaked from one app build often allow mass decryption across all installs if the same key is reused.

Common mistakes:

- Hardcoded API/crypto keys in `BuildConfig`, strings, or constants.
    
- Storing symmetric keys plainly in SharedPreferences or files.
    
- Shipping private keys or certificates inside APK/assets.
    
- Rolling your own key storage instead of using Android Keystore / hardware-backed keymaster.
    
- Reusing one static key across users/devices (shared master key).
    

---

### **Detection**

1. **Static analysis**
    
    - Decompile and grep:
        
        ```bash
        jadx-gui app.apk   # visually inspect
        strings app.apk | grep -Ei "key|secret|private|-----BEGIN|api[_-]?key"
        grep -R --line-number -E "API_KEY|SECRET|PRIVATE_KEY|ENCRYPTION_KEY|KEY_" .
        grep -R "BuildConfig\." -n
        ```
        
    - Inspect `res/values/strings.xml`, `assets/`, and `jniLibs/` for embedded data.
        
    - Use `apktool` to decode resources and check for hardcoded PEM blobs or base64 strings.
        
2. **Binary/native checks**
    
    - Run `strings` on native `.so` files and search for base64 blobs, PEM headers, or hex sequences:
        
        ```bash
        strings lib/armeabi-v7a/libnative.so | grep -E "BEGIN|PRIVATE|ENCRYPT"
        ```
        
    - Use `objdump` / `readelf` to inspect symbols; sometimes keys are concatenated or obfuscated but detectable.
        
3. **Dynamic analysis**
    
    - Run the app, authenticate, and inspect storage:
        
        ```bash
        adb shell run-as com.example.app cat /data/data/com.example.app/shared_prefs/*.xml
        adb shell run-as com.example.app ls -la /data/data/com.example.app/files
        adb shell run-as com.example.app sqlite3 /data/data/com.example.app/databases/app.db "pragma cipher_version;"  # if SQLCipher in use
        ```
        
    - Search for key material in exported backups or crash logs.
        
4. **Runtime hooking & tracing**
    
    - Hook crypto APIs to capture keys in memory or when they're built:
        
        - Hook `javax.crypto.spec.SecretKeySpec`, `KeyGenerator`, `KeyPairGenerator`, and `Cipher.init` calls with Frida to log key bytes or key IDs.
            
    - Monitor `FileOutputStream`/`FileInputStream` writes that store keys to disk.
        
5. **Indicators of weak management**
    
    - Presence of symmetric keys in prefs or files.
        
    - Use of `new SecretKeySpec(keyBytes, "AES")` without keystore-wrapped key material.
        
    - Lack of `KeyStore` usage or use of `KeyStore` but with keys exported or derived from static seeds.
        

---

### **Exploitation**

- **Decrypt local data**: Extracted symmetric key → decrypt SQLite DB, cached files, exported backups, or config blobs.
    
- **Impersonation / signing**: If private signing keys are stored, attacker can sign requests, forge tokens, or generate valid authentication artifacts.
    
- **Mass compromise**: If app uses one master key across users, breaking one device breaks all.
    
- **Key reuse pivot**: Keys reused across dev/test/prod or across multiple apps allow lateral escalation.
    
- **Offline decryption at scale**: Extracted key + stolen backups allow offline, automated decryption of many victims’ data.
    

Attacker vectors: reverse-engineer APK, pull files on rooted device or via adb/run-as on debuggable builds, extract from backups, memory-dump keys if app keeps them in memory unprotected.

---

### **Test cases / How I hunt this (practical checklist)**

- Static:
    
    - `grep -R -n -E "KEY|SECRET|PRIVATE|PASSWORD|ENCRYPTION|BEGIN|-----" .`
        
    - Inspect `res/values`, `assets`, `native libs`, `BuildConfig`.
        
- Dynamic:
    
    - Create test account, trigger encryption flows (save file, export backup), then inspect app storage for key material.
        
    - Attempt to decrypt data using discovered strings/base64.
        
- Hooking:
    
    - Frida hooks:
        
        - `javax.crypto.spec.SecretKeySpec` constructor to intercept key bytes.
            
        - `javax.crypto.Cipher.init` to capture mode/key parameters.
            
    - Capture stack traces to map where key was created/stored.
        
- Edge cases:
    
    - Check for keys derived from weak static seeds (e.g., device id + constant).
        
    - Inspect use of native obfuscation — large base64 blobs in `.so` may hide keys.
        
    - Check CI/CD artifacts (if app fetches keys from remote during build).
        

---

### **Detection signatures (grep / regex examples)**

```bash
# PEM private key
grep -R -n -E "-----BEGIN (RSA|EC|PRIVATE) KEY-----" .

# Base64-looking long strings (possible keys/blobs)
grep -R -n -E "[A-Za-z0-9+/]{40,}={0,2}" .

# Common key identifiers
grep -R -n -E "ENCRYPTION_KEY|ENCRYPT_KEY|MASTER_KEY|API_KEY|PRIVATE_KEY|SECRET_KEY|KEY_MATERIAL" .
```

---

### **Exploitation notes & concise PoC ideas**

- **POC A — Recover hardcoded key from resources**
    
    1. Decompile APK (jadx/apktool), locate key string or PEM block.
        
    2. Use local script / OpenSSL / crypto library to decrypt an encrypted blob shipped with the app (e.g., DB or config) using the extracted key to demonstrate plaintext recovery.
        
- **POC B — Hook runtime key creation**
    
    - Use Frida to intercept `SecretKeySpec` and `Cipher.init` to dump key bytes; use them to decrypt local encrypted DB to demonstrate impact.
        

(Keep PoC minimal and redacted for reports — show decrypted sample output with sensitive bits redacted.)

---

### **Mitigation**

1. **Never hardcode keys or ship private keys in the APK.** Treat any secret in the app as extractable.
    
2. **Use Android Keystore / hardware-backed keys**
    
    - Generate keys inside the Keystore (KeyPairGenerator / KeyGenerator) and mark them non-exportable. Use Keystore to perform crypto operations or wrap symmetric keys with a Keystore key.
        
    - Example: generate an AES key protected by KeyStore and use it for `Cipher` operations, or use Keystore-backed RSA to wrap/unwarp symmetric keys.
        
3. **Don’t persist raw key material**
    
    - If you must store symmetric keys, store only Keystore-wrapped keys or use `EncryptedSharedPreferences` / `EncryptedFile` that rely on Keystore-managed keys.
        
4. **Use per-device/per-user keys and rotate them**
    
    - Avoid a single master key across installs. Rotate keys and support server-side revocation.
        
5. **Apply user authentication & authorization for key use**
    
    - Use `setUserAuthenticationRequired()` so keys require user auth (PIN/fingerprint) for use.
        
6. **Derive keys securely, not from static seeds**
    
    - If deriving keys from user secrets, use proven KDFs (PBKDF2 with strong iteration, Argon2) and include per-user random salt.
        
7. **Avoid client-side signing of sensitive server trust artifacts**
    
    - Keep high-value signing/CA keys on the server. Client-side private keys should be ephemeral or user-bound.
        
8. **Minimize key scope & lifetime**
    
    - Short lived session keys, refreshable by the server; store minimal secrets on device.
        
9. **Obfuscation is not a defense**
    
    - Use ProGuard/R8 and native obfuscation only to raise cost — do not rely on it as a security control.
        
10. **Audit native code and libraries**
    

- Ensure third-party native libs do not embed keys or leak key material.
    

11. **Secure build & CI practices**
    

- Don’t bake production keys into build artifacts; use secure secret management in CI and inject keys only at runtime if needed (and still avoid shipping them).
    

12. **Monitor & rotate after incidents**
    

- If a key is suspected leaked, rotate keys and re-encrypt affected data ASAP.
    

---

### **Escalation paths & impact reasoning**

- **Decrypt & exfiltrate private user data** — local DBs, messages, stored files.
    
- **Forge authentication artifacts** — if keys sign tokens, attacker can mint valid tokens.
    
- **Mass decryption** — shared master keys allow batch decryption of many users’ data.
    
- **Bypass server-side checks** — stolen private keys may let attacker impersonate client or bypass integrity checks.
    
- **Compliance/regulatory fallout** — exposure of encrypted PII that was assumed protected can trigger legal consequences.
    

Impact depends on key usage (symmetric vs. signing), key scope, TTL, and whether server-side checks (device binding, revocation) exist.

---

✅ **Summary**

Improper key management is catastrophic because keys unlock everything. Hunt for hardcoded or persisted key material (strings, assets, native blobs), hook crypto APIs at runtime to confirm key creation/storage, and prioritize fixes that move key material into the Android Keystore (hardware-backed, non-exportable) or avoid storing keys on-device at all. Rotate quickly, apply user-auth gating, and never trust obfuscation as your only protection — make keys scarce, short-lived, and properly managed.