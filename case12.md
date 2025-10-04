# **Third-Party Library / SDK Issues**

📌 **Scenario**  
Apps pull in SDKs and libraries (analytics, crash reporters, ad SDKs, payment SDKs, social login, push, DRM, cloud storage helpers). Those SDKs often maintain their own caches, logs, tokens, crash dumps, or local databases — and they don’t always follow the host app’s security posture. Result: your app can indirectly leak sensitive info because an SDK:

- writes unencrypted tokens or PII to `shared_prefs`, files, or external storage,
    
- logs full HTTP bodies to Logcat,
    
- uploads crash dumps containing secrets to third-party consoles, or
    
- exposes a local IPC/content provider that is world-accessible.
    

You didn’t write the buggy code, but you ship the risk.

---

### **Detection**

1. **Inventory the dependencies**
    
    - List all SDKs (gradle deps, `google-services.json`, `AndroidManifest.xml` entries, native libs). `grep` for common SDK strings (`firebase`, `crashlytics`, `ads`, `mixpanel`, `appsflyer`, `adjust`, `branch`, `segment`, `onesignal`, etc.).
        
2. **Static probes**
    
    - Decompile and inspect SDK packages (look under `com.*` namespaces for suspicious storage calls).
        
    - Search for `SharedPreferences`, `getFilesDir()`, `openFileOutput`, `ContentProvider` declarations in SDK packages.
        
3. **Dynamic observation**
    
    - Run app, exercise flows. Then enumerate app storage (shared_prefs, files, databases). Many SDKs use their own pref names — look for unfamiliar XMLs or DBs.
        
    - Tail Logcat to catch SDK logs: `adb logcat | grep -iE "crash|sdk|analytics|token|api|error|exception"`.
        
    - Intercept network traffic (Burp/mitmproxy) to find SDK endpoints and what they send (crash dumps, analytics payloads).
        
4. **Hooking & monitoring**
    
    - Use Frida to hook SDK classes/methods (or generic APIs) that write files, call `Log.*`, or perform HTTP uploads.
        
    - Hook `java.io.FileOutputStream.write`, `SharedPreferences.Editor.putString`, and `android.util.Log.*` and filter by package name of SDK.
        
5. **Manifest & exported components**
    
    - Check `AndroidManifest.xml` for exported providers/services/receivers from SDKs that may be misconfigured: `android:exported="true"` without permission guards.
        
6. **Third-party console checks**
    
    - If possible, inspect third-party dashboards (crash/analytics) for uploaded stack traces or breadcrumbs that contain PII — sometimes accessible via dev accounts or observed via intercepted requests.
        

---

### **Exploitation**

- **Local extraction**: SDKs that store tokens/prefs in app storage allow extraction via `run-as`/root/backups.
    
- **Remote exfiltration**: SDKs that upload crash logs or analytics may send PII or tokens off-device to their servers, creating a second data leak channel.
    
- **Privilege exposure**: Exported content providers/services from SDKs may allow other apps to query or inject data, leaking user info.
    
- **Supply-chain abuse**: Compromised SDK update or malicious SDK can exfiltrate everything (install-time or runtime).
    
- **Chaining**: SDK logs might include backend endpoints, API keys, or internal IDs that help craft further attacks (API fuzzing, SSRF, replay).
    

Attacker vectors: other local apps, rooted devices, malicious SDK updates, network interception of SDK endpoints, or service-account/API misuse in SDK configuration.

---

### **Test cases / Practical checklist**

- Dependency list: `./gradlew app:dependencies` → audit each entry.
    
- After normal app usage:
    
    - `adb shell run-as com.example.app ls -la /data/data/com.example.app/shared_prefs/` — look for unfamiliar files.
        
    - `adb shell run-as com.example.app ls -la /data/data/com.example.app/files/`
        
    - `adb shell run-as com.example.app sqlite3 /data/data/com.example.app/databases/*.db "select * from sqlite_master;"`
        
- Log analysis:
    
    - `adb logcat -d > sdk-logs.txt` → grep for tokens/JWTs/PII.
        
- Network:
    
    - Intercept SDK traffic; inspect payloads for full JSON responses, stack traces, breadcrumbs.
        
- Manifest:
    
    - `aapt dump xmltree app.apk AndroidManifest.xml | grep -n "provider\|service\|receiver"` → inspect exported flags and permission requirements.
        
- Hooking:
    
    - Hook `SharedPreferences.Editor.putString`, `FileOutputStream.write`, and `Log.*` and filter by packages `com.crashlytics.*`, `com.adjust.*`, etc., to capture data flows.
        

---

### **Detection signatures (grep / regex examples)**

```bash
# find likely SDK namespaces and storage usage
grep -R -nE "com\.crashlytics|com\.google\.firebase|com\.mixpanel|com\.adjust|com\.branch|com\.appsflyer|onesignal|segment" .

# find prefs & file writes
grep -R -nE "getSharedPreferences|getFilesDir|openFileOutput|new File\\(" .

# logs and tokens from SDK traffic/logs
grep -iE "token|jwt|access[_-]?token|refresh|password|ssn|email" sdk-logs.txt
```

---

### **Real Bug Bounty Examples (what pays & why)**

- SDK crash dumps containing full API responses or JWTs → high severity because data leaves device to third-party servers.
    
- Analytics events that include PII (email, phone, SSN) persisted in SDK storage or sent to vendor → high severity (PII leakage).
    
- Exported provider from an SDK allowing unauthenticated reads of telemetry files → high severity (local attacker reads data).
    
- Hardcoded SDK keys in APK granting access to vendor APIs → critical (third-party API abuse).
    

Bounties reward these because the app owner’s data ends up in external ecosystems they don’t control; remediation often requires both app and SDK configuration changes.

---

### **Mitigation**

1. **Dependency hygiene**
    
    - Only include SDKs you trust; minimize SDK footprint; prefer modular imports (only the features you need).
        
2. **Audit SDK behavior**
    
    - Read SDK docs and privacy/security guides. Know where they store data and what they transmit.
        
3. **Runtime controls**
    
    - Configure SDKs to disable verbose logging, body-level network logs, or debug modes in release builds.
        
    - Disable automatic crash/analytics uploads for sensitive flows (or redact breadcrumbs).
        
4. **Sandboxing storage**
    
    - If SDK supports custom storage paths or callbacks for data handling, route its storage through app-managed encrypted storage (EncryptedSharedPreferences / EncryptedFile).
        
5. **Sanitization & filtering**
    
    - Provide SDK with sanitized metadata. Remove tokens, PII, or full request/response bodies from breadcrumbs or analytics events.
        
6. **Manifest hardening**
    
    - Ensure exported components from SDK are protected by permissions; if not, consider manifest mergers to override `android:exported` or add guards.
        
7. **Use SDK configuration flags**
    
    - Many SDKs provide options (e.g., disable automatic session tracking, redact fields, disable log uploads) — set them to the restrictive mode in production.
        
8. **Runtime monitoring & allowlist**
    
    - Intercept SDK network endpoints in staging to review uploads. Use allowlist for which domains SDK can contact (via network security config) if feasible.
        
9. **Vendor contracts & provenance**
    
    - Prefer SDKs from reputable providers, pin versions, and monitor update release notes. Consider repackaging vetted SDKs into internal artifacts.
        
10. **Least privilege keys**
    
    - If SDK requires API keys, generate least-privilege keys (scoped, time-limited) and rotate them regularly.
        
11. **Remove unused features**
    
    - Disable or remove modules (e.g., remote config, deep analytics) you don’t need; fewer features → smaller attack surface.
        
12. **Fail-closed for sensitive features**
    
    - If SDK misbehaves (uploads or leaks), app should have a toggle or remote config to disable it quickly.
        

---

### **Escalation paths & impact reasoning**

- **Indirect data leak** → PII ends up with third-party vendors; attacker may access vendor consoles or exfiltrate data via their APIs.
    
- **Token reuse** → SDK logs reveal tokens that can be replayed to backend APIs.
    
- **Platform-level pivot** → SDK with exported provider or weak ACLs allows other apps to query telemetry or config, leaking sensitive tokens.
    
- **Supply-chain compromise** → malicious SDK update pushes exfiltration logic to all apps using it — huge blast radius.
    

Impact scales with SDK distribution breadth, sensitivity of collected data, retention policy on vendor side, and whether vendors provide RBAC to their consoles.

---

### **Exploitation notes & POC ideas (concise)**

- **POC A — Find SDK-stored secrets**
    
    1. Use `run-as` or emulator to list prefs/files after exercising app.
        
    2. Show a redacted example where SDK stored an unencrypted token or PII in `shared_prefs` or files.
        
- **POC B — Intercept SDK uploads**
    
    1. MITM SDK endpoints in staging; demonstrate JSON payload containing PII or response bodies. Redact user-specific fields in report.
        
- **POC C — Exported provider abuse**
    
    1. Identify exported provider from SDK in merged manifest.
        
    2. Write a small test app that queries the provider and retrieves sensitive blobs (proof of accessible data).
        

Always redact PII in shared reports and provide minimal repro for triage.

---

✅ **Summary**

Third-party SDKs are loyal little moles — useful, but they bring their own storage, logging, and network behavior. Inventory them, audit what they persist/transmit, sandbox or encrypt their outputs, disable verbose uploads in production, and prefer minimal, well-configured SDK usage. Treat every SDK like a subsystem you must secure, not an oracle you can ignore.