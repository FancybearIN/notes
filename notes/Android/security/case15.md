# **Unintended Data Exposure in IPC (Intents / ContentProviders / Broadcasts)**

📌 **Scenario**  
Android apps communicate between components and apps via Intents, Broadcasts, ContentProviders, AIDL, Bound Services, and Uri permissions. If sensitive data (tokens, PII, files, SQL results) are sent through these IPC channels without appropriate permission checks, exported protection, or URI-scoped grants, any other app on the device — including malicious apps — can intercept or query that data. Common mistakes:

- Sending sensitive payloads in `Intent` extras (broadcasts or startActivity/startService) without using explicit/component-restricted intents.
    
- Exported `ContentProvider`s or `Service`s with no permission checks.
    
- Using `FLAG_GRANT_READ_URI_PERMISSION` incorrectly (overbroad grants), or relying on `file://` URIs instead of `content://` with proper grants.
    
- Using `LocalBroadcastManager` when not available (or mistakenly using global broadcasts).
    
- Exposing results via `PendingIntent` that another app can trigger to get data.
    

---

### **Detection**

1. **Static analysis**
    
    - Search for exported components and IPC usage:
        
        ```bash
        apktool d app.apk
        grep -R -nE "exported=\"true\"|android:exported|<provider|<service|<receiver" AndroidManifest.xml
        grep -R -nE "sendBroadcast|sendOrderedBroadcast|startService|bindService|getContentResolver\\(|query\\(|insert\\(|update\\(|delete\\(" .
        ```
        
    - Find `Intent` extras that look sensitive:
        
        ```bash
        grep -R -nE "putExtra\\(|getExtra\\(|EXTRA_|token|password|ssn|password|secret|auth|session" .
        ```
        
    - Check `FileProvider` config (res/xml/provider_paths.xml) and patterns allowing broad file access.
        
2. **Dynamic analysis**
    
    - Instrument device with a test app that listens for broadcasts (`registerReceiver`) to catch outgoing broadcasts and inspect extras.
        
    - Use `adb shell dumpsys package <pkg>` to list exported components and granted URI permissions.
        
    - Trigger flows (login, share, result callbacks) and monitor:
        
        - Listening for implicit broadcasts.
            
        - Observing content provider queries (via hooking) and returned rows.
            
3. **Runtime hooking**
    
    - Frida hooks to intercept `sendBroadcast`, `startActivity`, `ContentResolver.query/insert`, `FileProvider.getUriForFile`, and `grantUriPermission` to log data and stack traces.
        
        ```js
        // sketch: hook sendBroadcast
        Java.perform(function(){
          var Context = Java.use('android.content.ContextWrapper');
          Context.sendBroadcast.overload('android.content.Intent').implementation = function(i){
            send({action: i.getAction() + '', extras: i.getExtras() ? i.getExtras().toString() : ''});
            return this.sendBroadcast(i);
          };
        });
        ```
        
    - Hook `ContentProvider` methods in the app to inspect what they return.
        
4. **Manifest & merged manifest checks**
    
    - Look for manifest merges that unintentionally export providers/services due to libraries. Use `./gradlew :app:dependencies` and inspect merged manifest (`build/outputs/logs/manifest-merger-debug-report.txt`).
        

---

### **Exploitation**

- **Broadcast interception**
    
    - Implicit broadcasts with sensitive extras can be read by any app that registers for that action → steal tokens/PII.
        
- **ContentProvider enumeration**
    
    - Exported providers without `android:permission` allow other apps to `query()` or `openFile()` and read data (databases, attachments).
        
- **URI-grant abuse**
    
    - Overbroad `FLAG_GRANT_READ_URI_PERMISSION` combined with `file://` URIs allows apps with that grant to access files they shouldn’t.
        
- **PendingIntent abuse**
    
    - PendingIntents with mutable flags or incorrect target components can be hijacked to get results containing sensitive data.
        
- **Service binding / AIDL**
    
    - Bound services/AIDL interfaces exported without permission checks let attackers call methods that return secrets.
        
- **Result callbacks leakage**
    
    - `startActivityForResult` returning sensitive data in result extras can be intercepted if the activity is not component-explicit or if an attacker can spoof/trigger the intent.
        

Attacker vectors: malicious apps that register for actions, request URI grants, exploit exported providers, or piggyback on insecure PendingIntents.

---

### **Test cases / Practical checklist**

- Static:
    
    - `grep -R "android:exported=\"true\"" -n AndroidManifest.xml`
        
    - `grep -R -n "putExtra(" .` then inspect the keys/values around those calls.
        
    - Check `provider` entries: `xpath` or read `res/xml/provider_paths.xml`.
        
- Dynamic:
    
    - Create a test catcher app:
        
        - Register for broad intent filters (both implicit and known actions) and log extras.
            
        - Try to `query()` the target app’s providers (if exported) and `openInputStream()` for provider URIs.
            
    - After a login or sensitive action, run catcher to see if data is broadcasted or accessible.
        
- Frida:
    
    - Hook `getContentResolver().query`, `sendBroadcast`, `startService`, and log arguments and returned results.
        
- Edge cases:
    
    - App uses `exported="false"` but library merges make it true — check merged manifest.
        
    - Temporarily granted URI permissions via `Intent.setData()` and `grantUriPermission()` that aren’t revoked.
        

---

### **Detection signatures & grep snippets**

```bash
# exported components
grep -R -n "exported=\"true\"" AndroidManifest.xml

# Intent extras that look sensitive
grep -R -n -E "putExtra\\(.*(token|passwd|password|secret|session|auth|ssn|card|pan)" .

# provider usage
grep -R -n "getContentResolver\\(|query\\(|openFile" .

# file provider patterns
grep -R -n "FileProvider|provider_paths|grantUriPermission" .
```

---

### **Real Bug Bounty Examples (what pays & why)**

- **Exported ContentProvider leaking DB rows** → High (unrestricted read of user data).
    
- **Implicit broadcast including JWT/access token** → High (token theft).
    
- **PendingIntent with mutable flag returning sensitive result** → High (intent hijack & data leakage).
    
- **Exported AIDL interface exposing credential methods** → Critical (remote API access to secrets).
    

Programs value these because IPC leaks bypass many on-device protections and can be triggered silently by low-privileged apps.

---

### **Mitigation**

1. **Least privilege on components**
    
    - Mark components `android:exported="false"` unless explicitly needed. Enforce this in manifest and CI checks.
        
2. **Require permissions for exported components**
    
    - If export is required, protect with `android:permission` or custom permission with `protectionLevel="signature"` for internal-only APIs.
        
3. **Use explicit Intents**
    
    - Prefer explicit component references (`new Intent(context, MyService.class)`) rather than implicit actions for sensitive interactions.
        
4. **Avoid sending secrets in Intent extras**
    
    - Never pass tokens, passwords, or PII in extras. Pass references (IDs) and fetch sensitive data server-side or via secure, permission-protected APIs.
        
5. **Use content:// URIs + FileProvider + scoped grants**
    
    - Use `FileProvider` for files and grant the minimum necessary URI permission `grantUriPermission()` for a short-lived window; use `FLAG_GRANT_READ_URI_PERMISSION` carefully and revoke when done.
        
6. **Make ContentProviders restrictive**
    
    - Set `android:exported="false"` for providers by default; if exported, check `android:readPermission` / `android:writePermission` or enforce checks in `query/insert` methods.
        
7. **Harden PendingIntents**
    
    - Use immutable `PendingIntent` where appropriate (use `PendingIntent.FLAG_IMMUTABLE`) and keep them targeted. Avoid mutable intents that an attacker can modify.
        
8. **Validate incoming calls**
    
    - In services/AIDL, validate caller identity using `getCallingUid()`/`Binder.getCallingUid()` and map to expected package names/permissions.
        
9. **Sanitize broadcast recipients**
    
    - Use `sendBroadcast` carefully; prefer local broadcasts (`LocalBroadcastManager`) for intra-app messaging.
        
10. **Audit manifest merges**
    
    - CI check for unwanted exported components introduced by libraries; block builds that expose sensitive endpoints unintentionally.
        
11. **Time-limit grants and revoke after use**
    
    - Revoke temporary URI grants after consumption if possible; avoid long-lived grants.
        
12. **Document & test IPC surface**
    
    - Maintain an inventory of exposed IPC endpoints and include IPC testing in security reviews.
        

---

### **Escalation paths & impact reasoning**

- **Token & credential theft** → direct account takeover if tokens are reusable.
    
- **Mass data extraction** → exported provider or unprotected query endpoints allow bulk reads.
    
- **Privilege escalation** → AIDL/services without validation enable control flows normally reserved for the app.
    
- **Persistence & stealth** → malicious low-privilege app runs in background, intercepts broadcasts or queries provider regularly, exfiltrating data silently.
    

Severity depends on what data is exposed, whether access requires user interaction, and whether server-side checks exist (device binding, scope).

---

### **Exploitation notes & POC ideas (concise)**

- **POC A — Broadcast catcher**
    
    1. Install a small app that registers for broad implicit actions.
        
    2. Trigger sensitive flows in target app.
        
    3. Capture and show redacted extras containing tokens/PII.
        
- **POC B — ContentProvider query**
    
    1. Inspect merged manifest for exported provider authority.
        
    2. From attacker app or adb shell, run:
        
        ```java
        Cursor c = getContentResolver().query(Uri.parse("content://<authority>/path"), null, null, null, null);
        ```
        
    3. Dump first row showing sensitive fields (redact values).
        
- **POC C — PendingIntent hijack**
    
    1. If PendingIntent is mutable, craft an Intent to trigger the PendingIntent to return sensitive data to attacker-controlled component — show flow and minimal evidence.
        
- **POC D — AIDL/service call**
    
    1. Bind to exported service from a test app and call exposed method that returns sensitive data; log returned payload (redact values) to prove issue.
        

Always redact live secrets in public reports and include minimal reproduction steps.

---

✅ **Summary**

- IPC is convenient — and dangerous if treated casually. Secrets traveling in Intents, exports, mutable PendingIntents, or open providers are low-hanging fruit for local attackers.
    
- Hunt by auditing the manifest for exported components, grepping for `putExtra`/`query/insert`, using a broadcast-catching test app, and hooking IPC APIs at runtime.
    
- Fix by making components non-exported, enforcing permissions and caller checks, avoiding direct secret transfer via IPC, and using scoped `content://` URIs with minimal grants.
    

Treat your IPC surface like a public API: assume other apps will try it — restrict and authenticate accordingly.