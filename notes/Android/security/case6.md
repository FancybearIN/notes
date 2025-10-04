# **Logs (Logcat)**

📌 **Scenario**  
Android apps (and libraries) commonly log debugging and operational data to Logcat via `android.util.Log`, `Timber`, `System.out/err`, or logging frameworks (OkHttp/Retrofit/Volley wrappers). If logs contain sensitive values — access tokens, JWTs, API keys, full API responses, passwords, PAN/CC numbers, PII — they become readable to:

- anyone with **adb** access (`adb logcat`),
- attackers on rooted devices,
- system apps or apps signed with platform keys that retain `READ_LOGS` capability (or on older Android where `READ_LOGS` was permitted),
- malicious local apps on devices with lax permission models or compromised devices.

Logs may persist across runs (dumped files, log buffers) and appear in crash reports. Developers frequently leave verbose logging enabled in production builds or log entire JSON responses for convenience — a juicy target.

---

### **Detection**

1. **Static analysis (APK / source)**
    
    - Search APK for logging calls and frameworks:
        
        ```bash
        # inside decompiled smali/java dir or source
        grep -R --line-number -E "android.util.Log|Timber\.|System\.out|println|org.slf4j|java.util.logging|Logcat" .
        ```
        
    - Grep for likely tags/strings:
        
        ```bash
        grep -R --line-number -E "token|password|pwd|jwt|access[_-]?token|api[_-]?key|ssn|card|pan|ccv|cvv|authorization" .
        ```
        
    - Inspect network libraries: look for `OkHttp` interceptors, `HttpLoggingInterceptor`, `LoggingInterceptor`, where bodies may be logged.
        
    - Check `build.gradle` for debug flags accidentally enabled in release (e.g., `buildTypes.release.debuggable true`, `minifyEnabled false`, `shrinkResources false`, or logging libraries included in release).
        
2. **Dynamic analysis (runtime / adb)**
    
    - Dump current logs:
        
        ```bash
        adb logcat -d > device-logs.txt
        ```
        
    - Live tail while performing actions (login, payments, upload):
        
        ```bash
        adb logcat -v threadtime | grep -iE "token|jwt|password|authorization|api|card|ssn|email|phone"
        ```
        
    - Filter by app PID or tag:
        
        ```bash
        # get package PID
        adb shell pidof com.example.app
        adb logcat --pid=<PID> -v threadtime
        ```
        
    - Pull crash reporters or saved logs (some apps write logs to storage): check `/sdcard/` and app data folders.
        
3. **Runtime hooking / file system monitoring**
    
    - Use Frida to hook logging APIs and capture arguments:
        
        ```js
        // simple Frida snippet (hook android.util.Log.d)
        Java.perform(function(){
          var Log = Java.use('android.util.Log');
          Log.d.overload('java.lang.String','java.lang.String').implementation = function(tag,msg){
            send({type:'log', tag:tag, msg:msg});
            return this.d(tag,msg);
          };
        });
        ```
        
    - Hook network code to detect when response bodies are passed to loggers.
        
    - Monitor for `HttpLoggingInterceptor` instantiation at runtime (level BODY).
        
4. **Automated signatures**
    
    - Scan dumped logs for regexes:
        
        - JWT: `([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)`
            
        - Authorization header: `Authorization:\s*Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*`
            
        - Basic auth base64: `Authorization:\s*Basic\s+[A-Za-z0-9+/=]+`
            
        - Credit Card (Luhn-ish/simple): `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`
            
        - Email/phone/SSN approximate patterns.
            

---

### **Exploitation**

- **Immediate token theft / session hijack**
    
    - Extract a printed JWT or access token from logcat, replay it in API calls or set it in Authorization header to access user data (if tokens are not bound to device or rotated).
        
    - Example PoC flow:
        
        1. Run `adb logcat -v threadtime | grep -i token` while user logs in.
            
        2. Copy token from logs.
            
        3. `curl -H "Authorization: Bearer <token>" https://api.target/app/user/me` → if valid, you have account access.
            
- **Credential harvesting**
    
    - Passwords, API keys, client secrets printed in logs can be reused across services or escalated (dev API keys can allow workspace takeover).
        
- **Financial/PII exfiltration**
    
    - CC numbers or full JSON invoices logged can be exfiltrated from device by local malware or via adb backup if accessible.
        
- **Pivot & persistence**
    
    - Logs can reveal internal endpoints, admin tokens, debug endpoints, or feature flags. Use these to craft further requests or fuzz hidden APIs.
        
    - Crash logs may contain stack traces revealing versions, library usage, server endpoints, or user IDs.
        
- **Scope of attacker**
    
    - On non-rooted, modern Android: attacker typically needs ADB access, device compromise, or an app with system privileges. On rooted devices or via physical access, extraction is trivial.
        
    - On older Android versions or OEM builds that allow log access to third-party apps, a normal malicious app may read logs.
        

---

### **Test cases / How I hunt this (practical checklist)**

- Static:
    
    - `grep -R "HttpLoggingInterceptor" -n`
        
    - `grep -R -E "Log\.(d|e|w|i|v)\(|Timber\." -n`
        
    - Check `proguard-rules` to ensure logs are stripped/obfuscated.
        
- Dynamic:
    
    - Start `adb logcat`, perform:
        
        - Login (valid / invalid)
            
        - Password reset flow
            
        - Payment flow (mask cc in UI but observe logs)
            
        - OAuth redirects / token exchanges
            
    - Check for:
        
        - Full JSON responses printed
            
        - Stack traces with SQL/ORM info
            
        - `OkHttp`/`Retrofit` logs containing bodies
            
    - Try with `logcat -G` to increase buffer size to catch more output (if needed) — be mindful of device constraints.
        
- Frida / hooking:
    
    - Hook `java.io.PrintStream.println`, `android.util.Log.*`, and common logger wrappers to capture messages before formatting.
        
    - Hook `okhttp3.logging.HttpLoggingInterceptor` to catch when it logs BODY/HEADERS.
        
- Edge cases:
    
    - Logs in native code: check `__android_log_print` usages (NDK).
        
    - Crash reporters: check for `Fabric/Crashlytics` usage where logs may be sent to remote consoles — sometimes they include sensitive info in remote dashboards.
        

---

### **Detection signatures (grep / regex examples)**

```bash
# find likely sensitive logs inside dumped log file
grep -iE "authorization|bearer|jwt|access[_-]?token|refresh[_-]?token|api[_-]?key|password|passwd|pwd|credit|card|ccv|cvv|pan|ssn|social[_-]?security|email|phone" device-logs.txt

# jwt regex
grep -oE "([A-Za-z0-9_-]+\.){2}[A-Za-z0-9_-]+" device-logs.txt

# OkHttp/Retrofit tag hints
grep -iE "okhttp|retrofit|http|httpclient|response body" device-logs.txt
```

---

### **Real Bug Bounty Examples (what pays & why)**

- **Access tokens / refresh tokens printed** → High severity (session hijack), often triaged as Broken Authentication / Sensitive Data Exposure.
    
- **Full API responses (including PII) logged during login or password reset** → Medium–High severity (data leak).
    
- **Payment card numbers or invoices printed to logs** → High/critical (financial data exposure).
    
- **Hardcoded API keys or client secrets logged by backend wrappers** → Critical (attacker can call privileged APIs).
    

Bug programs reward these based on impact: token reuse across devices, token expiry/rotation policy, ability to access other users' data, or access to privileged administrative APIs.

---

### **Mitigation**

1. **Never log secrets or PII.** Strip or mask before logging.
    
    - Mask formats: `token=****<last4>`, `cc=**** **** **** 1234`.
        
2. **Guard log statements behind debug checks** — but **do not** rely solely on `BuildConfig.DEBUG` (devs may misconfigure release):
    
    - Example:
        
        ```java
        if (BuildConfig.DEBUG) {
            Log.d(TAG, "user token: " + token); // only in debug
        }
        ```
        
3. **Remove or disable verbose network logging (BODY/HEADERS) in production.**
    
    - For OkHttp: set logging level to `NONE` in release builds.
        
4. **ProGuard/R8**: don’t use it as the main defense for removing logs — use it to obfuscate code but still remove sensitive logging at source.
    
5. **Set `android:debuggable="false"` in release manifest.** Ensure CI does not flip this for releases.
    
6. **Secure crash reporting**: scrub sensitive fields before sending stack traces or network payloads to third-party crash/logging services.
    
7. **Audit third-party libraries**: ensure no dependency enables body-level logging in release.
    
8. **Platform hardening**: avoid granting `READ_LOGS` to non-system apps; follow least privilege.
    

---

### **Escalation paths & impact reasoning**

- **Session takeover:** tokens in logs → direct account access, escalate to impersonation, funds transfer, data exfiltration.
    
- **Credential reuse:** passwords or dev credentials leaked → attacker tries same creds on administrative consoles or other services.
    
- **Service abuse:** API keys/client secrets printed → attacker calls backend endpoints, extracts data, or raises resource usage to cause denial.
    
- **Privacy law exposure:** leaks of PII/financial data → regulatory fines, reputational damage.
    

Severity assessment depends on token binding, expiry, scopes, and whether the token enables privileged actions.

---

### **Exploitation notes & POC ideas (concise)**

- POC A — Grab auth token from logcat and call API:
    
    1. `adb logcat -v threadtime | grep -i token` — perform login.
        
    2. Extract token, run `curl -H "Authorization: Bearer <token>" https://api.target/user`.
        
    3. Document returned data and link to severity.
        
- POC B — Demonstrate CC leak:
    
    1. Perform purchase flow while tailing logs.
        
    2. Screenshot log containing full card or last 4 + BIN.
        
    3. If full PAN present, show reproduction and explain PCI implications.
        
- POC C — Hook logger with Frida to prove logs are emitted even when obscured:
    
    - Use the Frida snippet earlier to capture logs irrespective of log level.
        

Always redact sensitive details in public reports; include only what the program requires to reproduce.

---

### **Sample report text (copy-paste-ready)**

**Title:** Sensitive tokens & user data printed to Logcat (Log leakage via `android.util.Log`) — leads to account takeover / data exposure

**Severity:** High

**Description:** While performing authentication, the app writes an access token and full API response (containing user email and phone number) to Logcat using `Log.d()` / `OkHttp LoggingInterceptor (BODY)`. An attacker with local access to device logs (adb, rooted device, or privileged app) can extract the token and access the account.

**Steps to reproduce:**

1. Connect device/emulator: `adb devices`
    
2. Start logcat and filter: `adb logcat -v threadtime | grep -i token`
    
3. Open app and perform login with test account.
    
4. Observe access token in log output.
    
5. Use token to query user endpoint:
    
    ```bash
    curl -H "Authorization: Bearer <token>" https://api.example.com/v1/me
    ```
    
    → Returns user data.
    

**Impact:** Exposes authentication tokens and PII enabling account takeover, data exfiltration, and possible financial fraud depending on account privileges.

**Mitigation:**

- Remove all logging of tokens, passwords, PAN, and PII.
    
- Disable BODY-level network logging in release builds. Use `BuildConfig.DEBUG` gating.
    
- Scrub/sanitize data before sending to crash reporting services.
    
- Ensure `android:debuggable="false"` for production builds.
    

**PoC:** (redacted) included in private report. Logs saved at `[file]` show token and JSON payload. Reproduces reliably on clean device.

---

✅ **Summary**

- Logcat is a prime target: developers accidentally log tokens, API responses, passwords, card numbers, and PII.
    
- Attack vectors: adb access, rooted devices, system-privileged apps, or older Android devices that permit `READ_LOGS`.
    
- Hunting approach: static grep for logging calls, dynamic `adb logcat` while exercising sensitive flows, and Frida hooking to catch logs programmatically.
- Fix by removing/masking sensitive logs, gating logs behind debug checks, disabling verbose network logging in release, and sanitizing crash reports.
    
