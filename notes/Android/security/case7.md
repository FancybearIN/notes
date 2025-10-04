# **Clipboard Data**

📌 **Scenario**  
Apps often copy text to the system clipboard (passwords, OTPs, access tokens, recovery codes, email addresses, 2FA backup codes, etc.) for UX reasons — “Copy code”, “Share token”, “Copy link”. The problem: the Android clipboard is a shared resource. Other apps (or services) can read the clipboard depending on device Android version, accessibility settings, IME (keyboard), or if the device is rooted/compromised. Sensitive items left on the clipboard can be harvested silently and exfiltrated.

Clipboard leaks are especially nasty because users paste things in other apps (chat, search) accidentally and because clipboard entries persist until replaced or cleared. This creates a low-effort, high-reward path for local-attackers or malicious apps to steal secrets.

---

### **Detection**

1. **Static analysis**
    
    - Search APK/source for clipboard APIs and helpers:
        
        ```bash
        grep -R --line-number -E "ClipboardManager|setPrimaryClip|getPrimaryClip|setText|ClipData|getText" .
        ```
        
    - Look for direct copying of sensitive variables:
        
        ```bash
        grep -R --line-number -E "password|otp|pin|token|access[_-]?token|refresh[_-]?token|secret|code|recovery" .
        ```
        
    - Inspect UI code where "Copy" buttons exist (dialogs, share flows). Check whether text is copied verbatim or masked.
        
2. **Dynamic analysis**
    
    - Exercise flows that might copy data (login, password-view, share link, export keys).
        
    - Dump clipboard contents from the device:
        
        ```bash
        adb shell dumpsys clipboard
        ```
        
        or (older devices)
        
        ```bash
        adb shell am broadcast -a clipper.get
        ```
        
    - After the app action, run the dump and inspect for tokens, passwords, OTPs, PII.
        
    - On emulator: use `adb shell` then `dumpsys clipboard` — fast and reliable.
        
3. **Runtime hooking / monitoring**
    
    - Use Frida to hook `ClipboardManager.setPrimaryClip` / `setText` to capture what the app copies at runtime (works regardless of obfuscation).
        
    - Example Frida hook (concise):
        
        ```js
        Java.perform(function(){
          var CM = Java.use('android.content.ClipboardManager');
          CM.setPrimaryClip.overload('android.content.ClipData').implementation = function(cd){
            try{ send({action:'clip-set', data:cd.getItemAt(0).coerceToText(this.getContext())+''}); }catch(e){}
            return this.setPrimaryClip(cd);
          };
        });
        ```
        
    - Monitor for calls in third-party libraries that might copy full API responses to clipboard (rare but happens).
        
4. **Behavioral and permission checks**
    
    - Check app targetSdkVersion and minSdkVersion — older targets may imply legacy behaviors.
        
    - Inspect manifest for `AccessibilityService` usage or exported components that might enable clipboard abuse via privileged paths.
        

---

### **Exploitation**

- **Simple theft**
    
    - Malicious app reads clipboard and exfiltrates the content to a remote server. On older Android versions (pre-Android 10) or misconfigured devices, clipboard reads are allowed in background without the user noticing.
        
- **IME / Keyboard abuse**
    
    - Custom keyboards (IMEs) have rich permissions and can access clipboard content while running; a malicious IME can harvest copied passwords/OTP tokens.
        
- **Accessibility service abuse**
    
    - Accessibility services can read window content and can observe clipboard events or capture copied text.
        
- **Rooted / compromised device**
    
    - Clipboard state can be read trivially. Root malware can dump and forward sensitive clipboard entries.
        
- **Accidental exfiltration**
    
    - Users paste sensitive clipboard content into public apps (chat, search). That user behavior plus app-initiated clipboard copying increases risk.
        
- **Long-lived tokens**
    
    - If apps copy long-lived tokens or refresh tokens to the clipboard, an attacker can reuse them for account takeover if server-side checks are weak.
        

---

### **Test cases / How I hunt this (practical checklist)**

- Static:
   ```
     grep -R "ClipboardManager" -n
     grep -R "setPrimaryClip" -n
    ```
- Inspect copy buttons, "Share" or "Export" flows for what data they copy.
- Dynamic:
    
    - Start with a clean clipboard: `adb shell cmd clipboard set --primary ""` (API may vary).
        
    - Perform:
        
        - Login; press “copy token” / “copy code”
            
        - View password / secret toggles and press copy
            
        - Export backup keys / recovery codes
            
        - Use "Share" flows that copy or construct links (sometimes the token is embedded)
            
    - Immediately run:
        
        ```bash
        adb shell dumpsys clipboard | sed -n '1,200p'
        # or just
        adb shell dumpsys clipboard
        ```
        
    - Repeat with keyboard/IME installed or with accessibility service enabled to verify additional access.
        
- Frida / Hooking:
    
    - Hook `ClipboardManager` functions to capture exact values and contexts.
        
- Edge cases:
    
    - Check clipped HTML vs plain text (ClipData may contain URIs or Intent payloads).
        
    - Verify persistence: does the clipboard entry persist after app is killed or after device is locked/unlocked?
        
    - Test multi-user / work profile scenarios — clipboard may be shared across profiles on some devices.
        

---

### **Detection signatures (grep / commands)**

```bash
# Static search for clipboard usage
grep -R -n -E "ClipboardManager|setPrimaryClip|getPrimaryClip|ClipData|setText|getText" .

# Look for "copy" UI resources (strings/layouts)
grep -R -n -E "copy|copy code|copy token|share|export|recovery code" res/values strings.xml

# Dump clipboard to check what's present
adb shell dumpsys clipboard | sed -n '1,200p'

# Quick scan dumped clipboard for secrets
adb shell dumpsys clipboard | grep -iE "token|otp|password|pin|secret|access[_-]?token|refresh[_-]?token"
```

---

### **Real Bug Bounty Examples (what pays & why)**

- **Access tokens or refresh tokens copied to clipboard** → High severity when tokens are long-lived or can be used across devices (session hijack).
    
- **Passwords / recovery codes / 2FA backup codes copied to clipboard** → High severity (account takeover).
    
- **Sensitive personal data (SSN, PAN, bank account) copied for export** → High severity / PII exposure.
    
- **App copies full API responses or headers to clipboard** → Medium–High depending on content (may reveal secrets or endpoints).
    

Programs reward these based on the sensitivity, persistence, and exploitability of clipboard contents: tokens that allow immediate API access, secrets that enable account takeover, or data that exposes many users.

---

### **Mitigation**

1. **Don’t copy sensitive data to the system clipboard.** Avoid copying passwords, tokens, OTPs, PANs, recovery codes to the global clipboard.
    
2. **Use in-app ephemeral clipboard or internal paste buffer.** Keep the data in memory and provide a “Paste here” affordance within the app UI so the text never goes to the global clipboard.
    
3. **If copying is necessary, auto-clear clipboard quickly.** Immediately clear or overwrite the clipboard after a short window:
    
    ```java
    ClipboardManager cm = (ClipboardManager)getSystemService(CLIPBOARD_SERVICE);
    cm.setPrimaryClip(ClipData.newPlainText("token","<redacted>"));
    // schedule clearing after X seconds
    cm.setPrimaryClip(ClipData.newPlainText("",""));
    ```
    
    Note: clearing is best-effort (other apps may have grabbed it); still better than leaving it indefinite.
    
4. **Use timing & UX to discourage manual copying of secrets.** For example, display OTP in-app with a prominent “Paste” button in the destination field rather than “Copy”.
    
5. **Educate users & warn about clipboard risks** when showing sensitive items — show a warning about not pasting into other apps.
    
6. **Bind tokens to device/session & short TTLs.** Even if clipboard is leaked, rapid expiry and device binding reduce impact.
    
7. **Avoid storing secrets in shareable URIs** (e.g., do not construct `https://app.example/?token=…` and copy/share it).
    
8. **Audit third-party libs and SDKs** for any use of clipboard or copying behavior (some analytics or share SDKs might do odd things).
    
9. **On Android 10+ rely on platform protections** but do not assume they eliminate risk — keyboard/Accessibility/IME still can access clipboard.
    
10. **If user explicitly requests to copy** (e.g., copy address), mask or partially redact by default (show last 4 chars) unless user explicitly opts into the full copy.
    

---

### **Escalation paths & impact reasoning**

- **Token reuse / account takeover:** copied access/refresh tokens that aren’t device bound → attacker can access APIs.
    
- **Credential reuse:** copied password used across services → lateral movement across accounts.
    
- **PII/Financial leak:** copied PAN or bank info → fraud, identity theft.
    
- **Automated exfiltration:** clipboard-reading malware or malicious IME steals data silently and sends to attacker — large-scale compromise if present on many devices.
    

Severity depends on what was copied, TTL/rotation of secrets, whether tokens are device-bound, and whether clipboard clearing occurred.

---

### **Exploitation notes & POC ideas (concise)**

- **POC A — Verify clipboard leak (simple):**
    
    1. Clear clipboard: `adb shell cmd clipboard set --primary ""` (or reboot).
        
    2. In app: trigger the flow that copies data (e.g., “Copy recovery code”).
        
    3. Run: `adb shell dumpsys clipboard` → screenshot/output showing the sensitive value.
        
    4. Attempt to use copied token in an API call to demonstrate impact.
        
- **POC B — Frida hook to capture copy events:**
    
    - Use the Frida snippet above to log every `setPrimaryClip` call and include stack trace/context to show which part of the app copied the secret.
        
- **POC C — Malicious IME / Accessibility demonstration (non-operational description):**
    
    - Explain that a keyboard app with clipboard access or an accessibility service can read clipboard contents quietly — demonstrate via an instrumented benign app that reads clipboard and prints it to its logs (for researcher demo only).
        

Always redact live secrets in public reports; provide minimal repro steps required by the triage process.

---

### **Sample report text (copy-paste-ready)**

**Title:** Sensitive data copied to system clipboard — leads to potential data theft / account takeover

**Severity:** High

**Description:** The application copies sensitive information (e.g., access token / OTP / recovery code / password) to the Android system clipboard using `ClipboardManager.setPrimaryClip(...)`. System-wide clipboard entries can be read by other apps (keyboards/Accessibility services), or obtained via `adb` on tethered devices or on rooted devices. The clipboard entry persisted after the app flow and allowed retrieval of the secret.

**Steps to reproduce:**

1. Connect device: `adb devices`
    
2. Clear clipboard (optional): reboot or `adb shell cmd clipboard set --primary ""`
    
3. In the app, perform the export/copy action (e.g., tap **Copy recovery code**).
    
4. Immediately run: `adb shell dumpsys clipboard`
    
    - Observed clipboard content: `RECOVERY-CODE-EXAMPLE-XXXX`
        
5. Use the recovered code/token to perform the relevant privileged action (redacted PoC provided to vendor).
    

**Impact:** Exposure of authentication tokens, OTPs, passwords, or recovery codes to other apps on device or via physical access can enable account takeover and data exfiltration. Impact increases if the leaked secret is long-lived or reusable.

**Mitigation:**

- Avoid copying sensitive values to global clipboard.
    
- Use ephemeral in-app paste buffers or auto-clear the clipboard after a short window.
    
- If copying is unavoidable, display a prominent warning and clear clipboard programmatically.
    
- Shorten token TTL / bind tokens to device/session.
    

**PoC:** Included in private report; logs and `dumpsys clipboard` output captured (sensitive values redacted).

---

✅ **Summary**

- Copying secrets to the system clipboard is a frequent but under-appreciated source of leakage.
    
- Detection is straightforward: static grep for clipboard APIs and dynamic `adb shell dumpsys clipboard` during sensitive flows.
    
- An attacker needs only clipboard-access (IME/Accessibility/malicious app) or physical/root access to harvest values — making this high-risk for tokens, OTPs, passwords, and recovery codes.
    
- Fix by avoiding global clipboard use for secrets, use ephemeral in-app buffers, auto-clear clipboard, and reduce token lifetime.