# **Screenshots & Background Recording**

📌 **Scenario**  
Sensitive UI (OTP screens, full PAN/CC input, passwords, recovery codes, 2FA seeds, confidential documents) can be captured if the app _doesn't_ opt out of screen capture. Android provides `WindowManager.LayoutParams.FLAG_SECURE` to prevent screenshots/screen recordings and to block content from being shown in non-secure displays. If an app fails to set this flag (or fails to actively protect sensitive screens), attackers can:

- take screenshots via `adb` or via ordinary user screenshot buttons,
    
- record the screen via MediaProjection-based screen-recorders (user prompt required on modern Android, but social engineering or malicious IMEs/Accessibility abuse exist),
    
- harvest screenshots saved to storage by other apps or via cloud/backup synchronization,
    
- on rooted/compromised devices bypass protections entirely.
    

Apps also leak sensitive UI through notifications (visible previews) and recent-apps thumbnails; `FLAG_SECURE` also prevents thumbnails in recent apps on many devices.

---

### **Detection**

1. **Static analysis**
    
    - Search decompiled code for `FLAG_SECURE` and other protective calls:
        
        ```bash
        grep -R --line-number -E "FLAG_SECURE|setFlags\\(|addFlags\\(|setSecure" .
        ```
        
    - Look for activity lifecycle code that sets or clears flags:
        
        - `getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);`
            
        - `getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);`
            
    - Inspect layout/UI code for sensitive screens (OTP, card forms, recovery dialogs).
        
2. **Dynamic analysis**
    
    - While the sensitive screen is displayed, attempt to take a screenshot via adb:
        
        ```bash
        adb shell screencap -p /sdcard/screen.png
        adb pull /sdcard/screen.png
        ```
        
        - If the image is black/blank or contains placeholder text, FLAG_SECURE is likely set.
            
    - Use the device screenshot buttons or long-press power+volume; observe whether system blocks capture or produces blank image.
        
    - Start a screen recording (MediaProjection sample app or `adb shell screenrecord` on devices that allow it):
        
        ```bash
        adb shell screenrecord /sdcard/rec.mp4
        adb pull /sdcard/rec.mp4
        ```
        
        - Check whether sensitive content appears in the recording.
            
    - Check **recent apps** thumbnails: open sensitive screen, press Overview/Recent, does the thumbnail show raw content or is it blurred/blank?
        
    - Inspect saved screenshot directories:
        
        ```bash
        adb shell ls -l /sdcard/Pictures/Screenshots
        adb shell find /sdcard -iname "*screenshot*.png" -o -iname "*.mp4"
        ```
        
    - Test with backgrounding: open sensitive screen, press Home (send to background), then attempt recording/screenshot.
        
3. **Runtime hooking**
    
    - Hook window flag setters to see if/when `FLAG_SECURE` is applied:
        
        ```js
        // Frida sketch
        Java.perform(function(){
          var Activity = Java.use('android.app.Activity');
          Activity.onCreate.overload('android.os.Bundle').implementation = function(b){
            this.onCreate(b);
            // inspect flags after set
            var win = this.getWindow();
            var flags = win.getAttributes().flags.value; // may differ by API
            send({activity: this.getClass().getName(), flags: flags.toString()});
          };
        });
        ```
        
    - Hook `getWindow().addFlags` / `clearFlags` / `setFlags` calls to catch dynamic behaviour.
        
4. **Edge & OEM cases**
    
    - Some OEM skins or older Android versions may not honor FLAG_SECURE consistently for third-party overlays or remote screens (e.g., Chromecast). Test with casting/remote display if app supports it.
        

---

### **Exploitation**

- **Local theft via screenshot/screenrecord**
    
    - `adb screencap` or `screenrecord` on developer/tethered devices, or the user pressing screenshot keys, will capture data. If an attacker gains temporary physical access, screenshots are trivial.
        
- **Background recording via MediaProjection**
    
    - Apps can request MediaProjection permission (user must accept). Malicious apps may trick the user into granting it (social engineering), then silently record sensitive pages when target app is used.
        
- **Malicious IME/Accessibility / overlay techniques**
    
    - Malicious keyboards or accessibility services can monitor UI or induce the user to take actions that reveal secret data, or capture typed content. Accessibility can also read window content in some contexts.
        
- **Cloud/backup/sync leakage**
    
    - Screenshots saved on device may auto-upload to cloud backups (Google Photos, OEM cloud), exposing data off-device.
        
- **Root / system apps**
    
    - On rooted devices or when a system-privileged app is compromised, FLAG_SECURE can be bypassed — screen buffers can be read directly.
        

---

### **Test cases / Practical checklist**

- **Static**
    
    - `grep -R "FLAG_SECURE" -n`
        
    - Inspect Activities with sensitive UI (OTP, payments, recovery) — confirm flags set in `onCreate()` or before `setContentView()`.
        
- **Dynamic**
    
    - Repro steps:
        
        1. Display sensitive screen.
            
        2. Run: `adb shell screencap -p /sdcard/test.png && adb pull /sdcard/test.png`
            
            - Result: real capture => **FAIL** (no protection). Blank/blocked => **PASS**.
                
        3. Run: `adb shell screenrecord /sdcard/test.mp4` while sensitive content shown; pull and inspect.
            
        4. Press Overview/Recent — inspect thumbnail.
            
        5. Background the app and repeat screenrecord/adb screencap.
            
    - Check screenshots folder right after: `adb shell ls -l /sdcard/Pictures/Screenshots`
        
- **Frida / hooks**
    
    - Hook `getWindow().addFlags`/`clearFlags` to verify whether flag is applied around sensitive screens.
        
- **Corner cases**
    
    - WebViews: test if web content is protected when FLAG_SECURE set on Activity. (Usually yes.)
        
    - Video / DRM content: ensure FLAG_SECURE doesn’t break legitimate functionality.
        
    - Multi-window / split-screen behavior.
        
- **User consent flows**
    
    - Test MediaProjection flow: install a recorder sample, accept permission, then record sensitive UI — observe whether content is captured.
        

---

### **Detection signatures & grep snippets**

```bash
# Static scan for protective flags
grep -R -n "FLAG_SECURE" .

# Common runtime API usage
grep -R -n -E "getWindow\\(\\)\\.addFlags|getWindow\\(\\)\\.setFlags|clearFlags\\(|addFlags\\(" .

# Find Activities that look like payment/otp screens (heuristic)
grep -R -n -E "otp|pin|password|card|credit|cvv|payment|recover|recovery" res/values/strings.xml

# Check for screenshots after performing sensitive action
adb shell ls -l /sdcard/Pictures/Screenshots
adb shell find /sdcard -iname "*screenshot*.png" -o -iname "*rec*.mp4"
```

---

### **Mitigation**

1. **Set `FLAG_SECURE` for sensitive windows**
    
    - Best-practice: apply to Activities/screens that display secrets:
        
        ```java
        @Override
        protected void onCreate(Bundle savedInstanceState){
          super.onCreate(savedInstanceState);
          getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
          setContentView(R.layout.activity_sensitive);
        }
        ```
        
    - If only parts of an Activity are sensitive, consider moving them to a dedicated Activity or using a `Dialog`/`Fragment` with its own secure window.
        
2. **Clear sensitive UI when backgrounded**
    
    - In `onPause()` / `onStop()`, hide or blank sensitive fields (replace with masked text or placeholder). That reduces the window of exposure if background recording happens.
        
        ```java
        @Override
        protected void onPause(){
          super.onPause();
          // clear sensitive fields
          secureField.setText("");
        }
        ```
        
3. **Defend against MediaProjection social-engineering**
    
    - Reduce user confusion by explaining why screen-capture permission is risky; detect if MediaProjection is active (some heuristics) and warn user / blur sensitive UI.
        
    - Delay showing very sensitive data until after a short confirmation (e.g., "Show code" button) so users are less likely to grant projection right then.
        
4. **Avoid long-lived sensitive UI**
    
    - Auto-hide OTPs, tokens, and PAN data after a short TTL (e.g., 10–30 seconds).
        
5. **Protect notifications & recent-apps**
    
    - Disable sensitive content in notifications (`setPublicVersion()`), and use `FLAG_SECURE` to control recent-app thumbnails where supported.
        
6. **Don’t store screenshots**
    
    - Avoid offering “Save screenshot” flows for sensitive screens; if export is necessary, ensure data is redacted and user warned.
        
7. **Server-side mitigations**
    
    - Short TTLs for OTPs/tokens, device-binding, and risk-based checks reduce impact if a screen capture leaks data.
        
8. **User education**
    
    - Warn users about granting screen-capture or screen-record permissions to untrusted apps/recorders.
        
9. **Test across OEMs & Android versions**
    
    - Some devices may have quirks; test vendor builds (Samsung, Xiaomi, Huawei, etc.) to ensure FLAG_SECURE works as expected.
        

---

### **Escalation paths & impact reasoning**

- **Immediate account takeover** — screenshots of OTPs, one-time recovery codes, or displayed auth tokens allow instant misuse.
    
- **Financial fraud** — captured PAN/CVV used for card-not-present fraud if tokens aren’t masked or ephemeral.
    
- **Privacy breach** — captured documents, messages, or PII exfiltrated to attacker-controlled servers.
    
- **Persistent compromise** — recordings may capture multiple sensitive events over time (password entry, 2FA flows), supplying a richer dataset to attackers.
    

Severity increases if sensitive content is long-lived, if tokens aren’t bound to device/session, or if screenshots are auto-synced to cloud services.

---

### **Exploitation notes & POC ideas (concise)**

- **POC A — adb screencap**
    
    1. Open sensitive screen in target app.
        
    2. Run:
        
        ```bash
        adb shell screencap -p /sdcard/screen.png
        adb pull /sdcard/screen.png
        ```
        
    3. If the image shows secrets → app lacks protection.
        
- **POC B — screenrecord**
    
    1. Start recording while sensitive content shown:
        
        ```bash
        adb shell screenrecord /sdcard/test.mp4
        adb pull /sdcard/test.mp4
        ```
        
    2. Inspect for clear text of OTP/PAN.
        
- **POC C — recent-apps thumbnail**
    
    1. Display sensitive content, press Overview/Recent.
        
    2. Screenshot the thumbnail or show it to reviewer — if sensitive data is visible, FLAG_SECURE not applied.
        
- **POC D — Frida hook**
    
    - Hook `getWindow().addFlags`/`clearFlags` to capture whether `FLAG_SECURE` is toggled around sensitive screens; include stacktrace to identify source.
        

Always redact captured secrets in public reports; include minimal repro info required by the program.

---

✅ **Summary**

- Missing `FLAG_SECURE` and missing lifecycle-based clearing expose the app to trivial screenshots and recordings (adb, user screenshots, MediaProjection-based recorders, cloud sync).
    
- Detection is straightforward with `adb screencap` / `screenrecord`, checking recent-app thumbnails, and static grep for `FLAG_SECURE`.
    
- Fix by applying `WindowManager.LayoutParams.FLAG_SECURE` to sensitive windows, clearing sensitive UI on backgrounding, minimizing time secrets are visible, and educating users about screen-recording permissions.
    

If you want, I’ll now generate a compact Frida script that detects when an Activity sets/clears `FLAG_SECURE` (annotated and ready to run).