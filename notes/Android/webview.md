## What is WebView?

Think of **WebView** as a **mini browser engine** that Android apps can embed inside themselves.

- Normally, you open Chrome/Firefox for the web.
- With WebView, the developer can stick a little browser _inside their app_.


Example:

- When you click “Terms & Conditions” in an app and it opens inside the app instead of switching to Chrome → that’s WebView.
- It’s powered by the same rendering engine as Chrome (on newer Android), but it runs _inside the app’s sandbox_.

## How Developers Use It

A developer can tell WebView:

`webview.loadUrl("https://example.com");`

…and it will render that page.

They can also:

- Enable **JavaScript** (`setJavaScriptEnabled(true)`) → so the page can run JS.
- Allow **file access** (`setAllowFileAccess(true)`) → so WebView can open local `file://` URLs.
- Add **bridges** (`addJavascriptInterface`) → this connects JavaScript inside the page directly to Android methods in the app.
# Insecure WebView Implementation

### 📌 Scenario

- An Android app uses **WebView** to load arbitrary URLs provided by the user (or attacker-controlled input).
    
- Example code:
    
    ```java 
    webSettings.setJavaScriptEnabled(true);
    webView.loadUrl(userInput);
    ```
    
- Risky configurations:
    
    - `setJavaScriptEnabled(true)` → allows execution of attacker-supplied JavaScript.
        
    - `setAllowFileAccess(true)` → enables access to `file://` URIs, which can expose local files.
        
    - `addJavascriptInterface()` → can expose Java methods to attacker-controlled JS, leading to **RCE (Remote Code Execution)**.
        
- Problem → If the app doesn’t restrict or sanitize input, attacker-controlled content runs inside the app’s WebView context. This can lead to **phishing, local file theft, or device compromise**.
    

---

### 🔍 Detection (Pentester/Bug Hunter)

Ways to detect insecure WebView usage:

1. **Static Analysis** (APK reverse engineering):
    
    - Decompile app with **JADX/APKTool**.
        
    - Search for:
        
        - `setJavaScriptEnabled(true)`
            
        - `setAllowFileAccess(true)`
            
        - `addJavascriptInterface`
            
    - Example finding:
        
        ```java
        webSettings.setJavaScriptEnabled(true);
        webSettings.setAllowFileAccess(true);
        webView.addJavascriptInterface(new JSBridge(), "Android");
        ```
        
2. **Dynamic Testing**:
    
    - Locate any screen where user input or external data is passed into WebView.
        
    - Test payloads:
        
        - `javascript:alert(1)` → confirms JS execution.
            
        - `http://attacker.com/malicious.html` → confirms arbitrary domain loading.
            
        - `file:///data/data/<app_package>/databases/aGoat` → tests local file access.
            
    - Intercept traffic with **Burp Suite** or **mitmproxy** to monitor what WebView fetches.
        
3. **Runtime Tools**:
    
    - Use **Objection/Frida** to hook into WebView APIs and confirm dangerous flags at runtime.
        
    - Example:
        
        ```bash
        frida-trace -U -n com.example.app -m "*WebView*"
        ```
        

---

### 💣 Exploitation (Attacker POV)

If attacker controls the URL loaded in WebView:

- Execute arbitrary JavaScript in the app’s context:
    
    ```javascript
    javascript:alert(document.cookie)
    ```
    
- Load attacker-controlled phishing page inside the trusted app → steal credentials.
    
- If `setAllowFileAccess(true)`:
    
    - Load local sensitive files (`file://`) and exfiltrate.
        
    - Example: `file:///data/data/com.example.app/databases/user.db`
        
- If `addJavascriptInterface()` is exposed:
    
    - Call native Java methods directly from JS → **Remote Code Execution**.
        

---

### 🎯 Bug Bounty Perspective

When reporting in a bounty:

- Don’t just say “WebView has JS enabled”.
    
- Show **how it can be abused**:
    
    - Example: _“The app allows arbitrary URLs in WebView with `setJavaScriptEnabled(true)`. By entering a malicious URL, attacker can execute JavaScript and trigger the exposed `Android` JS bridge → read contacts and files. This leads to local file theft and possible RCE.”_
        

**Severity**:

- **High/Critical** if:
    
    - File access or JS interfaces allow data exfiltration/RCE.
        
- **Medium** if:
    
    - Limited to phishing / loading arbitrary attacker-controlled pages.
        

---

### 🛡️ Mitigation

- Disable risky settings unless absolutely necessary:
    
    - `setJavaScriptEnabled(false)`
        
    - `setAllowFileAccess(false)`
        
    - `setAllowUniversalAccessFromFileURLs(false)`
        
- Never expose sensitive methods via `addJavascriptInterface`.
    
- Validate and whitelist only trusted domains/URLs before loading.
    
- Consider using **Custom Tabs** instead of raw WebView for external content.
    

---
Perfect — let’s make this **offensive playbook** style. You want **commands (grep, JADX, adb)** that help you _detect insecure WebView usage_ quickly when pentesting / bug hunting.

---

# 🔍 Finding Insecure WebView Usage

### 1. **Static Analysis (Decompile & Grep)**

Decompile APK:

```bash
jadx-gui target.apk
```

or CLI:

```bash
jadx -d output/ target.apk
```

Now grep through the code:

```bash
grep -R "WebView" output/
grep -R "setJavaScriptEnabled" output/
grep -R "setAllowFileAccess" output/
grep -R "setAllowUniversalAccessFromFileURLs" output/
grep -R "setAllowFileAccessFromFileURLs" output/
grep -R "addJavascriptInterface" output/
grep -R "loadUrl" output/
grep -R "loadData" output/
```

👉 **Red flags to look for:**

- `webView.getSettings().setJavaScriptEnabled(true)`
- `webView.getSettings().setAllowFileAccess(true)`
- `WebView.getSettings().setAllowUniversalAccessFromFileURLs(true)`
- `webView.addJavascriptInterface(..., "...")`
- `webView.loadUrl("http://...")` (non-HTTPS, attacker-controlled URLs

---

### 2. **Dynamic Testing (Runtime on Device/Emulator)**

Use **adb** to watch WebView traffic + confirm runtime behavior.

Check loaded URLs:

```bash
adb logcat | grep -i "WebView"
adb logcat | grep -i "chromium"
```

Sometimes WebView logs URLs like:

```
I/chromium: [INFO:CONSOLE(1)] "Loading http://evil.com/..."
```

Pull WebView databases/cookies (if accessible):

```bash
adb shell run-as com.victim.app ls /data/data/com.victim.app/app_webview/
adb shell run-as com.victim.app cat /data/data/com.victim.app/app_webview/Cookies
```

Check if JavaScript interfaces exist:

```bash
adb shell run-as com.victim.app ls /data/data/com.victim.app/app_webview/
```

---

### 3. **On-the-Fly Testing (Objection / Frida)**

Objection shortcut:

```bash
objection -g com.victim.app explore
```

List JS interfaces:

```bash
android hooking list_webviews
android hooking check_javascript_enabled
android hooking search_classes WebView
```

---

⚡ **TL;DR**

- **Static (jadx + grep):** Spot dangerous APIs in code.
- **Dynamic (adb logcat):** Catch what WebView loads at runtime.
- **Frida/Objection:** Enumerate & exploit exposed JS bridges.