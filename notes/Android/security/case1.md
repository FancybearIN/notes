# Insecure Storage in Shared Preferences

### 📌 Scenario

- An Android app stores sensitive data (username, password, access token, API keys, PII) inside **Shared Preferences**.
    
- These preferences are stored as XML files under:
    
    `/data/data/<app_package>/shared_prefs/`
    
- Example file:
    
    `<map>   <string name="username">deepak</string>   <string name="password">supersecret123</string>   <string name="auth_token">eyJhbGciOiJIUz...</string> </map>`
    
- Problem → This XML is **plaintext**. On a rooted phone, or with backup extraction, an attacker can read it directly.
    

---

### 🔍 Detection (Pentester/Bug Hunter)

Ways to detect if an app stores sensitive data in Shared Preferences:

1. **Static Analysis** (APK reverse engineering):
    
    - Decompile app with **JADX** or **APKTool**.
        
    - Look for code like:
        
        `SharedPreferences prefs = getSharedPreferences("userInfo", MODE_PRIVATE); prefs.edit().putString("password", password).apply();`
        
    - This indicates sensitive data may be written to prefs.
        
2. **Dynamic Testing**:
    
    - Run the app, login/register.
        
    - Pull preferences file (on rooted device):
        
        `adb shell run-as com.example.app cat /data/data/com.example.app/shared_prefs/userInfo.xml`
        
    - Or with **Objection** (no need to hunt paths manually):
        
        `objection -g com.example.app explore android shared_prefs list android shared_prefs read userInfo.xml`
        
3. **Device Backup Inspection**:
    
    - On some devices, app data can be backed up and extracted → prefs included.
        

---

### 💣 Exploitation (Attacker POV)

If attacker gains access (rooted device, malware app, stolen phone):

- Read **auth_token** from prefs → use it in API calls → full account takeover.
- Extract **credentials** → reuse in credential stuffing.
- Dump **PII/financial info** → privacy violations, fraud.

**Example Exploit (API hijack):**

`curl -H "Authorization: Bearer eyJhbGciOiJIUz..." https://api.target.com/v1/user/details`

👉 Attacker now impersonates user with stolen token.

---

### 🎯 Bug Bounty Perspective

When reporting in a bounty:

- Don’t just say “sensitive data in prefs”.
- Show **business impact**:
    
    - Example: _“Access tokens stored in plaintext in Shared Preferences. On a rooted device, or if a malicious app gains filesystem access, attacker can hijack sessions → account takeover. Tested on com.bank.app v2.3.2. Impact: High severity (PCI-DSS & GDPR violation).”_
        

**Severity**:

- If it’s just username/email → Medium.
- If it’s passwords/tokens/CC info → High/Critical.

---

### 🛡️ Mitigation

- Don’t store sensitive data in Shared Preferences.    
- If necessary, use **EncryptedSharedPreferences** (AES encryption tied to Android Keystore).
    
- Store short-lived tokens in memory (RAM), not persistent storage.
    
- Never store passwords, only use secure server-side authentication.
    

---

⚡ **Quick Summary (Shared Prefs):**  
Plaintext XML → root/malware → extract tokens/passwords → account takeover