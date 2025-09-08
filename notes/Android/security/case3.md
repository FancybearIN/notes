## Internal Storage Files

### 📌 Scenario

Android apps often store user data, cached responses, configuration files, session tokens, or logs inside **internal storage** (e.g., `/data/data/<package_name>/files/`).  
Although internal storage is private to the app by default, if:

- The device is **rooted**, or
    
- The app uses **world-readable/writable file modes** (`MODE_WORLD_READABLE` / `MODE_WORLD_WRITEABLE`),
    

then sensitive data can be leaked to **other apps** or an attacker with access to the device.

📖 **Example:**  
An app stores `user_session.json` in internal storage:

`{   "username": "deepak",   "auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6..." }`

If file permissions are misconfigured → another malicious app or attacker can read this file.

---

### 🔍 Detection

1. **Static Analysis**
    
    - Decompile APK (`jadx`, `apktool`)
        
    - Look for file write operations using:
        
        `openFileOutput("user_session.json", MODE_WORLD_READABLE);`
        
    - Check for file writes using insecure flags (`MODE_WORLD_*`).
        
    - Search for suspicious file names like `passwords.txt`, `auth.json`, `log.txt`.
        
2. **Dynamic Analysis**
    
    - Install the app on an emulator / test device.
        
    - Use **adb shell** to explore:
        
        `adb shell run-as <package_name> ls -l /data/data/<package_name>/files/`
        
    - Dump file contents to check sensitive data:
        
        `run-as <package_name> cat /data/data/<package_name>/files/user_session.json`
        
    - If device is **rooted**, check for files directly:
        
        `su ls -l /data/data/<package_name>/files/`
        
3. **Automated Tools**
    
    - [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) flags insecure file storage.
        
    - Drozer or Frida scripts to check file permissions.
        

---

### 💣 Exploitation

- **Case 1: Misconfigured Permissions (`MODE_WORLD_READABLE`)**
    
    1. Attacker installs a malicious app on the same device.
        
    2. That app can read sensitive files from victim’s app storage.
        
        `File f = new File("/data/data/victim.app/files/user_session.json"); BufferedReader br = new BufferedReader(new FileReader(f)); System.out.println(br.readLine());`
        
- **Case 2: Rooted Device**
    
    1. Attacker gains root access.
        
    2. Reads internal files directly.
        
        `cat /data/data/victim.app/files/user_session.json`
        
    3. Extract tokens/passwords → replay requests → account takeover.
        
- **Case 3: Logs in Internal Storage**  
    If app logs sensitive data like API responses, attacker can scrape logs and reconstruct sessions.
    

---

### 🎯 Bug Bounty Impact

- Sensitive data exposure → **PII leak** or **authentication bypass**.
    
- Can chain with API replay attacks → account takeover.
    
- Report titles:
    
    - _"Sensitive auth tokens stored in internal storage in plaintext"_
        
    - _"Improper file permission allows other apps to read session data"_
        

---

### 🛡 Mitigation

✅ Best Practices:

1. Never use `MODE_WORLD_READABLE` or `MODE_WORLD_WRITEABLE` (deprecated in API 17).
    
2. Store sensitive files in **internal app sandbox** only.
    
3. Encrypt sensitive data before storing (AES with Android Keystore).
    
4. Avoid logging sensitive data.
    
5. Use external storage only for non-sensitive, public files.
    

📌 Example Secure Code:

`FileOutputStream fos = openFileOutput("user_session.json", Context.MODE_PRIVATE); fos.write(authToken.getBytes()); fos.close();`

---

⚡ **Summary:**

> If sensitive files (tokens, passwords, logs) are stored in internal storage with insecure permissions or plaintext → an attacker (root/malicious app) can extract them → session hijacking, PII exposure, account takeover.