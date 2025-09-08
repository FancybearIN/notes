# **Cache / Temporary Files**

📌 **Scenario**  
Many Android apps cache data (images, documents, session tokens, chat history, search history, PII, etc.) in:

- `/data/data/<package>/cache/` (app-specific cache)
    
- `/sdcard/Android/data/<package>/cache/` (external cache)
    
- `/tmp` (temporary files)
    

If the app stores sensitive info here without encryption, anyone with local access (rooted phone, adb, malware) can read it.  
Some apps also leave residual files even after logout.

---

### **Detection**

1. **Static Analysis**
    
    - Look into source code for `getCacheDir()`, `getExternalCacheDir()`, `createTempFile()` usage.
        
    - If sensitive data like tokens, session IDs, or user documents are being written → red flag.
        
2. **Dynamic Analysis**
    
    - Run the app → login / perform sensitive action.
        
    - Check directories:
        
        `adb shell ls -R /data/data/<package>/cache/ adb shell ls -R /sdcard/Android/data/<package>/cache/`
        
    - Dump contents:
        
        `adb shell cat /data/data/<package>/cache/somefile.tmp`
        
    - Look for PII, JWT tokens, chat history, payment details.
        
3. **File System Monitoring**
    
    - Use `strace` / `frida-trace` to hook file-writing functions and see what is cached.
        

---

### **Exploitation**

- If **sensitive data is cached in plaintext**:
    
    - Extract files directly from rooted device or with physical access.
        
    - If cache is on **external storage (SD card)** → no root needed, any app with `READ_EXTERNAL_STORAGE` can steal it.
        
- Example exploitation:
    
    - App caches **bank transaction history** in `/sdcard/Android/data/<package>/cache/txn.log`.
        
    - Malicious app reads it and uploads to attacker server.
        

---

### **Real Bug Bounty Example**

- Bug hunters often find:
    
    - **Access tokens cached** → session hijacking.
        
    - **Chat/media files cached** → sensitive exposure.
        
    - **PDF invoices cached** → financial leaks.
        
- These are usually rewarded as **Sensitive Data Exposure** or **Insecure Data Storage** in reports.
    

---

### **Mitigation**

1. **Do not cache sensitive data** (tokens, passwords, PII).
    
2. If caching is necessary → **encrypt before writing**.
    
3. Use `MODE_PRIVATE` when writing files.
    
4. Clear cache:
    
    - On logout: `context.getCacheDir().delete()`.
        
    - On app close if sensitive session exists.
        
5. Avoid writing to **external storage** for sensitive files.
    

---

✅ **Summary**:

- **Cache / temp files** are dangerous because developers forget to clear them.
    
- Attackers extract data from cache folders to steal sessions, chats, or financial data.
    
- Always test `/cache/` and `/tmp` directories after app usage.