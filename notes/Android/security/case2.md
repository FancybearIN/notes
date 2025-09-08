## Attack Vector 2: SQLite Databases

**Scenario**

- Many Android apps use **SQLite databases** for local data storage.
    
- Developers sometimes store **sensitive data** like:
    
    - Login credentials (username/password)
    - API keys / access tokens
    - Personally Identifiable Information (PII) – names, emails, phone numbers, addresses
    - Financial info (credit card numbers, transaction logs)
        
- Problem → Databases are stored in `/data/data/<package_name>/databases/` and often in **plaintext** (unencrypted).
    
- On a rooted device or via backup extraction, attackers can easily access these DB files.
---
## **Detection (Pentester/Bug Bounty Hunter)**

1. **Static Analysis**:
    
    - Decompile APK (Jadx/Bytecode Viewer) and look for `SQLiteOpenHelper` or raw SQL queries.
    - Hardcoded table/column names might hint sensitive storage.
        
2. **Dynamic Analysis**:
    
    - Install app in emulator / rooted device.
        
    - Check database path:
        
        `adb shell run-as <package_name> cd databases ls`
        
    - Pull database:
        
        `adb pull /data/data/<package_name>/databases/<db_name>.db`
        
3. **Inspection**:
    
    - Open with tools like `sqlite3`, **DB Browser for SQLite**, or `strings`.
        
    - Look for **passwords, tokens, PII**.
        

---

**💥 Exploitation**

- If sensitive data is stored **in plaintext**:
    
    - Extract and directly read user info (ex: dump full user list).
        
    - Retrieve **session tokens** and reuse them in API calls to impersonate users.
        
- If weak encryption is used (like Base64 or custom XOR) → easily reversible.
    
- Exploit chaining:
    
    - Use stolen **refresh tokens** → get new access tokens.
        
    - Combine with **Insecure Communication (no SSL pinning)** to hijack live sessions.
        

---

**💰 ==Bug Bounty Perspective**==

- ==This is considered **Sensitive Data Exposure / Insecure Data Storage** under **OWASP M2**.==
    
- ==Platforms like **HackerOne / Bugcrowd / Intigriti** accept these if:==
    
    - ==The data is highly sensitive (credentials, payment info, PII, tokens).==
        
    - ==You show **clear exploitability** (e.g., using dumped token → login to victim account).==
        
- ==Simply finding plaintext DB may not be enough; show **real impact** (account takeover, financial exposure).==
    
- ==Example valid report: _“The app stores OAuth refresh tokens unencrypted in SQLite DB. I was able to extract it and use it to log in as the victim without password.”_==
    

---

**🛡️ Mitigation**

- **Do NOT store sensitive data locally** unless absolutely necessary.
    
- If storage is required:
    
    - Use **Android Keystore** + database encryption (e.g., **SQLCipher**).
        
    - Apply **field-level encryption** for sensitive columns.
        
    - Use token expiration and rotate refresh tokens frequently.
        
- Enforce **root detection** to make extraction harder (not a fix, but adds friction).