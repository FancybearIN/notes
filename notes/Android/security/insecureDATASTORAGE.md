 
#  Insecure Data Storage
---

==**Insecure Data Storage** means the mobile app stores **sensitive information**== **(passwords, tokens, PII, financial data, etc.) in unsafe locations** on the device without proper protection.

These locations can be:

- **Shared Preferences** → XML files in plaintext
- **SQLite Databases** → stored locally without encryption
- **Internal/External Storage** → files accessible by other apps
- **Cache / Logs** → debug logs containing sensitive data
- **Clipboard / Screenshots** → accidentally leaking data

## Attack Vectors

How attackers exploit insecure data storage?
- Pulling local files via **ADB / Rooted device**.
- Reading **Shared Preferences (XML)**, **SQLite DBs**, or files in **internal/external storage**.
- Exploiting **weak or no encryption**.
- Reading **logs/cache/temporary files** with sensitive info.
- Malware apps accessing storage.
- Cloud storage misconfigurations (open buckets, weak ACLs).
- **Social engineering** → tricking users to give filesystem/app access

---

### 1. [**Shared Preferences (XML files)**](case1)

- Apps store sensitive data like tokens, passwords, PII in `shared_prefs/` folder.
- Problem: Stored in **plaintext XML**, easily readable on rooted device.

---

### 2. [**SQLite Databases**](case2)

- Apps use SQLite DB to store user accounts, credit card details, or logs    
- Problem: Stored unencrypted → attacker can dump with `adb` or `sqlite3`.

---

### 3. [**Internal Storage Files**](case3)

- Sensitive files (like config, keys, JSON responses) saved in internal app directory `/data/data/<pkg>/files/`.    
- Problem: No encryption or weak protection → attacker can read/tamper.

---

### 4. [**External Storage (SD Card / Public Storage)**](case4)

- Apps save sensitive data (backups, reports, downloads) in `/sdcard/`.
- Problem: Any other app with storage permission can access it.

---

### 5. [**Cache / Temporary Files**](case5)

- Apps temporarily store tokens, payment info, reports in `/cache/`.
- Problem: Not deleted after use → attacker retrieves them.

---

### 6. [**Logs (Logcat)**](case6.md)

- Debug logs often print sensitive info (API responses, JWT tokens, CC numbers).    
- Problem: Other apps with `READ_LOGS` (older Android) or attacker with physical access can dump logs.

---

### 7. [**Clipboard Data**](case7)
- App copies sensitive info (passwords, OTPs, tokens) to clipboard.
- Problem: Other apps can read clipboard data in background.

---

### 8. [**Screenshots & Background Recording**](case8)

- Sensitive screens (OTP, passwords, credit card info) can be captured in screenshots or screen-recording apps.
- Problem: No `FLAG_SECURE` in app → attacker/malware can capture.

---

### 9. [**Session Tokens Stored Insecurely**](case9)

- Session tokens, refresh tokens, or cookies stored in plaintext (DB, prefs).    
- Problem: Extracted token → full account takeover.

---

### 10. [**Improper Key Management**](case10)

- App stores **encryption keys** locally (hardcoded in code, or plaintext in storage)
- Problem: Attacker extracts key → decrypts all data.

---

### 11. [**Cloud Storage Misconfiguration**](case11)

- Firebase, AWS S3, or GCP bucket used by app to sync data.  
- Problem: Misconfigured permissions → public access to private data.

---

### 12. [**Third-Party Library / SDK Issues**](case12)

- SDKs store their own logs, cached tokens, or analytics data insecurely.    
- Problem: App indirectly leaks data due to insecure SDK storage.

---

### 13. [**Unprotected Backups**](case13)

- Android backup mechanism saves app data.    
- Problem: Sensitive files included in backups → attacker extracts from device backup.


---

### 14. **Improper Session Management**

- Session data not expired, stored locally in plaintext.    
- Problem: Attacker retrieves token even after logout → reuse for long-term access    

---

### 15. **Unintended Data Exposure in IPC (Inter-Process Communication)**

- Sensitive data passed between components via intents or content providers without proper permissions.    
- Problem: Other malicious apps intercept and read datav 