## External Storage (SD Card / Public Storage)

Apps often use external storage (`/sdcard/`, `/storage/emulated/0/`) to store files like images, logs, exports, backups.  
⚠️ Problem: External storage is **world-readable** (other apps can read/write without special permissions). If sensitive data is stored there → any app can steal it.

---

### 📌 Scenario

Imagine a banking app that exports **transaction logs** or **statements** as `.txt` or `.csv` into `/sdcard/BankApp/transactions.txt`.  
Another malicious app with only `READ_EXTERNAL_STORAGE` permission can grab that file.

---

### 🔎 Detection

How to find this during a pentest:

1. **Static Analysis**
    
    - Look for API calls like:
        
        `getExternalStorageDirectory() getExternalFilesDir() Environment.getExternalStoragePublicDirectory()`
        
    - Example risky code:
        
        `File file = new File(Environment.getExternalStorageDirectory(), "transactions.txt");`
        
2. **Dynamic Analysis**
    
    - Use the app, perform exports/downloads.
        
    - Check `/sdcard/Android/data/<package>/` and `/sdcard/<AppName>/` folders.
        
    - Tools: `adb shell ls -R /sdcard/` or file explorer (e.g., Amaze, ES File Explorer).
        

---

### 💥 Exploitation

- On a real device/emulator, install a **malicious app** with `READ_EXTERNAL_STORAGE`.
    
- That app can silently copy:
    
    - Bank statements
        
    - Authentication logs
        
    - Exported SQLite backups
        
    - Images or documents
        

Example PoC:

`File f = new File("/sdcard/BankApp/transactions.txt"); BufferedReader br = new BufferedReader(new FileReader(f)); String line; while ((line = br.readLine()) != null) {     Log.d("StolenData", line); }`

**Practical Exploit**:

- A pentester can show that another app (even a simple file manager) can read exported files without root.
    
- If tokens or API keys are stored here → reuse for account takeover.
    

---

### 🎯 Bug Bounty Impact

- **Medium → High severity** depending on what is stored.
    
    - Low → if only harmless images.
        
    - High → if files contain **PII, tokens, credentials, session data, banking statements, medical records**.
        
- Easy to prove with a **malicious PoC APK** that auto-reads sensitive files.
    

---

### 🛡️ Mitigation

1. Never store sensitive data on external storage.
    
2. If necessary → **encrypt files before writing**.
    
3. Use **Internal Storage** (`context.getFilesDir()`) instead.
    
4. For media-sharing needs → store only **non-sensitive** data externally.
    
5. Apply **scoped storage** (Android 10+) → limits what apps can access.