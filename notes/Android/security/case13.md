# **Unprotected Backups**

📌 **Scenario**  
Android's backup mechanisms (Auto Backup for Apps, `adb backup` on older devices, OEM cloud backups, or 3rd-party backup apps) can include app data by default. If sensitive files—databases, SharedPreferences, tokens, keys, cached media, or config files—are included without encryption or exclusion, an attacker who obtains the backup (from a stolen device, compromised cloud account, backup leakage, or via `adb backup` on a tethered device) can extract and read everything. Backups are a common blind spot: developers assume data lives only on-device, but backups replicate it elsewhere.

---

### **Detection**

1. **Static analysis**
    
    - Search `AndroidManifest.xml` for backup settings:
        
        - `android:allowBackup="true"` (default `true` on older targets)
            
        - `android:fullBackupContent="@xml/backup_rules"`
            
    - Inspect `res/xml/` for `<full-backup-content>` rules and see which files/paths are included/excluded.
        
        ```bash
        aapt dump xmltree app.apk AndroidManifest.xml | grep -n "allowBackup"
        apktool d app.apk && grep -R "fullBackupContent" -n res
        ```
        
    - Check for use of `android:allowBackup="false"` or explicit rules denying sensitive paths.
        
2. **Dynamic analysis**
    
    - Create a backup (emulator or test device) and inspect contents:
        
        - Old-style: `adb backup -f app.ab com.example.app` then unpack with `android-backup-extractor` tools.
            
        - Auto Backup on Android 6+: back up on emulator or capture the generated tar/zip on devices that allow it (in lab environments).
            
    - Inspect resulting archive for:
        
        - SharedPreferences XML files
            
        - SQLite DB files
            
        - Files under `files/`, `cache/`, `databases/`
            
        - Any key material, tokens, or PII.
            
    - On emulators: verify cloud/auto-backup behavior by enabling Google backup in settings and observing the synced payload in a controlled test account if possible.
        
3. **Runtime / source checks**
    
    - Grep code for paths written to `getFilesDir()`, `getExternalFilesDir()`, and `shared_prefs` (which are backup-included by default unless excluded).
        
    - Confirm where sensitive artifacts are stored and whether those paths are referenced in backup rules.
        
4. **Edge/third-party backups**
    
    - Check app interacts with device OEM cloud backup APIs or exposes content to third-party backup apps.
        
    - Review if app offers an in-app “export” or backup flow that writes to external storage or cloud without encryption.
        

---

### **Exploitation**

- **Local theft via backup extraction**
    
    - Attacker with physical access or an extracted cloud backup opens the archive, recovers plaintext tokens, passwords, or private data, and reuses them for account takeover.
        
- **Remote compromise via leaked backups**
    
    - Cloud backup leak or misconfigured cloud snapshot containing app files leads to mass data exposure.
        
- **Credential / key recovery**
    
    - Backups often contain refresh tokens, private keys, or DBs—extract and decrypt if keys are present or reuse tokens directly if not device-bound.
        
- **Persistent replays**
    
    - Restore a backup to a test device/emulator to replicate victim state and experiment with priv escalation or offline cracking.
        
- **Cross-device takeover**
    
    - Use extracted auth material to log in from attacker-controlled device if tokens aren’t strongly bound.
        

Attacker vectors: stolen device, compromised Google account/backups, malicious actor with temporary physical access (ADB backup), or backup storage providers with weak access controls.

---

### **Test cases / Practical checklist**

- Manifest & rules
    
    - `aapt dump xmltree app.apk AndroidManifest.xml | grep -n "allowBackup"`
        
    - `apktool d app.apk && grep -R "fullBackupContent" -n res`
        
    - Open `res/xml/backup_rules.xml` and review `<include>` / `<exclude>` patterns.
        
- Create & inspect backup
    
    - Old adb backup:
        
        ```bash
        adb backup -f app.ab com.example.app
        # convert app.ab to tar with android-backup-extractor (abe.jar) or pyabe, then inspect files
        java -jar abe.jar unpack app.ab app.tar
        tar -xf app.tar -C app-backup
        find app-backup -type f | sed -n '1,200p'
        ```
        
    - Auto Backup (Android 6+):
        
        - Emulate backup flow in a controlled account or use tools to capture backup payloads in testing environment. (Auto Backup produces a tar-like payload.)
            
    - Inspect for:
        
        - `shared_prefs/*.xml`
            
        - `databases/*.db`
            
        - `files/*.json`, `*.txt`, `*.pem`, `*.key`
            
        - Any `/cache` or exported files accidentally included.
            
- Verify exclusions
    
    - Ensure sensitive paths are present in `<exclude>` tags in `fullBackupContent`.
        
    - Test that excluded files do not appear in backup payload.
        
- Edge cases
    
    - WebView data, app-created external files, and files written to app-specific external directories — verify whether they are included.
        
    - In-app export features — test whether they write to backup-included locations.
        

---

### **Detection signatures & grep snippets**

```bash
# Manifest check
aapt dump xmltree app.apk AndroidManifest.xml | grep -n "allowBackup"

# Find backup content files
apktool d app.apk && grep -R -n "fullBackupContent" .

# Look for likely sensitive filenames in apk
strings app.apk | grep -Ei "shared_prefs|databases|\\.db|secret|key|token|credentials|prefs"

# After unpacking backup tar
find app-backup -type f | grep -iE "shared_prefs|databases|token|secret|key|password|credentials"
```

---

### **Real Bug Bounty Examples (what pays & why)**

- Backups containing `shared_prefs` with access/refresh tokens → High (account takeover).
    
- SQLite DB in backups with PII, messages, or payment records → High (privacy breach / financial exposure).
    
- Private keys or certificates stored on device and included in backups → Critical (decryption / signing abuse).
    
- Mass backup leaks from misconfigured cloud backup accounts → Critical (large-scale data exposure).
    

Programs pay well because backups are an easy, low-effort way to get a full snapshot of victim data and often bypass on-device protections.

---

### **Mitigation**

1. **Disable backups for sensitive apps or data**
    
    - Set in `AndroidManifest.xml`:
        
        ```xml
        <application android:allowBackup="false" ...>
        ```
        
        (Use thoughtfully — some apps rely on backups for UX; consider selective exclusions instead.)
        
2. **Use `fullBackupContent` to exclude sensitive paths**
    
    - Create `res/xml/backup_rules.xml` with `<exclude>` patterns for:
        
        - `databases/`, `shared_prefs/`, `files/` containing secrets, keys, token files.
            
        
        ```xml
        <full-backup-content>
          <exclude domain="sharedpref" path="."/>
          <exclude domain="database" path="."/>
          <exclude domain="file" path="sensitive.json"/>
        </full-backup-content>
        ```
        
3. **Do not store raw secrets in backup-included locations**
    
    - Avoid persisting keys/tokens to SharedPreferences or files that would be captured. Use Keystore-wrapped keys, or avoid persistent storage for high-value secrets.
        
4. **Encrypt sensitive data before writing**
    
    - If data must be persisted and included in backups, encrypt with a key not included in the backup (e.g., derive from user credential or keep in hardware-backed Keystore marked non-exportable).
        
5. **Avoid shipping private key material or long-lived credentials**
    
    - Ensure keys are generated per-device (Keystore) or fetched dynamically from server; do not write server-side secrets to disk.
        
6. **Limit in-app export & external file writes**
    
    - If app supports export, prompt the user and store exports in private encrypted blobs, or guide users to secure storage.
        
7. **Server-side mitigations**
    
    - Implement short token TTLs and binding. Revoke tokens on suspicious replays.
        
8. **Educate users & enterprise controls**
    
    - Warn users about backup risks; support enterprise policies that disallow backups for corporate data via managed configurations.
        
9. **Test backups during CI**
    
    - Include a QA step: generate backups in a controlled environment and scan for sensitive artifacts automatically.
        
10. **Rotate keys & tokens if backup leak suspected**
    
    - If an incident occurs, invalidate tokens and rotate keys; notify users if PII is affected.
        

---

### **Escalation paths & impact reasoning**

- **Account takeover** — extracted refresh tokens or cookies enable persistent access.
    
- **Data exfiltration** — messages, PII, and documents in backups provide full user context.
    
- **Key compromise** — private keys in backups allow decryption of data or forging signatures.
    
- **Mass impact** — backup leaks can expose many users if a cloud backup of many devices is compromised.
    
- **Forensic pivot** — restored backups on attacker devices allow offline analysis and exploitation of logic flaws.
    

Severity depends on what backups include (tokens, keys vs. harmless caches), token binding/TTL, and whether attackers can use artifacts remotely.

---

### **Exploitation notes & POC ideas (concise)**

- **POC A — adb backup extraction**
    
    1. `adb backup -f app.ab com.example.app` (lab/emulator).
        
    2. Use `android-backup-extractor` to unpack: `java -jar abe.jar unpack app.ab app.tar`.
        
    3. `tar -xf app.tar -C app-backup` and `find` sensitive files; show a redacted sample (e.g., presence of `shared_prefs/session.xml` with `<string name="refresh_token">…</string>`).
        
- **POC B — Auto Backup payload**
    
    1. Configure emulator/test device with backup enabled, perform app flows.
        
    2. Trigger/collect backup payload in controlled test account, inspect archive for included DBs or prefs.
        
- **POC C — Restore & reproduce**
    
    1. Restore backup to a clean emulator, run app, and demonstrate account access or reveal PII recovered—redact real values in external reports.
        

Always conduct backups and inspections in controlled, consented environments. Redact secrets in any submitted evidence.

---

✅ **Summary**

- Backups replicate your on-device data to other storage — a forgotten vector.
    
- Hunt by checking `allowBackup`, `fullBackupContent` rules, and actually making a backup to inspect included files.
    
- Fix by disabling backups or excluding sensitive paths, encrypting secrets with non-backupable keys (Keystore), minimizing persisted secret storage, and making backups part of your CI security tests.
    

Treat backup policies as part of data lifecycle design: what you persist today can be carried into an attacker’s hands tomorrow.