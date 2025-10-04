# **Cloud Storage Misconfiguration (Firebase / S3 / GCP buckets)**

📌 **Scenario**  
Mobile apps often sync user data (images, documents, backups, logs) to cloud storage: Firebase Storage, AWS S3, Google Cloud Storage, Azure Blob, etc. Misconfigured storage rules or ACLs — public read, public write, overly permissive Firebase rules, leaked credentials/keys, or wrong IAM roles — can expose private buckets/blobs. Consequences: mass data exposure, arbitrary uploads (malware hosting, defacement), user impersonation via backups, or server-side access to PII.

---

### **Detection**

1. **Static analysis**
    
    - Search app for bucket identifiers and config:
        
        ```bash
        # look for firebase bucket name in google-services.json or resources
        grep -R -n -E "storageBucket|bucket|s3.amazonaws.com|amazonaws.com|storage.googleapis.com|gs://|firebaseio.com" .
        strings app.apk | grep -Ei "s3.amazonaws.com|storage.googleapis.com|bucket|firebaseapp|googleapis"
        ```
        
    - Inspect embedded config files:
        
        - `google-services.json` → `project_info.client[].client_info.client_id`, `storage_bucket`
            
        - `awsconfiguration.json`, `aws-exports.js`, or environment constants for S3 bucket names or access keys.
            
    - Search for hardcoded cloud credentials: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `GOOGLE_APPLICATION_CREDENTIALS`, API keys.
        
2. **Dynamic analysis (network)**
    
    - Run the app and intercept network traffic (Burp/mitmproxy) to find direct storage URLs or signed URLs (`.s3.amazonaws.com/...`, `storage.googleapis.com/...`, Firebase download URLs).
        
    - Look for presigned URLs in API responses — note expiry and scope.
        
3. **Direct probing (external)**
    
    - Probe discovered bucket names publicly (from your test machine):
        
        ```bash
        # S3
        curl -sS "https://<bucket>.s3.amazonaws.com/" | head
        curl -I "https://<bucket>.s3.amazonaws.com/<known-object>"
        
        # Google Cloud
        curl -sS "https://storage.googleapis.com/<bucket>/" | head
        curl -I "https://storage.googleapis.com/<bucket>/<object>"
        
        # Firebase (often uses storage.googleapis.com)
        curl -I "https://firebasestorage.googleapis.com/v0/b/<bucket>/o"
        ```
        
    - Try listing or accessing common paths (images, uploads/, backups/) — sometimes `index` returns JSON list.
        
4. **Rule inspection (Firebase)**
    
    - If you can access project or rules endpoint, check `storage.rules`. For example, look for `allow read, write: if true;` or overly permissive `if request.auth == null` without object checks.
        
    - From the client side, inspect whether app authenticates with Firebase Auth before storage calls — lack of auth is a red flag.
        
5. **Credential leakage checks**
    
    - Grep repo-like artifacts or embedded files for base64 blobs or long hex strings (possible service account JSON).
        
    - Check if app ships with AWS IAM credentials; even limited keys may allow listing.
        
6. **Server-side vectors**
    
    - Observe API responses that embed object URLs or allow upload endpoints that accept arbitrary object names → potential write misconfig.
        

---

### **Exploitation**

- **Public-read buckets**
    
    - Exfiltrate all objects (photos, documents, backups) via simple GETs. Mass user data exposure is common and high-impact.
        
- **Public-write buckets / permissive rules**
    
    - Upload arbitrary content (malware, phishing pages, illegal content). Host malware or expose attacker-controlled content on a domain associated with the project.
        
- **Leaked credentials / weak IAM**
    
    - Use leaked keys to list, read, write, or delete objects; rotate keys or escalate by chaining with other services.
        
- **Presigned URL abuse**
    
    - If presigned URLs are generated with long TTLs, an attacker can reuse them for extended access.
        
- **Firebase rule bypass**
    
    - Miswritten rules (e.g., allowing `if resource.metadata.owner == request.auth.uid` without verifying metadata creation) allow privilege escalation.
        
- **Backup & restore pivot**
    
    - Download user backups from cloud, extract tokens/passwords, and attempt account takeover or offline cracking.
        

Attacker capability depends on the misconfiguration: read-only gives data leak, write gives hosting/pivot, full-control gives deletion and broad abuse.

---

### **Test cases / Practical checklist**

- **Find bucket names**
    
    - `grep -R -nE "bucket|s3.amazonaws.com|storage.googleapis.com|firebasestorage" .`
        
    - Inspect `google-services.json`, `awsconfiguration.json`, `res/values/strings.xml`, `assets/`.
        
- **Public probe**
    
    - `curl -s "https://<bucket>.s3.amazonaws.com/"` — S3 may return XML listing if public.
        
    - `curl -s "https://storage.googleapis.com/<bucket>/"`
        
    - `curl -s "https://firebasestorage.googleapis.com/v0/b/<bucket>/o"` — might need proper object query, but sometimes lists metadata.
        
- **List common paths**
    
    - Guess directories: `images/`, `uploads/`, `backups/`, `user/<uid>/`, `public/`.
        
    - Try `curl` or `wget` to fetch files found.
        
- **Check write capability**
    
    - Attempt PUT/POST to object URL (careful: do not upload harmful content).
        
    - For S3: try unsigned PUT to `https://<bucket>.s3.amazonaws.com/test-poc.txt` — many public-write configs will accept it.
        
        ```bash
        curl -X PUT --data 'poc' "https://<bucket>.s3.amazonaws.com/pentest-poc.txt"
        ```
        
    - If write succeeds, delete after verification or leave minimal tombstone per program policy (but follow bug bounty program rules — here we will not perform destructive actions).
        
- **Firebase rules testing**
    
    - If you can get an authenticated client token, test reads/writes with and without auth to see rule enforcement.
        
    - Use Firebase REST APIs to attempt listing: `https://firebasestorage.googleapis.com/v0/b/<bucket>/o?prefix=`
        
- **Credential checks**
    
    - Search for service account JSON or static keys in the APK: `grep -R -n "private_key" .` or `grep -R -n "AKIA"`
        
- **Chain with app flows**
    
    - Intercept uploads from app to see whether files are uploaded client-side straight to bucket (client-accessible) or via backend (safer). Direct-to-bucket uploads often require client credentials or presigned URLs — check their handling.
        

---

### **Detection signatures (grep / regex examples)**

```bash
# common bucket indicators
grep -R -nE "s3.amazonaws.com|amazonaws.com|storage.googleapis.com|firebasestorage.googleapis.com|gs://|firebaseio.com" .

# firebase bucket name in google-services.json
grep -R -n "storageBucket" google-services.json

# service account / private key artifacts
grep -R -n -E "private_key|client_email|project_id|type\": \"service_account\"" .

# AWS access keys
grep -R -n -E "AKIA[0-9A-Z]{16}" .
```

---

### **Exploitation notes & PoC ideas (concise)**

- **POC A — Read bucket contents (public-read)**
    
    1. Find bucket: from app strings/config or network logs (e.g., `<bucket>`).
        
    2. `curl "https://<bucket>.s3.amazonaws.com/"` — if listable, capture sample object URLs and download a redacted file to show sensitive content.
        
- **POC B — Verify write (public-write)**
    
    1. Try `PUT` a small benign file:
        
        ```bash
        curl -X PUT --data 'poc' "https://<bucket>.s3.amazonaws.com/pentest-poc.txt" -I
        ```
        
    2. Show that GET retrieves it. (If reporting, remove file or request vendor to remove; follow program rules.)
        
- **POC C — Firebase rules bypass**
    
    1. Use REST endpoint: `https://firebasestorage.googleapis.com/v0/b/<bucket>/o?prefix=`
        
    2. If returns object list without auth → listable.
        
    3. Attempt upload with REST API if rules allow unauthenticated writes.
        
- **POC D — Use leaked keys (non-destructive)**
    
    1. If credentials are found, use AWS CLI/GCP SDK with read-only to enumerate. Demonstrate read via single object fetch instead of mass exfiltration.
        

> Always redact or avoid downloading entire private datasets. Show minimal screenshots/metadata proving issue (object names, first-level JSON metadata), not entire user records.

---

### **Mitigation**

1. **Principle of least privilege**
    
    - Set bucket/object ACLs and IAM roles so only necessary principals (backend service accounts) can read/write. Avoid public ACLs unless absolutely required.
        
2. **Use signed URLs with short TTLs**
    
    - For client-side uploads/downloads, use presigned URLs generated by the backend with minimal expiry and scoped operations.
        
3. **Correct Firebase Storage rules**
    
    - Enforce `request.auth != null && request.auth.uid == resource.metadata.owner` semantics, validate `resource.name` patterns, and deny `allow write: if true;`.
        
4. **Avoid embedding credentials in apps**
    
    - Never ship service account keys, long-term AWS keys, or admin credentials in the APK. Use backend endpoints or token-vending services.
        
5. **Server-side mediation for sensitive data**
    
    - Let the app upload to backend; backend validates and stores in private buckets, or it mints short-lived signed URLs for direct upload.
        
6. **Bucket logging & alerting**
    
    - Enable access logging, object-level logging, and alerts for unusual list or read activity. Monitor public access changes.
        
7. **Destroy/rotate compromised keys**
    
    - If any key leaks, revoke immediately and rotate.
        
8. **Use VPC / private access where possible**
    
    - Restrict buckets to private networks or use private endpoints; require backend to access storage.
        
9. **Validate object uploads**
    
    - For write-enabled buckets, run server-side validation (scan for malware, enforce content types, size limits) and avoid serving uploads directly under the same origin without validation.
        
10. **Least-permission SDKs & roles**
    
    - Create dedicated service accounts with minimal scopes (read-only, write-only) per client need.
        
11. **Secure backups & lifecycle**
    
    - Prevent backups of sensitive bucket data to public locations; enforce lifecycle policies and retention controls.
        
12. **Regular audits**
    
    - Periodically audit IAM policies and bucket ACLs (automated scanners can help).
        

---

### **Real Bug Bounty Examples (what pays & why)**

- **Public S3 with PII / backups** → High/critical (mass data leakage).
    
- **Public-write buckets used for hosting** → High (malware hosting / supply-chain risks).
    
- **Leaked service account / AWS keys in APK** → Critical (full cloud compromise potential).
    
- **Misconfigured Firebase rules exposing all users’ images/backups** → High (user enumeration and PII exposure).
    

Programs pay well because cloud misconfigs can lead to broad, low-effort, high-impact exposure.

---

✅ **Summary**

- Hunt: grep for bucket names/credentials, inspect `google-services.json`/aws config, intercept network flows for storage URLs, then probe discovered buckets with safe reads.
    
- Impact: public-read = data exfiltration; public-write = hosting/abuse; leaked creds = full control.
    
- Fix: remove credentials from clients, tighten IAM/ACLs, use short-lived signed URLs, enforce strict Firebase rules, enable logging/alerts, and rotate keys quickly.
    

Cloud buckets are like unlocked server rooms — loud, obvious, and devastating if ignored. Protect them with the same paranoia you’d reserve for your house keys.