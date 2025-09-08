Absolutely, Fancy. Let’s now cover the **A02:2021 – Cryptographic Failures** in the **same detailed format** as Broken Access Control, including root causes, exploitation methods, detection, mitigation, and common subtypes.

---

# 🥈 A02:2021 – **Cryptographic Failures** (Previously: Sensitive Data Exposure)

---

## ✅ 1. **Definition (What It Is)**

**Cryptographic Failures** occur when sensitive data is not properly protected **in storage or transmission** due to:

- Use of weak or broken encryption algorithms,
- Insecure key management,
- Lack of encryption,
- Or improper SSL/TLS configuration.
    

> 🛑 This is **not just about crypto algorithms**, but also **data exposure risks** due to improper protection.

---

## 📊 2. **OWASP Stats**

|Metric|Value|
|---|---|
|**OWASP Rank (2021)**|#2|
|**Formerly Known As**|Sensitive Data Exposure|
|**Common Weaknesses (CWEs)**|CWE-259 (Hardcoded Password), CWE-319 (Cleartext Transmission), CWE-327 (Broken Crypto Algorithm), CWE-522 (Missing Encryption)|
|**Data Types at Risk**|Passwords, Credit Cards, PII, Health Records, Session Tokens|

---

## 🔥 3. **Exploitation Techniques (How to Exploit)**

|Exploit Type|Example|
|---|---|
|**Plaintext Transmission**|Intercept unencrypted login credentials (HTTP, no TLS)|
|**Weak SSL/TLS Configuration**|Downgrade attack via SSLv2/v3, no HSTS|
|**Hardcoded/Exposed Keys**|Keys found in source code, GitHub, JavaScript|
|**Weak Hashing**|Use MD5/SHA1 for passwords → Crack using hashcat|
|**Insecure Storage**|Database stores passwords in plaintext or reversible encryption|
|**Padding Oracle Attacks**|Use padding flaws in CBC-mode encryption to decrypt data|
|**Insecure JWT**|Use `alg=none`, unsigned or improperly signed JWT tokens|
|**Improper CORS**|Secrets leak to cross-origin sites due to bad CORS policy|

---

## 🔍 4. **How to Detect**

|Technique|What to Look For|
|---|---|
|**Burp Suite**|Mixed content (HTTP), missing HSTS, weak SSL/TLS|
|**Nikto / SSLScan**|Old SSL versions, weak cipher suites|
|**Code Review**|Look for `MD5`, `base64`, hardcoded keys|
|**Manual Analysis**|Check login and sensitive forms use HTTPS|
|**Intercept & Replay**|Capture unencrypted tokens or credentials|
|**JWT Tools**|Decode tokens, test for `alg=none`, expired tokens|

---

## 🧩 5. **Subtypes with Detection, Exploitation, and Mitigation**

| No. | Subtype                           | Description                        | Detection                  | Exploitation                    | Mitigation                               |
| --- | --------------------------------- | ---------------------------------- | -------------------------- | ------------------------------- | ---------------------------------------- |
| 1   | **Plaintext Data Transmission**   | Data sent via HTTP (no TLS)        | Burp → Check HTTP requests | Intercept login/token data      | Use HTTPS everywhere, redirect HTTP      |
| 2   | **No Encryption at Rest**         | Sensitive data stored unencrypted  | DB/code review             | Read DB dump or stolen disk     | Encrypt sensitive fields (AES-256)       |
| 3   | **Weak Hashing Algorithms**       | MD5/SHA1 for passwords             | Look for `MD5()` in code   | Crack hashes with hashcat       | Use `bcrypt`, `argon2`, `PBKDF2`         |
| 4   | **Hardcoded Keys/Secrets**        | Secrets in code or config          | Grep, GitHub dorking       | Attacker gets full access       | Store secrets in env vars/vaults         |
| 5   | **Broken SSL/TLS Config**         | Use of SSLv2/3, weak ciphers       | SSLScan, testssl.sh        | Downgrade or MITM               | Use TLS 1.2+, strong cipher suites, HSTS |
| 6   | **Insecure JWT**                  | No signature, weak algs            | Decode JWT                 | Modify payload if `alg=none`    | Use HS256/RS256, validate signature      |
| 7   | **Key Reuse Across Services**     | Same key for all users or services | Code review                | Compromise one = compromise all | Unique key/token per user/session        |
| 8   | **Improper Padding / Mode**       | Use ECB/CBC incorrectly            | Code audit + crypto attack | Padding Oracle, replay attacks  | Use authenticated encryption (GCM/CCM)   |
| 9   | **Weak Random Number Generation** | `rand()` or predictable RNG        | Code review                | Predict token values            | Use CSPRNGs like `crypto.randomBytes()`  |

---

## 🛡️ 6. **Mitigation (How to Prevent)**

|Area|Strategy|
|---|---|
|**TLS**|Enforce TLS 1.2/1.3; enable HSTS, disable SSLv2/v3|
|**Passwords**|Use strong salted hashes like `bcrypt` or `argon2`|
|**Key Management**|Store keys in secure vaults (e.g., HashiCorp Vault, AWS KMS), **never hardcode**|
|**Sensitive Data**|Encrypt PII/credentials at rest and in transit|
|**JWT**|Validate tokens, use secure algorithms (RS256/HS256), short expiry|
|**Avoid Base64**|Don't confuse `base64` with encryption—it’s reversible!|
|**Static + Dynamic Testing**|Use tools to find insecure crypto in code and runtime|
|**Regular Patching**|Crypto libraries must be up to date (OpenSSL, BouncyCastle, etc.)|

---

## 🧠 7. Root Causes of Cryptographic Failures

|Cause|Explanation|
|---|---|
|Misunderstanding of crypto|Devs use insecure/weak algorithms like `MD5`, `Base64`|
|Misconfiguration|Weak TLS setup, disabled validation|
|Hardcoded credentials|Secrets or keys exposed in code or repositories|
|Token misuse|JWTs without proper validation or short expiry|
|Legacy support|Old systems still use SSLv3, RC4, or ECB mode|
|No key rotation|Same key used indefinitely or across environments|

---

## 📚 8. References & Tools

|Resource|Use|
|---|---|
|[SSL Labs Test](https://www.ssllabs.com/ssltest/)|Check SSL/TLS security of web server|
|[OWASP Crypto Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)|Secure crypto implementation guide|
|[testssl.sh](https://testssl.sh/)|Scan SSL/TLS configuration|
|[jwt.io](https://jwt.io/)|Decode & analyze JSON Web Tokens|
|[hashcat](https://hashcat.net/hashcat/)|Crack weak password hashes|
|[Burp Suite / ZAP](https://portswigger.net/burp)|Detect mixed content, crypto failures|
|[CyberChef](https://gchq.github.io/CyberChef/)|Decode/analyze crypto formats and encoding|

---

## 🧪 Example Attack Scenarios

### 📌 **Scenario 1: No HTTPS on Login Page**

- App loads login form over `http://example.com/login`
    
- Attacker on public WiFi sniffs the network and captures plaintext credentials
    

### 📌 **Scenario 2: JWT Token with `alg=none`**

- JWT header: `{ "alg": "none" }`
    
- No signature used → Attacker modifies token payload (e.g., changes role to admin)
    

### 📌 **Scenario 3: Passwords Stored with MD5**

- Devs use `MD5(password)` and store it in DB
    
- Attacker dumps the DB → Uses hashcat to crack all passwords in seconds
    
