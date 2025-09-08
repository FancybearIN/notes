
# 🥉 A03:2021 – **Injection**

---

## ✅ 1. **Definition (What It Is)**

**Injection** occurs when **untrusted input** is sent to an interpreter (like SQL, OS shell, or LDAP) as part of a command or query, causing the interpreter to **execute unintended commands** or **access unauthorized data**.

> **Injection = Attacker-controlled input + no sanitization → arbitrary command execution.**

It’s one of the oldest, most critical, and most widely exploited vulnerabilities.

---

## 📊 2. **OWASP Stats**

|Metric|Value|
|---|---|
|**OWASP Rank (2021)**|#3|
|**Formerly Known As**|Injection (No change from 2017)|
|**Common Weaknesses (CWEs)**|CWE-89 (SQLi), CWE-77 (OS Command Injection), CWE-94 (Code Injection), CWE-20 (Improper Input Validation)|
|**Top Attack Types**|SQL Injection, OS Command Injection, HTML Injection, LDAP Injection, NoSQL Injection|

---

## 💣 3. **Exploitation Techniques (How to Exploit)**

| Type                                      | Example Payload                   | Effect                                      |
| ----------------------------------------- | --------------------------------- | ------------------------------------------- |
| **SQL Injection**                         | `' OR 1=1 --`                     | Bypass login/auth, dump DB                  |
| **Command Injection**                     | `; rm -rf /`                      | Execute arbitrary system commands           |
| **LDAP Injection**                        | `_)(uid=_))(                      | (uid=*`                                     |
| **NoSQL Injection**                       | `{ "username": { "$ne": null } }` | Bypass MongoDB login                        |
| **XPath Injection**                       | `' or '1'='1`                     | Bypass XML-based auth                       |
| **HTML/Tag Injection**                    | `<marquee>Hacked</marquee>`       | Modify page rendering (stored or reflected) |
| **Server-Side Template Injection (SSTI)** | `{{7*7}}` → `49`                  | Remote code execution in template engines   |

---

## 🔍 4. **How to Detect**

|Technique|What to Look For|Tools|
|---|---|---|
|Manual Payload Testing|`'`, `"`, `--`, `;`|Burp Repeater|
|Error-Based Testing|SQL errors like `You have an error in your SQL syntax`|Observe responses|
|Boolean Testing|Try `' OR 1=1 --` vs `' AND 1=2 --`|Behavior changes|
|Time-Based Blind|`'; WAITFOR DELAY '0:0:5' --`|Observe delay|
|Fuzzing Inputs|Automate payloads|Burp Intruder, wfuzz|
|Source Code Review|Raw SQL queries with string concatenation|Look for `+` or unparameterized SQL|

---

## 🧩 5. **Subtypes with Detection, Exploitation, and Mitigation**

|No.|Subtype|Description|Detection|Exploitation|Mitigation|
|---|---|---|---|---|---|
|1|**SQL Injection**|Input modifies SQL query logic|Use `' OR '1'='1`|Bypass auth, dump DB|Use parameterized queries (`PreparedStatement`)|
|2|**Command Injection**|Input becomes part of OS command|`; whoami`|Execute arbitrary system commands|Use safe APIs, never build shell from input|
|3|**LDAP Injection**|Input modifies LDAP query|`*)(uid=*))`|Get unauthorized LDAP entries|Sanitize inputs, use LDAP escaping|
|4|**NoSQL Injection**|Injection in NoSQL queries (e.g., MongoDB)|`{ "$ne": null }`|Bypass login|Strict input typing, parameterize queries|
|5|**XPath Injection**|Bypass in XML queries|`' or '1'='1`|Read unauthorized XML nodes|Sanitize inputs, use safe APIs|
|6|**HTML Injection (Reflected/Stored)**|Inject HTML/DOM elements|`<h1>Hacked</h1>`|Deface pages, phishing|HTML encode user input|
|7|**SSTI (Template Injection)**|Exploit logic in server-side template|`{{7*7}}`|Remote code exec (in some engines)|Sandbox templates, strict delimiters|

---

## 🛡️ 6. **Mitigation (How to Prevent)**

|Strategy|Explanation|
|---|---|
|**Use Parameterized Queries**|Avoid direct string concatenation in SQL|
|**Input Validation (Whitelist)**|Accept only expected formats|
|**Escaping**|Escape special characters (SQL, XML, LDAP)|
|**Safe API Functions**|Use language-native methods (e.g., `execFile()` over `exec()`)|
|**Minimal Privileges**|DB users should have least permissions|
|**Disable Unused Interpreters**|Don’t expose shell, eval, or dynamic templating|
|**Web Application Firewall (WAF)**|Helps detect/block common injection attempts|
|**Logging + Monitoring**|Alert on error messages, anomalies|

---

## ⚠️ 7. Root Causes of Injection Vulnerabilities

|Root Cause|Example|
|---|---|
|Unsanitized Input|`" + input + "` in SQL query|
|Direct Use of Shell|`os.system('ping ' + ip)`|
|Improper Escaping|Not escaping user input before sending to backend|
|Trusting User Input|Using input in SQL/XML without checks|
|Using Dangerous Functions|`eval()`, `exec()`, etc. on user-controlled input|
|Poor DB/User Permissions|DB user has `DROP`, `DELETE`, `ALTER` access unnecessarily|

---

## 📚 8. Resources & Tools

|Tool|Purpose|
|---|---|
|**sqlmap**|Automated SQLi detection/exploitation|
|**Burp Suite**|Manual and semi-auto injection testing|
|**wfuzz/ffuf**|Fuzzing parameters for injection|
|**JWT.io**|Decode and test tokens|
|**NoSQLMap**|Test for MongoDB injection|
|**xsstrike**|XSS/injection test automation|
|**OWASP Juice Shop / DVWA / bWAPP**|Practice injection in safe environments|
|**CodeQL**|Static analysis for injection flaws in code|

---

## 🧪 9. Example Attack Scenarios

### 📌 **Scenario 1: SQL Injection in Login**

```sql
SELECT * FROM users WHERE username = '$input' AND password = '$input';
```

Input: `' OR 1=1 --`  
Result: Logs in without knowing credentials.

---

### 📌 **Scenario 2: Command Injection in IP Field**

```bash
ping -c 4 $ip
```

Input: `127.0.0.1; whoami`  
Result: Attacker executes system commands.

---

### 📌 **Scenario 3: NoSQL Injection**

```js
db.users.find({ username: req.body.username, password: req.body.password });
```

Input:

```json
{
  "username": { "$ne": null },
  "password": { "$ne": null }
}
```

Result: Bypasses authentication in MongoDB.

---

### 📌 **Scenario 4: SSTI in Flask/Jinja2**

Input:

```
{{ config.items() }}
```

Result: Leaks server-side config, potential RCE in Jinja2.

---

Would you like me to continue next with:

- 🧬 A04:2021 – **Insecure Design**,
    
- 🧪 Give labs for each injection type,
    
- 🧰 Custom recon & test script for injection vectors?
    

Let me know how you'd like to proceed — your OWASP prep is getting sharp!