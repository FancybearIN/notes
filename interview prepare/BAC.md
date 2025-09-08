## **Definition (What it is)**

**Access Control** ensures users can only **perform actions and access data** they're authorized for.

> **Broken Access Control** occurs when users can act **outside their assigned permissions**—view, edit, delete, or create resources without proper validation.

## **Exploitation Techniques (How to Exploit)**

| Technique                       | Example                                            |
| ------------------------------- | -------------------------------------------------- |
| 🔢 IDOR                         | Modify `user_id` to access others’ accounts        |
| 🌐 Forced Browsing              | Access `/admin` directly                           |
| ⬆️ Privilege Escalation         | Change role from user → admin in cookie or request |
| 🔄 Method Tampering             | Change `POST` to `DELETE`                          |
| 🛠️ Token/Metadata Manipulation | Modify JWT, cookies, hidden form fields            |
| 🌍 CORS Misconfig               | Access APIs from unauthorized origins              |
| 🚪 Unauthenticated Access       | Visit authenticated/privileged pages without login |

## Exploitation Types in Broken Access Control (BAC)

|No.|Exploitation Type|Description|Detection Method|Example Exploit|Mitigation|
|---|---|---|---|---|---|
|1|**IDOR** (Insecure Direct Object Reference)|Directly referencing internal objects (like user IDs) without proper checks|Change `user_id` or `file_id` in API/URL|`GET /user/102` (not your ID)|Verify ownership on backend, use UUIDs|
|2|**Forced Browsing**|Accessing pages or functions by navigating directly (bypassing UI)|Try accessing `/admin`, `/internal` URLs|Visit `https://site.com/admin/report` without auth|Use deny-by-default access rules, restrict URLs|
|3|**Vertical Privilege Escalation**|Gaining access to higher-level (admin) functions as a normal user|Modify role in cookie/session/JWT|Change `role=user` to `role=admin` and call admin API|Enforce RBAC on the server side|
|4|**Horizontal Privilege Escalation**|Accessing other users' data at same privilege level|Change another user’s ID in the request|Normal user accesses `GET /orders/124` (someone else's)|Enforce per-record ownership checks|
|5|**Method-Based Access Control Bypass**|Access control enforced only for specific HTTP methods (GET/POST), but not others|Try HTTP verbs: PUT, DELETE, PATCH|Send `DELETE /user/3` instead of `GET`|Validate actions regardless of HTTP method|
|6|**Missing Function-Level Access Control**|Backend doesn’t check user’s permission to access critical functions|Manually call sensitive endpoints|User calls `/admin/deleteUser?id=4` directly|Check permissions at every function/API level|
|7|**Client-Side Access Control Only**|Access control enforced only by frontend (disabling buttons, hiding forms)|Inspect frontend code or modify DOM|Enable "delete" button via DevTools and send request|Server-side validation for every action|
|8|**Token or Metadata Manipulation**|Tampering with JWTs, cookies, or hidden form fields to elevate access|Decode JWT, edit claims like `admin: true`|Modify token to set `isAdmin=true` and reuse|Use signed, short-lived tokens and validate every field|
|9|**CORS Misconfiguration Abuse**|Improper CORS allows unauthorized cross-origin access to APIs|Test `Access-Control-Allow-Origin` using curl or Burp|Attacker's site sends malicious JS to access `api.site.com`|Strictly whitelist allowed origins; avoid `*`|
### Quick Difference Between **Vertical** and **Horizontal Privilege Escalation**

|Type|Meaning|Real-Life Example|
|---|---|---|
|**Vertical**|Low-priv user becomes high-priv user (e.g., admin)|Normal user changes role or calls admin API|
|**Horizontal**|User accesses **peer** user’s data/function|User A accesses User B’s profile or documents|
### Tools to Simulate/Detect These Exploits:

- **Burp Suite** – Repeater, Autorize plugin
## Why is it called **"Insecure Direct Object Reference" (IDOR)?**

### 🔑 Breakdown of the term:

|Term|Meaning|
|---|---|
|**Insecure**|Because the access control is weak or missing.|
|**Direct**|The application exposes **actual internal identifiers** (like user IDs, file names, database keys).|
|**Object**|Refers to **a resource or entity** in the system — like a file, user record, invoice, or order.|
|**Reference**|The app uses a **direct reference (like `user_id=123`)** to locate the object.|