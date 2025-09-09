# 🛠 Bug Bounty Functional Mapping Template

## 🎯 Program Overview

- **Program Name:**
    
- **Scope (domains, apps, APIs):**
    
- **Payout Range:**
    
- **Notes on Scope Rules:**
    

---

## 🌐 Assets

- **Web:**
    
- **API:**
    
- **Mobile:**
    
- **Third-Party Integrations:**
    

---

## 🔍 Recon & Discovery

- **Subdomains (alive):**
    
- **Directories/Endpoints:**
    
- **JS Files (notes/secrets):**
    
- **IP ranges / ASN:**
    
- **Interesting Headers / Tech Stack:**
    

---

## 🧩 Functionality Map

### 1. Authentication & Session

- Login:
    
- Signup:
    
- 2FA:
    
- Password reset:
    
- OAuth/SSO:
    

**Bug Classes to Test:**

- Weak session handling, token reuse, bypass flows, OAuth misconfig, password reset abuse.
    

---

### 2. User Profile & Settings

- Update info:
    
- Avatar upload:
    
- Preferences:
    

**Bug Classes:**

- IDOR, file upload bypass, stored XSS, CSRF.
    

---

### 3. Payments & Billing

- Checkout:
    
- Coupons/Discounts:
    
- Refunds:
    
- Subscription tiers:
    

**Bug Classes:**

- Race conditions, logic abuse, negative payment, privilege escalation.
    

---

### 4. Messaging / Notifications

- Direct messages:
    
- Group chat:
    
- Email/SMS triggers:
    

**Bug Classes:**

- IDOR in message access, XSS in messages, notification spoofing, SSRF via webhook integrations.
    

---

### 5. Search / Data Filtering

- Global search:
    
- Filters:
    
- Sorting:
    

**Bug Classes:**

- SQLi, Elasticsearch abuse, injection in filters, info leaks.
    

---

### 6. File Uploads / Media

- Allowed file types:
    
- Storage location:
    
- Previews:
    

**Bug Classes:**

- MIME confusion, XSS in preview, S3 bucket misconfig, LFI/RFI tricks.
    

---

### 7. Admin / Moderator

- Admin panel:
    
- Role management:
    
- Content moderation:
    

**Bug Classes:**

- Privilege escalation, IDOR, hidden endpoints, bypass of RBAC.
    

---

### 8. APIs

- REST:
    
- GraphQL:
    
- Mobile APIs:
    

**Bug Classes:**

- Mass assignment, auth bypass, hidden methods, rate-limit issues, GraphQL introspection.
    

---

### 9. Third-Party Integrations

- OAuth providers:
    
- Webhooks:
    
- External tools (Slack, GitHub, analytics):
    

**Bug Classes:**

- Token leakage, webhook SSRF, trust boundary bypass.
    

---

## 📋 Exploit Mapping (Per Feature)

```
Functionality: Password Reset
Asset: https://target.com/reset
Attack Surface:
  - /reset-password
  - POST /api/v1/reset
Bug Classes:
  - Token predictability
  - Replay attacks
  - Rate-limit bypass
Findings:
  - 2025-09-09 → Token can be reused once (P3)
Next Steps:
  - Automate brute-force w/ Burp Intruder
```

---

## 🏆 Findings Tracker

|Date|Asset|Functionality|Vulnerability|Severity|Status (reported/fixed)|Bounty $|
|---|---|---|---|---|---|---|
|2025-09-09|api.target|Password reset|Token reuse|High|Reported|$1200|

---

## 🧠 Notes & Weird Observations

- Unexpected responses, verbose error messages, weird HTTP codes.
    
- Any logic that feels “off” → revisit later.
    
