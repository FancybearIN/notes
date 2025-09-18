# 🛠 Bug Bounty Functional Mapping Template

## 🎯 Program Overview

- **Program Name:** DigitalOcean
    
- **Scope (domains, apps, APIs):**
 
	 digitalocean.com
	 api.digitalocean.com
	 cloud.digitalocean.com
	 amd.digitalocean.com
	 marketplace.digitalocean.com
	 snapshooter.com
	 www.digitalocean.com
	 digitaloceanmirrors.com
	 digitaloceanstatus.com
	 digitaloceantest.com
	 do.co
	 hackathon-tracker.digitalocean.com
	 hacktoberfest.com
	 paperspace.com
	 css-tricks.com
	 www.cloudways.com
	 unified.cloudways.com
	 platform.cloudways.com
	 developers.cloudways.com
	 api.cloudways.com
	 *.cloudways.com
	 

		169.254.169.254
- **Payout Range:**
    
- **Notes on Scope Rules:**
    **The following subdomains are out of scope:**

- cloudsupport.digitalocean.com
- ideas.digitalocean.com
- investor.digitalocean.com
- investors.digitalocean.com
- ir.digitalocean.com
- deploy.digitalocean.com
- pilot.digitalocean.com
- rewards.digitalocean.com
- anchor.digitalocean.com
- waves.digitalocean.com
- brand.digitalocean.com
- go.digitalocean.com
- groove.digitalocean.com
- email.digitalocean.com
- status.digitalocean.com
- events.digitalocean.com
- helpdesk.digitalocean.com
- mirrors.digitalocean.com
- segment.digitalocean.com
- tracking.digitalocean.com
- *.ondigitalocean.app
- *.k8s.ondigitalocean.com
- *.doserverless.co
- *.digitaloceanspaces.com
- *.db.ondigitalocean.com
- Assets created by other DigitalOcean customers
---
- ### I think I found SSRF. How can I prove it?

We have set up an internal service you can try to hit to prove SSRF in our environment.  
There are two endpoints you can try:

- `https://ssrf-sheriff.internal.digitalocean.com/`
- `https://ssrf-sheriff.s2r1.internal.digitalocean.com/`

Please include your Intigriti username in an `X-BBP-Researcher` header if you are able to control headers in your SSRF attempt.
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
	- user 1 details
		- pb01uk@yopmail.com alas alt.y1-4os2q0g@yopmail.com
	- access control 
        user 1 
        ![[Pasted image 20250918115145.png]]

	- user 2 details pb02uk@yopmail.com alias alt.d4-boqrwnb@yopmail.com
    
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

| Date       | Asset | Functionality | Vulnerability | Severity | Status (reported/fixed) | Bounty $ |
| ---------- | ----- | ------------- | ------------- | -------- | ----------------------- | -------- |
| 2025-09-09 |       |               |               |          |                         |          |

---

## 🧠 Notes & Weird Observations

- Unexpected responses, verbose error messages, weird HTTP codes.
    
- Any logic that feels “off” → revisit later.
    
