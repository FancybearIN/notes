# Duplicate Registration (Twinning) Vulnerability Notes

  

## Overview

Duplicate Registration, also called **Twinning**, occurs when an application allows a user to register multiple accounts using the same identifier (email, phone number, username) through inconsistencies in validation, normalization, or backend checks.  

This can be exploited for **account takeover, privilege escalation, or bypassing business logic**.

  

---

  

## Why It Happens

1. **Improper Normalization**: Application fails to normalize identifiers (e.g., case sensitivity, dots in Gmail, Unicode homographs).

2. **Weak Uniqueness Enforcement**: Backend only checks some identifiers (e.g., email but not phone, or vice versa).

3. **Race Conditions**: Two registrations at the same time bypass uniqueness checks.

4. **Third-Party Auth Inconsistencies**: Different handling between OAuth/SSO and native registration.

5. **Multiple Identifier Fields**: Email, phone, and username being partially validated allow overlaps.

  

---

  

## Test Cases

  

### Email-based

- Register with `test@example.com` and again with `Test@example.com` (case-insensitive bypass).

- Gmail trick: `test@gmail.com` vs `te.st@gmail.com` vs `test+1@gmail.com`.

- IDN homograph: `test@exаmple.com` (Cyrillic `а` instead of Latin `a`).

  

### Phone-based

- `+91 9876543210` vs `9876543210` vs `00919876543210`.

- Different formats with dashes/spaces: `987-654-3210`, `(987)6543210`.

- Leading zeros stripped inconsistently.

  

### Username-based

- `user`, `User`, `uSer`.

- Unicode tricks: `uѕer` (Cyrillic `ѕ`) vs `user`.

  

### OAuth / SSO

- Register via Google/Facebook with `test@example.com`, then via native flow with the same email.

- Check if the system links accounts or creates separate ones.

  

### Race Condition

- Send two registration requests for the same email simultaneously (Burp Turbo Intruder / custom script).

  

---

  

## Impacts

- **Account Takeover**: Hijacking accounts by re-registering identifiers.

- **Privilege Escalation**: Registering with admin emails (e.g., `admin@company.com`) if not verified.

- **Business Logic Abuse**: Multiple trial accounts with the same email/phone.

- **Data Leakage**: Access to another user’s PII (due to linked identifiers).

- **SSO Confusion Attacks**: Mismatched accounts created via OAuth.

  

---

  

## Escalation Paths

- **From Duplicate Account to ATO**: Register as victim’s email → takeover confirmation link.

- **Privilege Escalation**: Register admin email → reset password flow gives control.

- **Chaining With DSAR**: Request victim data under duplicate account → exfiltrate PII.

- **Fraud/Bypass**: Abuse trial credits, referral bonuses, or coupons with “twin” accounts.

  

---

  

## Technologies & Areas to Look

- **Identity providers**: OAuth, SAML, OpenID.

- **Email verification systems**: Check normalization & enforcement.

- **Phone verification APIs**: Twilio, Nexmo – often inconsistent formatting.

- **Web frameworks**: Django, Laravel, Spring – misconfig in `unique=true` enforcement.

- **Race-prone apps**: PHP/MySQL with delayed `INSERT ... UNIQUE` handling.

  

---

  

## Practical Exploitation Tips

- Always test case sensitivity and formatting differences.

- Check for different flows (OAuth vs Native, API vs Web).

- Automate registration with variations (`+`, `.`, casing, Unicode).

- Try simultaneous registration to trigger race conditions.

- Inspect reset-password & DSAR endpoints for potential chaining.

  

---

  

## References

- [Shahjerry - Duplicate Registration Writeup](https://shahjerry33.medium.com/duplicate-registration-the-twinning-twins-883dfee59eaf)

- [PortSwigger Research: Account Takeover](https://portswigger.net)

- Bug Bounty Writeups: Real cases of Twinning exploitation.

  

---