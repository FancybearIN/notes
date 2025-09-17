# High-Value Web Misconfigurations — Likely Bounty Targets (HackerOne / Bugcrowd)

  

*Purpose:* focused list of misconfiguration issues that commonly result in valid, payable bounty reports on major platforms (HackerOne, Bugcrowd). Each item includes a brief description, why it's high-value, a simple detection hint, and a suggested PoC approach.

  

> **Note:** Always confirm target scope and program rules before testing. This file focuses on issues that historically attract bounties; payout depends on impact and program policy.

  

---

  

## 1. Exposed VCS metadata (`.git/`, `.svn/`)

- **Why high-value:** Full source / secrets can be leaked, leading to critical RCE or creds leakage.

- **Detect:** `GET /.git/HEAD` or probe `.git/` paths.

- **PoC:** Fetch `.git/HEAD` and show sensitive file content or secrets found.

  

## 2. Backup/config files in webroot (`.env`, `config.php.bak`, `db_backup.sql`)

- **Why high-value:** Often contain DB credentials, API keys, tokens.

- **Detect:** Common filenames enumeration (ffuf, wordlists).

- **PoC:** Retrieve file showing secrets or connection strings.

  

## 3. S3 / cloud storage bucket exposure (public buckets)

- **Why high-value:** Bulk data exfiltration, PII, credentials.

- **Detect:** Try `bucket.s3.amazonaws.com` and bucket enumeration.

- **PoC:** List objects or download a sensitive file.

  

## 4. Subdomain takeover (dangling CNAME -> unclaimed service)

- **Why high-value:** Full site takeover; serve phishing, JS, cookies.

- **Detect:** CNAME points to non-existent service (e.g., `some.s3-website-...`).

- **PoC:** Claim the service (if allowed) or show DNS + unreachable service evidence and how takeover is possible per program rules.

  

## 5. Exposed admin / debug consoles without auth

- **Why high-value:** Immediate administrative access.

- **Detect:** Common paths (`/admin`, `/phpmyadmin`, `/actuator`).

- **PoC:** Screenshot of admin UI reachable, or actions that show admin privileges (read-only unless program allows active tests).

  

## 6. Missing or misconfigured access controls (IDOR)

- **Why high-value:** Direct access to other users' data (privacy / account takeover).

- **Detect:** Increment numeric IDs or test JWT/IDs for access to other resources.

- **PoC:** Show resource accessible by changing ID; provide request/response pair.

  

## 7. Authentication bypass via misconfig / header trust

- **Why high-value:** Account takeover / privilege escalation.

- **Detect:** Abuse `X-Forwarded-For`, `X-Auth-User`, or missing session checks.

- **PoC:** Demonstrate login bypass or access to protected endpoint by header or parameter tampering.

  

## 8. Sensitive tokens / API keys in JS or accessible endpoints

- **Why high-value:** Immediate pivot to API abuse.

- **Detect:** Scan JS files, public assets, and repos for `AKIA`, `api_key`, `secret`.

- **PoC:** Show API key usage or a sample API call that proves validity (non-destructive).

  

## 9. Unprotected object storage / backup endpoints (downloadable snapshots)

- **Why high-value:** Data theft, credential exposure.

- **Detect:** Direct download endpoints not requiring auth.

- **PoC:** Download a non-public snapshot or file.

  

## 10. Open redirect in auth flow (leading to token theft/phishing)

- **Why high-value:** Can be chained to phishing or token capture.

- **Detect:** Parameter like `redirect` accepts arbitrary URL.

- **PoC:** Redirect to a controlled domain showing redirect occurs; explain impact.

  

## 11. Excessive CORS (`Access-Control-Allow-Origin: *` with credentials)

- **Why high-value:** If combined with sensitive endpoints, can enable token theft via XSS on attacker site.

- **Detect:** Check preflight and response headers for ACAO and ACA-Credentials.

- **PoC:** Demo a crafted page that can read protected endpoint (non-destructive / conceptual PoC per policy).

  

## 12. Origin/server misconfiguration exposing internal IPs / metadata

- **Why high-value:** Useful for SSRF, lateral movement.

- **Detect:** Error pages, debug endpoints leaking internal hostnames/IPs.

- **PoC:** Show response containing internal addresses or service names.

  

## 13. Misconfigured OAuth / SAML redirect URIs

- **Why high-value:** Token theft or account takeover via auth flow manipulation.

- **Detect:** Test redirect parameters or ACS URL handling.

- **PoC:** Demonstrate redirect to attacker-controlled URL capturing code/token (only if allowed by program; otherwise show proof-of-concept flow).

  

## 14. Unrestricted file upload leading to webshell (or unsafe file handling)

- **Why high-value:** RCE or persistent compromise.

- **Detect:** Upload endpoints accepting `image/*` but not validating content.

- **PoC:** Upload a benign file that triggers server to store in webroot (non-destructive); show upload path.

  

## 15. Incorrectly protected backup endpoints or admin APIs

- **Why high-value:** Automated backup endpoints often provide wide access.

- **Detect:** Probe for `/_backup`, `/export`, `/admin/export` without auth.

- **PoC:** Access an export listing or file.

  

## 16. TLS misconfiguration exposing sensitive ciphers / weak cert chains

- **Why high-value:** Man-in-the-middle risk and compliance issues; notable for high impact programs.

- **Detect:** Use SSL Labs or `openssl s_client` to fingerprint.

- **PoC:** Report chain issues and downgrade possibilities (explain impact).

  

## 17. Broken session management (cookie flags missing / predictable session IDs)

- **Why high-value:** Session hijack / account takeover.

- **Detect:** Inspect `Set-Cookie` flags (`HttpOnly`, `Secure`, `SameSite`).

- **PoC:** Show missing flags and describe exploitation chain.

  

## 18. Publicly accessible staging or dev environments with real data

- **Why high-value:** Lower-guarded envs with production data.

- **Detect:** `staging.`, `dev.`, or `internal.` subdomains.

- **PoC:** Show access to staging UI and evidence of prod data leakage.

  

## 19. Misconfigured reverse proxy (header normalization missing)

- **Why high-value:** Enables request smuggling/host header issues and auth bypass.

- **Detect:** Test Host variations, `Host :`, duplicate headers, and Request Smuggler tools.

- **PoC:** Demonstrate parser discrepancy or header passed differently to backend.

  

## 20. Transfer-Encoding / Content-Length inconsistencies (request smuggling)

- **Why high-value:** Can lead to desync, RQP, or cache poisoning; high bounties on critical domains.

- **Detect:** CL/TE probe variants and HTTP Request Smuggler detection.

- **PoC:** Safe proof that shows discrepancy (response differences) and potential impact.

  

## 21. Exposed error stacks / verbose debug info revealing secrets

- **Why high-value:** Leak of secrets, paths, credentials.

- **Detect:** Trigger 500 errors; inspect response body.

- **PoC:** Capture stack trace showing file paths or credentials (redact sensitive parts when reporting).

  

## 22. Unprotected API keys with excessive privileges

- **Why high-value:** Full account takeover or billing abuse.

- **Detect:** Find `Authorization` tokens, API keys and test scope.

- **PoC:** Non-destructive query demonstrating privileged access (e.g., list resources).

  

## 23. Insecure direct object references on privileged endpoints

- **Why high-value:** Access to others' private resources or admin functions.

- **Detect:** Increment object IDs for admin/resource endpoints.

- **PoC:** Show access to resource of another user.

  

## 24. CSRF protections missing on sensitive state-changing endpoints

- **Why high-value:** Account takeover, unauthorized actions.

- **Detect:** Check for anti-CSRF tokens on POST/PUT/DELETE endpoints.

- **PoC:** Explain possible CSRF chain; safer to provide reproduction steps rather than destructive exploit.

  

## 25. Exposed SSO metadata or misconfigured SAML endpoints

- **Why high-value:** Identity assertions can be abused for account takeover.

- **Detect:** Request SAML metadata or probe ACS endpoints.

- **PoC:** Demonstrate missing validation of ACS/relay state handling (conceptual).

  

## 26. Open Graph/asset endpoints leaking secrets (tokens in URLs)

- **Why high-value:** Tokens in URLs are logged/shared; can be abused.

- **Detect:** Check asset links in HTML/JS for query-string tokens.

- **PoC:** Show URL containing token and ability to access resource.

  

## 27. Weak brute-force protections on auth/OTP/resend endpoints

- **Why high-value:** Account compromise via credential stuffing.

- **Detect:** Try rapid logins and test rate limits (respect program rules).

- **PoC:** Show lack of lockout or exponential backoff.

  

## 28. Unsafely trusting client-sent `X-Forwarded-*` headers

- **Why high-value:** IP spoofing, auth bypass, or privilege escalation.

- **Detect:** Send forged X-Forwarded-For and observe behavior.

- **PoC:** Show access change or logging reflecting spoofed IP.

  

## 29. Misconfigured Caching/Cache-Control on private pages

- **Why high-value:** Sensitive page cached in CDN or shared cache.

- **Detect:** Access protected page, check caching headers and cached copies.

- **PoC:** Show private content served from cache or exposed via cache key.

  

## 30. Sensitive files exposed via predictable paths (logs, db dumps)

- **Why high-value:** Direct access to sensitive data.

- **Detect:** Enumerate common filenames and directories.

- **PoC:** Retrieve a sample (non-destructive) confirming exposure.

  

---

  

## Quick triage & reporting tips

- Include exact raw request/response pairs (hexdump) in your report.  

- Demonstrate impact without exfiltrating real user data (redact where necessary).  

- Explain remediation: remove files, require auth, enable header normalization, rotate keys.  

- Prioritize reproducibility and minimal noise.

  

---

  

**Good hunting.** Drop this file into your notes and use it as your bounty checklist for HackerOne / Bugcrowd targets.