# **Improper Session Management**

📌 **Scenario**  
Apps create sessions using access tokens, refresh tokens, cookies, or device-bound session identifiers. Improper session management occurs when these artifacts are not expired, not invalidated on logout, stored insecurely, or lack proper server-side checks (replay protection, device binding, rotation). Result: an attacker who extracts the token (from storage, cache, backups, logs, or clipboard) can continue to use it long after the user logs out—leading to account takeover, persistent data access, or privileged actions.

---

### **Detection**

1. **Static analysis**
    
    - Search code for session storage and lifecycle patterns:
        
        ```bash
        grep -R -n -E "putString\\(|putLong\\(|setCookie|CookieManager|SharedPreferences|getSharedPreferences|refresh_token|access_token|session" .
        ```
        
    - Look for missing logout flows or `clear()` calls: `prefs.edit().remove("token")` / `deleteDatabase()` / `EncryptedSharedPreferences` usage.
        
    - Check for code that treats logout purely as UI change (navigating to login screen) without server-side revoke calls.
        
2. **Dynamic analysis**
    
    - Login with test user; capture access & refresh tokens during auth (intercept or Frida).
        
    - Logout from app UI; do **not** delete captured token.
        
    - Attempt to reuse token (API with `Authorization` header) after logout:
        
        ```bash
        curl -H "Authorization: Bearer <token>" "https://api.target/user/me"
        ```
        
        - If token still valid → improper session invalidation.
            
    - Check refresh behavior:
        
        - Use refresh token to mint new access token after logout. If refresh still works → refresh tokens not revoked.
            
3. **Storage inspection**
    
    - Inspect SharedPreferences, DBs, files and backups to see where tokens persist post-logout:
        
        ```bash
        adb shell run-as com.example.app cat /data/data/com.example.app/shared_prefs/app_prefs.xml
        ```
        
    - Verify cookies in WebView/CookieManager remain after logout.
        
4. **Server-side behavior**
    
    - Observe token TTLs and revocation endpoints.
        
    - Test concurrent sessions: login on two devices, logout one, check whether session on other device invalidates.
        
5. **Runtime hooking**
    
    - Hook token-write calls to log where tokens are stored and whether delete calls happen on logout (stack traces help map omission).
        

---

### **Exploitation**

- **Token replay**
    
    - Use extracted access token to call APIs after victim logged out; if token is still valid, attacker retains access.
        
- **Refresh token abuse**
    
    - If refresh tokens are long-lived and not revoked on logout, attacker can mint fresh access tokens repeatedly.
        
- **Cookie reuse**
    
    - Extracted cookies reused in WebView or API clients bypass re-authentication.
        
- **Multi-device persistence**
    
    - If server lacks device binding, attacker with token can act from any device/location.
        
- **Privilege escalation via stale tokens**
    
    - Tokens issued with broad scopes/privileges remain usable; attacker can perform sensitive operations.
        
- **Persistence through backups/logs**
    
    - Tokens stored in backups or logs survive logout; attacker can extract them later.
        

Attacker vectors: local storage theft, backups, leaked logs, clipboard, malicious SDKs, device compromise.

---

### **Test cases / Practical checklist**

- Authenticate → capture tokens (access + refresh).
    
- Logout via UI → immediately:
    
    - Attempt API calls with access token.
        
    - Attempt refresh flow to mint new access token.
        
    - Inspect device storage for token remnants.
        
- Test server revocation:
    
    - Call logout endpoint, then check sessions list (if API exposes it) or call `GET /sessions`.
        
- Test token expiry:
    
    - Determine TTL by issuing token and calling until it expires (or inspect `exp` in JWT).
        
- Test device-binding:
    
    - Use stolen token from different IP/device — observe server checks (IP/device restrictions).
        
- Edge cases:
    
    - Test token reuse after password change or account disable (should invalidate tokens).
        
    - Test concurrent logout: logout one session and check others.
        

---

### **Detection signatures (grep / regex examples)**

```bash
# find likely token storage and logout functions
grep -R -nE "access[_-]?token|refresh[_-]?token|Authorization|logout|revoke|invalidate|clear\\(|remove\\(" .

# JWT pattern (to detect tokens in dumps/logs)
grep -oE "([A-Za-z0-9_-]+\.){2}[A-Za-z0-9_-]+" device-dump.txt

# Look for missing revoke calls (heuristic)
grep -R -n "logout" . | xargs -I{} sed -n '1,120p' {}
```

---

### **Real Bug Bounty Examples (what pays & why)**

- **Refresh tokens remain valid after logout** → High/Critical (persistent takeover).
    
- **Access tokens valid until long TTL despite logout** → High (session replay).
    
- **Tokens not invalidated after password change** → High (failure to rotate/blacklist).
    
- **Multiple active sessions without user-visible control or server-side session listing** → Medium–High (user cannot detect compromise).
    

Payouts reflect attacker effort vs blast radius: persistent tokens enabling full account access are high-impact.

---

### **Mitigation**

1. **Server-side session revocation**
    
    - On logout, call server revoke endpoint to invalidate refresh/access tokens (add token to revocation blacklist).
        
    - Implement centralized session store (`session_id`) server-side and mark sessions invalid on logout.
        
2. **Short TTLs + rotation**
    
    - Use short-lived access tokens and rotating refresh tokens; ensure refresh tokens rotate on use and old refresh tokens are invalidated.
        
3. **Bind tokens to device/context**
    
    - Tie tokens to device identifiers or per-device session IDs and validate on every request (with care for privacy).
        
    - Consider proof-of-possession tokens (mutual TLS or signed client assertions) for high-risk flows.
        
4. **Revoke on sensitive events**
    
    - Revoke tokens on password change, account recovery, suspicious activity, or when user explicitly requests session termination.
        
5. **Secure storage & deletion**
    
    - Store tokens securely (Keystore-wrapped, `EncryptedSharedPreferences`) and ensure logout clears persisted tokens reliably:
        
        ```java
        prefs.edit().remove("access_token").remove("refresh_token").apply();
        ```
        
    - Clear WebView cookies: `CookieManager.getInstance().removeAllCookies(null)`.
        
6. **Implement server-side session listings**
    
    - Allow users to view active sessions and remotely revoke them.
        
7. **Defensive logging & monitoring**
    
    - Monitor token reuse patterns, simultaneous use from different geolocations, and unusual refresh patterns — trigger revocation or MFA.
        
8. **Invalidate tokens after logout even if client fails**
    
    - Make logout a server-driven action: if client calls logout, server treats token as revoked regardless of client clearance.
        
9. **Graceful handling for offline clients**
    
    - For offline logouts, ensure server-side revocation occurs next time backend receives a logout signal (or provide push revocation).
        
10. **Avoid storing long-lived credentials**
    
    - Prefer ephemeral tokens; if refresh tokens are required, treat them as high-value secrets (encrypt, short TTL, rotate).
        
11. **Secure backup & logging**
    
    - Ensure backups & logs do not contain tokens; redact tokens in logs and exclude sensitive paths from backups.
        

---

### **Escalation paths & impact reasoning**

- **Persistent account takeover** — non-expiring/long-lived tokens allow long-term impersonation.
    
- **Lateral movement** — tokens with cross-service scopes enable broader compromise.
    
- **Silent persistence** — attacker maintains access even after user attempts remediation (logout), complicating detection.
    
- **Regulatory and financial damage** — if tokens enable transactions or expose PII.
    

Severity increases with token lifetime, scope, whether refresh tokens are abused, and lack of server-side revocation.

---

### **Exploitation notes & POC ideas (concise)**

- **POC A — Access token reuse after logout**
    
    1. Capture access token (intercept auth).
        
    2. Logout in-app.
        
    3. Immediately call protected endpoint with the captured token. If successful, document endpoint and returned data (redacted).
        
- **POC B — Refresh after logout**
    
    1. Capture refresh token.
        
    2. Logout in-app.
        
    3. Attempt refresh flow to obtain new access token. If successful, demonstrate access using new token.
        
- **POC C — Persistence after password change**
    
    1. Capture token.
        
    2. Change account password.
        
    3. Use token to access APIs — if still valid, shows tokens not rotated/revoked on credential change.
        
- **POC D — Cross-device reuse**
    
    1. Obtain token from device A.
        
    2. Use from device B / different IP. If server doesn't check device binding, access succeeds — demonstrate session hijack.
        

Always redact tokens in shared evidence; provide minimal repro steps required for triage.

---

✅ **Summary**

- Improper session management (no revocation, long TTLs, insecure storage, no device binding) gives attackers small secrets that open big doors.
    
- Hunt by capturing tokens, logging out, and attempting reuse/refresh; check storage/backups and server-side revocation behavior.
    
- Fix by revoking sessions server-side on logout, using short TTLs with rotating refresh tokens, binding tokens to context, encrypting stored tokens, and giving users session visibility & control.
    

Session artifacts are tiny keys — treat them like crown jewels.