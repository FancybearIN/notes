## 1️⃣ **CSRF ke liye REQUIRED headers (kyon attack possible hota hai)**

- **Cookie** → browser automatically session cookie bhej deta hai, attacker ko access nahi chahiye hota
- **Authorization** → bearer/basic token auto-sent ya reused ho jata hai
- **Content-Type** → simple types (`application/x-www-form-urlencoded`) CSRF allow kar dete hain
- **Host** → same target host hone se browser request allow karta hai.

---
## 2️⃣ **CSRF ke liye RESPONSIBLE / CHECKED headers (kyon validation hoti hai)**

- **Origin** → request kis domain se aayi verify karne ke liye
- **Referer** → previous page ka source check karne ke liye
- **Sec-Fetch-Site** → same-site vs cross-site distinguish karne ke liye
- **Sec-Fetch-Mode** → navigation ya fetch type identify karne ke liye
- **Sec-Fetch-User** → user-initiated request confirm karne ke liye
---

## 3️⃣ **CSRF MITIGATION headers (kyon attack block hota hai)**

- **X-CSRF-Token / X-XSRF-Token** → attacker token guess ya read nahi kar sakta
- **Set-Cookie: SameSite=Strict/Lax** → cross-site request me cookie hi nahi jati
- **Set-Cookie: Secure** → cookie sirf HTTPS me jati
- **Access-Control-Allow-Origin** → unauthorized origins se request block hoti hai
- **Access-Control-Allow-Credentials** → credentials ke saath cross-site access control hota hai
- **Content-Security-Policy: form-action** → form submit sirf allowed domains pe hota hai
- **X-Frame-Options** → clickjacking based CSRF block hota hai