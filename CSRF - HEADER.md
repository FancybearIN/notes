==CSRF tab hota hai jab server browser ke bharose pe action kar leta hai bina user intent verify kiye.==
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
- **Set-Cookie: [SameS
- 
- ite](same_site)=Strict/Lax** → cross-site request me cookie hi nahi jati
- **Set-Cookie: Secure** → cookie sirf HTTPS me jati
- **Access-Control-Allow-Origin** → unauthorized origins se request block hoti hai
- **Access-Control-Allow-Credentials** → credentials ke saath cross-site access control hota hai
- **Content-Security-Policy: form-action** → form submit sirf allowed domains pe hota hai     
- **X-Frame-Options** → clickjacking based CSRF block hota hai
## Developer side (CSRF rokne ke liye kya karna hota hai)

1. **Auth cookie pe `SameSite=Lax` ya `Strict` lagao**  
    → cross-site request me cookie hi nahi jayegi
2. **Har state-changing request me CSRF token verify karo**  
    → attacker valid token generate nahi kar sakta
3. **`Origin` header validate karo (whitelist)**  
    → request trusted site se aayi ya nahi
4. **GET request ko kabhi state-change ke liye use mat karo**  
    → GET CSRF easy hota hai
    
5. **JSON APIs me `Content-Type: application/json` enforce karo**  
    → browser CSRF form se JSON nahi bhej sakta
    
6. **`Sec-Fetch-Site = cross-site` ho to reject karo**  
    → background CSRF block hota hai