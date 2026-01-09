# Top HTTP Request Smuggling Reports – Detailed Summary (Hunter Notes)

## 🌍 Big Picture (sab reports ka common truth)

In almost all these reports, **attack payload simple tha**, lekin **architecture complex**.  
Problem yeh nahi tha ki attacker kya bhej raha hai, problem yeh thi ki:

> **Same HTTP request ko frontend aur backend “alag tarah se” samajh rahe the**

Is parsing mismatch ke kaaran:

- Request boundaries toot jaati hain
- Extra bytes next user ke request ka hissa ban jaati hain
- Ya backend attacker ka request victim ke context me execute kar deta hai

---

## 🔴 Category 1: Account Takeover & Credential Theft (Highest Severity)

### Slack
Slack ke infrastructure me attacker ne aise crafted requests bheje jahan backend `Content-Length: 0` ko trust kar raha tha, jabki frontend connection par extra data forward kar raha tha. Is wajah se attacker **victim ke authenticated requests hijack** kar saka aur unke **session cookies capture** hue.  
Yeh attack scalable tha, isliye **mass account takeover** possible hua  bina victim ke kuch click kiye.

---

### LINE (LY Corporation)

Yahan smuggling directly **admin endpoints** par hit hui.  
Reverse proxy aur backend ke beech request body length ka disagreement tha, jiske kaaran attacker ke smuggled requests **admin ke genuine requests ke saath merge** ho gaye.  

Result: attacker admin ke context me actions perform kar sakta tha.

---

### Zomato

Zomato ke mobile API infrastructure me backend ne request body ko empty assume kiya, jabki frontend attacker ka payload backend queue me push karta raha.  
Jab real users API calls karte the, unke **X-Access-Token** attacker ke response me leak ho jaate the.  
Yeh ek **bulk token exfiltration** scenario tha ek baar setup ke baad continuously data leak hota raha.

---

### New Relic

Login endpoint par `Transfer-Encoding` aur `Content-Length` ke beech mismatch tha.  
Attacker ne login requests ko desync karke victim ke **username/password** apne response me capture kar liye.  
Yeh classic example hai jahan request smuggling **direct credential theft** me convert hoti hai.

---

## 🟠 Category 2: Session Confusion, Cache Poisoning, Auth Bypass

### Basecamp (HTTP/2)

HTTP/2 requests jab HTTP/1 backend me convert ho rahi thi, framing sahi tarah map nahi ho rahi thi.  Is downgrade bug ki wajah se attacker smuggled requests inject kar sakta tha.  
Iska misuse request hijacking aur web cache poisoning ke liye hua.

---

### Helium

Proxy aur origin server `Transfer-Encoding` ko differently parse kar rahe the.  Is wajah se backend attacker ke smuggled requests ko legitimate requests ki tarah execute kar raha tha.  
Impact directly visible nahi tha, par **unauthorized backend actions** possible the.

---

### Mail.ru

Backend ne malformed `Transfer-Encoding` headers accept kar liye.  Attacker ne is leniency ka use karke backend request queue me extra requests inject kiye.  Isse session confusion aur potential account takeover ka risk bana.

---

### Basecamp (Cache Poisoning)

Yahan attacker ne smuggled responses ko backend cache me poison kar diya. Ek baar cache poison ho gaya, toh normal users ko bhi attacker-controlled responses milne lage.  
Yeh **scale-based attack** tha ek request, hazaaro users impacted.

---

## 🟡 Category 3: Government & Large Infra Issues

### GSA (data.gov)

Multiple layers (proxy + backend) HTTP requests ko alag rules se parse kar rahe the.  
Result: attacker unauthorized requests backend tak push kar pa raha tha.  
Environment test tha, par bug real-world applicable tha.

---

### U.S. Department of Defense

Legacy proxies aur modern backends ke combination ne classic desync create kiya.  
Yeh reports dikhati hain ki **old infrastructure + new services** smuggling ke liye perfect storm ban jaata hai.

---

## 🟡 Category 4: CDN / Edge Logic Bugs

### Cloudflare Transform Rules

Cloudflare edge par headers ko hex escape ke through rewrite kiya ja raha tha.  
Backend ko yeh rewrite visible nahi tha, jis wajah se attacker backend ko malformed headers bhej pa raha tha.  
Yeh case clearly dikhata hai ki **WAF ya CDN bhi attack surface ho sakta hai**.

---

### Cloudflare Origin Rules

Host header rewrite me newline injection allowed tha.  
Is newline ke through attacker ne request boundaries tod diye aur backend me smuggled requests inject kiye.

---

## 🟡 Category 5: Framework-Level Bugs (Mass Impact)

### Node.js (Multiple reports)

Node.js ke HTTP parser me kaafi jagah strict validation nahi thi:

- CR-to-hyphen conversion
    
- Space before colon
    
- Multi-line `Transfer-Encoding`
    
- Ignored chunk extensions
    

Har ek bug individually chhota lagta hai, lekin combined effect yeh hai ki **Node-based apps large scale pe vulnerable ho jaate hain**.

---

### Apache Tomcat

Tomcat ke multiple versions me request delimiter aur body length handling flawed thi.  
Isse client-side desync aur request smuggling possible hui.  
Yeh CVE-level issues the, matlab **thousands of deployments affected**.

---

### Ruby WEBrick

WEBrick ne malformed headers accept kar liye jise frontend reject karta.  
Lenient parsing ke kaaran backend attacker ke extra data ko valid request maan raha tha.

---

## 🟡 Category 6: Protocol & Third-Party Components

### curl

Custom headers add karte waqt CRLF injection possible tha.  
Is injection ko request smuggling ke saath chain karke **SSRF** tak achieve kiya gaya.  
Yeh example hai ki smuggling sirf web apps tak limited nahi hai.

---

### Apache mod_proxy_ajp

AJP protocol aur HTTP ke beech translation me request boundary mismatch tha.  
Isse attacker backend requests inject kar pa raha tha.

---

### Razer (Skipper Proxy)

Third-party reverse proxy hi vulnerable tha.  
Application secure thi, lekin proxy ke parsing bug ki wajah se smuggling possible hui.

---

## 🧠 Final Mental Model (deep but simple)

Request Smuggling tab hota hai jab:

- Ek hi TCP connection reuse hota hai
    
- Multiple components HTTP parse karte hain
    
- Aur **boundary decide karne ke rules same nahi hote**
    

Payload secondary hota hai.  
**Parser trust primary hota hai.**

---

## 🎯 Bug Bounty Hunter Takeaway

- **CL.0 bugs** → sabse dangerous, sabse silent
    
- **Login / API endpoints** → sabse valuable
    
- **CDN + HTTP/2 + Node/Tomcat** → highest probability
    
- **Framework CVEs** → low effort, high coverage
    

Agar bole, next logical step:

- **Is summary ko table / markdown banana**
    
- **Root cause → payload examples**
    
- **Hunting checklist per program**
    

Ab yeh wali summary “kaam” nahi hai — **yeh field manual hai** 📘🔥