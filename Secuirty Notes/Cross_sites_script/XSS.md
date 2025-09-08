Perfect timing ⚡ — you’re asking for the **DOM XSS Source & Sink master list**. This is exactly what professional pentesters and bug bounty hunters rely on. I’ll give you a **complete, categorized list** (not missing anything important), including **sources → sinks** mapping.

---

# 🔹 1. Sources (User-controlled data entry points)

These are DOM properties or objects that can carry attacker-controlled input into the application.

### **Location-based sources**

- `location`
    
- `location.href`
    
- `location.search`
    
- `location.hash`
    
- `location.pathname`
    
- `document.URL`
    
- `document.documentURI`
    
- `document.baseURI`
    

### **Referrer & opener**

- `document.referrer`
    
- `window.name`
    
- `opener.location`
    

### **Storage**

- `localStorage`
    
- `sessionStorage`
    
- `IndexedDB` (rare but possible)
    

### **Messaging APIs**

- `postMessage()` (data in `event.data`)
    
- `BroadcastChannel` messages
    
- `SharedWorker` / `ServiceWorker` messages
    

### **Cookies**

- `document.cookie`
    

### **User Input**

- `document.forms[...]`
    
- `input.value`
    
- `textarea.value`
    
- Drag-and-drop data
    
- Clipboard API (`navigator.clipboard.readText()`)
    

---

# 🔹 2. Sinks (Dangerous execution or HTML insertion points)

### **JavaScript execution sinks (direct code execution)**

- `eval()`
    
- `Function()`
    
- `setTimeout(string, ...)`
    
- `setInterval(string, ...)`
    
- `execScript()` (IE only)
    
- `script.src = "javascript:..."`
    

### **HTML injection sinks**

- `document.write()`
    
- `document.writeln()`
    
- `element.innerHTML`
    
- `element.outerHTML`
    
- `element.insertAdjacentHTML()`
    
- `element.innerText` / `outerText` (sometimes dangerous if parsed)
    
- `iframe.srcdoc`
    

### **URL-based execution sinks**

- Assigning user input to attributes that accept URLs:
    
    - `location = ...`
        
    - `location.href = ...`
        
    - `<a href=...>`
        
    - `<iframe src=...>`
        
    - `<script src=...>`
        
    - `<link href=...>`
        
    - `<img src=...>`
        
    - `<embed src=...>`
        
    - `<object data=...>`
        
    - `<form action=...>`
        
- If attacker injects `javascript:` scheme → XSS
    

### **Event handler attributes**

- `element.setAttribute("onclick", input)`
    
- Inline attributes like `onerror`, `onload`, `onmouseover`, etc.
    

### **Other lesser-known sinks**

- `document.domain` (rare chaining vector)
    
- `document.location.replace()`
    
- `window.open(input)`
    
- `window.execScript(input)` (legacy IE)
    
- `MSApp.execUnsafeLocalFunction(input)` (MS Edge/IE legacy)
    

---

# 🔹 3. Source → Sink Example Chains

Here’s how they usually appear in vulnerable code:

```js
// Example 1: Simple location to eval
var data = location.hash.substring(1); 
eval(data);

// Example 2: Referrer to innerHTML
document.getElementById("box").innerHTML = document.referrer;

// Example 3: postMessage to setTimeout
window.addEventListener("message", function(e) {
    setTimeout(e.data, 1000);
});
```

---

# 🔹 4. Quick Cheatsheet Table

|**Source** (Attacker input)|**Dangerous Sink** (Execution)|**Payload Example**|
|---|---|---|
|`location.hash`|`innerHTML`|`#<img src=x onerror=alert(1)>`|
|`document.URL`|`document.write`|`?q=<svg onload=alert(1)>`|
|`document.referrer`|`setTimeout()`|`javascript:alert(1)`|
|`window.name`|`eval()`|`window.name=alert(1)`|
|`postMessage().data`|`Function()`|`parent.postMessage("alert(1)", "*")`|
|`localStorage.item`|`insertAdjacentHTML()`|`<img src=x onerror=alert(1)>`|

---

# 🔹 5. Golden Rules for Testing

1. Always map **sources** → **sinks** with DevTools search (`Ctrl+Shift+F` → search `location`, `referrer`, etc).
    
2. Track variables (input may be reassigned before hitting sink).
    
3. If inside HTML context → use tag/event payloads (`<img onerror=...>`).
    
4. If inside JS execution sink → supply raw JS (`alert(1)`).
    
5. If inside URL context → try `javascript:alert(1)` or data URIs.
    

---

✅ This list covers **all major DOM XSS sources and sinks** used in real-world bug bounty and CTFs.

Do you want me to also give you a **ready-to-use Burp Suite DOM XSS hunt regex** (to grep for these sources/sinks automatically when auditing JavaScript files)?

Perfect 🔥 — this is exactly how hunters automate **DOM XSS discovery**. You can build a **Burp Suite search / regex list** for both **sources** and **sinks** to quickly flag suspicious JS code during recon or manual review.

---

# 🔹 1. Regex for **Sources**

```regex
(location|location\.href|location\.search|location\.hash|location\.pathname|document\.URL|document\.documentURI|document\.baseURI|document\.referrer|window\.name|opener\.location|localStorage|sessionStorage|document\.cookie|postMessage|BroadcastChannel|clipboard|navigator\.clipboard|indexedDB)
```

---

# 🔹 2. Regex for **Sinks**

```regex
(eval|Function|setTimeout|setInterval|execScript|document\.write|document\.writeln|innerHTML|outerHTML|insertAdjacentHTML|srcdoc|location\s*=|location\.href|window\.open|setAttribute\s*\(\s*["']on|on[a-zA-Z]+\s*=)
```

---

# 🔹 3. Combined Source → Sink Hunt Regex

If you want a single **catch-all scanner** in Burp/Grep:

```regex
(location(\.href|\.search|\.hash|\.pathname)?|document\.(URL|documentURI|baseURI|referrer|cookie)|window\.name|opener\.location|localStorage|sessionStorage|postMessage|BroadcastChannel|clipboard|navigator\.clipboard|indexedDB).*(eval|Function|setTimeout|setInterval|execScript|document\.write|document\.writeln|innerHTML|outerHTML|insertAdjacentHTML|srcdoc|location\s*=|location\.href|window\.open|setAttribute\s*\(\s*["']on|on[a-zA-Z]+\s*=)
```

This flags when a **source flows near a sink** inside the same line/block.

---

# 🔹 4. How to Use in Burp Suite

1. Go to **Burp → Proxy → HTTP history**.
    
2. Right-click a JS file → **“Send to Search”**.
    
3. Paste the regex in **Search → Match using regex**.
    
4. Burp will highlight suspicious lines.
    
5. You can also configure **Burp Scanners → Custom passive rules** to auto-flag them.
    

---

# 🔹 5. Pro Tips

- Use **Ctrl+Shift+F** in Chrome DevTools to manually confirm flows after Burp flags something.
    
- Pair this with **LinkFinder / Relative URL Extractor** to crawl JS for hidden endpoints while grepping for sinks.
    
- Not every match = vulnerability (e.g., `setTimeout("safeFunction()",1000)`), but it helps **find needles in haystacks**.
    

---

⚡ Do you want me to also make you a **Python script** (grepper) that scans all `.js` files in scope and highlights **Source → Sink flows**, so you can automate this outside Burp as well?

Great question 💡 — this is **core to DOM XSS understanding**. Let’s break it down simply:

---

# 🔹 **Source vs Sink in DOM XSS**

## ✅ Source

- **Definition:**  
    A **source** is any place in the browser’s JavaScript environment where **user-controlled data** can enter.
    
- **Role:**  
    Think of it as the **entry point** of attacker input.
    
- **Examples:**
    
    - `location.hash` → attacker controls via `#payload`
        
    - `document.cookie` → attacker controls if they can set cookies
        
    - `window.name` → attacker sets when opening window
        
    - `postMessage` → attacker sends cross-domain message
        
- **Analogy:**  
    Source = the “river mouth” where water (input) enters the system.
    

---

## ✅ Sink

- **Definition:**  
    A **sink** is a function, property, or DOM method that **executes or interprets data**.
    
- **Role:**  
    Think of it as the **execution point** where malicious input becomes dangerous.
    
- **Examples:**
    
    - `eval()` → executes attacker’s string as JS
        
    - `innerHTML` → injects attacker’s string into DOM as HTML
        
    - `setTimeout(string, ...)` → executes string after delay
        
    - `document.write()` → injects directly into page
        
- **Analogy:**  
    Sink = the “engine” that runs whatever you feed it.
    

---

# 🔹 Major Difference (in one line)

- **Source = where attacker input enters.**
    
- **Sink = where that input gets executed/interpreted unsafely.**
    

---

# 🔹 Example Flow

```js
var input = location.hash;    // SOURCE
document.write(input);        // SINK
```

- If URL = `http://site.com/#<script>alert(1)</script>`
    
- `location.hash` (source) = `"<script>alert(1)</script>"`
    
- `document.write()` (sink) injects it → XSS executes ✅
    

---

# 🔹 Visual Summary

```
Attacker Input → [ SOURCE ] → (flows through variables/functions) → [ SINK ] → Code Executes (XSS)
```

---

⚡ Would you like me to make you a **flow diagram cheatsheet** (Sources → Processing → Sinks → XSS) that you can keep handy for bug bounty testing?