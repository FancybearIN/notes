**Web cache poisoning is an advanced technique whereby an attacker exploits the behavior of a web server and cache so that a harmful HTTP response is served to other users.**

Two type attacks 

phase 1 ->  First, the attacker must work out how to elicit a response from the back-end server that inadvertently contains some kind of dangerous payload. Once successful, they need to make sure that their response is cached and subsequently served to the intended victims.

phase 2 -> A poisoned web cache can potentially be a devastating means of distributing numerous different attacks, exploiting vulnerabilities such as XSS, JavaScript injection, open redirection, and so on.

### How does a web cache work?

 If a server had to send a new response to every single HTTP request separately, this would likely overload the server, resulting in latency issues and a poor user experience, especially during busy periods. Caching is primarily a means of reducing such issues.

The cache sits between the server and the user, where it saves (caches) the responses to particular requests, usually for a fixed amount of time. If another user then sends an equivalent request, the cache simply serves a copy of the cached response directly to the user, without any interaction from the back-end. This greatly eases the load on the server by reducing the number of duplicate requests it has to handle.

#### Cache keys

|Key Component|Description|
|---|---|
|`Host`|Can poison multi-tenant apps|
|`X-Forwarded-Host`|Sometimes used internally in dynamic routing|
|`X-Forwarded-For`|May affect backend behavior or logs|
|`X-Original-URL`|Influences backend routing in some setups|
|`X-Forwarded-Scheme`|Can cause mixed content issues or redirects|
|`X-HTTP-Method-Override`|May override the request method|
|`Referer`|Sometimes reflected in response headers|
|`User-Agent`|Reflected in response, may poison|
|`Accept-Encoding`|Affects gzip or brotli caching behavior|
|`Cookie`|Often stripped from cache key → tricky|
|`X-Accel-Redirect`, `X-Rewrite-URL`|Affects cache key or logic|

### 🧠 Simple Summary: Cache Key in Web Cache Poisoning

When a server or CDN (like Cloudflare or Varnish) gets a request, it checks if it already has a **cached response** to serve quickly — instead of going to the backend.

To do this, it compares only **specific parts of the request**, called the **"cache key"** (usually things like the URL path and `Host` header).

- If two requests have the **same cache key**, they are treated as **equivalent**, and the **same cached response is sent**.    
- Other parts of the request (like extra headers or query params) are often **ignored** by the cache — these are called **"unkeyed"**.
    

---

### ⚠️ Why This Matters in Attacks:

If an attacker **adds a malicious header or param** that is **ignored by the cache** but **used by the backend**, they can **poison** the cache with a harmful response that gets served to **all users** with the same cache key.

---

### 🧪 Example:

1. **Attacker's request:**
    
    ```
    GET /profile HTTP/1.1
    Host: example.com
    X-Host: evil.com
    ```
    
    Backend trusts `X-Host` and renders something malicious.
    
2. Cache **ignores `X-Host`**, sees only the `GET /profile` + `Host`, and stores the poisoned response.
    
3. Other users visit `/profile` and get the **attacker's malicious cached content**.
    
