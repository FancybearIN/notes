A web cache is a system that sits between the origin server and the user. When a client requests a static resource, the request is first directed to the cache. If the cache doesn't contain a copy of the resource (known as a cache miss), the request is forwarded to the origin server, which processes and responds to the request. The response is then sent to the cache before being sent to the user. The cache uses a preconfigured set of rules to determine whether to store the response.![[caching.svg]]
==Caching has become a common and crucial aspect of delivering web content, particularly with the widespread use o**f Content Delivery Networks (CDNs),** which use caching to store copies of content on distributed servers all over the world. CDNs speed up delivery by serving content from the server closest to the user, reducing load times by minimizing the distance data travels.==

### What is a **Cache Key**?

A **cache key** is like a unique identifier or fingerprint that a **cache system** creates from parts of an HTTP request. It uses this key to check if it already has a saved (cached) response for that request.

### Why is it important?

When a request comes in, the cache:

1. **Generates a cache key** based on certain parts of the request (like URL, query params, headers, etc.).
    
2. **Checks if it has a stored response** for that key.
    
    - If yes → It **serves the cached response** (faster, saves resources).
    - If no → It **forwards the request to the origin server**, gets the response, saves it with the key, and serves it.
        

---

### 🧱 What makes up a Cache Key?

By default, the cache key **usually includes**:

- The **URL path**: `/products/item123`
- The **query string**: `?color=red&size=large`


It **can also include**:

- HTTP **headers** (e.g., `Accept-Encoding`, `User-Agent`)
- **Cookies** (sometimes, though often avoided to improve cache efficiency)
- **Request method** (GET vs POST)
- **Protocol** (HTTP vs HTTPS)
- **Content type** or other request metadata
---

### 📦 Example

Imagine you have two requests:

`GET /products/item123?color=red GET /products/item123?color=blue`

Even though the path is the same, the **query parameters are different**, so the cache keys will be different. The cache treats these as **two separate requests** and stores separate responses for each.

If you request the **same exact URL with same parameters and headers** again, the cache will recognize it (same cache key) and serve the saved response.

---

### 🚫 If Cache Keys Are Too Broad or Too Specific

- **Too broad** (e.g., using only the path): Might serve the wrong cached response to different users.
- **Too specific** (e.g., including irrelevant headers): May result in too many unique keys → poor cache hit rate → less benefit from caching.


---

How to attack -> [cache](cache.md)

---

### What Are **Cache Rules**?

**Cache rules** tell the caching system **what to cache, when to cache it, and for how long**. These rules help improve performance by reducing the load on origin servers and delivering content faster to users.

Rules are usually configured in:

- **Content delivery networks (CDNs)**
- **Reverse proxies** (e.g., NGINX, Varnish)
- **Browser or server-level cache settings**
### Types of Cache Rules

1. **📁 Static File Extension Rules**
    
    - Targets common file types: `.css`, `.js`, `.jpg`, `.png`, `.svg`, `.woff2`, etc.
    - These files rarely change, so they’re ideal for long-term caching.
    - **Example rule:**  
        Cache `.css` files for 1 year.
        
2. **📂 Static Directory Rules**
    
    - Applies caching to all paths under a given directory.
    - Often used for folders like `/assets/`, `/static/`, or `/media/`.
    - **Example rule:**  
        All files under `/static/` are cached for 30 days.
        
3. **📄 File Name Rules**
    
    - Caches specific file names that are universal and rarely change.
    - Examples include:
        - `robots.txt`
        - `favicon.ico`
        - `manifest.json   
    - **Example rule:**  
        Cache `favicon.ico` for 7 days.
        
4. **⚙️ Custom Rules**
    - Based on:
        - **Query parameters** (`?lang=en`)
        - **User-agent**
        - **Cookies**
        - **Request headers**
            
    - Or even based on **behavioral analysis** or **dynamic detection** of what’s cacheable.
### Web Cache Deception — Simplified Steps

1. **Find a Dynamic Page with Sensitive Info**  
    Look for pages like `/account`, `/profile`, etc., that show private user data (like emails or tokens). Use tools like **Burp Suite** to check the full HTTP response, not just what you see in the browser.
    
2. **Look for a URL Parsing Difference**  
    Check if the **cache server** and the **web server** treat URLs differently. For example:
    
    - The cache sees `/profile.js` as a static file.    
    - The server still treats it as a dynamic page.
        
3. **Create a Tricky URL**  
    Build a fake URL like this:
    `/account/settings.css`
    Even though it looks like a CSS file (which caches), it actually returns sensitive content.
    
4. **Get a Victim to Open That URL**  
    When a logged-in user visits that fake-looking URL, the cache saves their **personal data**.
    
5. **Grab the Cached Response**  
    Now you (the attacker) visit the same URL and get **the victim’s cached info** from the server.
### Using a Cache Buster (Made Simple)

When you're testing for Web Cache Deception, it's important that **each request you send is treated as unique** by the cache. Otherwise, you might accidentally get an old (cached) response — not a real one from the server.
### Why Use a Cache Buster?

Caches use parts of the request — like the **URL path** and **query parameters** — to decide if a response is already stored.
If you send the **same URL** repeatedly, the cache might just give you an old response. This can **ruin your test results**.

## Detecting cached responses

- The `X-Cache` header provides information about whether a response was served from the cache. Typical values include:
    - `X-Cache: hit` - The response was served from the cache.
    - `X-Cache: miss` - The cache did not contain a response for the request's key, so it was fetched from the origin server. In most cases, the response is then cached. To confirm this, send the request again to see whether the value updates to hit.
    - `X-Cache: dynamic` - The origin server dynamically generated the content. Generally this means the response is not suitable for caching.
    - `X-Cache: refresh` - The cached content was outdated and needed to be refreshed or revalidated.
- The `Cache-Control` header may include a directive that indicates caching, like `public` with a `max-age` higher than `0`. Note that this only suggests that the resource is cacheable. It isn't always indicative of caching, as the cache may sometimes override this header.
## Exploiting static extension cache rules

Cache rules often target static resources by matching common file extensions like `.css` or `.js`. This is the default behavior in most CDNs.

If there are discrepancies in how the cache and origin server map the URL path to resources or use delimiters, an attacker may be able to craft a request for a dynamic resource with a static extension that is ignored by the origin server but viewed by the cache.

## Path mapping discrepancies

URL path mapping is the process of associating URL paths with resources on a server, such as files, scripts, or command executions. There are a range of different mapping styles used by different frameworks and technologies. Two common styles are traditional URL mapping and RESTful URL mapping.

==Traditional URL mapping ==represents a direct path to a resource located on the file system. Here's a typical example:

`http://example.com/path/in/filesystem/resource.html`

- `http://example.com` points to the server.
- `/path/in/filesystem/` represents the directory path in the server's file system.
- `resource.html` is the specific file being accessed.

In contrast, ==REST-style URLs== don't directly match the physical file structure. They abstract file paths into logical parts of the API:

`http://example.com/path/resource/param1/param2`

- `http://example.com` points to the server.
- `/path/resource/` is an endpoint representing a resource.
- `param1` and `param2` are path parameters used by the server to process the request.

## Path mapping discrepancies - Continued

Discrepancies in how the cache and origin server map the URL path to resources can result in web cache deception vulnerabilities. Consider the following example:

`http://example.com/user/123/profile/wcd.css`

- An origin server using REST-style URL mapping may interpret this as a request for the `/user/123/profile` endpoint and returns the profile information for user `123`, ignoring `wcd.css` as a non-significant parameter.
- A cache that uses traditional URL mapping may view this as a request for a file named `wcd.css` located in the `/profile` directory under `/user/123`. It interprets the URL path as `/user/123/profile/wcd.css`. If the cache is configured to store responses for requests where the path ends in `.css`, it would cache and serve the profile information as if it were a CSS file.
## Exploiting path mapping discrepancies

To test how the origin server maps the URL path to resources, add an arbitrary path segment to the URL of your target endpoint. ==If the response still contains the same sensitive data as the base response,== it indicates that the origin server abstracts the URL path and ignores the added segment.

- TRY this
		For example, this is the case if modifying `/api/orders/123` to `/api/orders/123/foo` still returns order information.

To test how the cache maps the URL path to resources, you'll need to modify the path to attempt to match a cache rule by adding a static extension. 

For example, update `/api/orders/123/foo` to `/api/orders/123/foo.js`. If the response is cached, this indicates:

- That the cache interprets the full URL path with the static extension.
- That there is a cache rule to store responses for requests ending in `.js`.

Caches may have rules based on specific static extensions. Try a range of extensions, including `.css`, `.ico`, and `.exe`.

You can then craft a URL that returns a dynamic response that is stored in the cache. Note that this attack is limited to the specific endpoint that you tested, as the origin server often has different abstraction rules for different endpoints.

# Test cases 1

## Exploiting path mapping for web cache deception

### **Reason for Vulnerability**

This vulnerability arises due to **inconsistent behavior between the cache layer and the backend server** regarding URL path parsing and caching mechanisms:

- The **origin server** treats `/my-account`, `/my-account/abc`, and `/my-account/abc.js` **as the same resource** due to path normalization (ignoring extra path segments).
    
- The **caching layer**, however, sees `/my-account/abc.js` as a **different and cacheable static file** due to the `.js` extension.


- This discrepancy allows an attacker to **store a cached response** (containing sensitive info like an API key) and later **retrieve it from the cache** using the crafted path.


==Try checking for cache-related headers by navigating to a sensitive endpoint. Use a static extension in the path, such as `/my-account/abc.js`, and observe the response headers. If you see `X-Cache: miss` and `Cache-Control: max-age=...`, it indicates the response is cacheable. Repeating the request within the cache time window and receiving `X-Cache: hit` confirms that the response was cached — meaning the payload was successfully stored and can be served to others, indicating a cache poisoning vulnerability.==

## ==Delimiter discrepancies==

Delimiters specify boundaries between different elements in URLs. The use of characters and strings as delimiters is generally standardized. For example, `?` is generally used to separate the URL path from the query string. 

However, as the URI RFC is quite permissive, variations still occur between different frameworks or technologies.

Discrepancies in how the cache and origin server use characters and strings as delimiters can result in web cache deception vulnerabilities.

Consider the example `/profile;foo.css`

- The Java Spring framework uses the `;` character to add parameters known as matrix variables. An origin server that uses Java Spring would therefore interpret `;` as a delimiter. It truncates the path after `/profile` and returns profile information.

- Most other frameworks don't use `;` as a delimiter. Therefore, a cache that doesn't use Java Spring is likely to interpret `;` and everything after it as part of the path. If the cache has a rule to store responses for requests ending in `.css`, it might cache and serve the profile information as if it were a CSS file.

`Consider these requests to an origin server running the Ruby on Rails framework, which uses `.` as a delimiter to specify the response format`

- `/profile` - This request is processed by the default HTML formatter, which returns the user profile information.

- `/profile.css` - This request is recognized as a CSS extension. There isn't a CSS formatter, so the request isn't accepted and an error is returned.

- `/profile.ico` - This request uses the `.ico` extension, which isn't recognized by Ruby on Rails. The default HTML formatter handles the request and returns the user profile information. In this situation, if the cache is configured to store responses for requests ending in `.ico`, it would cache and serve the profile information as if it were a static file.

- The OpenLiteSpeed server uses the encoded null `%00` character as a delimiter. An origin server that uses OpenLiteSpeed would therefore interpret the path as `/profile`.

- Most other frameworks respond with an error if `%00` is in the URL. However, if the cache uses Akamai or Fastly, it would interpret `%00` and everything after it as the path.

## Exploiting delimiter discrepancies

- ==You may be able to use a delimiter discrepancy to add a static extension to the path that is viewed by the cache, but not the origin server.== 

- ==To do this, you'll need to identify a character that is used as a delimiter by the origin server but not the cache.==

- ==find characters that are used as delimiters by the origin server. Start this process by adding an arbitrary string to the URL of your target endpoint.==

For example, modify `/settings/users/list` to `/settings/users/listaaa`.

- Add a possible delimiter character between the original path and the arbitrary string, for example `/settings/users/list;aaa`:

   - If the response is identical to the base response, this indicates that the `;` character is used as a delimiter and the origin server interprets the path as `/settings/users/list`.

  - If it matches the response to the path with the arbitrary string, this indicates that the `;` character isn't used as a delimiter and the origin server interprets the path as `/settings/users/list;aaa`.
# How to find ?

Once you’ve figured out which delimiters (like slashes `/`, dots `.`, or other special characters) the origin server understands, you need to check if the caching layer treats them the same way.

To do this:

- Add a **static file extension** (like `.js`) to the end of the path.
    
- If the response gets **cached**, it means:
    
    - The cache **does not recognize the delimiter** and treats the whole path as a single URL.
    - There might be a **cache rule** that allows caching of paths ending with file types like `.js`.
        
You should also test with different ASCII characters and common static file extensions like:
- `.css`, `.ico`, `.exe`, etc.
    

The labs provide a **delimiter list** you can use to help identify bypass characters.

To speed this up, use **Burp Intruder**:

- Add all delimiter characters to the payload list.
- IMPORTANT: In Burp Intruder, **turn off automatic encoding** in the **Payloads > Payload Encoding** section so the special characters are sent exactly as-is.

You can then construct an exploit that triggers the static extension cache rule. For example, consider the payload `/settings/users/list;aaa.js`. The origin server uses `;` as a delimiter:

- The cache interprets the path as: `/settings/users/list;aaa.js`
- The origin server interprets the path as: `/settings/users/list`

The origin server returns the dynamic profile information, which is stored in the cache.

Because delimiters are generally used consistently within each server, you can often use this attack on many different endpoints.

`Some delimiter characters may be processed by the victim's browser before it forwards the request to the cache. This means that some delimiters can't be used in an exploit. For example, browsers URL-encode characters like `{`, `}`, `<`, and `>`, and use `#` to truncate the path.`

If the cache or origin server decodes these characters, it may be possible to use an encoded version in an exploit

---

## 🔐 Common **Delimiter Characters** for Web Cache Deception Bypass

| Character | Description / Use                                   | Bypass Example                |
| --------- | --------------------------------------------------- | ----------------------------- |
| `;`       | **Matrix parameter** (used in Java Spring)          | `/profile;foo.js`             |
| `.`       | File extension / format specifier (used in Rails)   | `/profile.js`, `/profile.ico` |
| `%00`     | Encoded **null byte** (used in OpenLiteSpeed)       | `/profile%00.js`              |
| `:`       | Alternate path (some servers truncate after `:`)    | `/profile:evil.js`            |
| `%2F`     | Encoded slash (some servers decode it)              | `/profile%2Fsecret.js`        |
| `?`       | Start of query string (usually ignored by cache)    | `/profile.js?ignored`         |
| `#`       | Fragment identifier (browser truncates after this)  | `/profile.js#section`         |
| `%23`     | Encoded `#` (sometimes bypasses browser truncation) | `/profile%23.js`              |
| `&`       | Additional query param separator                    | `/profile.js?x=1&y=2`         |
| `=`       | Assign query values (can be useful in deception)    | `/profile.js?user=admin`      |
| `-`       | Safe char, used in combination                      | `/profile-admin.js`           |
| `_`       | Also safe, used in combined paths                   | `/profile_admin.js`           |
| `~`       | May be ignored by server in some cases              | `/profile~backup.js`          |
| `!`       | Sometimes acts like a separator                     | `/profile!temp.js`            |
| `,`       | Can be used in some APIs (e.g., for format lists)   | `/profile.css,js`             |
| `%2e`     | Encoded dot (used to fake extension)                | `/profile%2ejs`               |
| `%3b`     | Encoded `;` (used to bypass WAFs)                   | `/profile%3bfoo.js`           |
| `%3f`     | Encoded `?`                                         | `/profile.js%3fadmin`         |

---

## 🧪 Testing Strategy (Using Burp Suite or Similar Tools)

1. **Start with your target endpoint:**
    
    ```
    /account/details
    ```
    
2. **Add a string and a delimiter:**
    
    ```
    /account/details;abc.js
    /account/details%00.js
    /account/details.css
    ```
    
3. **Check for:**
    
    - `X-Cache: hit` or `X-Cache: miss` in the response.
        
    - Presence of sensitive info (e.g., API key, user data).
        
    - Status code differences (e.g., 200 vs. 404).
        

---

## 💡 Example Exploit Flow

```bash
Original:      /my-account
Test:          /my-account;foo.js      ← Spring truncates after `;`
Test:          /my-account%00.js       ← OpenLiteSpeed truncates
Test:          /my-account.ico         ← Rails treats `.ico` as static
Test:          /my-account.js?user=x   ← Cache stores as `.js`
```

---

## Exploiting static directory cache rules

It's common practice for web servers to store static resources in specific directories. Cache rules often target these directories by matching specific URL path prefixes, like `/static`, `/assets`, `/scripts`, or `/images`. These rules can also be vulnerable to web cache deception.

# Normalization discrepancies

Normalization involves converting various representations of URL paths into a standardized format. This sometimes includes decoding encoded characters and resolving dot-segments, but this varies significantly from parser to parser.

Discrepancies in how the cache and origin server normalize the URL can enable an attacker to construct a path traversal payload that is interpreted differently by each parser. Consider the example `/static/..%2fprofile`:

- An origin server that decodes slash characters and resolves dot-segments would normalize the path to `/profile` and return profile information.

- A cache that doesn't resolve dot-segments or decode slashes would interpret the path as `/static/..%2fprofile`. If the cache stores responses for requests with the `/static` prefix, it would cache and serve the profile information.

As shown in the above example, each dot-segment in the path traversal sequence needs to be encoded. Otherwise, the victim's browser will resolve it before forwarding the request to the cache. Therefore, an exploitable normalization discrepancy requires that either the cache or origin server decodes characters in the path traversal sequence as well as resolving dot-segments.

Here’s a **simple and easy-to-understand version** of how to **test path normalization behavior in both origin server and cache**:

---

## 🔍 What is Normalization?

**Normalization** means converting a weird-looking path (like `aaa/..%2fprofile`) into a proper one (`/profile`) by decoding and resolving `..` and `%2f` (encoded slash `/`).

---

## 🧪 1. Detecting Normalization by the **Origin Server**

### ✅ Goal:

See if the **origin server** changes or resolves strange path inputs.

### 🛠 How to Test:

1. Choose an endpoint that does something (not just shows info). For example, use a `POST` request to `/profile`.
    
2. Change the path like this:
    

```
/profile → /aaa/..%2fprofile
```

### 🔍 What to Observe:

- If it **still works** (shows profile info), it means:
    
    - The server **decoded** `%2f` to `/`
        
    - It **resolved** `aaa/../` to nothing  
        ✅ So, final path = `/profile`
        
- If it **fails** (like 404), it means:
    
    - Server didn't normalize it  
        ❌ Final path = `/aaa/..%2fprofile` (treated as literal)
        

---

## 🧪 2. Detecting Normalization by the **Cache**

### ✅ Goal:

See how the **cache** (like CDN or reverse proxy) treats weird paths.

### 🛠 How to Test:

1. Go to **Proxy > HTTP history** in Burp Suite.
    
2. Find static files (like JavaScript, CSS, images) with:
    
    - `200` status codes (filter for 2xx)
        
    - Types like `script`, `image`, or `css`
        
3. Choose a cached file like:
    

```
/assets/js/stockCheck.js
```

4. Send this modified request:
    

```
/aaa/..%2fassets/js/stockCheck.js
```

### 🔍 What to Observe:

- If the **response is not cached anymore**, then:
    
    - Cache did **not normalize** the path.
        
    - It treated `/aaa/..%2fassets` as a separate path.  
        ✅ Cache rules are based on `/assets`
        
- If the **response is still cached**, then:
    
    - Cache **normalized** the path to `/assets/js/stockCheck.js`  
        ✅ Cache rules work even after normalization.
        
- If the **response is not cached**, and path becomes `/js/stockCheck.js`:
    
    - Cache **normalized too much**, skipped `assets`  
        ❌ Might leak other resources by changing path meaning
        

---

### 📌 Summary Table

|Test|What You Send|What It Means If It Works|
|---|---|---|
|Origin server|`/aaa/..%2fprofile`|Server normalized path → `/profile`|
|Cache test|`/aaa/..%2fassets/js/file.js`|Cache normalized path or not depending on response|

## Exploiting normalization by the origin server

If the origin server resolves encoded dot-segments, but the cache doesn't, you can attempt to exploit the discrepancy by constructing a payload according to the following structure:

`/<static-directory-prefix>/..%2f<dynamic-path>`

For example, consider the payload `/assets/..%2fprofile`:

- The cache interprets the path as: `/assets/..%2fprofile`
- The origin server interprets the path as: `/profile`

The origin server returns the dynamic profile information, which is stored in the cache.

## Exploiting origin server normalization for web cache deception

payload
https://0add00bc032fc8db8108caa7001700b0.web-security-academy.net/resources/..%2fmy-account?asd.js

when to viticm change the value.

## Exploiting normalization by the cache server

If the cache server resolves encoded dot-segments but the origin server doesn't, you can attempt to exploit the discrepancy by constructing a payload according to the following structure:

`/<dynamic-path>%2f%2e%2e%2f<static-directory-prefix>`

#### Note

When exploiting normalization by the cache server, encode all characters in the path traversal sequence. Using encoded characters helps avoid unexpected behavior when using delimiters, and there's no need to have an unencoded slash following the static directory prefix since the cache will handle the decoding.

In this situation, path traversal alone isn't sufficient for an exploit. For example, consider how the cache and origin server interpret the payload `/profile%2f%2e%2e%2fstatic`:

- The cache interprets the path as: `/static`
- The origin server interprets the path as: `/profile%2f%2e%2e%2fstati`
- 
To exploit this discrepancy, you'll need to also identify a delimiter that is used by the origin server but not the cache. Test possible delimiters by adding them to the payload after the dynamic path:

- If the origin server uses a delimiter, it will truncate the URL path and return the dynamic information.
- If the cache doesn't use the delimiter, it will resolve the path and cache the response.

For example, consider the payload `/profile;%2f%2e%2e%2fstatic`. The origin server uses `;` as a delimiter:

- The cache interprets the path as: `/static`
- The origin server interprets the path as: `/profile`

## Exploiting file name cache rules

Certain files such as `robots.txt`, `index.html`, and `favicon.ico` are common files found on web servers. They're often cached due to their infrequent changes. Cache rules target these files by matching the exact file name string.

how to find the web cache deception.

first find how the site is intract with cache, based on this try use which delmitor than check other files are common use by server how that resources reacting to cache attack than try senstive on the page. 

## Preventing web cache deception vulnerabilities

You can take a range of steps to prevent web cache deception vulnerabilities:

- Always use `Cache-Control` headers to mark dynamic resources, set with the directives `no-store` and `private`.
- Configure your CDN settings so that your caching rules don't override the `Cache-Control` header.
- Activate any protection that your CDN has against web cache deception attacks. Many CDNs enable you to set a cache rule that verifies that the response `Content-Type` matches the request's URL file extension. For example, Cloudflare's Cache Deception Armor.

- Verify that there aren't any discrepancies between how the origin server and the cache interpret URL paths.