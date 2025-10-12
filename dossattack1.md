https://lab.wallarm.com/graphql-batching-attack/
# Batch Query Attack — Notes (based on _Preventing GraphQL batching attacks_). ([DEV Community](https://dev.to/ivandotv/preventing-graphql-batching-attacks-56o3 "Preventing GraphQL batching attacks - DEV Community"))

**What it is**  
Sending multiple GraphQL operations in one HTTP request (or abusing aliases to call the same resolver multiple times) to multiply server work and cause slowdowns / DoS. Example: many aliased `login` calls or repeated large `getUsers(first: N)` queries in a single payload. ([DEV Community](https://dev.to/ivandotv/preventing-graphql-batching-attacks-56o3 "Preventing GraphQL batching attacks - DEV Community"))

**How it works (brief mechanics)**  
GraphQL lets you alias fields and include multiple operations in one request; servers typically execute each alias/operation independently, so expensive resolvers run N× per batch. If batching is treated as “one request” by rate-limiters, attacker gets more work through per-request limits. ([DEV Community](https://dev.to/ivandotv/preventing-graphql-batching-attacks-56o3 "Preventing GraphQL batching attacks - DEV Community"))

**Defensive techniques from the article (practical)**

- **Disable duplicate queries/mutations**: use a validation rule that rejects duplicate calls of the same field or mutation within one request (the article shows `graphql-no-alias`). You can apply via a schema directive (`@noAlias`) or via an imperative config object. ([DEV Community](https://dev.to/ivandotv/preventing-graphql-batching-attacks-56o3 "Preventing GraphQL batching attacks - DEV Community"))
    
- **Limit total queries per request**: pair duplicate-blocking with a „no batched queries“ validator that caps the number of queries/mutations in a single request. The article’s author recommends using both together. ([DEV Community](https://dev.to/ivandotv/preventing-graphql-batching-attacks-56o3 "Preventing GraphQL batching attacks - DEV Community"))
    
- **(Article also notes) Consider heavier solutions**: Query complexity analysis and DataLoader can reduce exposure but are trickier to implement correctly and may cause false positives or require resolver changes. Use those only when you understand your query patterns. ([DEV Community](https://dev.to/ivandotv/preventing-graphql-batching-attacks-56o3 "Preventing GraphQL batching attacks - DEV Community"))
    

**Quick hunter mindset / approach (lab style)**

- Check if endpoint accepts batch payloads (JSON array) or returns an array of responses.
    
- Try simple aliasing: call the same cheap resolver many times aliased — does the server execute them all? Measure single vs batched latency.
    
- Identify a heavy resolver (e.g., `getUsers(first:1000)` or `posts.comments`) and send a small batch to observe multiplicative cost. Ramp slowly; stop at instability.
    
- Note whether batching bypasses any per-request throttles.
    

**Damn-Vulnerable lab scenario (one-liner)**  
`/graphql` accepts batches; `getUsers(first:N)` triggers a full table scan. Send `[ {query: "query{ getUsers(first:1000) }" }, ... ]` and observe median latency jump from ~200ms → seconds as batch size grows. Reproduceable in lab. (Use safe limits.)

**Minimal mitigation checklist (what to recommend in a report)**

- Reject duplicate field/mutation calls per request (use graphql-no-alias or equivalent). ([DEV Community](https://dev.to/ivandotv/preventing-graphql-batching-attacks-56o3 "Preventing GraphQL batching attacks - DEV Community"))
    
- Enforce a max number of operations per request (deny big batches). ([DEV Community](https://dev.to/ivandotv/preventing-graphql-batching-attacks-56o3 "Preventing GraphQL batching attacks - DEV Community"))
    
- Add per-client quotas & count operations inside batches.
    
- Consider cost/complexity analysis and DataLoader caching for expensive resolvers (note: more complex to implement). ([DEV Community](https://dev.to/ivandotv/preventing-graphql-batching-attacks-56o3 "Preventing GraphQL batching attacks - DEV Community"))
    

**PoC reporting bullets (copy-paste)**

- Endpoint: `/graphql`
    
- Payload used (minimal): `[{ "query": "query { getUsers(first:1000) }" }, { "query": "query { getUsers(first:1000) }" }]`
    
- Observed: response time increased from X → Y ms; server returned array; batching bypassed per-request rate-limit (if observed).
    
- Impact: multiplicative resource consumption → DoS risk / cost increase.
    
- Fix summary: block duplicate aliases, cap operations-per-request, add cost limits.
    

Want this as a 6–8 line markdown node (exactly the size you drop into your notes), or do you want a tiny lab-crafted request body and a safe ramp script you can run in your local DV lab?