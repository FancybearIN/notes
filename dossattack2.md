# Nested / Circular Introspection (DoS) — Quick Hunting Node

What it is  ?
A GraphQL query that exploits circular relationships (often via introspection `__schema`/`__type` or transitive fields) to blow up depth × breadth and produce exponentially large work and responses — can cause CPU/memory exhaustion and DoS.

How it works ? 
Introspection and circular schema links let you recurse arbitrarily: each nested step expands the object graph, doubling/tripling nodes processed. Servers that don’t count introspective fields in depth/complexity calculations or lack depth/complexity limits will happily resolve huge trees.

Lab-style scenario (Damn-Vuln)  
`query { __schema { types { fields { type { fields { type { fields { name } } } } } } } }`  increase nesting and watch response size / time escalate predictably. Same pattern works with app fields that form cycles (e.g., `project → group → projects → group → …`).

Safe testing / hunting approach (minimal & non-destructive)

1. Baseline: run a tiny introspection (or a short nested field) and record latency + response size.
    
2. Micro-ramp: add one extra nested level, measure, repeat until you see substantial growth or reach lab limits. Stop at any sign of instability.
    
3. Compare: test same nesting for both introspection and normal schema fields to see if depth limits treat them differently.
    
4. Auth check: test unauthenticated vs authenticated to determine attack surface.
    
5. Automation: write a small script that increases nesting by 1 per request and logs response size/time — use only in lab or under scope.  
    Collect: request bodies, response sizes, timings, HTTP status codes, and any server errors or 5xx spikes.
    

Detection signals you’ll see

- Response size and CPU/time growing superlinearly with nesting.
    
- Timeouts, 5xx, or memory growth on server.
    
- Depth/complexity checks that ignore introspective fields (discrepancy between expected limit and observed work).
    
- Identical behavior for unauthenticated requests (high risk).
    

Quick evidence to include in report

- Minimal query that shows measurable growth (attach request).
    
- Timing: single-level vs N-level latency and response size.
    
- Whether auth required.
    
- Server errors or resource spikes (if accessible).
    
- Impact statement: DoS risk, possible cascading effects, and whether public access makes it exploitable at scale.
    

Straight-to-the-point mitigations (what to recommend)

- Enforce depth limits that include introspective fields.
    
- Add query complexity analysis (count nodes, breadth × depth) and reject/score expensive queries.
    
- Set max response size and max objects served per query; fail fast.
    
- Implement per-request timeouts and per-client rate-limits (count operations inside batches).
    
- Consider disabling introspection in production or gate it behind auth for public instances.
    
- Add server-side circuit-breakers & memory/CPU quotas for GraphQL workers.
    
- Provide a separate schema/explorer endpoint (or separate schema service) so docs can be served without risking API availability.
    
- Instrument & alert on abnormal query sizes, high introspection usage, and rapid nesting patterns.
    

Severity guidance

- **High** if unauthenticated and public (easy DoS).
    
- **Medium** if needs auth but can still exhaust shared resources.
    
- Prioritize fixes that block introspective recursion and add depth/complexity checks.
    

One-line remediation suggestion for reports  
“Limit query depth including introspective fields, enforce query-complexity limits, add per-client quotas/timeouts, and consider disabling or gating introspection in production.”