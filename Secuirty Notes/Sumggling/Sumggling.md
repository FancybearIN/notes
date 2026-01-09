## slack 

Description :
This report described a **serious HTTP Request Smuggling issue** in Slack’s infrastructure. The researcher (defparam) crafted specially malformed HTTP requests that exploited inconsistencies between how Slack’s front-end and back-end proxies parsed requests. Because different proxy layers _disagreed on where a request body ended and the next began_, the attacker could **smuggle extra requests** into the processing queue. This allowed the attacker to **hijack authenticated connections from other customers**, effectively leading to **mass account takeovers** by pushing arbitrary requests into another user’s session context

Root cause : (logic)
The core issue is classic **HTTP Request Smuggling**  a discrepancy attack where malformed headers (e.g., conflicting `Content-Length` vs. `Transfer-Encoding`) cause front and back servers to interpret request boundaries differently, enabling injection of attacker data into adjacent user sessions. In this case, the attacker _didn’t need credentials_ of those users to crack their sessions; the smuggled data corrupted the normal request processing in a way that tilted session context to the attacker’s control.

Impact :
The impact speaks to _session isolation failures_ at scale not low-impact headers or edge errors, but **account control escalation across users** triggered via proxy parsing bugs. If you’re drilling HTTP desync/CL.TE smuggling, this is the archetype of a high-impact real-world hit