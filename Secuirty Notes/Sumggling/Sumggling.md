
defoaram - https://hackerone.com/reports/737140

What the bug was:
The researcher found an **HTTP Request Smuggling** vulnerability in a Slack endpoint. HTTP request smuggling happens when inconsistent parsing of HTTP requests between a front-end component (like a CDN or proxy) and a backend server allows the attacker to “smuggle” crafted requests that get interpreted differently across components. That discrepancy can let an attacker influence how subsequent requests are handled by the backend.

How it was abused:
Using this smuggling flaw, the researcher was able to **hijack other users’ requests** by injecting a malicious request into the request stream. This manipulation let them steal session cookies or otherwise impersonate other users, leading to **mass account takeovers** on Slack (effectively forging a way to control sessions of other logged-in users).