
defoaram - https://hackerone.com/reports/737140

The researcher found an **HTTP Request Smuggling** vulnerability in a Slack endpoint. HTTP request smuggling happens when inconsistent parsing of HTTP requests between a front-end component (like a CDN or proxy) and a backend server allows the attacker to “smuggle” crafted requests that get interpreted differently across components. That discrepancy can let an attacker influence how subsequent requests are handled by the backend.