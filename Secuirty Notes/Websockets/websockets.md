# What are WebSockets?

WebSockets are a bi-directional, full duplex communications protocol initiated over HTTP. They are commonly used in modern web applications for streaming data and other asynchronous traffic.

In this section, we'll explain the difference between HTTP and WebSockets, describe how WebSocket connections are established, and outline what WebSocket messages look like. 


# Manipulating WebSocket traffic

Finding WebSockets security vulnerabilities generally involves manipulating them in ways that the application doesn't expect. You can do this using Burp Suite.

You can use Burp Suite to:

    Intercept and modify WebSocket messages.
    Replay and generate new WebSocket messages.
    Manipulate WebSocket connections.

**Note : -
You can configure whether client-to-server or server-to-client messages are intercepted in Burp Proxy. Do this in the Settings dialog, in the WebSocket interception rules settings**

# Intercepting and modifying WebSocket messages

You can use Burp Proxy to intercept and modify WebSocket messages, as follows:

    Open Burp's browser.
    Browse to the application function that uses WebSockets. You can determine that WebSockets are being used by using the application and looking for entries appearing in the WebSockets history tab within Burp Proxy.
    In the Intercept tab of Burp Proxy, ensure that interception is turned on.
    When a WebSocket message is sent from the browser or server, it will be displayed in the Intercept tab for you to view or modify. Press the Forward button to forward the message.

## Replaying and generating new WebSocket messages


 - In Burp Proxy, select a message in the WebSockets history, or in the Intercept tab, and choose "Send to Repeater" from the context menu.

- In Burp Repeater, you can now edit the message that was selected, and send it over and over.
    You can enter a new message and send it in either direction, to the client or server.
 
    - In the "History" panel within Burp Repeater, you can view the history of messages that have been transmitted over the WebSocket connection. This includes messages that you have generated in Burp Repeater, and also any that were generated by the browser or server via the same connection.
 -   If you want to edit and resend any message in the history panel, you can do this by selecting the message and choosing "Edit and resend" from the context menu.


## Manipulating WebSocket connections

As well as manipulating WebSocket messages, it is sometimes necessary to manipulate the WebSocket handshake that establishes the connection.

There are various situations in which manipulating the WebSocket handshake might be necessary:

- It can enable you to reach more attack surface.

- Some attacks might cause your connection to drop so you need to establish a new one.

-    Tokens or other data in the original handshake request might be stale and need updating.

# 
WebSockets security vulnerabilities

In principle, practically any web security vulnerability might arise in relation to WebSockets:

-    User-supplied input transmitted to the server might be processed in unsafe ways, leading to vulnerabilities such as SQL injection or XML external entity injection.

- Some blind vulnerabilities reached via WebSockets might only be detectable using out-of-band (OAST) techniques.

- If attacker-controlled data is transmitted via WebSockets to other application users, then it might lead to XSS or other client-side vulnerabilities.

## xss payload

     {"message":"<img src=1 onerror='alert(1)'>"}