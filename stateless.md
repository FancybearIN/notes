Stateless means the server does not store any user session data.

# Statless
One is **stateless JWT**, where the server does not store anything. The server only checks the JWT signature and claims on every request. This is the most common usage and the main reason JWT exists.

Each request is independent, and the server does not rely on previous requests. That is why JWT authentication is called stateless.

Stateful 
The other is **stateful JWT**, where the server still stores something, like a session ID, token blacklist, or token record in a database or cache. Even though a JWT is used, the server checks it against stored data. This is done to support logout, token revocation, or extra security.