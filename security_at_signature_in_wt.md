The signature works like a tamper-proof seal.

When the JWT is created, the server takes the header and payload, combines them, and creates a signature using a secret key or a private key. This signature is added to the token.

When the server receives the JWT, it creates the signature again using the same data and key. If even one character in the header or payload was changed, the new signature will be different. Because the signatures do not match, the server knows the token was modified and rejects it.

So the signature does not hide the data, it only proves that the data was not changed after the token was issued.