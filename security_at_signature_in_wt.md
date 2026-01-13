The signature works like a tamper-proof seal.

When the JWT is created, the server takes the header and payload, combines them, and creates a signature using a secret key or a private key. This signature is added to the token.

When the server receives the JWT, it creates the signature again using the same data and key. If even one character in the header or payload was changed, the new signature will be different. Because the signatures do not match, the server knows the token was modified and rejects it.

So the signature does not hide the data, it only proves that the data was not changed after the token was issued.

#### ==but differ algo have change in the signature , in that how its seecure ?==

Yes, different algorithms create the signature in different ways, **but security does not come from the algorithm name**. Security comes from **using the correct key with the correct algorithm and enforcing it strictly**.

When a server issues a JWT, it already knows which algorithm it uses, for example HS256 or RS256. During verification, the server must **force the same algorithm** and use the correct key. If the header says a different algorithm and the server still accepts it, that is a misconfiguration and becomes a vulnerability.

So even though HS256 and RS256 produce different signatures, the server only trusts the signature if:

- the algorithm is the expected one
    
- the correct secret or public key is used
    
- the signature matches exactly
    

If an attacker changes the algorithm in the header, the signature will no longer verify unless the server is wrongly coded to trust that change. When servers enforce the algorithm properly, changing the algorithm breaks the signature and the token is rejected.