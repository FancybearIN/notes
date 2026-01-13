The signature works like a tamper-proof seal.

When the JWT is created, the server takes the header and payload, combines them, and creates a signature using a secret key or a private key. This signature is added to the token.

==When the server receives the JWT, it creates the signature again using the same data and key. If even one character in the header or payload was changed, the new signature will be different.== 

Because the signatures do not match, the server knows the token was modified and rejects it.

So the signature does not hide the data, it only proves that the data was not changed after the token was issued.

#### ==but differ algo have change in the signature , in that how its seecure ?==

Yes, different algorithms create the signature in different ways, **but security does not come from the algorithm name**. Security comes from **using the correct key with the correct algorithm and enforcing it strictly**.

When a server issues a JWT, it already knows which algorithm it uses, for example HS256 or RS256. During verification, the server must **force the same algorithm** and use the correct key. If the header says a different algorithm and the server still accepts it, that is a misconfiguration and becomes a vulnerability.

So even though HS256 and RS256 produce different signatures, the server only trusts the signature if:

- the algorithm is the expected one
- the correct secret or public key is used
- the signature matches exactly

If an attacker changes the algorithm in the header, the signature will no longer verify unless the server is wrongly coded to trust that change. When servers enforce the algorithm properly, changing the algorithm breaks the signature and the token is rejected.


# In symmetric key JWT, 
the same secret key is used to create and verify the signature. The server signs the token using this secret, and during verification it recreates the signature using the same secret. If the data is changed, the signature breaks. The problem is that if an attacker ever gets this secret, they can also create a valid signature, so they can change the data and still make the token look valid.

# In asymmetric key JWT,
the server uses a private key to create the signature, and only a public key is used to verify it. Even though anyone can see the public key, it cannot be used to create a valid signature. If an attacker changes the data, they cannot generate a new valid signature because they do not have the private key. That is why asymmetric JWT is safer.

Algorithm-based attacks happen only when the server trusts what the token says about the algorithm. If the server blindly accepts a changed algorithm, it may use the wrong key to verify the signature. In a properly configured system, 

the server fixes the algorithm and key in advance, so changing the algorithm or payload always breaks the signature and the token is rejected.

Mitigation 

- Strict control on how the JWT is verified.
- Sever must never trust the algo in jwt. it should be hard coded to accept only one expected algo. (RS256).
- algo changed token immediately fail verification.
-  server should b