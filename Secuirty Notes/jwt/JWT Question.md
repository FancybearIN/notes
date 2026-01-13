
1. What is a JWT and why is it used?
	    A JWT (JSON Web Token) is a small token used to securely send user information between a client and a server. It is mainly used for authentication, so once a user logs in, the server gives a JWT and the user sends it with every request instead of logging in again.
	    - It is used because it is fast, [stateless](stateless), and easy to verify. The server does not need to store session data, and it can trust the token as long as the signature is valid.
2. What are the three parts of a JWT?
    
3. What information is stored inside a JWT?
    
4. Is JWT encrypted or just encoded?
    
5. What is the purpose of the signature in a JWT?
    
6. What happens if someone changes the payload of a JWT?
    
7. What is the difference between authentication and authorization in JWT?
    
8. What does `alg` mean in the JWT header?
    
9. What is the difference between HS256 and RS256?
    
10. What is a secret key in JWT?
    
11. What is a public key and private key in JWT?
    
12. Who creates the JWT and who verifies it?
    
13. Can a client modify a JWT?
    
14. What happens if the JWT secret key is leaked?
    
15. Why is RS256 safer than HS256 for public applications?
    
16. What is `exp` in JWT?
    
17. What happens when a JWT is expired?
    
18. Can a JWT be reused after logout?
    
19. What is `alg: none` and why is it dangerous?
    
20. Why should the server never trust JWT data without verification?