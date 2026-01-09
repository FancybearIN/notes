**SameSite ka role sirf ek jagah hota hai**  **Cookie ke behaviour control karna**. Bas.

usme hote hai 3 attributes hote hai 



| **SameSite=None**                                             |     |
| ------------------------------------------------------------- | --- |
| **Role:**  <br>Cookie **har cross-site request** me jayegi    |     |
| **Use case:**<br>- SSO<br>- Third-party integrations          |     |
| **Rule:**<br>- `Secure` mandatory<br>`SameSite=None; Secure`  |     |
| **CSRF impact:**  <br>❌ **Sabse risky** (CSRF fully possible) |     |


## **SameSite=None**


**Use case:**
- SSO
- Third-party integrations

**Rule:**
- `Secure` mandatory
`SameSite=None; Secure`

**CSRF impact:**  
❌ **Sabse risky** (CSRF fully possible)