**SameSite ka role sirf ek jagah hota hai**  **Cookie ke behaviour control karna**. Bas.

usme hote hai 3 attributes hote hai 



| **SameSite=None**                                             | SameSite=Lax                                                                      |
| ------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| **Role:**  <br>Cookie **har cross-site request** me jayegi    | **Role:**  <br>Cookie **top-level navigation (GET)** pe jayegi                    |
| **Use case:**<br>- SSO<br>- Third-party integrations          | **Allowed:**<br>- User link click kare                  - Address bar me URL dale |
| **Rule:**<br>- `Secure` mandatory<br>`SameSite=None; Secure`  |                                                                                   |
| **CSRF impact:**  <br>❌ **Sabse risky** (CSRF fully possible) |                                                                                   |


