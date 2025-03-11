
Insecure direct object references (IDOR) are a type of access control vulnerability that arises when an application uses user-supplied input to access objects directly

### IDOR vulnerability with direct reference to database objects

Consider a website that uses the following URL to access the customer account page, by retrieving information from the back-end database:

`https://insecure-website.com/customer_account?customer_number=132355`

Here, the customer number is used directly as a record index in queries that are performed on the back-end database. If no other controls are in place, an attacker can simply modify the `customer_number` value, bypassing access controls to view the records of other customers. This is an example of an IDOR vulnerability leading to horizontal privilege escalation

In some cases, the identifier may not be in the URL, but rather in the POST body, as shown in the following example:

`<form action="/update_profile" method="post">   <!-- Other fields for updating name, email, etc. -->   <input type="hidden" name="user_id" value="12345">   <button type="submit">Update Profile</button> </form>`

In this example, the application allows users to update their profiles by submitting a form with the user ID in a hidden field. If the app doesn't perform proper access control on the server-side, attackers can manipulate the "user_id" field to modify profiles of other users without authorization.

## Mitigation[¶](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html#mitigation "Permanent link")

To mitigate IDOR, implement access control checks for each object that users try to access. Web frameworks often provide ways to facilitate this. Additionally, use complex identifiers as a defense-in-depth measure, but remember that access control is crucial even with these identifiers.

Avoid exposing identifiers in URLs and POST bodies if possible. Instead, determine the currently authenticated user from session information. When using multi-step flows, pass identifiers in the session to prevent tampering.

When looking up objects based on primary keys, use datasets that users have access to. For example, in Ruby on Rails:

`// vulnerable, searches all projects @project = Project.find(params[:id]) // secure, searches projects related to the current user @project = @current_user.projects.find(params[:id])`

Verify the user's permission every time an access attempt is made. Implement this structurally using the recommended approach for your web framework.

As an additional defense-in-depth measure, replace enumerable numeric identifiers with more complex, random identifiers. You can achieve this by adding a column with random strings in the database table and using those strings in the URLs instead of numeric primary keys. Another option is to use UUIDs or other long random values as primary keys. Avoid encrypting identifiers as it can be challenging to do so securely.

[resouce fo medium ](https://medium.com/@insightfulrohit/all-about-insecure-direct-object-reference-idor-666cad6a94f0)