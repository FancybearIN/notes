# Access control vulnerabilities and privilege escalation

Access control is the application of constraints on who or what is authorized to perform actions or access resources.

- Authentication confirms that the user is who they say they are.

- Session management identifies which subsequent HTTP requests are being made by that same user.

- Access control determines whether the user is allowed to carry out the action that they are attempting to perform

# !! IMPORTANT

## Vertical access controls

Vertical access controls are mechanisms that restrict access to sensitive functionality to specific types of users.

**With vertical access controls, different types of users have access to different application functions. For example, an administrator might be able to modify or delete any user's account, while an ordinary user has no access to these actions. Vertical access controls can be more fine-grained implementations of security models designed to enforce business policies such as separation of duties and least privilege.**

## Horizontal access controls

Horizontal access controls are mechanisms that restrict access to resources to specific users.

**With horizontal access controls, different users have access to a subset of resources of the same type. For example, a banking application will allow a user to view transactions and make payments from their own accounts, but not the accounts of any other user.**

## Context-dependent access controls

Context-dependent access controls restrict access to functionality and resources based upon the state of the application or the user's interaction with it. 

### Broken access control resulting from platform misconfiguration

Some applications enforce access controls at the platform layer. they do this by restricting access to specific URLs and HTTP methods based on the user's role. For example, an application might configure a rule as follows:

        DENY: POST, /admin/deleteUser, managers

**This rule denies access to the POST method on the URL /admin/deleteUser, for users in the managers group. Various things can go wrong in this situation, leading to access control bypasses.**

Some application frameworks support various non-standard HTTP headers that can be used to override the URL in the original request, such as X-Original-URL and X-Rewrite-URL. If a website uses rigorous front-end controls to restrict access based on the URL, but the application allows the URL to be overridden via a request header, then it might be possible to bypass the access controls using a request like the following:

        POST / HTTP/1.1
        X-Original-URL: /admin/deleteUser
        ...


## Insecure direct object references

         Insecure direct object references (IDORs) are a subcategory of access control vulnerabilities. IDORs occur if an application uses user-supplied input to access objects directly and an attacker can modify the input to obtain unauthorized access. It was popularized by its appearance in the OWASP 2007 Top Ten. It's just one example of many implementation mistakes that can provide a means to bypass access controls. 

### original 
        GET /download-transcript/2.txt HTTP/2
        Host: 0aa000b30469196e8410552c00c60018.web-security-academy.net
        Cookie: session=fWjkyaK8IJcmzWZN13RvdKFYYkD61ayR
        User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
        Accept: */*
        Accept-Language: en-US,en;q=0.5
        Accept-Encoding: gzip, deflate, br
        Referer: https://0aa000b30469196e8410552c00c60018.web-security-academy.net/chat
        Te: trailers
### modified
        GET /download-transcript/1.txt HTTP/2 # basic idor
        Host: 0aa000b30469196e8410552c00c60018.web-security-academy.net
        Cookie: session=fWjkyaK8IJcmzWZN13RvdKFYYkD61ayR
        User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
        Accept: */*
        Accept-Language: en-US,en;q=0.5
        Accept-Encoding: gzip, deflate, br
        Referer: https://0aa000b30469196e8410552c00c60018.web-security-academy.net/chat
        Te: trailers

# Access control vulnerabilities in multi-step processes


    - A variety of inputs or options need to be captured.
    - The user needs to review and confirm details before the action is performed.

## the administrative function to update user details might involve the following steps:

    - Load the form that contains details for a specific user.
    - Submit the changes.
    - Review the changes and confirm.

**A website will implement rigorous access controls over some of these steps, but ignore others. Imagine a website where access controls are correctly applied to the first and second steps, but not to the third step. The website assumes that a user will only reach step 3 if they have already completed the first steps, which are properly controlled. An attacker can gain unauthorized access to the function by skipping the first two steps and directly submitting the request for the third step with the required parameters.** 