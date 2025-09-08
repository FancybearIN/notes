# File upload

- File upload vulnerabilities are when a web server allows users to upload files to its filesystem without sufficiently validating things like their name, type, contents, or size. 

- Failing to properly enforce restrictions on these could mean that even a basic image upload function can be used to upload arbitrary and potentially dangerous files instead. 

- This could even include server-side script files that enable remote code execution. 

## Impact of file upload vulnerabilities

 The impact of file upload vulnerabilities generally depends on two key factors:

    - Which aspect of the file the website fails to validate properly, whether that be its size, type, contents, and so on.
    
    - What restrictions are imposed on the file once it has been successfully uploaded.

In the worst case scenario, the file's type isn't validated properly, and the server configuration allows certain types of file (such as .php and .jsp) to be executed as code. In this case, an attacker could potentially upload a server-side code file that functions as a web shell, effectively granting them full control over the server. 