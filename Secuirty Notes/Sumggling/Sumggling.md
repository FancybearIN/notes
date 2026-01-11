HTTP request smuggling is a technique for interfering with the way a web site processes sequences of HTTP requests that are received from one or more users. Request smuggling vulnerabilities are often critical in nature, allowing an attacker to bypass security controls, gain unauthorized access to sensitive data, and directly compromise other application users.

## What happens in an HTTP request smuggling attack?



 Content-length : Is a header tell size of the server how bigger request body.
 Transfer-encoding : do same in chunk by chunk to server.

http parsing is way of tell the server figure out which type of request send by web application.