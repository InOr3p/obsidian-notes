OAuth is a commonly used **authorization framework** that enables websites and web applications to request limited access to a user's account on another application. Crucially, OAuth allows the user to grant this access without exposing their login credentials to the requesting application.

The basic OAuth process is widely used to integrate third-party functionality that requires access to certain data from a user's account. For example, an application might use OAuth to request access to your email contacts list so that it can suggest people to connect with. However, the same mechanism is also used to provide third-party authentication services, allowing users to log in with an account that they have with a different website.

OAuth 2.0 was originally developed as a way of sharing access to specific data between applications. It works by defining a series of interactions between three distinct parties:

- **Client application** - The website or web application that wants to access the user's data.
- **Resource owner** - The user whose data the client application wants to access.
- **OAuth service provider** - The website or application that controls the user's data and access to it. They support OAuth by providing an API for interacting with both an *authorization server* and a *resource server*.

There are numerous different ways that the actual OAuth process can be implemented. These are known as OAuth **flows** or **grant types**. We'll focus on the **authorization code** and **implicit** grant types as these are by far the most common.

The grant type affects how the client application communicates with the OAuth service at each stage, including how the access token itself is sent.

For any OAuth grant type, the client application has to specify which data it wants to access and what kind of operations it wants to perform. It does this using the `scope` parameter of the authorization request it sends to the OAuth service.

### Authorization code grant type

![[oauth-authorization-code-flow.jpg]]

#### 1. Authorization request

The client application sends a request to the OAuth service's `/authorization` endpoint asking for permission to access specific user data. Note that the endpoint mapping may vary between providers. However, you should always be able to identify the endpoint based on the parameters used in the request.

```http
GET /authorization?client_id=12345&redirect_uri=https://client-app.com/callback&response_type=code&scope=openid%20profile&state=ae13d489bd00e3c24 HTTP/1.1 
Host: oauth-authorization-server.com
```

This request contains the following noteworthy parameters, usually provided in the query string:

- `client_id`
    
    Mandatory parameter containing the unique identifier of the client application. This value is generated when the client application registers with the OAuth service.
    
- `redirect_uri`
    
    The URI to which the user's browser should be redirected when sending the authorization code to the client application. This is also known as the "callback URI" or "callback endpoint".
    
- `response_type`
    
    Determines which kind of response the client application is expecting and, therefore, which flow it wants to initiate. For the authorization code grant type, the value should be `code`.
    
- `scope`
    
    Used to specify which subset of the user's data the client application wants to access.
    
- `state`
    
    Stores a unique, unguessable value that is tied to the current session on the client application. The OAuth service should return this exact value in the response, along with the authorization code. This parameter serves as a form of **CSRF token** for the client application by making sure that the request to its `/callback` endpoint is from the same person who initiated the OAuth flow.

#### 2. User login and consent

When the authorization server receives the initial request, it will redirect the user to a login page, where they will be prompted to log in to their account with the OAuth provider. For example, this is often their social media account.

They will then be presented with a list of data that the client application wants to access. This is based on the scopes defined in the authorization request. The user can choose whether or not to consent to this access.

The first time the user selects "Log in with social media", they will need to manually log in and give their consent, but if they revisit the client application later, they will often be able to log back in with a single click.

#### 3. Authorization code grant

If the user consents to the requested access, their browser will be redirected to the `/callback` endpoint that was specified in the `redirect_uri` parameter of the authorization request. The resulting `GET` request will contain the authorization code as a query parameter. Depending on the configuration, it may also send the `state` parameter with the same value as in the authorization request.

```http
GET /callback?code=a1b2c3d4e5f6g7h8&state=ae13d489bd00e3c24 HTTP/1.1 
Host: client-app.com
```

#### 4. Access token request

Once the client application receives the authorization code, it needs to exchange it for an access token.  To do this, it sends a server-to-server `POST` request to the OAuth service's `/token` endpoint.

All communication from this point on takes place in a secure back-channel (**backend-to-backend**) and, therefore, cannot usually be observed or controlled by an attacker.

```http
POST /token HTTP/1.1 
Host: oauth-authorization-server.com 
... 
client_id=12345&client_secret=SECRET&redirect_uri=https://client-app.com/callback&grant_type=authorization_code&code=a1b2c3d4e5f6g7h8
```

In addition to the `client_id` and authorization `code`, you will notice the following new parameters:

- `client_secret`
    
    The client application must authenticate itself by including the secret key that it was assigned when registering with the OAuth service.
    
- `grant_type`
    
    Used to make sure the new endpoint knows which grant type the client application wants to use. In this case, this should be set to `authorization_code`.

#### 5. Access token grant

The OAuth service will validate the access token request. If everything is as expected, the server responds by granting the client application an access token with the requested scope.

```json
{ "access_token": "z0y9x8w7v6u5", "token_type": "Bearer", "expires_in": 3600, "scope": "openid profile", … }
```

#### 6. API call

Now that the client application has the access code, it can finally fetch the user's data from the resource server. To do this, it makes an API call to the OAuth service's `/userinfo` endpoint. The access token is submitted in the `Authorization: Bearer` header to prove that the client application has permission to access this data.

```http
GET /userinfo HTTP/1.1 
Host: oauth-resource-server.com 
Authorization: Bearer z0y9x8w7v6u5
```

#### 7. Resource grant

The resource server should verify that the token is valid and that it belongs to the current client application. If so, it will respond by sending the user's data based on the scope of the access token.

```json
{ "username":"carlos", "email":"carlos@carlos-montoya.net", … }
```


The client application can finally use this data for its intended purpose. In the case of OAuth authentication, it will typically be used as an ID to grant the user an authenticated session, effectively logging them in.

### Implicit grant type

The implicit grant type is much simpler. Rather than first obtaining an authorization code and then exchanging it for an access token, the client application receives the access token immediately after the user gives their consent. 
It is far less secure, because all communication happens via browser redirects - there is no secure back-channel like in the authorization code flow. This means that the sensitive access token and the user's data are more exposed to potential attacks.


![[oauth-implicit-flow.jpg]]



## Vulnerabilities

- Open redirects lead to token theft
- Improper validation
- Custom implementations
- Excessive trust on confidentiality of tokens stored in the browser (if there is XSS, tokens can be stolen)

## Labs

#### Flawed CSRF protection

Although many components of the OAuth flows are optional, some of them are strongly recommended, like the `state` parameter.

The `state` parameter should ideally contain an unguessable value, such as the hash of something tied to the user's session when it first initiates the OAuth flow. This value is then passed back and forth between the client application and the OAuth service as a form of CSRF token for the client application. Therefore, if you notice that the authorization request does not send a `state` parameter, it potentially means that you can initiate an OAuth flow before tricking a user's browser into completing it, similar to a traditional CSRF attack.

Consider a website that allows users to log in using either a classic, password-based mechanism or by linking their account to a social media profile using OAuth. In this case, if the application fails to use the `state` parameter, an attacker could potentially hijack a victim user's account on the client application by binding it to their own social media account.
###### Force OAuth profile linking

- There's no state, hence no binding between profile and code (received by the OAuth server)
- If there are some problems: do not use "Login with social media", use instead "Attach social profile"

### Leaking authorization codes and access tokens

The most infamous OAuth-based vulnerability is when the configuration of the OAuth service itself enables attackers to steal authorization codes or access tokens associated with other users' accounts. By stealing a valid code or token, the attacker may be able to access the victim's data. Ultimately, this can completely compromise their account - the attacker could potentially log in as the victim user on any client application that is registered with this OAuth service.

Depending on the grant type, either a code or token is sent via the victim's browser to the `/callback` endpoint specified in the `redirect_uri` parameter of the authorization request. If the OAuth service fails to validate this URI properly, an attacker may be able to construct a CSRF-like attack, tricking the victim's browser into initiating an OAuth flow that will send the code or token to an attacker-controlled `redirect_uri`.

In the case of the authorization code flow, an attacker can potentially steal the victim's code before it is used. They can then send this code to the client application's legitimate `/callback` endpoint (the original `redirect_uri`) to get access to the user's account. In this scenario, an attacker does not even need to know the client secret or the resulting access token. As long as the victim has a valid session with the OAuth service, the client application will simply complete the code/token exchange on the attacker's behalf before logging them in to the victim's account.

Note that using `state` or `nonce` protection does not necessarily prevent these attacks because an attacker can generate new values from their own browser.
###### OAuth accoung hijacking via redirect_uri

- There's no check on the redirect_uri (we can inject a malicious uri, that is the exploit server)
- Take the /auth request and modify the redirect_uri to point to a landing page of the exploit server.  
- Trigger top-level navigation and take the code from the log.  
- Invalidate your session (delete the session cookie).  
- Use the code to authenticate (visit /oauth-callback with the stolen code).

## Prevention

- Use allow list to avoid malicious open redirects and improper validation
-  Use only well established libraries
- Confidentiality of tokens:
	- Application storage is better than cookies: at least data is not transmitted with every request
	- Session storage is better than application storage: different tabs, different data
	- Browser memory is better than session storage: must study the source code to find data