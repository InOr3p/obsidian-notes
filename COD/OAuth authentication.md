




## Labs

###### Force OAuth profile linking

- There's no state, hence no binding between profile and code (receive by the OAuth server)
- If there are some problems: do not use "Login with social media", use instead "Attach social profile"

###### OAuth accoung hijacking via redirect_uri

- There's no check on the redirect_uri (we can inject a malicious uri, that is the exploit server)