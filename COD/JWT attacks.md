
**JWT (JSON Web Token)** is a standardized format for sending cryptographically signed JSON data. Often used for AuthN and AuthZ.

It's formed by 3 parts:
- **Header**: base64-encoded, cryptographically clear. Here there are fields like the algorithm.
- **Payload**: base64-encoded, can be cryptographically clear or not. Here there are fields like the token issuer, the expiration date. 
- **Signature**

## JWT header parameter injections

According to the JWS specification, only the `alg` header parameter is mandatory. In practice, however, JWT headers (also known as JOSE headers) often contain several other parameters. The following ones are of particular interest to attackers:

- `jwk` (JSON Web Key) - Provides an embedded JSON object representing the key.
- `jku` (JSON Web Key Set URL) - Provides a URL from which servers can fetch a set of keys containing the correct key.
- `kid` (Key ID) - Provides an ID that servers can use to identify the correct key in cases where there are multiple keys to choose from. Depending on the format of the key, this may have a matching `kid` parameter.

## Vulnerabilities and Labs

- Accepting tokens with no signature
- Accepting tokens with tampered algorithm
- Weak encryption keys
- Misunderstand symmetric and asymmetric encryption
- Using JWS and thinking data is not readable


###### Lab: JWT authentication bypass via unverified signature

The server doesn't verify the signature of any JWTs that it receives.

###### Lab: JWT authentication bypass via flawed signature verification

The server is insecurely configured to accept unsigned JWTs.

###### Lab: JWT authentication bypass via weak signing key

Use hashcat to brute-force the secret key

###### Lab: JWT authentication bypass via jwk header injection

The server supports the `jwk` parameter in the JWT header. This is sometimes used to embed the correct verification key directly in the token. However, it doesn't check whether the provided key came from a trusted source. Hence, we can inject a malicious `jwk` parameter.

###### Lab: JWT authentication bypass via jku header injection

The server supports the `jku` parameter in the JWT header. However, it doesn't check whether the provided URL belongs to a trusted domain before fetching the key.