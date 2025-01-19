## What is authentication?

- **Authentication** (**AuthN**) verifies who the user claim to be. In a website AuthN determines if the user claiming to be Alice is the same person who created the account

- **Authorization** (**AuthZ**) verifies what the user is allowed to do. AuthZ is often referred to as Access Control

## Authentication factors

- **Something you know** (knowledge factors): Password, PIN, answers to prearranged questions. It may be guessed, stealed or forgotten

- **Something you have** (possession factors): Tokens from electronic keycards, smart cards, and physical keys. It may be forged, stealed or lost

- **Something you are** (static inherence factors): Static biometrics like fingerprint, retina, and face. User acceptance, cost, and convenience

- **Something you do** (dynamic inherence factors): Dynamic biometrics like voice pattern, handwriting characteristics, and typing rhythm. User acceptance, cost, and convenience

## Vulnerabilities in authentication mechanisms

A website's authentication system usually consists of several distinct mechanisms where vulnerabilities may occur. Some vulnerabilities are applicable across all of these contexts. Others are more specific to the functionality provided.

Some of the most common vulnerabilities are:
- **Vulnerabilities in password-based login**
- **Vulnerabilities in multi-factor authentication**
- **Vulnerabilities in other authentication mechanisms**

### Vulnerabilities in password-based login

- **Password-based authentication**: users provide credentials, a username and a password. The system compares the credentials with those stored, granting access if a match is found.

In this scenario, the fact that they know the secret password is taken as sufficient proof of the user's identity. This means that the security of the website is compromised if an attacker is able to either obtain or guess the login credentials of another user.

If a website can send you your password, it means that the website stores your password somewhere, and it’s bad! If a website can check if your new password is similar to the previous five, that website stores your last five passwords somewhere!
#### Brute-force attacks

A brute-force attack is when an attacker uses a system of trial and error to guess valid user credentials. These attacks are typically automated using wordlists of usernames and passwords.

Types of brute-force attacks:
- **Brute-forcing usernames**
- **Brute-forcing passwords**
- **Username enumeration** (when an attacker is able to observe changes in the website's behavior in order to identify whether a given username is valid). In this case, you should pay particular attention to any differences in:
	- **Status codes**: During a brute-force attack, the returned HTTP status code is likely to be the same for the vast majority of guesses because most of them will be wrong. If a guess returns a different status code, this is a strong indication that the username was correct. It is best practice for websites to always return the same status code regardless of the outcome, but this practice is not always followed.
	- **Error messages**: Sometimes the returned error message is different depending on whether both the username AND password are incorrect or only the password was incorrect. It is best practice for websites to use identical, generic messages in both cases, but small typing errors sometimes creep in. Just one character out of place makes the two messages distinct, even in cases where the character is not visible on the rendered page.
	- **Response times**: If most of the requests were handled with a similar response time, any that deviate from this suggest that something different was happening behind the scenes. This is another indication that the guessed username might be correct. For example, a website might only check whether the password is correct if the username is valid. This extra step might cause a slight increase in the response time. This may be subtle, but an attacker can make this delay more obvious by entering an excessively long password that the website takes noticeably longer to handle.

###### Lab: Username enumeration via different responses

- Intercept the login request and fuzz on the username by using the provided wordlists.

- Notice that there's a response with a size different from the others. The username associated to this response is a registered user (*asia*).

- Then, fuzz on the password by using the provided wordlists and using the username previously found. The password will be *159753*.

###### Lab: Username enumeration via response timing

This lab can be solved only via script. The script should do:

- username enumeration using the provided wordlist, that is fuzzing on the usernames by changing every time the *X-Forwarded-For* header with a random value;

- sort the usernames by largest time responses;

- do the same thing with the passwords (fixing the username on the one with the largest time response) and stopping when we get a status code 302.

### Vulnerabilities in multi-factor authentication

- **Multifactor authentication**: use multiple authentication factors (not two times the same factor)

###### Lab: 2FA simple bypass

1. Log in to your own account (credentials `wiener:peter`). Your 2FA verification code will be sent to you by email. 
2. Log out of your account (by going back to `/login` endpoint).
3. Log in using the victim's credentials (credentials `carlos-montoya`).
4. When prompted for the verification code, manually change the URL to navigate to `/my-account`.

###### Lab: Password reset broken logic

- Intercept the reset password request:

```http
POST https://0ae000910474c34383a31031002a0003.web-security-academy.net/forgot-password?temp-forgot-password-token=g3kr0iay75ugx1ub30ww9ztn914yz0b1 HTTP/1.1

temp-forgot-password-token=g3kr0iay75ugx1ub30ww9ztn914yz0b1&username=wiener&new-password-1=peter&new-password-2=peter
```

- Notice that in the request body there's the username together with the new password.

- Try to change the username to `carlos`:

```http
temp-forgot-password-token=g3kr0iay75ugx1ub30ww9ztn914yz0b1&username=wiener&new-password-1=peter&new-password-2=peter
```

- Now if you should be able to login as `carlos:peter`!

## Prevention

- Don’t save users’ passwords! Not in clear, not even encrypted
- Store the **hash value** of the password combined with a **salt** value! Salt makes **rainbow tables** exponentially bigger (so they cannot be produced). Modern password hash/salt scheme use **Bcrypt**, which includes a cost variable (the number of iterations of the hash function)
- Use the **Password Protocol**: the server sends to the client a **nonce** which will be used to hash the password. The client will then send to the server the hashed password. The nonce protects against **replay attacks** (since it changes at every session)!
- Use the **Token Protocol**: user password is used to generate a token, which is stored on the server
- Use **HTTPS** (redirect any HTTP request to HTTPS)
- Prevent username enumeration: generic and identical error messages for invalid username or password
- Implement robust brute-force protection: implement CAPTCHA test with every login attempt
- Slow down login attempts: lock the attacked account or block attacker’s IP address