Access control, also know as **Authorization** or **AuthZ**, is the application of constraints on who or what is authorized to perform actions or access resources. 

Access control implements a **security policy** that specifies who or what may have access to
each specific system resource, and the type of access that is permitted in each instance.

In the context of web applications, access control is dependent on authentication and session management:

- **Authentication** confirms that the user is who they say they are.
- **Session management** identifies which subsequent HTTP requests are being made by that same user.
- **Access control** determines whether the user is allowed to carry out the action that they are attempting to perform.

Broken access controls are common and often present a critical security vulnerability. Access control design decisions have to be made by humans so the potential for errors is high.

## What are access control security models?

An access control security model is a formally defined definition of a set of access control rules that is independent of technology or implementation platform. Access control security models are implemented within operating systems, networks, database management systems and back office, application and web server software.

An access control security policy or model makes use of the following elements:

- **a set of constraints or rules** made of triples (subjects, objects, access rights)
- **subject**: 
	- a user, a group, or a role 
	- the owner of the object
	- a user with some attributes
- **access right**:
	- read
	- write
	- execute
	- delete
	- create
	- search

Policies are not mutually exclusive, but they are often combined (it could be a bad idea)!

### Discretionary access control (DAC)

- The owner of each resource states who can have access to that resource, and what can be done.
- Used in UNIX file systems
- It can be implemented by using an **access matrix** (has users as rows, files as columns and access rights in each cell) which can be:
	- **ACL** (*Access Control List*): a **linked list** that decomposes an access matrix by columns. Good to determine which subjects have which rights on a specific resource. Bad to determine the access rights of a specific subject
	- **Capabilities tickets**: a **linked list** that decomposes an access matrix by rows. Bad to determine which subjects have which rights on a specific resource. Good to determine the access rights of a specific subject
	- **Authorization Tables**: a table that just represent triples! Filter by subject to obtain a capability list. Filter by object to obtain an ACL. One row for each access right of each subject on each object

![[Schermata del 2025-01-12 19-32-03.png]]

![[Schermata del 2025-01-12 19-32-31.png]]


![[Schermata del 2025-01-12 19-32-52.png]]

![[Schermata del 2025-01-12 19-33-11.png]]

### Mandatory access control (MAC)

- Each resource is assigned a *security label (critical level)*, and entities are assigned *security clearances (access level)*
- Main rules to access a resource are:
	- **No Read Up**: a user can read only resources of lower critical level than the user's access level. **Example**: a user with access level *confidential* cannot read a level *secret* resource but can read a level *public* resource  
	- **No Write Down**: a user can write only resources of the same level of the user's access level. **Example**: a user with access level *confidential* cannot write a level *public* resource and cannot neither write a level *secret* resource, since he cannot read it for the No Read Up rule. Hence, he can write only *confidential* level resources
- Emerged for military security. Computer systems needs more flexibility
- **Centralized** access control: unlike DAC the users and owners of resources have no capability to delegate or modify access rights for their resources

### Role-based access control (RBAC)

- **Roles** assigned to entities (both subjects and resources)
- There are rules stating each role what resource can access
- Simple and powerful
- Each user can be associated to single or multiple roles
- Users and their association with roles may change frequently
- The set of roles is relatively static!

### Attribute-based access control (ABAC)

- Access based on attributes of entities and resources
- Resources can be accessed only by users who have specific values for an attribute
- Really powerful, but expensive!

![[Schermata del 2025-01-12 19-56-36.png]]

## Examples of broken access controls

Broken access control vulnerabilities exist when a user can access resources or perform actions that they are not supposed to be able to.

### Vertical privilege escalation

User gains access to not permitted **functionality**.

#### Unprotected functionality
###### Lab: Unprotected admin functionality

- Access the `robots.txt` endpoint and see `Disallow: /administrator-panel` 

- Access the `/administrator-panel` endpoint


##### Secuity through obscurity
###### Lab: Unprotected admin functionality with unpredictable URL

- Access the home page source code and notice the following line of code:

```javascript
adminPanelTag.setAttribute('href', '/admin-eq3apk');
```

- Try to accesso to the `/admin-eq3apk` endpoint

#### Parameter-based access control methods

Some applications determine the user's access rights or role at login, and then store this information in a user-controllable location. This could be:

- A hidden field
- A cookie
- A preset query string parameter

###### Lab: User role controlled by request parameter

- Login as `wiener:peter` and try to access to the `/admin` endpoint but notice the message `Admin interface only available if logged in as an administrator`

- Inspect the cookies in the browser and notice the cookie `Admin: false`

- Inject `Admin: true` and reload the `/admin` page

###### Lab: User role can be modified in user profile

- Login as `wiener:peter` and try to access to the `/admin` endpoint but notice the message `Admin interface only available if logged in as an administrator`

- Update the email address associated with your account

- Intercept again the update email request and add `"roleid": 2` into the JSON in the request body and resend it

```json
{"email":"newemail@gmail.com", "roleid": 2}
```

- Observe that the response shows your `roleid` has changed to 2

- Browse to `/admin` and delete `carlos`

#### Broken access control resulting from platform misconfiguration

###### Lab: Method-based access control can be circumvented

- Login as `administrator:admin` to understand the upgrade-downgrade user process.

- To upgrade-downgrade a user, you must send a request like this:

```http
POST https://0a0e006e04a3f22b847fb35b009e0079.web-security-academy.net/admin-roles HTTP/1.1

Cookie: session=adminCookie
username=carlos&action=upgrade
```

- Now try to login as `wiener:peter` and send again the upgrade-downgrade user request

- See that we get a `401 Unauthorized` response

- Change the request to a `GET` and move `username` (that should have `wiener` as value) and `action` (`upgrade`) from the body to the request params:
```http
GET https://0a0e006e04a3f22b847fb35b009e0079.web-security-academy.net/admin-roles?username=wiener&action=upgrade HTTP/1.1

Cookie: session=wienerCookie
```

- Now the user wiener should be an admin

### Horizontal privilege escalation

User gains access to **resources of another user**.

###### Lab: User ID controlled by request parameter

- Login as `wiener:peter` and notice the URL:

```http
https://0a7e007a045e1e0f82c774d300ba0023.web-security-academy.net/my-account?id=wiener
```

- Change the id from `id=wiener` to `id=carlos` and retreive carlos' API key

###### Lab: User ID controlled by request parameter, with unpredictable user IDs

- Login as `wiener:peter` and notice the URL:

```http
https://0aa800be039caa61815bd4e300320030.web-security-academy.net/my-account?id=568a2d3d-aada-4304-b9a4-500299ddae12
```

- We need to find carlos' GUID

- Go back to the home page and open a blog post. See that the post's writer is carlos and open carlos user page. The URL is:

```http
https://0aa800be039caa61815bd4e300320030.web-security-academy.net/blogs?userId=02948b40-99d7-44a9-a796-a7f7559c347b
```
- We've just found carlos GUID! Use `02948b40-99d7-44a9-a796-a7f7559c347b` as a value for the `id` parameter in `/my-account` endpoint:
```http
https://0aa800be039caa61815bd4e300320030.web-security-academy.net/my-account?id=02948b40-99d7-44a9-a796-a7f7559c347b
```

- Now we're carlos!

### Horizontal to vertical privilege escalation

Often, a horizontal privilege escalation attack can be turned into a vertical privilege escalation, by compromising a more privileged user. For example, a horizontal escalation might allow an attacker to capture the password belonging to another user. If the attacker targets an administrative user, then they can gain administrative access and so perform vertical privilege escalation.

###### Lab: User ID controlled by request parameter with password 

- Login as `wiener:peter` and notice the hidden password in `/my-account` endpoint

- Intercept the request `/my-account?id=wiener` and change the `id` parameter to `administrator`. Notice that in the response we get the administrator's password:

```html
<label>Password</label>  
<input required type="hidden" name="csrf" value="QROewDbxeoxhn1mYjv57oKoQPFskJdiw">  
<input required type=password name=password value='zsc63w4wbydyca1oqyif'/>  
<button class='button' type='submit'> Update password </button>
```

### Access control vulnerabilities in multi-step processes

Many websites implement important functions over a series of steps.

For example, the administrative function to update user details might involve the following steps:

1. Load the form that contains details for a specific user.
2. Submit the changes.
3. Review the changes and confirm.

Imagine a website where access controls are correctly applied to the first and second steps, but not to the third step. The website assumes that a user will only reach step 3 if they have already completed the first steps, which are properly controlled. An attacker can gain unauthorized access to the function by skipping the first two steps and directly submitting the request for the third step with the required parameters.

###### Lab: Multi-step process with no access control on one step

- Login as `administrator:admin` and try to upgrade the user carlos.

- The requests sent are the following:

1. Upgrade request:

```http
POST https://0ad600510347a98182f8e29e002300c2.web-security-academy.net/admin-roles HTTP/1.1

username=carlos&action=upgrade
```

2. Confirmation request:

```http
POST https://0ad600510347a98182f8e29e002300c2.web-security-academy.net/admin-roles HTTP/1.1
Cookie: session=adminCookie

action=upgrade&confirmed=true&username=carlos
```

- Now logout and login again as `wiener:peter` and try to upgrade wiener user to admin but skipping the first request.

- So, send only the confirmation request with wiener's cookie:

```http
POST https://0ad600510347a98182f8e29e002300c2.web-security-academy.net/admin-roles HTTP/1.1
Cookie: session=wienerCookie

action=upgrade&confirmed=true&username=wiener
```

- Now wiener should be admin!

### Referer-based access control

Some websites base access controls on the `Referer` header submitted in the HTTP request. The `Referer` header can be added to requests by browsers to indicate which page initiated a request.

For example, an application robustly enforces access control over the main administrative page at `/admin`, but for sub-pages such as `/admin/deleteUser` only inspects the `Referer` header. If the `Referer` header contains the main `/admin` URL, then the request is allowed.

In this case, the `Referer` header can be fully controlled by an attacker. This means that they can forge direct requests to sensitive sub-pages by supplying the required `Referer` header, and gain unauthorized access.

###### Lab: Referer-based access control

Login as `administrator:admin` to understand the upgrade-downgrade user process.

- To upgrade-downgrade a user, you must send a request like this:

```http
GET https://0ac9007e04b2f86c817c522e009c00c4.web-security-academy.net/admin-roles?username=carlos&action=upgrade HTTP/1.1

Referer: https://0ac9007e04b2f86c817c522e009c00c4.web-security-academy.net/admin
Cookie: session=adminCookie
```

- Now try to login as `wiener:peter` and send again the upgrade-downgrade user request but changing the username parameter with `wiener` and the cookie header value with wiener's cookie:
```http
GET https://0ac9007e04b2f86c817c522e009c00c4.web-security-academy.net/admin-roles?username=wiener&action=upgrade HTTP/1.1

Referer: https://0ac9007e04b2f86c817c522e009c00c4.web-security-academy.net/admin
Cookie: session=wienerCookie
```

- Now the user wiener should be an admin

## Insecure direct object references (IDOR)

- Insecure direct object references (IDOR) are a type of access control vulnerability that arises when there's a missing access control on a resource that can be accessed by directly referencing the object ID.

### Example

Consider a website that uses the following URL to access the customer account page, by retrieving information from the back-end database:

`https://insecure-website.com/customer_account?customer_number=132355`

Here, the customer number is used directly as a record index in queries that are performed on the back-end database. If no other controls are in place, an attacker can simply modify the `customer_number` value, bypassing access controls to view the records of other customers. This is an example of an IDOR vulnerability leading to horizontal privilege escalation.

### IDOR vulnerability with direct reference to static files

IDOR vulnerabilities often arise when sensitive resources are located in static files on the server-side filesystem. For example, a website might save chat message transcripts to disk using an incrementing filename and allow users to retrieve these by visiting a URL like the following:

```http
https://insecure-website.com/static/12144.txt
```

In this situation, an attacker can simply modify the filename to retrieve a transcript created by another user and potentially obtain sensitive data.

###### Lab: Insecure direct object references

- Enter the `live-chat` page and try to send a message and view the transcript

- Intercept these requests and notice the download transcript request:

```http
GET https://0ad2003e03fefd2c852c5b7300d1006d.web-security-academy.net/download-transcript/3.txt HTTP/1.1
```

- Each transcript is stored with an incremental filename. Try to retrieve the file `1.txt`:

```http
GET https://0ad2003e03fefd2c852c5b7300d1006d.web-security-academy.net/download-transcript/1.txt HTTP/1.1
```

- We get a chat of another user (carlos) and we can retrieve carlos' password!

## Prevention

- Don't rely on **obfuscation**!
- Secure default configurations:
	- Deny access by default
	- Authorize only administrators by default
- Don’t mix different access control mechanisms
- Have tests for access controls