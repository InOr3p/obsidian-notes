
Information disclosure, also known as **information leakage**, is when a website unintentionally reveals sensitive information to its users. Depending on the context, websites may leak all kinds of information to a potential attacker, including:

- Data about other users, such as usernames or financial information
- Sensitive commercial or business data
- Technical details about the website and its infrastructure

### Examples

- Files for web crawlers (*/robots.txt* and */sitemap.xml*)
- Directory listings: easier to discover unintended files
- Developer comments (credentials or known bugs)
- Error messages and debugging data (stack trace and other internal data)
- Backup files and version control history containing source codes or credentials

###### Lab: Information disclosure in error messages

- This lab's verbose error messages reveal that it is using a vulnerable version of a third-party framework.
- Open one of the product pages.
- Notice that the `GET` request for product pages contains a `productID` parameter. Note that your `productId` might be different depending on which product page you loaded.
- Change the value of the `productId` parameter to a non-integer data type, such as a string. Send the request:

```http
GET /product?productId="example"
```

- The unexpected data type causes an exception, and a full stack trace is displayed in the response. This reveals that the lab is using Apache Struts 2 2.3.31.

###### Lab: Information disclosure on debug page

- Open the Home page source code and notice this comment:

```html
<!-- <a href=/cgi-bin/phpinfo.php>Debug</a> -->
```

- Try to access to the endpoint `/cgi-bin/phpinfo.php`
- In the php info page, search for `SECRET_KEY`

###### Lab: Source code disclosure via backup files

- Access to the `robots.txt` file and notice this line:

`Disallow: /backup`

- Try to access to the `/backup` endpoint and then view the source code

###### Lab: Authentication bypass via information disclosure

- This lab's administration interface has an authentication bypass vulnerability, but it is impractical to exploit without knowledge of a custom HTTP header used by the front-end.

- To solve the lab, obtain the header name then use it to bypass the lab's authentication. Access the admin interface and delete the user `carlos`.

- If you try to accesso to the /admin endpoint, you can notice the message *"Admin interface only available to local users"*

- Add the header `X-Custom-IP-Authorization: 127.0.0.1` to the endpoint `delete?username=carlos`. Now you should have been deleted the user carlos

## Prevention

- Identify all sensitive information (every developer must be aware of them)
- Audit code for potential information disclosure
- Don’t hardcode credentials and sensitive information
- Use generic error messages:
	- Implement a global exception handler
- Debugging and diagnostic features must be disabled
	- Test for them in the deployed system
- Don’t use configurations or third-party technologies if you don’t understand them