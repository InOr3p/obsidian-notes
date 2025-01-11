
- Also known as **shell injection**, it's an injection that causes the execution of OS commands, often arbitrary **RCE** (*Remote Command Execution*)

- It allows an attacker to execute operating system (OS) commands on the server that is running an application

## Example

In this example, a shopping application lets the user view whether an item is in stock in a particular store. This information is accessed via a URL:

`https://insecure-website.com/stockStatus?productID=381&storeID=29`

To provide the stock information, the application must query various legacy systems. The functionality is implemented by calling out to a shell command with the product and store IDs as arguments:

`stockreport.pl 381 29`

This command outputs the stock status for the specified item, which is returned to the user.

The application implements no defenses against OS command injection, so an attacker can submit the following input to execute an arbitrary command:

`& echo aiwefwlguh &`

If this input is submitted in the `productID` parameter, the command executed by the application is:

`stockreport.pl & echo aiwefwlguh & 29`

The `echo` command causes the supplied string to be echoed in the output. This is a useful way to test for some types of OS command injection. The `&` character is a shell command separator. In this example, it causes three separate commands to execute, one after another. The output returned to the user is:

`Error - productID was not provided aiwefwlguh 29: command not found`

The three lines of output demonstrate that:

- The original `stockreport.pl` command was executed without its expected arguments, and so returned an error message.
- The injected `echo` command was executed and the supplied string was echoed in the output.
- The original argument `29` was executed as a command, which caused an error.

###### Lab: OS command injection, simple case

The application executes a shell command containing user-supplied product and store IDs, and returns the raw output from the command in its response.

Execute the `whoami` command to determine the name of the current user.

- Intercept the stock checker request and modify it like this:

```http
productId=2%26whoami&storeId=1
```

- Notice the `%26` which indicates the URL-encoding of the character `&`

## Blind OS command injection vulnerabilities

Many instances of OS command injection are blind vulnerabilities. This means that the application does not return the output from the command within its HTTP response. Blind vulnerabilities can still be exploited, but different techniques are required.

As an example, imagine a website that lets users submit feedback about the site. The user enters their email address and feedback message. The server-side application then generates an email to a site administrator containing the feedback. To do this, it calls out to the `mail` program with the submitted details:

`mail -s "This site is great" -aFrom:peter@normal-user.net feedback@vulnerable-website.com`

The output from the `mail` command (if any) is not returned in the application's responses, so using the `echo` payload won't work. In this situation, you can use a variety of other techniques to detect and exploit a vulnerability.

### Detecting blind OS command injection using time delays

You can use an injected command to trigger a time delay, enabling you to confirm that the command was executed based on the time that the application takes to respond. The `ping` command is a good way to do this, because lets you specify the number of ICMP packets to send. This enables you to control the time taken for the command to run:

`& ping -c 10 127.0.0.1 &`

This command causes the application to ping its loopback network adapter for 10 seconds.

###### Lab: Blind OS command injection with time delays

- Intercept the submit feedback request and change its body like this:

```http
csrf=kFOMLHCqKs6SA7wZBUarSwAPHX2MqFUf&name=name&email=%26 ping -c 10 127.0.0.1 %26&subject=ciao&message=message
```

### Exploiting blind OS command injection by redirecting output

You can redirect the output from the injected command into a file within the web root that you can then retrieve using the browser. For example, if the application serves static resources from the filesystem location `/var/www/static`, then you can submit the following input:

`& whoami > /var/www/static/whoami.txt &`

The `>` character sends the output from the `whoami` command to the specified file. You can then use the browser to fetch `https://vulnerable-website.com/whoami.txt` to retrieve the file, and view the output from the injected command.

###### Lab: Blind OS command injection with output redirection

This lab contains a blind OS command injection vulnerability in the feedback function.

The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response. However, you can use output redirection to capture the output from the command. There is a writable folder at:

`/var/www/images/`

The application serves the images for the product catalog from this location. You can redirect the output from the injected command to a file in this folder and then use the image loading URL to retrieve the contents of the file.

Execute the `whoami` command and retrieve the output.

- Intercept the submit feedback request and change its body like this:

```http
csrf=zfvuXIJxZZsDoeWROKNXjSRQsS1fMAx9&name=name&email=%26 whoami > /var/www/images/whoami.txt %26&subject=subj&message=message
```

Then, open an image in another tab and access the file just created (`whoami.txt`) by modifying the URL:

```http
https://0aab00df03a9661e814d84bc0015004c.web-security-academy.net/image?filename=whoami2.txt
```

## Ways of injecting OS commands

You can use a number of shell metacharacters to perform OS command injection attacks.

A number of characters function as command separators, allowing commands to be chained together. The following command separators work on both Windows and Unix-based systems:

- `&`
- `&&`
- `|`
- `||`

The following command separators work only on Unix-based systems:

- `;`
- Newline (`0x0a` or `\n`)

On Unix-based systems, you can also use backticks or the dollar character to perform inline execution of an injected command within the original command:

- `` ` `` injected command `` ` ``
- `$(` injected command `)`

## Other code injections

### Python


![[Schermata del 2025-01-11 18-55-39.png]]

![[Schermata del 2025-01-11 18-56-02.png]]


## Prevention

- If possible, avoid shell commands, and use APIs
- Validate!
- Use allow lists, not disallow lists
- Use DDD!