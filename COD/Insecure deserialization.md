- **Serialization** is the process of converting complex data structures, such as objects and their fields, into a "flatter" format that can be sent and received as a sequential stream of bytes.
- **Deserialization** is the process of restoring this byte stream to a fully functional replica of the original object, in the exact state as when it was serialized.

- Many programming languages have serialization and deserialization mechanisms to store and transfer objects. Often such mechanisms are unsafe.

## What is insecure deserialization?

Insecure deserialization is when user-controllable data is deserialized by a website. This potentially enables an attacker to manipulate serialized objects in order to pass harmful data into the application code.


## How to identify insecure deserialization

During auditing, you should look at all data being passed into the website and try to identify anything that looks like serialized data (just identify the format that different languages use).

#### PHP serialization format

PHP uses a mostly human-readable string format, with letters representing the data type and numbers representing the length of each entry. For example, consider a `User` object with the attributes:

```php
$user->name = "carlos"; 
$user->isLoggedIn = true;
```

When serialized, this object may look something like this:

```php
O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}
```

The native methods for PHP serialization are `serialize()` and `unserialize()`. Instead of these methods, use `json_encode()` and `json_decode()`.

#### Java serialization format

Java uses binary serialization formats. (more difficult to read). Any class that implements the interface `java.io.Serializable` can be serialized and deserialized.

## Labs

###### Lab: Modifying serialized objects

Take the cookie, URL-decode and then Base64-decode. You'll get this PHP deserialized object:

```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:5:"admin";b:0;}
```

Change `admin` field from 0 to 1.

### Modifying data types

- PHP-based logic is particularly vulnerable to serialized object manipulation due to the behavior of its *loose comparison operator* (`==`) when comparing different data types. For example, PHP evaluates `5 == "5"` to `true`. Unusually, this also works for any alphanumeric string that starts with a number. Therefore, `5 == "5 of something"` is in practice treated as `5 == 5`. Likewise, on PHP 7.x and earlier the comparison `0 == "Example string"` evaluates to `true`.

**Note**: in PHP 8 and later, the `0 == "Example string"` comparison evaluates to `false` because strings are no longer implicitly converted to `0` during comparisons. As a result, this exploit is not possible on these versions of PHP.

###### Lab: Modifying serialized data types

Change the session cookie from

```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"ye6g4a3tsxr26s60dz55xgxrn31vlm71";}
```

to

```
O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}
```

Injecting this new serialized object as a session cookie (URL-encoded and Base64-encoded) will cause a **privilege escalation attack** (we're now administrators).





```
gobuster dir -u <URL> -w path/to/wordlist
```

It'll spawn some threads which will fuzz some URL-words

## Prevention

- Deserialization of user input should be avoided unless absolutely necessary.
- If you do need to deserialize data from untrusted sources, incorporate robust measures to make sure that the data has not been tampered with. For example, you could implement a digital signature to check the integrity of the data. However, remember that any checks must take place **before** beginning the deserialization process.