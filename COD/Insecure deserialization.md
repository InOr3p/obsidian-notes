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

Take the cookie, URL-decode and then Base64-decode it. You'll get this PHP deserialized object:

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

### Using application functionality

A website's functionality might also perform dangerous operations on data from a deserialized object. In this case, you can use insecure deserialization to pass in unexpected data and leverage the related functionality to do damage.

For example, as part of a website's "Delete user" functionality, the user's profile picture is deleted by accessing the file path in the `$user->image_location` attribute. If this `$user` was created from a serialized object, an attacker could exploit this by passing in a modified object with the `image_location` set to an arbitrary file path. Deleting their own user account would then delete this arbitrary file as well.

###### Lab: Using application functionality to exploit insecure deserialization

Take the session cookie, decode it (URL and Base64): 
```
O:4:"User":3:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"g4o1z9tikapjpind30f9mc7lsxl8vd0g";s:11:"avatar_link";s:19:"users/wiener/avatar";}
```

Change `"users/wiener/avatar"` to `"/home/carlos/morale.txt"` and its size. Then delete the user in order to delete the file morale.txt.

### Magic methods

Magic methods are a special subset of methods that you do not have to explicitly invoke. Instead, they are invoked automatically whenever a particular event or scenario occurs. Magic methods are a common feature of object-oriented programming in various languages. They are sometimes indicated by prefixing or surrounding the method name with double-underscores.

One of the most common examples in PHP is `__construct()`, which is invoked whenever an object of the class is instantiated, similar to Python's `__init__`.

Magic methods are widely used and do not represent a vulnerability on their own. But they can become dangerous when the code that they execute handles attacker-controllable data, for example, from a deserialized object. This can be exploited by an attacker to automatically invoke methods on the deserialized data when the corresponding conditions are met.

Most importantly in this context, some languages have magic methods that are invoked automatically during the deserialization process. For example:
- PHP's `unserialize()` method looks for and invokes an object's `__wakeup()` magic method.
Anyway, there are many magic methods called automatically:

- `__constructor()` and `__wakeup()` are used during instantiation;
- `__destruct()` is called when the object is not needed anymore
- `__call()` is invoked when an undefined method is called

Note that users may tamper also the class name, hence it’s sufficient to have a single vulnerable class to have problems.

### Gadget chains

A "gadget" is a snippet of code that exists in the application that can help an attacker to achieve a particular goal. An individual gadget may not directly do anything harmful with user input. However, the attacker's goal might simply be to invoke a method that will pass their input into another gadget. By chaining multiple gadgets together in this way, an attacker can potentially pass their input into a dangerous "sink gadget", where it can cause maximum damage.

Manually identifying gadget chains can be a fairly arduous process, and is almost impossible without source code access. Fortunately, there are a few options for working with pre-built gadget chains, for example for PHP-based sites you can use **"PHP Generic Gadget Chains" (PHPGGC)**.


```
gobuster dir -u <URL> -w path/to/wordlist
```

It'll spawn some threads which will fuzz some URL-words

## Prevention

- Deserialization of user input should be avoided unless absolutely necessary.
- If you do need to deserialize data from untrusted sources, incorporate robust measures to make sure that the data has not been tampered with. For example, you could implement a digital signature to check the integrity of the data. However, remember that any checks must take place **before** the beginning of the deserialization process.