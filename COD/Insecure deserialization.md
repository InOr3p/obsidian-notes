- **Serialization** is the process of converting complex data structures, such as objects and their fields, into a "flatter" format that can be sent and received as a sequential stream of bytes.
- **Deserialization** is the process of restoring this byte stream to a fully functional replica of the original object, in the exact state as when it was serialized.

- Many programming languages have serialization and deserialization mechanisms to store and transfer objects. Often such mechanisms are unsafe.

## What is insecure deserialization?

Insecure deserialization is when user-controllable data is deserialized by a website. This potentially enables an attacker to manipulate serialized objects in order to pass harmful data into the application code.

gobuster dir -u <URL> -w path/to/wordlist

It'll spawn some threads which will fuzz some URL-words