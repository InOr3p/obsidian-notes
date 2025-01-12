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

### Horizontal privilege escalation

User gains access to **resources of another user**.