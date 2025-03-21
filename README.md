# toolbox-trivial-spring-jwt-auth
#Toolbox :

This toolbox provides useful Java utilities.

My "Toolbox" projects will be a series of projects designed to do common things in a number of different ways, from the complex to the trivial.
They could be used as skeletons to start working on your own code, or by comparing different versions to understand what needs to be done to do things in a better way.
They might also be useful as test stubs. 

---

This project's documentation (including this README.md) is licensed under the Creative Commons Attribution-ShareAlike 4.0 International License  CC BY-SA 4.0 (Creative Commons Attribution-ShareAlike 4.0).

---

Code License:

This project's code is dual-licensed under the MIT License and the Apache License 2.0.
(Followed by the full license texts)

You may choose to use this software under the terms of either the MIT License or the Apache License 2.0.

##  A trivial spring jwt auth microservice. 

This is a microservice providing a ridiculously simple authentication microservice that might be useful for testsing purposes.

It has basic roles, but can only have up to four of them and a user can only have one role.

If you want more use toolbox-simple-spring-jwt-auth which uses an embedded database and has data maintenance pages.

Any changes to the list of users or the port are expected to be made before building and using.

You will need to manage access to the key file. This should be changed before deployment, it ciontains a base64 encoded key.. 
The spring application.properties is the only config file, apart from the key which is kept in config/jwt-key.txt.

It contains:

server.port by default 8081
app.username.regex=^(user1|user2|user3)$
app.passwordPrefix=
app.passwordSuffix=pass

This means the password for user1 will be user1pass

You should change these fake values, as while this authentication service sends clear passwords and is not safe using standard known values could be even more dangerous if for example this service were to be more exposed than intended.

This service is trivial, but could still be useful in its own right in testing. 

It only has simple console logging enabled.

