# my_sockets

# Supported OSes:

Built and tested on Windows10 and Linux Mint (based on Ubuntu 18.04).

# External Dependencies:
None

# Why this library?

Almost all c++ socket libraries I have found have external dependencies (annoying, can be a pain to configure), or try to do too much (example: protocols such as HTTP) are built in (so you get the cruft whether you need it or not), are not header-only, look like C++ used as 'a better C', enforce weird coding styles like multiple lambda, or add 'extra stuff' like event loops or require the introduction of asio. 

If you need HTTP, or 'extra stuff' for your project of course you can build that on top of this library. my_sockets does one thing and one thing only: efficiently abstracts away the creation, connection, data sending and receiving and teardown of your system's native C sockets library.
This library is only concerned with the common tasks required to create, connect and read and write raw data. No extra cruft. If you need some protocol, you code it on top of cppsocks.

# Simple, easy to understand language use

You do not need to be some template meta-programming genius to use my sockets. This style is indeed (sparingly) used in the implementation of this library, but you don't need to concern yourself with it -- unless you want to!
Use the exposed classes to connect/listen and then read and write raw data. 
If you understand classes in C++ (plus a little inheritance and virtual calls in some use-cases), then you can use this library!

# All OS-specific sockets code is hidden away in the library

Just use my_sockets' classes by including a couple header files in your project. 
They work the same in Windows or Linux.
For Windows, the Winsock library is automatically initialised and de-initialised 
for you when you use this project's classes.

Good for ipv4 and ipv6 TCP common use-cases of server, 
client sockets connected to a server, and remote client sockets.

I never use UDP sockets, but there are enough enumerations for you to build your own UDP sockets class if you need to.

