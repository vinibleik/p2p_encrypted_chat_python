# P2P Encrypted Chat App
#### A simple to use chat program that uses sockets and multi-threading

This is a p2p encrypted chat program written in python. 

## 1. Getting started

Create a new environment and install the requirements
```sh
$ python3 -m venv venv 
$ source venv/bin/activate
$ pip install -r requirements.txt
````

Now move to the cryptography directory
```sh
$ cd cryptography/
````

Start the server using 
```sh
$ python Server.py
````
The Server handle all connections, distributing every message that comes to it for each socket that are connect to the server, except for the one that sent the message.

The clients can connect to the server through Client.py
```sh
$ python Client.py [username]
````
The optional parameter given to Client.py is your username, if don\'t given, a random username will be used instead.
Any number of clients can be connected to the Server, or as many as your pc can handle kk.
All the communication is encrypted using the cryptography library.
First of all, the Asymmetric RSA public key is distributed for all members in the chat.
So, the Fernet symmetric key is sent back encrypted by this public key.
Now all the communication is made by symmetric encryption using the Fernet key. 
Also, each message carry your original hash, that are verified at each deserialization of the message. And if anything got wrong, this corrupted message is ignored. But if, something got wrong at the symmetric key exchange, the client will be disconnected from the chat, because he can\'t communicate secretly.

----
There is no need to configure any PORT or HOST ip, everything is done automatically, if you wish to change something, modify the default PORT and HOST in both files Client.py and Server.py. 
By default the HOST is 127.0.0.1 and Server\'s PORT is 5535

##4. License
This work is licensed with the MIT license

####The MIT License (MIT)
Copyright (c) 2015 Rakshith G & (c) 2023 Vinicius

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
