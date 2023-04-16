#! /usr/bin/env python

import select
import socket
import sys
import traceback
from threading import Thread

"""
    threading.Thread python class for Threads

    Its subclasses only can override the __init__ and run methods.

    To start a Thread its method start() need to be called at most once per Thread object, this will arrange to the run method to be invoked in a separated thread of control.

    Daemon threads needs to be set before the call to start() method.
    The entire Python program exits when no alive non-daemon threads are left. 
"""
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5535
DEFAULT_BUFFSIZE = 1024


class Client:
    def __init__(
        self,
        user_name: str,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        buffsize: int = DEFAULT_BUFFSIZE,
    ) -> None:
        self.user_name = user_name
        self.host = host
        self.port = port
        self.buffsize = buffsize
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.configure_socket()
        self.run()

    def configure_socket(self) -> None:
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def run(self) -> None:
        with self.socket as client:
            print(
                f"Connecting to: ({self.host}, {self.port}) as {self.user_name}"
            )
            client.connect((self.host, self.port))
            print(
                f"Connected to {client.getpeername()} as {self.user_name}:{client.getsockname()}"
            )
            thread_send = Thread(target=self.send)
            thread_listen = Thread(target=self.listen, daemon=True)
            thread_send.start()
            thread_listen.start()
            thread_send.join()

    def send(self) -> None:
        while (msg := input(">> ")) != "exit":
            if msg == "":
                continue
            data = f"{self.user_name}: {msg}"
            self.socket.send(data.encode())

    def listen(self) -> None:
        while True:
            [read], _, _ = select.select([self.socket], [], [])
            try:
                msg = read.recv(self.buffsize)
                print(f"Message from {msg.decode()}\n>> ", end="")
            except Exception:
                traceback.print_exc(file=sys.stdout)
                break


if __name__ == "__main__":
    if len(sys.argv) > 1:
        Client(sys.argv[1])
    else:
        Client("vinibaggio")
