#! /usr/bin/env python

import base64
import select
import socket
import sys
import traceback
from random import randint
from threading import Thread

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5535
DEFAULT_BUFSIZE = 1024


class Client:
    def __init__(
        self,
        user_name: str,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        bufsize: int = DEFAULT_BUFSIZE,
    ) -> None:
        self.user_name = user_name
        self.host = host
        self.port = port
        self.bufsize = bufsize
        self.__init_keys()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__configure_socket()
        self.run()

    def __init_keys(self) -> None:
        self.__private_key: X25519PrivateKey = X25519PrivateKey.generate()
        self.public_key: X25519PublicKey = self.__private_key.public_key()
        self.__shared_key: bytes = b""
        self.__derived_key: bytes = b""
        self.__symmetric_key: Fernet | None = None

    def __generate_derived_key(self, peer_public_key: bytes) -> None:
        public_key = X25519PublicKey.from_public_bytes(peer_public_key)
        self.__shared_key = self.__private_key.exchange(public_key)
        self.__derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data",
        ).derive(self.__shared_key)

    def __generate_symmetric_key(self, peer_public_key: bytes = b"") -> None:
        if peer_public_key != b"":
            self.__generate_derived_key(peer_public_key)
        urlsafe_b64_encode = base64.urlsafe_b64encode(self.__derived_key)
        self.__symmetric_key = Fernet(urlsafe_b64_encode)

    def __configure_socket(self) -> None:
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
            while self.__symmetric_key is None:
                msg = "public_key,".encode()
                msg += self.public_key.public_bytes_raw()
                self.socket.send(msg)
                data = self.socket.recv(self.bufsize)
                if data != b"":
                    type, peer_public_key = data.split(b",")
                    self.__generate_symmetric_key(
                        peer_public_key=peer_public_key
                    )
                    if type == b"public_key":
                        msg = "response,".encode()
                        msg += self.public_key.public_bytes_raw()
                        self.socket.send(msg)

            thread_send = Thread(target=self.send)
            thread_listen = Thread(target=self.listen, daemon=True)
            thread_send.start()
            thread_listen.start()
            thread_send.join()

    def send(self) -> None:
        while (msg := input(">> ")) != "exit":
            if msg == "":
                continue
            data = f"{self.user_name}: {msg}".encode()
            encrypted_data = self.__symmetric_key.encrypt(data)
            self.socket.send(encrypted_data)
        self.socket.send(msg.encode())

    def listen(self) -> None:
        while True:
            [read], _, _ = select.select([self.socket], [], [])
            try:
                msg = read.recv(self.bufsize)
                decrypted_msg = self.__symmetric_key.decrypt(msg)
                print(f"Message from {decrypted_msg.decode()}\n>> ", end="")
            except Exception:
                traceback.print_exc(file=sys.stdout)
                break


if __name__ == "__main__":
    if len(sys.argv) > 1:
        Client(sys.argv[1])
    else:
        user = f"user{randint(0,1_000_000)}"
        Client(user)
