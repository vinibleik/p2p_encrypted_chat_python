#! /usr/bin/env python

import select
import socket
import sys
import time
import traceback
from random import randint
from threading import Thread

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5535
DEFAULT_BUFSIZE = 4096


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
        self.__init_asymmetric_keys()
        self.__configure_socket()
        self.run()

    def __configure_socket(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def __init_asymmetric_keys(self) -> None:
        self.__private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=1024
        )
        self.public_key = self.__private_key.public_key()

    def public_key_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def __init_symmetric_keys(self, key: bytes = b"") -> None:
        if key:
            self.__symmetric_key = key
            self.symmetric_key = Fernet(key)
        else:
            self.__symmetric_key = Fernet.generate_key()
            self.symmetric_key = Fernet(self.__symmetric_key)

    def decrypt_asymmetric_message(self, message: bytes) -> bytes:
        return self.__private_key.decrypt(
            message,
            padding=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def encrypt_asymmetric_message(
        self, message: bytes, peer_public_key: bytes = b""
    ) -> bytes:
        public_key = (
            serialization.load_pem_public_key(peer_public_key)
            if peer_public_key
            else self.public_key
        )

        return public_key.encrypt(
            message,
            padding=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def decrypt_symmetric_message(self, message: bytes) -> bytes:
        return self.symmetric_key.decrypt(message)

    def encrypt_symmetric_message(self, message: bytes) -> bytes:
        return self.symmetric_key.encrypt(message)

    def new_message(self, data: bytes, type: str = "msg") -> bytes:
        msg = f"{type}:{self.user_name}:"
        return msg.encode() + data

    def decode_message(self, message: bytes) -> tuple[bytes, bytes, bytes]:
        (type, user, data, *_) = message.split(b":")
        return (type, user, data)

    def run(self) -> None:
        with self.socket as client:
            print(
                f"Connecting to: ({self.host}, {self.port}) as {self.user_name}"
            )
            client.connect((self.host, self.port))
            print(
                f"Connected to {client.getpeername()} as {self.user_name}:{client.getsockname()}"
            )

            time.sleep(1)
            msg = self.new_message(self.public_key_bytes(), type="public_key")
            client.send(msg)
            (type, _, data) = self.decode_message(client.recv(self.bufsize))
            if type == b"public_key":
                self.__init_symmetric_keys()
                msg = self.encrypt_asymmetric_message(
                    self.__symmetric_key, data
                )
                msg = self.new_message(msg, type="symmetric_key")
                client.send(msg)
            elif type == b"symmetric_key":
                data = self.decrypt_asymmetric_message(data)
                self.__init_symmetric_keys(key=data)

            thread_send = Thread(target=self.send)
            thread_listen = Thread(target=self.listen, daemon=True)
            thread_send.start()
            thread_listen.start()
            thread_send.join()

    def send(self) -> None:
        while (msg := input(">> ")) != "exit":
            if msg == "":
                continue
            data = self.new_message(msg.encode())
            encrypted_data = self.encrypt_symmetric_message(data)
            self.socket.send(encrypted_data)
        self.socket.send(msg.encode())

    def listen(self) -> None:
        while True:
            [read], _, _ = select.select([self.socket], [], [])
            try:
                msg = read.recv(self.bufsize)
                try:
                    decrypted_msg = self.decrypt_symmetric_message(message=msg)
                except InvalidToken:
                    decrypted_msg = msg
                (type, user, data) = self.decode_message(decrypted_msg)
                if type == b"msg":
                    print(
                        f"Message from {user.decode()}: {data.decode()}\n>> ",
                        end="",
                    )
                elif type == b"public_key":
                    msg = self.encrypt_asymmetric_message(
                        self.__symmetric_key, data
                    )
                    msg = self.new_message(msg, type="symmetric_key")
                    time.sleep(randint(1, 10))
                    read.send(msg)
            except Exception:
                traceback.print_exc(file=sys.stdout)
                break


if __name__ == "__main__":
    if len(sys.argv) > 1:
        Client(sys.argv[1])
    else:
        user = f"user{randint(0,1_000_000)}"
        Client(user)
