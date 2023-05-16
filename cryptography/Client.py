#! /usr/bin/env python

import contextlib
import select
import socket
import sys
import time
import traceback
from random import randint
from threading import Thread

from messages import DecodeException, HashException, Message
from security import AsymmetricKeyRSA, SymmetricKeyFernet

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5535
DEFAULT_BUFSIZE = 2048


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
        self.asymmetric_key = AsymmetricKeyRSA()
        self.__configure_socket()
        self.run()

    def __configure_socket(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def __init_symmetric_keys(self, key: bytes = b"") -> None:
        self.symmetric_key = SymmetricKeyFernet(key=key)

    def new_message(self, data: bytes, code: bytes = b"message") -> bytes:
        msg = Message(
            sender=self.user_name.encode(),
            data=data,
            code=code,
        )
        return msg.serialize_message()

    def decode_message(self, message: bytes) -> Message:
        return Message.deserialize_message(message)

    def send_public_key(self) -> None:
        msg = self.new_message(
            data=self.asymmetric_key.get_public_key(), code=b"public_key"
        )
        self.socket.send(msg)

    def send_symmetric_key(self, public_key: bytes) -> None:
        msg = self.new_message(
            data=self.symmetric_key.get_symmetric_key(),
            code=b"symmetric_key",
        )
        enc_msg = AsymmetricKeyRSA.pem_public_encrypt(
            pem_public_key=public_key, message=msg
        )
        self.socket.send(enc_msg)

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
            self.send_public_key()

            msg = client.recv(self.bufsize)
            with contextlib.suppress(Exception):
                msg = self.asymmetric_key.decrypt(msg)

            try:
                message = Message.deserialize_message(msg)
            except (DecodeException, HashException) as e:
                client.send(b"exit")
                raise SystemExit(
                    "Erro no estabelecimento de segurança!"
                ) from e

            match message.m_code():
                case b"public_key":
                    self.__init_symmetric_keys()
                    self.send_symmetric_key(message.m_data())
                case b"symmetric_key":
                    self.__init_symmetric_keys(message.m_data())
                case _:
                    print(f"{self.user_name} saindo... no run")
                    client.send(b"exit")
                    raise SystemExit("Erro no estabelecimento de segurança!")

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
            encrypted_data = self.symmetric_key.encrypt(data)
            self.socket.send(encrypted_data)
        self.socket.send(msg.encode())

    def listen(self) -> None:
        while True:
            [read], _, _ = select.select([self.socket], [], [])
            try:
                msg = read.recv(self.bufsize)

                with contextlib.suppress(Exception):
                    msg = self.symmetric_key.decrypt(msg)

                try:
                    message = Message.deserialize_message(msg)
                except (DecodeException, HashException):
                    continue

                match message.m_code():
                    case b"message":
                        sender = message.m_sender().decode()
                        msg = message.m_data().decode()
                        print(
                            f"Message from {sender}: {msg}\n>> ",
                            end="",
                        )
                    case b"public_key":
                        # time.sleep(randint(1, 10))
                        self.send_symmetric_key(message.m_data())
                    case _:
                        continue
            except Exception:
                traceback.print_exc(file=sys.stdout)
                break


if __name__ == "__main__":
    if len(sys.argv) > 1:
        Client(sys.argv[1])
    else:
        user = f"user{randint(0,1_000_000)}"
        Client(user)
