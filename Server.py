#! /usr/bin/env python

import select
import socket
from threading import Thread

IP = "127.0.0.1"
PORT = 5535


class Server:
    def __init__(self, host: str = IP, port: int = PORT) -> None:
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.configure_socket()
        self.init_socket()
        self.socket_list: list[socket.socket] = [self.socket]
        self.to_be_sent: list[tuple[bytes, socket.socket]] = []
        self.run()

    def configure_socket(self) -> None:
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def init_socket(self) -> None:
        self.socket.bind((self.host, self.port))
        self.socket.listen()
        print(f"Server {self.socket.getsockname()} started")

    def run(self) -> None:
        with self.socket:
            thread_listen = Thread(target=self.listen_connections)
            thread_handle_connections = Thread(target=self.handle_connections)
            thread_listen.start()
            thread_handle_connections.start()
            thread_listen.join()

    def listen_connections(self) -> None:
        while True:
            read, _, _ = select.select(self.socket_list, [], [], 0)
            for socket in read:
                if socket == self.socket:
                    conn, addr = self.socket.accept()
                    print(f"New connection: {conn}, {addr}")
                    self.socket_list.append(conn)
                else:
                    try:
                        msg = socket.recv(1024)
                        if msg == b"exit":
                            self.socket_list.remove(socket)
                        elif msg != b"":
                            self.to_be_sent.append((msg, socket))
                    except Exception as e:
                        print(e)

    def handle_connections(self) -> None:
        while True:
            _, write, _ = select.select([], self.socket_list, [], 0)
            for msg, sender in self.to_be_sent:
                for socket in write:
                    if sender != socket:
                        print(f"Sending to {socket.getpeername()}")
                        socket.send(msg)
            self.to_be_sent = []


if __name__ == "__main__":
    srv = Server()
