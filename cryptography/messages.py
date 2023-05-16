from __future__ import annotations

import hashlib

MESSAGES_CODES = {
    b"message",
    b"public_key",
    b"symmetric_key",
}


class DecodeException(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class HashException(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)


class Message:
    def __init__(
        self,
        sender: str | bytes,
        data: str | bytes,
        code: str | bytes = b"message",
        hash_data: bytes = b"",
    ) -> None:
        self.__sender = (
            sender if isinstance(sender, bytes) else sender.encode()
        )
        self.__data = data if isinstance(data, bytes) else data.encode()
        code = code if isinstance(code, bytes) else code.encode()
        if code not in MESSAGES_CODES:
            code = b"message"
        self.__code = code
        self.__hash = (
            hash_data
            if hash_data
            else hashlib.sha256(self.__data).hexdigest().encode()
        )

    def m_code(self) -> bytes:
        return self.__code

    def m_sender(self) -> bytes:
        return self.__sender

    def m_data(self) -> bytes:
        return self.__data

    def verify_hash(self) -> bool:
        return self.__hash == hashlib.sha256(self.__data).hexdigest().encode()

    def serialize_message(self) -> bytes:
        return (
            self.__code
            + b":"
            + self.__sender
            + b":"
            + self.__data
            + b":"
            + self.__hash
        )

    @classmethod
    def deserialize_message(cls, message: str | bytes) -> Message:
        if isinstance(message, str):
            message = message.encode()

        try:
            (code, sender, *data, hash_data) = message.split(b":")
        except ValueError as e:
            raise DecodeException("Wrong Decode") from e

        data = b":".join(data)

        msg = cls(
            sender=sender,
            data=data,
            code=code,
            hash_data=hash_data,
        )

        if msg.verify_hash() is False:
            raise HashException("Data corrupted!")

        return msg
