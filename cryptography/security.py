from abc import abstractmethod

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class Crypto:
    @abstractmethod
    def encrypt(self, message: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, message: bytes) -> bytes:
        pass


class AsymmetricKeyRSA(Crypto):
    def __init__(self) -> None:
        self.__private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.__public_key = self.__private_key.public_key()

    def decrypt(self, message: bytes) -> bytes:
        return self.__private_key.decrypt(
            message,
            padding=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def encrypt(self, message: bytes) -> bytes:
        return self.__public_key.encrypt(
            message,
            padding=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def get_public_key(self) -> bytes:
        return self.__public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    @staticmethod
    def pem_public_encrypt(pem_public_key: bytes, message: bytes) -> bytes:
        public_key = serialization.load_pem_public_key(pem_public_key)
        return public_key.encrypt(
            message,
            padding=padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )


class SymmetricKeyFernet(Crypto):
    def __init__(self, key: bytes = b"") -> None:
        self.__symmetric_key = key if key else Fernet.generate_key()
        self.symmetric_key = Fernet(self.__symmetric_key)

    def encrypt(self, message: bytes) -> bytes:
        return self.symmetric_key.encrypt(message)

    def decrypt(self, message: bytes) -> bytes:
        return self.symmetric_key.decrypt(message)

    def get_symmetric_key(self) -> bytes:
        return self.__symmetric_key
