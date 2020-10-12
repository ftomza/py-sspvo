from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict


class AbstractCrypto(ABC):
    @abstractmethod
    def get_verify_crypto(self, cert: str) -> "AbstractCrypto":
        pass

    @abstractmethod
    def get_cert(self) -> str:
        pass

    @abstractmethod
    def hash(self, data: bytes) -> bytes:
        pass

    @abstractmethod
    def sign(self, digest: bytes) -> bytes:
        pass

    @abstractmethod
    def verify(self, sign: bytes, digest: bytes) -> bool:
        pass


@dataclass
class ClientResponse:
    code: int
    body: bytes
    header: Dict[str, str]


class Response(ABC):
    @abstractmethod
    def client_response(self) -> ClientResponse:
        pass

    @abstractmethod
    def set_client_response(self, resp: ClientResponse):
        pass

    @abstractmethod
    def data(self) -> bytes:
        pass


class Message(ABC):
    @abstractmethod
    def path_method(self) -> str:
        pass

    @abstractmethod
    def get_jwt(self) -> bytes:
        pass

    @abstractmethod
    def response(self) -> Response:
        pass


class Client(ABC):
    @abstractmethod
    def send(self, msg: Message) -> Response:
        pass

    @abstractmethod
    def prepare(self, msg: Message) -> bytes:
        pass


@dataclass
class Token:
    header: str
    payload: str
    sign: str
