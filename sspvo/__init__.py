#  Copyright © 2020-present Artem V. Zaborskiy <ftomza@yandex.ru>. All rights reserved.
#
#  This source code is licensed under the Apache 2.0 license found
#  in the LICENSE file in the root directory of this source tree.

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Any, Callable


class Fields(Enum):
    ogrn = "OGRN"
    kpp = "KPP"
    cls = "CLS"
    cert = "Cert64"
    token = "token"
    action = "action"
    data_type = "data_type"
    idjwt = "IDJWT"


def set_field(field: Fields, value: Any) -> Callable:
    def m(f: Dict[str, Any]):
        f[field.value] = value

    return m


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
    headers: Any


class AbstractResponse(ABC):

    @property
    @abstractmethod
    def client_response(self) -> ClientResponse:
        pass

    @client_response.setter
    @abstractmethod
    def client_response(self, value: ClientResponse):
        pass

    @abstractmethod
    def data(self) -> bytes:
        pass


class AbstractMessage(ABC):

    @abstractmethod
    def update_jwt_fields(self, *args) -> "AbstractMessage":
        pass

    @property
    @abstractmethod
    def path_method(self) -> str:
        pass

    @abstractmethod
    def get_jwt(self) -> bytes:
        pass

    @abstractmethod
    def response(self) -> AbstractResponse:
        pass


class AbstractClient(ABC):
    @abstractmethod
    def send(self, msg: AbstractMessage) -> AbstractResponse:
        pass

    @abstractmethod
    def prepare(self, msg: AbstractMessage) -> bytes:
        pass


@dataclass
class Token:
    header: str = ""
    payload: str = ""
    sign: str = ""
