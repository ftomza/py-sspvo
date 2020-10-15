#  Copyright © 2020-present Artem V. Zaborskiy <ftomza@yandex.ru>. All rights reserved.
#
#  This source code is licensed under the Apache 2.0 license found
#  in the LICENSE file in the root directory of this source tree.
import json
from base64 import b64decode
from typing import Optional

from sspvo import AbstractResponse, ClientResponse, AbstractCrypto, Token, Fields
from sspvo.exceptions import BadResponse, BadRequest, BadSign

field_response_token = "ResponseToken"


class Response(AbstractResponse):

    def __init__(self):
        self._client_response: Optional[ClientResponse] = None

    @property
    def client_response(self) -> ClientResponse:
        return self._client_response

    @client_response.setter
    def client_response(self, value: ClientResponse):
        self._client_response = value

    def data(self) -> bytes:
        if self._client_response.code > 299:
            raise BadResponse(self._client_response.code, self._client_response.body)

        return self._client_response.body


class ResponseSign(Response):

    def __init__(self, crypto: AbstractCrypto):
        super().__init__()
        self._crypto = crypto

        if not self._crypto:
            raise BadRequest("Crypto not set")

    def data(self) -> bytes:
        data = super().data()
        package = json.loads(data)
        if field_response_token not in package:
            return data

        token = self._parse_token(package[field_response_token])
        if not token.header:
            return data

        if not self._verify_token(token):
            raise BadSign("Not valid sign response")

        return data

    @classmethod
    def _parse_token(cls, data: str) -> Token:
        token = Token()
        parts = data.split(".")
        if not parts[0]:
            return token
        token.header = parts[0]
        if len(parts) == 3:
            token.payload = parts[1]
            token.sign = parts[2]
        else:
            token.sign = parts[1]
        return token

    def _verify_token(self, token: Token) -> bool:
        header = json.loads(b64decode(token.header).decode())
        if Fields.cert.value not in header:
            return True

        cert = f"-----BEGIN CERTIFICATE-----\n{header[Fields.cert.value]}\n-----END CERTIFICATE-----"
        sign = b64decode(token.sign)
        crypto = self._crypto.get_verify_crypto(cert)

        data4sign = f"{token.header}.{token.payload}".encode()
        return crypto.verify(sign, data4sign)
