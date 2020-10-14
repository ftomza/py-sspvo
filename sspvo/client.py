#  Copyright © 2020-present Artem V. Zaborskiy <ftomza@yandex.ru>. All rights reserved.
#
#  This source code is licensed under the Apache 2.0 license found
#  in the LICENSE file in the root directory of this source tree.
from typing import Optional

from requests import Session

from sspvo import AbstractClient, AbstractMessage, AbstractResponse, ClientResponse, set_field, Fields
from sspvo.exceptions import BadRequest


class Client(AbstractClient):

    def __init__(self, ogrn: str, kpp: str, api_base: Optional[str]=None):
        self._ogrn = ogrn
        self._kpp = kpp
        self._api_base = api_base or ""

        if not self._ogrn:
            raise BadRequest("OGRN not set")

        if not self._kpp:
            raise BadRequest("KPP not set")

    def send(self, msg: AbstractMessage) -> AbstractResponse:
        raise NotImplementedError()

    def prepare(self, msg: AbstractMessage) -> bytes:
        return msg.update_jwt_fields(set_field(Fields.kpp, self._kpp), set_field(Fields.ogrn, self._ogrn)).get_jwt()


class RequestsClient(Client):

    def __init__(self, session: Session, *, ogrn: str, kpp: str, api_base: str):
        super().__init__(ogrn, kpp, api_base)
        self._session = session

    def send(self, msg: AbstractMessage) -> AbstractResponse:
        response = self._session.post(f"{self._api_base}/{msg.path_method}", self.prepare(msg))
        client_response = msg.response()
        client_response.client_response = ClientResponse(response.status_code, response.content, response.headers)
        return client_response
