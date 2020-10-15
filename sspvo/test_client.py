#  Copyright © 2020-present Artem V. Zaborskiy <ftomza@yandex.ru>. All rights reserved.
#
#  This source code is licensed under the Apache 2.0 license found
#  in the LICENSE file in the root directory of this source tree.
import pytest

from sspvo.client import Client, RequestsClient
from sspvo.exceptions import BadRequest
from sspvo.message import CLSMessage, CLS


class TestClient:
    def setup(self):
        self.client = Client("OGRN", "KPP", "/api")

    def test_init_ok(self):
        c = Client("ogrn", "kpp", "base")
        assert c._ogrn == "ogrn"
        assert c._kpp == "kpp"
        assert c._api_base == "base"

    def test_init_ok2(self):
        c = Client("ogrn", "kpp")
        assert c._ogrn == "ogrn"
        assert c._kpp == "kpp"
        assert c._api_base == ""

    def test_init_raise_ogrn(self):
        with pytest.raises(BadRequest):
            Client("", "kpp", "base")

    def test_init_raise_kpp(self):
        with pytest.raises(BadRequest):
            Client("ogrn", "", "base")

    def test_send_ok(self):
        with pytest.raises(NotImplementedError):
            self.client.send(None)

    def test_prepare_ok(self):
        msg = CLSMessage(CLS.Directions)
        r = self.client.prepare(msg)
        assert r == b'{"CLS": "Directions", "KPP": "KPP", "OGRN": "OGRN"}'


class TestRequestsClient:

    @pytest.fixture()
    def client(self, mocker):
        cli = RequestsClient(mocker.Mock(), ogrn="OGRN", kpp="KPP", api_url="/api")
        return cli

    def test_send_ok(self, client):
        client._session.post.return_value.status_code = 200
        client._session.post.return_value.content = b'TEST'
        client._session.post.return_value.headers = {}
        msg = CLSMessage(CLS.Directions)
        r = client.send(msg)
        client._session.post.assert_called_once()
        assert r.client_response.code == 200
        assert r.client_response.body == b'TEST'
        assert r.client_response.headers == {}
