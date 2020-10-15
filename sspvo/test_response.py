#  Copyright © 2020-present Artem V. Zaborskiy <ftomza@yandex.ru>. All rights reserved.
#
#  This source code is licensed under the Apache 2.0 license found
#  in the LICENSE file in the root directory of this source tree.
from unittest.mock import call

import pytest

from sspvo import ClientResponse, AbstractCrypto, Token
from sspvo.exceptions import BadResponse, BadSign
from sspvo.response import Response, ResponseSign


class TestClient:
    def setup(self):
        pass

    def test_data_ok(self):
        r = Response()
        r.client_response = ClientResponse(200, b"TEST", {})
        assert r.data() == b"TEST"

    def test_data_fail(self):
        r = Response()
        r.client_response = ClientResponse(400, b"TEST", {})
        try:
            r.data()
        except BadResponse as e:
            assert f"{e}" == "400: b'TEST'"
            assert e.code == 400
            assert e.body == b"TEST"


class TestResponseSign:

    @pytest.fixture()
    def response(self, mocker):
        resp = ResponseSign(mocker.Mock(spec_set=AbstractCrypto))
        return resp

    def test__parse_token_empty(self):
        token = ResponseSign._parse_token("..")
        assert token == Token()

    def test__parse_token_all(self):
        token = ResponseSign._parse_token("headers.payload.sign")
        assert token == Token("headers", "payload", "sign")

    def test__parse_token_half(self):
        token = ResponseSign._parse_token("headers.sign")
        assert token == Token("headers", "", "sign")

    def test__parse_token_half2(self):
        token = ResponseSign._parse_token("headers..sign")
        assert token == Token("headers", "", "sign")

    def test__verify_token_ok(self, response):
        assert response._verify_token(Token('eyJhY3Rpb24iOiAiQWRkIn0='))

    def test__verify_token_ok2(self, response):
        response._crypto.get_verify_crypto.return_value = response._crypto
        response._crypto.verify.return_value = True
        ok = response._verify_token(Token('eyJDZXJ0NjQiOiAiVEVTVCJ9', 'VEVTVA==', 'U0lHTg=='))
        assert response._crypto.mock_calls == [
            call.get_verify_crypto('-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----'),
            call.verify(b'SIGN', b'eyJDZXJ0NjQiOiAiVEVTVCJ9.VEVTVA=='),
        ]
        response._crypto.get_verify_crypto.assert_called_once()
        response._crypto.verify.assert_called_once()
        assert ok

    def test_data_ok(self, response):
        body = b'{"ResponseToken": "eyJDZXJ0NjQiOiAiVEVTVCJ9.VEVTVA==.U0lHTg=="}'
        response.client_response = ClientResponse(200, body, {})
        assert response.data() == body

    def test_data_ok2(self, response):
        body = b'{"Error": "Fail"}'
        response.client_response = ClientResponse(200, body, {})
        assert response.data() == body

    def test_data_ok3(self, response):
        body = b'{"ResponseToken": ".."}'
        response.client_response = ClientResponse(200, body, {})
        assert response.data() == body

    def test_data_raise(self, response):
        body = b'{"ResponseToken": "eyJDZXJ0NjQiOiAiVEVTVCJ9.VEVTVA==.U0lHTg=="}'
        response._crypto.get_verify_crypto.return_value = response._crypto
        response._crypto.verify.return_value = False
        response.client_response = ClientResponse(200, body, {})
        with pytest.raises(BadSign):
            response.data()