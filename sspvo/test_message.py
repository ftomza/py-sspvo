#  Copyright © 2020-present Artem V. Zaborskiy <ftomza@yandex.ru>. All rights reserved.
#
#  This source code is licensed under the Apache 2.0 license found
#  in the LICENSE file in the root directory of this source tree.
from unittest.mock import call

import pytest

from sspvo import set_field, Fields, AbstractCrypto
from sspvo.exceptions import BadRequest, BadSign
from sspvo.message import Message, MessageSign, CLSMessage, CLS, ActionMessage, Actions, DataTypes, IDJWTMessage, \
    ConfirmMessage, InfoMessage, InfoAllMessage, BaseInfoMessage
from sspvo.response import Response, ResponseSign

test_cert = "\n-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"


class TestMessage:

    def setup(self):
        self.msg = Message()

    def test_update_jwt_fields(self):
        m = self.msg.update_jwt_fields(set_field(Fields.idjwt, 1))
        assert m._fields == {"IDJWT": 1}

    def test_path_method(self):
        with pytest.raises(NotImplementedError):
            assert self.msg.path_method

    def test_get_jwt(self):
        m = self.msg.update_jwt_fields(set_field(Fields.idjwt, 1))
        assert m.get_jwt() == b'{"IDJWT": 1}'

    def test_response(self):
        assert isinstance(self.msg.response(), Response)


class TestMessageSign:

    @pytest.fixture()
    def message(self, mocker):
        msg = MessageSign(mocker.Mock(spec_set=AbstractCrypto), b'TEST')
        return msg

    def test_init_ok(self, mocker):
        msg = MessageSign(mocker.Mock(), b'TEST')
        assert msg._crypto
        assert msg._data == b'TEST'

    def test_init_raise(self):
        with pytest.raises(BadRequest):
            MessageSign(None, b'TEST')

    def test_path_method(self, message):
        with pytest.raises(NotImplementedError):
            assert message.path_method

    def test_response(self, message):
        resp = message.response()
        assert isinstance(resp, ResponseSign)
        assert resp._crypto == message._crypto

    def test__sign_token_ok(self, message):
        message._crypto.get_cert.return_value = test_cert
        message._crypto.hash.return_value = b"HASH"
        message._crypto.sign.return_value = b"SIGN"
        message._crypto.verify.return_value = True
        token = message._sign_token()
        assert message._crypto.mock_calls == [
            call.get_cert(),
            call.hash(b'eyJDZXJ0NjQiOiAiVEVTVCJ9.VEVTVA=='),
            call.sign(b"HASH"),
            call.verify(b'SIGN', b"HASH")
        ]
        message._crypto.hash.assert_called_once()
        message._crypto.sign.assert_called_once()
        message._crypto.get_cert.assert_called_once()
        assert token.sign == 'U0lHTg=='
        assert token.payload == 'VEVTVA=='
        assert token.header == 'eyJDZXJ0NjQiOiAiVEVTVCJ9'

    def test__sign_token_ok2(self, message):
        message._data = None
        message._crypto.get_cert.return_value = test_cert
        message._crypto.hash.return_value = b"HASH"
        message._crypto.sign.return_value = b"SIGN"
        message._crypto.verify.return_value = True
        token = message._sign_token()
        assert message._crypto.mock_calls == [
            call.get_cert(),
            call.hash(b'eyJDZXJ0NjQiOiAiVEVTVCJ9.'),
            call.sign(b"HASH"),
            call.verify(b'SIGN', b"HASH")
        ]
        message._crypto.hash.assert_called_once()
        message._crypto.sign.assert_called_once()
        message._crypto.get_cert.assert_called_once()
        assert token.sign == 'U0lHTg=='
        assert token.payload == ''
        assert token.header == 'eyJDZXJ0NjQiOiAiVEVTVCJ9'

    def test__sign_token_raise(self, message):
        message._crypto.get_cert.return_value = test_cert
        message._crypto.hash.return_value = b"HASH"
        message._crypto.sign.return_value = b"SIGN"
        message._crypto.verify.return_value = False
        with pytest.raises(BadSign):
            message._sign_token()

    def test_get_jwt(self, message):
        message._crypto.get_cert.return_value = test_cert
        message._crypto.hash.return_value = b"HASH"
        message._crypto.sign.return_value = b"SIGN"
        message._crypto.verify.return_value = True
        assert message.get_jwt() == b'{"token": "eyJDZXJ0NjQiOiAiVEVTVCJ9.VEVTVA==.U0lHTg=="}'



class TestCLSMessage:

    def test_init_ok(self):
        m = CLSMessage(CLS.Directions)
        assert m._fields == {"CLS": "Directions"}

    def test_path_method_ok(self):
        m = CLSMessage(CLS.Directions)
        assert m.path_method == "cls/request"


class TestActionMessage:

    def test_init_ok(self, mocker):
        m = ActionMessage(mocker.Mock(), Actions.Add, DataTypes.subdivision_org)
        assert m._fields == {'action': 'Add', 'data_type': 'subdivision_org'}

    def test_path_method_ok(self, mocker):
        m = ActionMessage(mocker.Mock(), Actions.Add, DataTypes.subdivision_org)
        assert m.path_method == "token/new"


class TestIDJWTMessage:

    def test_init_ok(self, mocker):
        m = IDJWTMessage(mocker.Mock(), 1)
        assert m._fields == {'IDJWT': 1}

    def test_path_method(self, mocker):
        m = IDJWTMessage(mocker.Mock(), 1)
        with pytest.raises(NotImplementedError):
            assert m.path_method


class TestConfirmMessage:

    def test_init_ok(self, mocker):
        m = ConfirmMessage(mocker.Mock(), 1)
        assert m._fields == {'IDJWT': 1, 'action': 'MessageConfirm'}

    def test_path_method_ok(self, mocker):
        m = ConfirmMessage(mocker.Mock(), 1)
        assert m.path_method == "token/confirm"


class TestBaseInfoMessage:

    def test_path_method_ok(self):
        m = BaseInfoMessage()
        assert m.path_method == "token/info"


class TestInfoMessage:

    def test_init_ok(self, mocker):
        m = InfoMessage(mocker.Mock(), 1)
        assert m._fields == {'IDJWT': 1, 'action': 'GetMessage'}

    def test_path_method_ok(self, mocker):
        m = InfoMessage(mocker.Mock(), 1)
        assert m.path_method == "token/info"


class TestInfoAllMessage:

    def test_init_ok(self):
        m = BaseInfoMessage()
        assert m._fields == {}

    def test_path_method_ok(self):
        m = InfoAllMessage()
        assert m.path_method == "token/info"
