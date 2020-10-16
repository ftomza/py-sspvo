#  Copyright © 2020-present Artem V. Zaborskiy <ftomza@yandex.ru>. All rights reserved.
#
#  This source code is licensed under the Apache 2.0 license found
#  in the LICENSE file in the root directory of this source tree.
import json
from base64 import b64encode
from enum import Enum
from typing import Callable, Optional

from sspvo import AbstractMessage, AbstractResponse, Token, Fields, AbstractCrypto, set_field
from sspvo.exceptions import BadSign, BadRequest
from sspvo.response import Response, ResponseSign

CLS = Enum("CLS", "Directions CampaignType CampaignStatus Benefit EducationForm EducationLevel "
                  "EducationSource EntranceTestType LevelBudget OlympicDiplomaType OlympicLevel "
                  "Subject EduLevelsCampaignTypes AchievementCategory ApplicationStatuses "
                  "CompatriotCategories CompositionThemes DisabilityTypes DocumentCategories "
                  "DocumentTypes EntranceTestDocumentTypes EntranceTestResultSources Genders "
                  "MinScoreSubjects Okcms Oktmos OlympicMinEge OrderAdmissionStatuses "
                  "OrderAdmissionTypes OrphanCategories ParentsLostCategories RadiationWorkCategories "
                  "Regions ReturnTypes VeteranCategories ViolationTypes OlympicsProfiles OlyProfiles "
                  "Olympics AppealStatuses MilitaryCategories")

Actions = Enum("Actions", "Add Edit Remove Get GetMessage MessageConfirm")

DataTypes = Enum("DataTypes", "subdivision_org campaign achievements admission_volume "
                              "distributed_admission_volume "
                              "competitive_groups competitive_group_programs competitive_benefits "
                              "entrance_tests entrance_test_benefits entrants compatriot composition "
                              "disability educations ege identification militaries olympics orphans "
                              "other parents_lost radiation_work veteran applications edit_application_status "
                              "entrance_test_agreed entrance_test_result order_admission "
                              "completitive_groups_applications_rating app_achievements applications_rating "
                              "competitive_groups_applications_rating entrant_photo_files")


class PathMethods(Enum):
    action = "token/new"
    cls = "cls/request"
    info = "token/info"
    confirm = "token/confirm"


class Message(AbstractMessage):
    _action = None

    def __init__(self):
        self._fields = {}
        if self._action:
            self.update_jwt_fields(set_field(Fields.action, self._action))

    def update_jwt_fields(self, *args) -> "AbstractMessage":
        for opt in args:
            opt(self._fields)
        return self

    @property
    def path_method(self) -> str:
        raise NotImplementedError

    def get_jwt(self) -> bytes:
        return json.dumps(self._fields).encode()

    def response(self) -> AbstractResponse:
        return Response()


class MessageSign(Message):

    def __init__(self, crypto: AbstractCrypto, data: Optional[bytes] = None):
        super().__init__()
        self._crypto = crypto
        self._data = data

        if not self._crypto:
            raise BadRequest("Crypto not set")

    @property
    def path_method(self) -> str:
        raise NotImplementedError()

    def response(self) -> AbstractResponse:
        return ResponseSign(self._crypto)

    def get_jwt(self) -> bytes:
        token = self._sign_token()
        fields = {}
        _set_token(token)(fields)
        return json.dumps(fields).encode()

    def _sign_token(self) -> Token:
        self.update_jwt_fields(_set_cert(self._crypto.get_cert()))
        header_json = json.dumps(self._fields).encode()
        header = b64encode(header_json).decode()
        payload = ""
        if self._data:
            payload = b64encode(self._data).decode()
        data4sign = f"{header}.{payload}".encode()
        digest = self._crypto.hash(data4sign)
        sign_data = self._crypto.sign(digest)
        if not self._crypto.verify(sign_data, digest):
            raise BadSign("Not valid sign after evaluate this")
        sign = b64encode(sign_data).decode()
        return Token(header, payload, sign)


class CLSMessage(Message):

    def __init__(self, cls: "CLS"):
        super().__init__()
        self.update_jwt_fields(set_field(Fields.cls, cls.name))

    @property
    def path_method(self) -> str:
        return PathMethods.cls.value


class ActionMessage(MessageSign):

    def __init__(self, crypto: AbstractCrypto, action: "Actions", data_type: "DataTypes", data: Optional[bytes] = None):
        super().__init__(crypto, data)
        self.update_jwt_fields(set_field(Fields.action, action.name), set_field(Fields.data_type, data_type.name))

    @property
    def path_method(self) -> str:
        return PathMethods.action.value


class IDJWTMessage(MessageSign):
    _action = None

    def __init__(self, crypto: AbstractCrypto, idjwt: int):
        super().__init__(crypto)
        self.update_jwt_fields(set_field(Fields.idjwt, idjwt))

    @property
    def path_method(self) -> str:
        raise NotImplementedError()


class BaseInfoMessage(Message):
    _action = Actions.GetMessage.name

    @property
    def path_method(self) -> str:
        return PathMethods.info.value


class ConfirmMessage(IDJWTMessage):
    _action = Actions.MessageConfirm.name

    @property
    def path_method(self) -> str:
        return PathMethods.confirm.value


class InfoMessage(BaseInfoMessage, IDJWTMessage):
    pass


class InfoAllMessage(BaseInfoMessage):
    pass


def _set_token(token: Token) -> Callable:
    return set_field(Fields.token, f"{token.header}.{token.payload}.{token.sign}")


def _set_cert(cert: str) -> Callable:
    return set_field(Fields.cert, _prepare_cert_for_field(cert))


def _prepare_cert_for_field(cert: str) -> str:
    def cert_is_pem_format():
        return cert.startswith("-----")

    cert = cert.strip()
    if cert_is_pem_format():
        lines = cert.split("\n")
        cert = "".join(lines[1:-1])
    return cert
