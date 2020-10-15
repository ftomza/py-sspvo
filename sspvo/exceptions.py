#  Copyright © 2020-present Artem V. Zaborskiy <ftomza@yandex.ru>. All rights reserved.
#
#  This source code is licensed under the Apache 2.0 license found
#  in the LICENSE file in the root directory of this source tree.

class BadRequest(Exception):
    pass


class BadSign(Exception):
    pass


class BadResponse(Exception):
    def __init__(self, code, response, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._code = code
        self._response = response

    def __repr__(self):
        return f"{self._code}: {self._response}"

    def __str__(self):
        return self.__repr__()

    @property
    def code(self):
        return self._code

    @property
    def body(self):
        return self._response


class CertNotValid(Exception):
    pass


class KeyNotValid(Exception):
    pass
