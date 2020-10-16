import json
from time import sleep

from requests import Session

from sspvo import Fields
from sspvo.client import RequestsClient
from sspvo.crypto import GOSTCrypto
from sspvo.exceptions import BadResponse
from sspvo.message import ActionMessage, Actions, DataTypes, InfoMessage, ConfirmMessage

cert = """
-----BEGIN CERTIFICATE-----
MIIEfDCCBCmgAwIBAgIEXek0LjAKBggqhQMHAQEDAjCB8TELMAkGA1UEBhMCUlUxKjAoBgNVBAgMIdCh0LDQvdC60YLRii3Q
n9C10YLQtdGA0LHRg9GA0LPRijEuMCwGA1UECgwl0JbRg9GA0L3QsNC7ICLQodC+0LLRgNC10LzQtdC90L3QuNC6IjEfMB0G
A1UECwwW0KDRg9C60L7QstC+0LTRgdGC0LLQvjEoMCYGA1UEDAwf0JPQu9Cw0LLQvdGL0Lkg0YDQtdC00LDQutGC0L7RgDE7
MDkGA1UEAwwy0JDQu9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhyDQn9GD0YjQutC40L0wHhcNMjAwOTIyMjEw
MDAwWhcNNDAwOTIyMjEwMDAwWjCB8TELMAkGA1UEBhMCUlUxKjAoBgNVBAgMIdCh0LDQvdC60YLRii3Qn9C10YLQtdGA0LHR
g9GA0LPRijEuMCwGA1UECgwl0JbRg9GA0L3QsNC7ICLQodC+0LLRgNC10LzQtdC90L3QuNC6IjEfMB0GA1UECwwW0KDRg9C6
0L7QstC+0LTRgdGC0LLQvjEoMCYGA1UEDAwf0JPQu9Cw0LLQvdGL0Lkg0YDQtdC00LDQutGC0L7RgDE7MDkGA1UEAwwy0JDQ
u9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhyDQn9GD0YjQutC40L0wZjAfBggqhQMHAQEBATATBgcqhQMCAiQA
BggqhQMHAQECAgNDAARAyuHXvOdPT/R94KICw82bdgiBfEXkEJxqXIN4uav8zIvgDe/q7yzK+HJnbLWLIWc2z+eqbaiUbj0Y
e1RoNUa5NaOCAZ4wggGaMA4GA1UdDwEB/wQEAwIB/jAxBgNVHSUEKjAoBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMD
BggrBgEFBQcDBDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSalTlfa+t/MpLv76stCkVlU18TazCCASMGA1UdIwSCARow
ggEWgBSalTlfa+t/MpLv76stCkVlU18Ta6GB96SB9DCB8TELMAkGA1UEBhMCUlUxKjAoBgNVBAgMIdCh0LDQvdC60YLRii3Q
n9C10YLQtdGA0LHRg9GA0LPRijEuMCwGA1UECgwl0JbRg9GA0L3QsNC7ICLQodC+0LLRgNC10LzQtdC90L3QuNC6IjEfMB0G
A1UECwwW0KDRg9C60L7QstC+0LTRgdGC0LLQvjEoMCYGA1UEDAwf0JPQu9Cw0LLQvdGL0Lkg0YDQtdC00LDQutGC0L7RgDE7
MDkGA1UEAwwy0JDQu9C10LrRgdCw0L3QtNGAINCh0LXRgNCz0LXQtdCy0LjRhyDQn9GD0YjQutC40L2CBF3pNC4wCgYIKoUD
BwEBAwIDQQBlY4HdS/G7zAWOEWH6pBx4FSli5ipbEtvr/lkjEApvlrch5cMlmy7rglAbE7ct+sKFtDKv6cIhqu3rQMAla/gb
-----END CERTIFICATE-----
"""

key = """
-----BEGIN PRIVATE KEY-----
MEgCAQAwHwYIKoUDBwEBBgEwEwYHKoUDAgIkAAYIKoUDBwEBAgIEIgQgAnLfE4VXwFTuD5HbBX84W9f/NLDcxNXUWHB+Atu/
6BE=
-----END PRIVATE KEY-----
"""


def main():

    sess = Session()
    sspvo_client = RequestsClient(sess, ogrn="test", kpp="test", api_url="http://85.142.162.12:8031/api")

    crypto = GOSTCrypto(cert=cert, key=key)

    ##
    # Send package add actions
    #

    data = """
    <?xml version="1.0" encoding="utf-8"?>
    <PackageData>
        <SubdivisionOrg>
            <UID>TEST69</UID>
            <Name>Подвал</Name>
        </SubdivisionOrg>
    </PackageData>
    """.encode()

    message = ActionMessage(crypto, action=Actions.Add, data_type=DataTypes.subdivision_org, data=data)
    response = sspvo_client.send(message)
    try:
        answer = response.data()
    except BadResponse as e:
        print("Error:", e.body)
        return
    print(answer.decode())

    sleep(10)

    idjwt = int(json.loads(answer)[Fields.idjwt.value])

    ##
    # Get info for add actions
    #

    message = InfoMessage(crypto, idjwt=idjwt)
    response = sspvo_client.send(message)
    try:
        answer = response.data()
    except BadResponse as e:
        print("Error:", e.body)
        return
    print(answer.decode())

    ##
    # Confirm info for add actions
    #

    message = ConfirmMessage(crypto, idjwt=idjwt)
    response = sspvo_client.send(message)
    try:
        answer = response.data()
    except BadResponse as e:
        print("Error:", e.body)
        return
    print(answer.decode())


if __name__ == '__main__':
    main()

# Output:
# {"IDJWT":"1405161"}
# {"ResponseToken":".."}
# {"IDJWT":"1405161","Result":"true"}
