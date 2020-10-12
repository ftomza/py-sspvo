from base64 import b64encode
from unittest import TestCase

from pyderasn import ObjectIdentifier, Any
from pygost import gost3410, gost34112012256
from pygost.asn1schemas.x509 import GostR34102012PublicKeyParameters

from sspvo.crypto import GOSTCrypto
from sspvo.errors import CertNotValid, BadRequest, KeyNotValid

valid_cert = """
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

valid_key = """
-----BEGIN PRIVATE KEY-----
MEgCAQAwHwYIKoUDBwEBBgEwEwYHKoUDAgIkAAYIKoUDBwEBAgIEIgQgAnLfE4VXwFTuD5HbBX84W9f/NLDcxNXUWHB+Atu/
6BE=
-----END PRIVATE KEY-----
"""

bad_cert = """
-----BEGIN CERTIFICATE-----
MIICYjCCAg+gAwIBAgIBATAKBggqhQMHAQEDAjBWMSkwJwYJKoZIhvcNAQkBFhpHb3N0UjM0MTAtMjAxMkBleGFtcGxlLmNvb
TEpMCcGA1UEAxMgR29zdFIzNDEwLTIwMTIgKDI1NiBiaXQpIGV4YW1wbGUwHhcNMTMxMTA1MTQwMjM3WhcNMzAxMTAxMTQwMj
M3WjBWMSkwJwYJKoZIhvcNAQkBFhpHb3N0UjM0MTAtMjAxMkBleGFtcGxlLmNvbTEpMCcGA1UEAxMgR29zdFIzNDEwLTIwMTI
gKDI1NiBiaXQpIGV4YW1wbGUwZjAfBggqhQMHAQEBATATBgcqhQMCAiQABggqhQMHAQECAgNDAARAut/Qw1MUq9KPqkdHC2xA
F3K7TugHfo9n525D2s5mFZdD5pwf90/i4vF0mFmr9nfRwMYP4o0Pg1mOn5RlaXNYraOBwDCBvTAdBgNVHQ4EFgQU1fIeN1HaP
bw+XWUzbkJ+kHJUT0AwCwYDVR0PBAQDAgHGMA8GA1UdEwQIMAYBAf8CAQEwfgYDVR0BBHcwdYAU1fIeN1HaPbw+XWUzbkJ+kH
JUT0ChWqRYMFYxKTAnBgkqhkiG9w0BCQEWGkdvc3RSMzQxMC0yMDEyQGV4YW1wbGUuY29tMSkwJwYDVQQDEyBHb3N0UjM0MTA
tMjAxMiAoMjU2IGJpdCkgZXhhbXBsZYIBATAKBggqhQMHAQEDAgNBAF5bm4BbARR6hJLEoWJkOsYV3Hd7kXQQjz3CdqQfmHrz
6TI6Xojdh/t8ckODv/587NS5/6KsM77vc6Wh90NAT2ugAwIBAgIBAQ==
-----END CERTIFICATE-----
"""

bad_key = """
-----BEGIN PRIVATE KEY-----
MEgCAQAwHwYIKoUDBwEBBgEwEwYHKoUDAgIkAAYIKoUDBwEBAgIEIgQgAnLfE4VXwFTuD5HbBX84W9f/NLDcxNXUWHB+Atu/6
BFUQUlM
-----END PRIVATE KEY-----
"""

bad_cert2 = """
-----BEGIN CERTIFICATE-----
MIIEgzCCBCWgAwIBAgIEUsAnJzAOBgorBgEEAa1ZAQMCBQAwgfExCzAJBgNVBAYTAlJVMSowKAYDVQQIDCHQodCw0L3QutGC
0Yot0J/QtdGC0LXRgNCx0YPRgNCz0YoxLjAsBgNVBAoMJdCW0YPRgNC90LDQuyAi0KHQvtCy0YDQtdC80LXQvdC90LjQuiIx
HzAdBgNVBAsMFtCg0YPQutC+0LLQvtC00YHRgtCy0L4xKDAmBgNVBAwMH9CT0LvQsNCy0L3Ri9C5INGA0LXQtNCw0LrRgtC+
0YAxOzA5BgNVBAMMMtCQ0LvQtdC60YHQsNC90LTRgCDQodC10YDQs9C10LXQstC40Ycg0J/Rg9GI0LrQuNC9MB4XDTIwMDky
OTIxMDAwMFoXDTQwMDkyOTIxMDAwMFowgfExCzAJBgNVBAYTAlJVMSowKAYDVQQIDCHQodCw0L3QutGC0Yot0J/QtdGC0LXR
gNCx0YPRgNCz0YoxLjAsBgNVBAoMJdCW0YPRgNC90LDQuyAi0KHQvtCy0YDQtdC80LXQvdC90LjQuiIxHzAdBgNVBAsMFtCg
0YPQutC+0LLQvtC00YHRgtCy0L4xKDAmBgNVBAwMH9CT0LvQsNCy0L3Ri9C5INGA0LXQtNCw0LrRgtC+0YAxOzA5BgNVBAMM
MtCQ0LvQtdC60YHQsNC90LTRgCDQodC10YDQs9C10LXQstC40Ycg0J/Rg9GI0LrQuNC9MF4wFgYKKwYBBAGtWQEGAgYIKoZI
zj0DAQcDRAAEQQRJ47ST4jDv6emPar8XzCAcIb2adsob+TH53QR7YsJHsX6lFh1Y3zpZnfVc/ehMRbD9UcubR5QMptQcGp6k
7PEto4IBnjCCAZowDgYDVR0PAQH/BAQDAgH+MDEGA1UdJQQqMCgGCCsGAQUFBwMBBggrBgEFBQcDAgYIKwYBBQUHAwMGCCsG
AQUFBwMEMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFMvx8MZSQjkPMV8WNliFVx4we65ZMIIBIwYDVR0jBIIBGjCCARaA
FMvx8MZSQjkPMV8WNliFVx4we65ZoYH3pIH0MIHxMQswCQYDVQQGEwJSVTEqMCgGA1UECAwh0KHQsNC90LrRgtGKLdCf0LXR
gtC10YDQsdGD0YDQs9GKMS4wLAYDVQQKDCXQltGD0YDQvdCw0LsgItCh0L7QstGA0LXQvNC10L3QvdC40LoiMR8wHQYDVQQL
DBbQoNGD0LrQvtCy0L7QtNGB0YLQstC+MSgwJgYDVQQMDB/Qk9C70LDQstC90YvQuSDRgNC10LTQsNC60YLQvtGAMTswOQYD
VQQDDDLQkNC70LXQutGB0LDQvdC00YAg0KHQtdGA0LPQtdC10LLQuNGHINCf0YPRiNC60LjQvYIEUsAnJzAOBgorBgEEAa1Z
AQMCBQADSAAwRQIhAL8w+O7XUmYUQfhaCTF0VLz+mB9NYXXT7TXfVBwMtb5kAiBYZ/XkDSyUHCKUPEOFsIH9XXg2wtN7+Q55
SNoNf4LG8g==
-----END CERTIFICATE-----
"""

bad_key2 = """
-----BEGIN PRIVATE KEY-----
MEgCAQAwHwYIKoUDBwEBBgEwEwYHKoUDAgIkAAYIKoUDBwEBAgIEIgQgAnLfFIVXwFTuD5HbBX84W9f/NLDcxNXUWHB+Atu/6BE=
-----END PRIVATE KEY-----
"""

pub_key = (63233666624051439876354823295566418637012564188384438200469674371110357426634,
           24299932244005800117978005500793438667981994951685184390218551551204573253088)

prv_key = 8100551082987309382040692774861374330127499061554316741502830866978492609026

digest_hash = gost34112012256.GOST34112012256

cert_curve = gost3410.CURVES["id-GostR3410-2001-CryptoPro-XchA-ParamSet"]


class TestGOSTCrypto(TestCase):

    def setUp(self) -> None:
        self.crypto = GOSTCrypto

    def test__parse_pem_ok(self):
        self.assertIsNotNone(self.crypto._parse_pem(valid_cert))

    def test__parse_pem_raise(self):
        with self.assertRaises(BadRequest):
            self.assertIsNotNone(self.crypto._parse_pem("BAD"))

    def test__parse_asn_cert_ok(self):
        pem = self.crypto._parse_pem(valid_cert)
        self.assertIsNotNone(self.crypto._parse_asn_cert(pem))

    def test__parse_asn_cert_raise(self):
        pem = self.crypto._parse_pem(bad_cert)
        with self.assertRaises(CertNotValid):
            self.assertIsNotNone(self.crypto._parse_asn_cert(pem))

    def test__parse_asn_key_info_ok(self):
        pem = self.crypto._parse_pem(valid_key)
        self.assertIsNotNone(self.crypto._parse_asn_prv_info(pem))

    def test__parse_asn_key_info_raise(self):
        pem = self.crypto._parse_pem(bad_key)
        with self.assertRaises(KeyNotValid):
            self.assertIsNotNone(self.crypto._parse_asn_prv_info(pem))

    def test__parse_asn_params_cert_ok(self):
        cert = self.crypto._parse_asn_tbs_cert(valid_cert)
        self.assertIsNotNone(self.crypto._parse_asn_params_cert(cert))

    def test__parse_asn_params_cert_raise(self):
        cert = self.crypto._parse_asn_tbs_cert(valid_cert)
        cert["subjectPublicKeyInfo"]["algorithm"]["parameters"]._value += "TAIL".encode()
        with self.assertRaises(CertNotValid):
            self.assertIsNotNone(self.crypto._parse_asn_params_cert(cert))

    def test__get_curve_ok(self):
        cert = self.crypto._parse_asn_tbs_cert(valid_cert)
        curve = self.crypto._get_curve(cert)
        self.assertEqual(curve, cert_curve)

    def test__get_curve_raise(self):
        cert = self.crypto._parse_asn_tbs_cert(valid_cert)
        cert["subjectPublicKeyInfo"]["algorithm"]["parameters"] = Any(GostR34102012PublicKeyParameters((
            ("publicKeyParamSet", ObjectIdentifier("1.2.643.7.1.2.1.2.9999")),
        )))
        with self.assertRaises(CertNotValid):
            self.crypto._get_curve(cert)

    def test__parse_asn_private_key_ok(self):
        pem = self.crypto._parse_pem(valid_key)
        info = self.crypto._parse_asn_prv_info(pem)
        self.assertIsNotNone(self.crypto._parse_asn_private_key(info))

    def test__parse_asn_private_key_raise(self):
        pem = self.crypto._parse_pem(valid_key)
        info = self.crypto._parse_asn_prv_info(pem)
        info["privateKey"]._value += "TAIL".encode()
        with self.assertRaises(KeyNotValid):
            self.assertIsNotNone(self.crypto._parse_asn_private_key(info))

    def test__parse_asn_public_key_ok(self):
        tbs_cert = self.crypto._parse_asn_tbs_cert(valid_cert)
        info = self.crypto._get_asn_subject_pub_info(tbs_cert)
        self.assertIsNotNone(self.crypto._parse_asn_public_key(info))

    def test__parse_asn_public_key_raise(self):
        tbs_cert = self.crypto._parse_asn_tbs_cert(valid_cert)
        info = self.crypto._get_asn_subject_pub_info(tbs_cert)
        t1, t2 = info["subjectPublicKey"]._value
        t2 += "TAIL".encode()
        info["subjectPublicKey"]._value = (t1, t2)
        with self.assertRaises(CertNotValid):
            self.assertIsNotNone(self.crypto._parse_asn_public_key(info))

    def test__parse_private_key_ok(self):
        prv = self.crypto._parse_private_key(valid_key)
        self.assertEqual(prv, prv_key)

    def test__parse_public_key_ok(self):
        pub = self.crypto._parse_public_key(valid_cert)
        self.assertEqual(pub, pub_key)

    def test__parse_public_key_hash_ok(self):
        hasher = self.crypto._parse_public_key_hash(valid_cert)
        self.assertEqual(hasher, digest_hash)

    def test__parse_public_key_hash_raise(self):
        pem_cert = self.crypto._parse_pem(valid_cert)
        asn_cert = self.crypto._parse_asn_cert(pem_cert)
        asn_cert["tbsCertificate"]["subjectPublicKeyInfo"]["algorithm"]["parameters"] = Any(
            GostR34102012PublicKeyParameters((
                ("publicKeyParamSet", ObjectIdentifier("1.2.643.7.1.2.1.2.9999")),
                ("digestParamSet", ObjectIdentifier("1.2.643.7.1.2.1.2.9999")),
            )))
        cert_new = b64encode(asn_cert.encode()).decode()
        with self.assertRaises(CertNotValid):
            self.crypto._parse_public_key_hash(
                "-----BEGIN CERTIFICATE-----\n" + cert_new + "\n-----END CERTIFICATE-----")

    def test_init_ok(self):
        crypto = self.crypto(valid_cert, valid_key)
        self.assertEqual(crypto._hash, digest_hash)
        self.assertEqual(crypto._prv_key, prv_key)
        self.assertEqual(crypto._pub_key, pub_key)
        self.assertEqual(crypto._curve, cert_curve)

    def test_init_raise(self):
        with self.assertRaises(BadRequest):
            self.crypto(valid_cert, bad_key2)

    def test_hash_ok(self):
        dgst = self.crypto(valid_cert, valid_key).hash("test".encode())
        self.assertEqual(dgst, bytes.fromhex("57381c88028d0db1d099af299d2b596bcf148707fdf2e5f104551b193808a512"))

    def test_sign_ok(self):
        crypto = self.crypto(valid_cert, valid_key)
        dgst = crypto.hash("test".encode())
        sign = crypto.sign(dgst)
        self.assertTrue(crypto.verify(sign, dgst))

    def test_verify_ok(self):
        crypto = self.crypto(valid_cert, valid_key)
        dgst = crypto.hash("test".encode())
        sign = bytes.fromhex(
            "187c82f8f70620ae217897f49c61b059944faebaebf07f7621272dea77d8af49c86a1135c418e25a4d7612b1f1b7d4ee4b00559a7d7ee6f7c708c41453396b55")
        sign2 = bytes.fromhex(
            "1068bd702e8f0ff9bfafb61a78f5e7fcbd7b4ded63c6d734daa9c72a13143bd26f7bc9b249e537b04a0b84d7b508a3c6b70b3f50182d361cd050d925997ecd85")
        self.assertTrue(crypto.verify(sign, dgst))
        self.assertTrue(crypto.verify(sign2, dgst))

    def test_get_verify_crypto_ok(self):
        crypto = self.crypto(valid_cert, valid_key)
        verify_crypto = crypto.get_verify_crypto(valid_cert)
        self.assertEqual(verify_crypto._hash, digest_hash)
        self.assertIsNone(verify_crypto._prv_key)
        self.assertEqual(verify_crypto._pub_key, pub_key)
        self.assertEqual(verify_crypto._curve, cert_curve)
