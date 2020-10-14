#  Copyright © 2020-present Artem V. Zaborskiy <ftomza@yandex.ru>. All rights reserved.
#
#  This source code is licensed under the Apache 2.0 license found
#  in the LICENSE file in the root directory of this source tree.

from base64 import b64decode
from typing import Tuple, Optional, Dict

import pem as pem
from pyderasn import ObjectIdentifier, OctetString
from pygost import gost3410, gost34112012256, gost34112012512
from pygost.asn1schemas.prvkey import PrivateKeyInfo, PrivateKey
from pygost.asn1schemas.x509 import Certificate, AlgorithmIdentifier, GostR34102012PublicKeyParameters, \
    SubjectPublicKeyInfo, TBSCertificate
from pygost.gost3410 import GOST3410Curve
from pygost.iface import PEP247

from sspvo import AbstractCrypto
from sspvo.exceptions import BadRequest, CertNotValid, KeyNotValid

oid_curve_names = {
    ObjectIdentifier("1.2.643.2.2.35.1"): "id-GostR3410-2001-CryptoPro-A-ParamSet",
    ObjectIdentifier("1.2.643.2.2.35.2"): "id-GostR3410-2001-CryptoPro-B-ParamSet",
    ObjectIdentifier("1.2.643.2.2.35.3"): "id-GostR3410-2001-CryptoPro-C-ParamSet",
    ObjectIdentifier("1.2.643.2.2.36.0"): "id-GostR3410-2001-CryptoPro-XchA-ParamSet",
    ObjectIdentifier("1.2.643.2.2.36.1"): "id-GostR3410-2001-CryptoPro-XchB-ParamSet",
    ObjectIdentifier("1.2.643.7.1.2.1.1.1"): "id-tc26-gost-3410-2012-256-paramSetA",
    ObjectIdentifier("1.2.643.7.1.2.1.1.2"): "id-tc26-gost-3410-2012-256-paramSetB",
    ObjectIdentifier("1.2.643.7.1.2.1.1.3"): "id-tc26-gost-3410-2012-256-paramSetC",
    ObjectIdentifier("1.2.643.7.1.2.1.1.4"): "id-tc26-gost-3410-2012-256-paramSetD",
    ObjectIdentifier("1.2.643.7.1.2.1.2.1"): "id-tc26-gost-3410-12-512-paramSetA",
    ObjectIdentifier("1.2.643.7.1.2.1.2.2"): "id-tc26-gost-3410-12-512-paramSetB",
    ObjectIdentifier("1.2.643.7.1.2.1.2.3"): "id-tc26-gost-3410-12-512-paramSetC",
}

oid_digest_names = {
    ObjectIdentifier("1.2.643.7.1.1.2.2"): "id-tc26-gost-3411-12-256",
    ObjectIdentifier("1.2.643.7.1.1.2.3"): "id-tc26-gost-3411-12-512",
}

hashes: Dict[str, PEP247] = {
    "id-tc26-gost-3411-12-256": gost34112012256.GOST34112012256,
    "id-tc26-gost-3411-12-512": gost34112012512.GOST34112012512,
}


class Crypto(AbstractCrypto):
    """
    Crypto Basic structure that implements the sspvo.AbstractCrypto interface.
    """

    def __init__(self, cert: str, key: Optional[str] = None):
        self._cert = cert
        self._key = key
        self._hash = None
        if not self._cert:
            raise BadRequest("Cert not set")

    def get_verify_crypto(self, cert: str) -> "Crypto":
        raise NotImplementedError()

    def get_cert(self) -> str:
        return self._cert

    def hash(self, data: bytes) -> bytes:
        if not self._hash:
            raise BadRequest("Hash not set")

        return self._hash(data).digest()

    def sign(self, digest: bytes) -> bytes:
        raise NotImplementedError()

    def verify(self, sign: bytes, digest: bytes) -> bool:
        raise NotImplementedError()


class GOSTCrypto(Crypto):
    def __init__(self, cert: str, key: Optional[str] = None):
        super().__init__(cert, key)
        self._pub_key: Tuple[int, int] = self._parse_public_key(self._cert)
        self._curve: GOST3410Curve = self._parse_curve(self._cert)
        self._prv_key: Optional[int] = None
        if key:
            self._prv_key = self._parse_private_key(self._key)
            public_key = gost3410.public_key(self._curve, self._prv_key)
            if public_key != self._pub_key:
                raise BadRequest("Private and Public key mismatch")
        self._hash = self._parse_public_key_hash(self._cert)

    def hash(self, data: bytes) -> bytes:
        digest = super().hash(data)
        return digest[::-1]

    def get_verify_crypto(self, cert: str) -> "GOSTCrypto":
        return GOSTCrypto(cert)

    def sign(self, digest: bytes) -> bytes:
        sign = gost3410.sign(self._curve, self._prv_key, digest)
        return sign

    def verify(self, sign: bytes, digest: bytes) -> bool:
        ok = gost3410.verify(self._curve, self._pub_key, digest, sign)
        return ok

    @classmethod
    def _parse_public_key(cls, cert: str) -> Tuple[int, int]:
        tbs_cert = cls._parse_asn_tbs_cert(cert)
        info = cls._get_asn_subject_pub_info(tbs_cert)
        private_key = cls._parse_asn_public_key(info)
        return gost3410.pub_unmarshal(bytes(private_key))

    @classmethod
    def _parse_private_key(cls, key: str) -> int:
        pem_key = cls._parse_pem(key)
        info = cls._parse_asn_prv_info(pem_key)
        private_key = cls._parse_asn_private_key(info)
        return gost3410.prv_unmarshal(bytes(private_key))

    @classmethod
    def _parse_curve(cls, cert: str) -> GOST3410Curve:
        tbs_cert = cls._parse_asn_tbs_cert(cert)
        return cls._get_curve(tbs_cert)

    @classmethod
    def _parse_public_key_hash(cls, cert: str) -> PEP247:
        tbs_cert = cls._parse_asn_tbs_cert(cert)
        params = cls._parse_asn_params_cert(tbs_cert)
        param_set = params["digestParamSet"]
        if param_set not in oid_digest_names:
            raise CertNotValid(f"unknown GOST digest param set: {param_set}")

        digest_name = oid_digest_names[param_set]
        return hashes[digest_name]

    @classmethod
    def _parse_asn_tbs_cert(cls, x509: str) -> TBSCertificate:
        pem_cert = cls._parse_pem(x509)
        asn_cert = cls._parse_asn_cert(pem_cert)
        return asn_cert["tbsCertificate"]

    @classmethod
    def _parse_asn_public_key(cls, info: SubjectPublicKeyInfo) -> OctetString:
        private_key, tail = OctetString().decode(bytes(info["subjectPublicKey"]))
        if tail:
            raise CertNotValid("trailing data after ASN.1 of public key info")
        return private_key

    @classmethod
    def _parse_asn_private_key(cls, info: PrivateKeyInfo) -> PrivateKey:
        private_key, tail = PrivateKey().decode(bytes(info["privateKey"]))
        if tail:
            raise KeyNotValid("trailing data after ASN.1 of private key info")
        return private_key

    @classmethod
    def _get_asn_subject_pub_info(cls, cert: TBSCertificate) -> SubjectPublicKeyInfo:
        return cert["subjectPublicKeyInfo"]

    @staticmethod
    def _parse_pem(data: str) -> str:
        pems = pem.parse(data.encode())
        if not pems:
            raise BadRequest("data not PEM")
        lines = pems[0].as_text().strip().split("\n")
        pem_cert = "".join(lines[1:-1])
        return pem_cert

    @staticmethod
    def _parse_asn_cert(pem_cert: str) -> Certificate:
        cert_raw = b64decode(pem_cert)
        cert, tail = Certificate().decode(cert_raw)
        if tail:
            raise CertNotValid("trailing data after ASN.1 of certificate")
        return cert

    @staticmethod
    def _parse_asn_prv_info(pem_key: str) -> PrivateKeyInfo:
        key_raw = b64decode(pem_key)
        info, tail = PrivateKeyInfo().decode(key_raw)
        if tail:
            raise KeyNotValid("trailing data after ASN.1 of private key")
        return info

    @classmethod
    def _get_asn_algo_cert(cls, cert: TBSCertificate) -> AlgorithmIdentifier:
        return cls._get_asn_subject_pub_info(cert)["algorithm"]

    @classmethod
    def _parse_asn_params_cert(cls, cert: TBSCertificate) -> GostR34102012PublicKeyParameters:
        algo = bytes(cls._get_asn_algo_cert(cert)["parameters"])
        params, tail = GostR34102012PublicKeyParameters().decode(algo)
        if tail:
            raise CertNotValid("trailing data after GOST parameters")
        return params

    @classmethod
    def _get_curve(cls, cert: TBSCertificate) -> GOST3410Curve:
        params = cls._parse_asn_params_cert(cert)
        param_set = params["publicKeyParamSet"]

        if param_set not in oid_curve_names:
            raise CertNotValid(f"unknown GOST param set: {param_set}")
        curve_name = oid_curve_names[param_set]
        curve = gost3410.CURVES[curve_name]
        return curve
