from __future__ import absolute_import, division, print_function

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

import mock
import pytest
import six
from humancrypto import PrivateKey, PublicKey, CSR, Certificate, Error


class TestPrivateKey(object):

    def test_create(self):
        key = PrivateKey.create()
        assert isinstance(key, PrivateKey)
        assert key.key_size == 2048

    def test_serialize(self):
        key = PrivateKey.create()
        serialized = key.dump()
        assert isinstance(serialized, six.binary_type)

    def test_load(self):
        key = PrivateKey.create()
        key2 = PrivateKey.load(key.dump())
        assert key.dump() == key2.dump()

    def test_load_filename(self, tmpdir):
        key = PrivateKey.create()
        fh = tmpdir.join('private.key')
        fh.write(key.dump())
        key2 = PrivateKey.load(filename=fh.strpath)
        assert key.dump() == key2.dump()

    def test_public_key(self):
        priv = PrivateKey.create()
        pub = priv.public_key
        assert isinstance(pub, PublicKey)

    def test_public_key_same_instance(self):
        priv = PrivateKey.create()
        pub1 = priv.public_key
        pub2 = priv.public_key
        assert pub1 is pub2

    def test_encryption(self):
        priv = PrivateKey.create()
        cipher = priv.public_key.encrypt(six.b('some bytes'))
        plain = priv.decrypt(cipher)
        assert plain == six.b('some bytes')

    def test_signing(self):
        priv = PrivateKey.create()
        signature = priv.sign(six.b('a message'))
        assert isinstance(signature, six.binary_type)
        assert priv.public_key.verify(six.b('a message'), signature) is True

    def test_self_signed_cert(self):
        priv = PrivateKey.create()
        cert = priv.self_signed_cert({'common_name': u'jose'})
        assert isinstance(cert, Certificate)
        assert cert.subject.attribs['common_name'] == u'jose'
        assert cert.issuer.attribs['common_name'] == u'jose'

        cert = x509.load_pem_x509_certificate(
            cert.dump(), default_backend()
        )
        assert cert.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME)[0].value == u'jose'
        assert cert.issuer.get_attributes_for_oid(
            NameOID.COMMON_NAME)[0].value == u'jose'

    def test_sign_csr(self):
        priv = PrivateKey.create()
        cert1 = priv.self_signed_cert({'common_name': u'alice'})
        csr = CSR.create(priv, {'common_name': u'bob'})
        cert2 = priv.sign_csr(csr, cert1)
        assert cert1.subject.attribs == cert2.issuer.attribs
        assert cert2.issuer.attribs['common_name'] == u'alice'
        assert cert2.subject.attribs['common_name'] == u'bob'

    def test_sign_csr_invalid_signature(self):
        priv = PrivateKey.create()
        cert1 = priv.self_signed_cert({'common_name': u'alice'})
        csr = CSR.create(priv, {'common_name': u'bob'})
        csr._csr = mock.MagicMock()
        csr._csr.is_signature_valid = False
        with pytest.raises(Error):
            priv.sign_csr(csr, cert1)


class TestPublicKey(object):

    def test_load(self):
        priv = PrivateKey.create()
        pub = priv.public_key
        pub2 = PublicKey.load(pub.dump())
        assert pub2.dump() == pub.dump()

    def test_load_filename(self, tmpdir):
        priv = PrivateKey.create()
        pub = priv.public_key
        fh = tmpdir.join('pub.key')
        fh.write(pub.dump())
        pub2 = PublicKey.load(filename=fh.strpath)
        assert pub2.dump() == pub.dump()


class TestCSR(object):

    def test_create(self):
        priv = PrivateKey.create()
        csr = CSR.create(priv, {'common_name': u'bob', 'state': u'CA'})
        assert isinstance(csr, CSR)
        assert csr.attribs['common_name'] == u'bob'
        assert csr.attribs['state'] == u'CA'

    def test_create_from_private_key(self):
        priv = PrivateKey.create()
        csr = priv.signing_request({'common_name': u'bob', 'state': u'CA'})
        assert isinstance(csr, CSR)
        assert csr.attribs['common_name'] == u'bob'
        assert csr.attribs['state'] == u'CA'

    def test_load(self):
        priv = PrivateKey.create()
        csr = CSR.create(priv, {'common_name': u'alice'})
        csr2 = CSR.load(csr.dump())
        assert isinstance(csr2, CSR)
        assert csr2.attribs['common_name'] == u'alice'

    def test_load_filename(self, tmpdir):
        priv = PrivateKey.create()
        csr = CSR.create(priv, {'common_name': u'alice'})
        fh = tmpdir.join('something.csr')
        fh.write(csr.dump())
        csr2 = CSR.load(filename=fh.strpath)
        assert csr2.dump() == csr.dump()

    def test_multiple_value_attribs(self):
        priv = PrivateKey.create()
        csr = CSR.create(priv, {'common_name': [u'bob', u'sam']})
        assert csr.attribs['common_name'] == [u'bob', u'sam']


class TestCertificate(object):

    def test_load(self):
        priv = PrivateKey.create()
        cert = priv.self_signed_cert({'common_name': u'betty'})
        cert2 = Certificate.load(cert.dump())
        assert isinstance(cert2, Certificate)
        assert cert.dump() == cert2.dump()

    def test_load_filename(self, tmpdir):
        priv = PrivateKey.create()
        cert = priv.self_signed_cert({'common_name': u'betty'})
        fh = tmpdir.join('something.cert')
        fh.write(cert.dump())
        cert2 = Certificate.load(filename=fh.strpath)
        assert cert2.dump() == cert.dump()
