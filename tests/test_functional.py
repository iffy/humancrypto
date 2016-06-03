from __future__ import absolute_import, division, print_function

import six
from humancrypto import PrivateKey, PublicKey


class TestPrivateKey(object):

    def test_create(self):
        key = PrivateKey.create()
        assert isinstance(key, PrivateKey)
        assert key.key_size == 2048

    def test_serialize(self):
        key = PrivateKey.create()
        serialized = key.serialize()
        assert isinstance(serialized, six.binary_type)

    def test_load(self):
        key = PrivateKey.create()
        key2 = PrivateKey.load(key.serialize())
        assert key.serialize() == key2.serialize()

    def test_load_filename(self, tmpdir):
        key = PrivateKey.create()
        fh = tmpdir.join('private.key')
        fh.write(key.serialize())
        key2 = PrivateKey.load(filename=fh.strpath)
        assert key.serialize() == key2.serialize()

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


class TestPublicKey(object):

    def test_load(self):
        priv = PrivateKey.create()
        pub = priv.public_key
        pub2 = PublicKey.load(pub.serialize())
        assert pub2.serialize() == pub.serialize()

    def test_load_filename(self, tmpdir):
        priv = PrivateKey.create()
        pub = priv.public_key
        fh = tmpdir.join('pub.key')
        fh.write(pub.serialize())
        pub2 = PublicKey.load(filename=fh.strpath)
        assert pub2.serialize() == pub.serialize()
