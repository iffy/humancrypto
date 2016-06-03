from __future__ import absolute_import, division, print_function

from humancrypto.cli import main
from humancrypto import PrivateKey, PublicKey


class TestCLI(object):

    def test_keygen(self, tmpdir):
        keyfile = tmpdir.join('foo.key')
        main(['private', keyfile])
        key = PrivateKey.load(filename=keyfile)
        assert key.key_size == 2048

    def test_public(self, tmpdir):
        privfile = tmpdir.join('something.key')
        pubfile = tmpdir.join('something.pub')
        main(['private', privfile])
        main(['public', privfile, pubfile])
        PublicKey.load(filename=pubfile)
