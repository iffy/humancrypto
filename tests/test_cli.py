from __future__ import absolute_import, division, print_function

from humancrypto.cli import main
from humancrypto import PrivateKey, PublicKey


class TestCLI(object):

    def test_create_private(self, tmpdir):
        keyfile = tmpdir.join('foo.key')
        main(['create-private', keyfile.strpath])
        key = PrivateKey.load(filename=keyfile.strpath)
        assert key.key_size == 2048

    def test_extract_public(self, tmpdir):
        privfile = tmpdir.join('something.key')
        pubfile = tmpdir.join('something.pub')
        main(['create-private', privfile.strpath])
        main(['extract-public', privfile.strpath, pubfile.strpath])
        PublicKey.load(filename=pubfile.strpath)
