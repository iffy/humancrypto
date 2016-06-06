from __future__ import absolute_import, division, print_function

import six

from humancrypto.cli import main
from humancrypto import PrivateKey, PublicKey, Certificate, CSR


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

    def test_self_signed_cert(self, tmpdir):
        keyfile = tmpdir.join('foo.key')
        certfile = tmpdir.join('foo.crt')
        main(['create-private', keyfile.strpath])
        main([
            'self-signed-cert', keyfile.strpath, certfile.strpath,
            '-d', 'common_name=jim', '-d', six.u('state=CA'),
        ])
        cert = Certificate.load(filename=certfile.strpath)
        assert cert.issuer.attribs['common_name'] == u'jim'
        assert cert.subject.attribs['common_name'] == u'jim'
        assert cert.issuer.attribs['state'] == u'CA'
        assert cert.subject.attribs['state'] == u'CA'

    def test_create_csr(self, tmpdir):
        keyfile = tmpdir.join('foo.key')
        csrfile = tmpdir.join('foo.csr')
        main(['create-private', keyfile.strpath])
        main([
            'create-csr', keyfile.strpath, csrfile.strpath,
            '-d', 'common_name=jim', '-d', six.u('state=CA'),
        ])
        csr = CSR.load(filename=csrfile.strpath)
        assert csr.attribs['common_name'] == u'jim'
        assert csr.attribs['state'] == u'CA'
