from __future__ import absolute_import, division, print_function

import six

from humancrypto.cli import main
from humancrypto import PrivateKey, PublicKey, Certificate, CSR


class Test_token(object):

    def do(self, args, stdin=None):
        stdout = six.StringIO()
        stderr = six.StringIO()
        if stdin:
            stdin = six.StringIO(stdin)
        main(args, stdin=stdin, stdout=stdout, stderr=stderr)
        return stdout.getvalue(), stderr.getvalue()

    def test_bytes(self):
        self.do(['y2016', 'token'])

    def test_hex(self):
        self.do(['y2016', 'token', '--hex'])

    def test_urlsafe(self):
        self.do(['y2016', 'token', '--urlsafe'])


class Test_pw(object):

    def do(self, args, stdin=None):
        stdout = six.StringIO()
        stderr = six.StringIO()
        if stdin:
            stdin = six.StringIO(stdin)
        main(args, stdin=stdin, stdout=stdout, stderr=stderr)
        return stdout.getvalue(), stderr.getvalue()

    def test_store2016(self):
        stored, _ = self.do(
            ['y2016', 'pw', 'store'],
            stdin='password')
        result, _ = self.do(
            ['y2016', 'pw', 'verify', stored],
            stdin='password')
        assert result == 'ok\n'

    def test_store2016_wrong_password(self):
        stored, _ = self.do(
            ['y2016', 'pw', 'store'],
            stdin='password')
        try:
            self.do(
                ['y2016', 'pw', 'verify', stored],
                stdin='wrong')
            assert False, "Should have raised SystemExit"
        except SystemExit as e:
            assert e.code == 1, "Should exit with 1 cause wrong password"

    def test_store44bc_old(self):
        stored, _ = self.do(
            ['y44bc', 'pw', 'store'],
            stdin='password')
        try:
            self.do(
                ['y2016', 'pw', 'verify', stored],
                stdin='password')
            assert False, "Should have raised SystemExit"
        except SystemExit as e:
            assert e.code == 2, "Should exit with 2 cause wrong year"

    def test_store44BC(self):
        stored, _ = self.do(
            ['y44bc', 'pw', 'store'],
            stdin='password')
        result, _ = self.do(
            ['y44bc', 'pw', 'verify', stored],
            stdin='password')
        assert result == 'ok\n'


class Test_rsa(object):

    def do(self, args):
        return main(['rsa'] + args)

    def test_create_private(self, tmpdir):
        keyfile = tmpdir.join('foo.key')
        self.do(['create-private', keyfile.strpath])
        key = PrivateKey.load(filename=keyfile.strpath)
        assert key.key_size == 2048

    def test_extract_public(self, tmpdir):
        privfile = tmpdir.join('something.key')
        pubfile = tmpdir.join('something.pub')
        self.do(['create-private', privfile.strpath])
        self.do(['extract-public', privfile.strpath, pubfile.strpath])
        PublicKey.load(filename=pubfile.strpath)

    def test_self_signed_cert(self, tmpdir):
        keyfile = tmpdir.join('foo.key')
        certfile = tmpdir.join('foo.crt')
        self.do(['create-private', keyfile.strpath])
        self.do([
            'self-signed-cert', keyfile.strpath, certfile.strpath,
            '--common-name', 'jim', '--state', six.u('CA'),
        ])
        cert = Certificate.load(filename=certfile.strpath)
        assert cert.issuer.attribs['common_name'] == u'jim'
        assert cert.subject.attribs['common_name'] == u'jim'
        assert cert.issuer.attribs['state'] == u'CA'
        assert cert.subject.attribs['state'] == u'CA'

    def test_create_csr(self, tmpdir):
        keyfile = tmpdir.join('foo.key')
        csrfile = tmpdir.join('foo.csr')
        self.do(['create-private', keyfile.strpath])
        self.do([
            'create-csr', keyfile.strpath, csrfile.strpath,
            '--common-name', 'jim', '--state', six.u('CA'),
        ])
        csr = CSR.load(filename=csrfile.strpath)
        assert csr.attribs['common_name'] == u'jim'
        assert csr.attribs['state'] == u'CA'

    def test_create_csr_extended_attrib(self, tmpdir):
        keyfile = tmpdir.join('foo.key')
        csrfile = tmpdir.join('foo.csr')
        self.do(['create-private', keyfile.strpath])
        self.do([
            'create-csr', keyfile.strpath, csrfile.strpath,
            '--common-name', 'jim',
            '--subject-alternative-name', 'dns:jose',
        ])
        csr = CSR.load(filename=csrfile.strpath)
        assert csr.attribs['common_name'] == u'jim'
        assert csr.extensions['subject_alternative_name']['dns'] == [u'jose']

    def test_sign_csr(self, tmpdir):
        cakey = tmpdir.join('ca.key')
        cacrt = tmpdir.join('ca.crt')
        otherkey = tmpdir.join('other.key')
        othercsr = tmpdir.join('other.csr')
        othercrt = tmpdir.join('other.crt')
        self.do(['create-private', cakey.strpath])
        self.do([
            'self-signed-cert', cakey.strpath, cacrt.strpath,
            '--common-name', 'bob',
            '--state', 'WA',
        ])

        self.do(['create-private', otherkey.strpath])
        self.do([
            'create-csr', otherkey.strpath, othercsr.strpath,
            '--common-name', 'jim',
            '--state', 'CA',
        ])
        self.do([
            'sign-csr', cakey.strpath, cacrt.strpath, othercsr.strpath,
            othercrt.strpath,
        ])
        cert = Certificate.load(filename=othercrt.strpath)
        assert cert.issuer.attribs['common_name'] == u'bob'
        assert cert.subject.attribs['common_name'] == u'jim'
        assert cert.issuer.attribs['state'] == u'WA'
        assert cert.subject.attribs['state'] == u'CA'

    def test_sign_csr_server(self, tmpdir):
        cakey = tmpdir.join('ca.key')
        cacrt = tmpdir.join('ca.crt')
        otherkey = tmpdir.join('other.key')
        othercsr = tmpdir.join('other.csr')
        othercrt = tmpdir.join('other.crt')
        self.do(['create-private', cakey.strpath])
        self.do([
            'self-signed-cert', cakey.strpath, cacrt.strpath,
            '--common-name', 'bob',
            '--state', 'WA',
        ])

        self.do(['create-private', otherkey.strpath])
        self.do([
            'create-csr', otherkey.strpath, othercsr.strpath,
            '--common-name', 'jim',
            '--state', 'CA',
            '--server',
        ])
        self.do([
            'sign-csr', cakey.strpath, cacrt.strpath, othercsr.strpath,
            othercrt.strpath,
        ])
        cert = Certificate.load(filename=othercrt.strpath)
        assert cert.issuer.attribs['common_name'] == u'bob'
        assert cert.subject.attribs['common_name'] == u'jim'
        assert cert.issuer.attribs['state'] == u'WA'
        assert cert.subject.attribs['state'] == u'CA'
        assert cert.extensions['key_usage']['key_encipherment'] is True

    def test_sign_csr_client(self, tmpdir):
        cakey = tmpdir.join('ca.key')
        cacrt = tmpdir.join('ca.crt')
        otherkey = tmpdir.join('other.key')
        othercsr = tmpdir.join('other.csr')
        othercrt = tmpdir.join('other.crt')
        self.do(['create-private', cakey.strpath])
        self.do([
            'self-signed-cert', cakey.strpath, cacrt.strpath,
            '--common-name', 'bob',
            '--state', 'WA',
        ])

        self.do(['create-private', otherkey.strpath])
        self.do([
            'create-csr', otherkey.strpath, othercsr.strpath,
            '--common-name', 'jim', '--state', 'CA',
            '--client',
        ])
        self.do([
            'sign-csr', cakey.strpath, cacrt.strpath, othercsr.strpath,
            othercrt.strpath,
        ])
        cert = Certificate.load(filename=othercrt.strpath)
        assert cert.issuer.attribs['common_name'] == u'bob'
        assert cert.subject.attribs['common_name'] == u'jim'
        assert cert.issuer.attribs['state'] == u'WA'
        assert cert.subject.attribs['state'] == u'CA'
        assert cert.extensions['key_usage']['digital_signature'] is True
