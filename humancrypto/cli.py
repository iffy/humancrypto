from __future__ import print_function
import argparse

import six
from humancrypto import PrivateKey, Certificate, CSR


def do(parser):
    def deco(f):
        parser.set_defaults(func=f)
        return f
    return deco


def out(*x):
    print(*x)


ap = argparse.ArgumentParser()


sp = ap.add_subparsers(title='subcommands', dest='command')

# --------------------------------------------------------
# create-private
# --------------------------------------------------------
p = sp.add_parser(
    'create-private',
    help='Create a private key')
p.add_argument(
    'filename',
    help='Private key filename')


@do(p)
def create_private(args):
    PrivateKey.create().save(args.filename)
    out('wrote', args.filename)

# --------------------------------------------------------
# extract-public
# --------------------------------------------------------
p = sp.add_parser(
    'extract-public',
    help='Extract a public key from a private key')
p.add_argument(
    'privatekey',
    help='Private key filename')
p.add_argument(
    'publickey',
    help='Public key filename')


@do(p)
def extract_public(args):
    pub = PrivateKey.load(filename=args.privatekey).public_key
    pub.save(args.publickey)
    out('wrote', args.publickey)

# --------------------------------------------------------
# self-signed-cert
# --------------------------------------------------------
p = sp.add_parser(
    'self-signed-cert',
    help='Create a self-signed certificate')
p.add_argument(
    'privatekey',
    help='Private key filename')
p.add_argument(
    'certfile',
    help='Certificate filename')
p.add_argument(
    '-d', '--data',
    action='append',
    help='Subject/Issuer attributes. (e.g. common_name=jim)')


@do(p)
def self_signed_cert(args):
    attribs = {}
    for arg in (args.data or []):
        key, value = arg.split('=', 1)
        if not isinstance(value, six.text_type):
            value = value.decode('utf-8')
        attribs[key] = value
    priv = PrivateKey.load(filename=args.privatekey)
    cert = priv.self_signed_cert(attribs)
    cert.save(args.certfile)
    out('wrote', args.certfile)

# --------------------------------------------------------
# create-csr
# --------------------------------------------------------
p = sp.add_parser(
    'create-csr',
    help='Create a Certificate Signing Request (CSR)')
p.add_argument(
    'privatekey',
    help='Private key filename')
p.add_argument(
    'csr',
    help='CSR filename')
p.add_argument(
    '-d', '--data',
    action='append',
    help='Subject attributes. (e.g. common_name=jim)')
p.add_argument(
    '--server',
    action='store_true',
    help='If given, use sane server-certificate defaults.')
p.add_argument(
    '--client',
    action='store_true',
    help='If given, use sane client-certificate defaults.')


@do(p)
def create_csr(args):
    attribs = {}
    for arg in (args.data or []):
        key, value = arg.split('=', 1)
        if not isinstance(value, six.text_type):
            value = value.decode('utf-8')
        attribs[key] = value
    priv = PrivateKey.load(filename=args.privatekey)
    csr = priv.signing_request(attribs, server=args.server, client=args.client)
    csr.save(args.csr)
    out('wrote', args.csr)


# --------------------------------------------------------
# sign-csr
# --------------------------------------------------------
p = sp.add_parser(
    'sign-csr',
    help='Sign a Certificate Signing Request to make a certificate')
p.add_argument(
    'signingkey',
    help='Filename of private key to sign with.')
p.add_argument(
    'signingcert',
    help='Filename of certificate to sign with.')
p.add_argument(
    'csr',
    help='CSR to sign')
p.add_argument(
    'cert',
    help='Filename to write resulting cert to.')


@do(p)
def sign_csr(args):
    signing_key = PrivateKey.load(filename=args.signingkey)
    signing_cert = Certificate.load(filename=args.signingcert)
    csr = CSR.load(filename=args.csr)
    cert = signing_key.sign_csr(csr, signing_cert)
    cert.save(args.cert)
    out('wrote', args.cert)


def main(args=None):
    parsed = ap.parse_args(args)
    parsed.func(parsed)
