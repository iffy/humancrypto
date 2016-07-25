from __future__ import print_function
import argparse

import six
from humancrypto import PrivateKey, Certificate, CSR
from humancrypto import pki


def do(parser):
    def deco(f):
        parser.set_defaults(func=f)
        return f
    return deco


def out(*x):
    print(*x)


def _acceptBasicAttributes(parser):
    for key in sorted(pki.OID_MAPPING):
        ckey = key.replace('_', '-')
        parser.add_argument('--{0}'.format(ckey), action='append')


def _basicAttributes2Dict(args):
    ret = {}
    for key in pki.OID_MAPPING:
        values = getattr(args, key)
        if values is None:
            continue
        clean_values = []
        for val in values:
            if not isinstance(val, six.text_type):
                val = val.decode('utf-8')
            clean_values.append(val)
        ret[key] = clean_values
    return ret


def _acceptSomeExtendedAttributes(parser):
    parser.add_argument('--subject-alternative-name', action='append')


def _extAttributes2Dict(args):
    ret = {}
    for key in pki.EXT_MAPPING:
        values = getattr(args, key, None)
        if values is None:
            continue
        clean_values = []
        for val in values:
            if not isinstance(val, six.text_type):
                val = val.decode('utf-8')
            clean_values.append(val)
        ret[key] = clean_values
    return ret


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
_acceptBasicAttributes(p)


@do(p)
def self_signed_cert(args):
    attribs = _basicAttributes2Dict(args)
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
    '--server',
    action='store_true',
    help='If given, use sane server-certificate defaults.')
p.add_argument(
    '--client',
    action='store_true',
    help='If given, use sane client-certificate defaults.')
_acceptBasicAttributes(p)
_acceptSomeExtendedAttributes(p)


@do(p)
def create_csr(args):
    attribs = _basicAttributes2Dict(args)
    extensions = _extAttributes2Dict(args)
    priv = PrivateKey.load(filename=args.privatekey)
    csr = priv.signing_request(
        attribs,
        extensions=extensions,
        server=args.server,
        client=args.client)
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
