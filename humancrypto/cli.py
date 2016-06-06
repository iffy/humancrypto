from __future__ import print_function
import argparse

import six
from humancrypto import PrivateKey


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
        print('arg', arg)
        key, value = arg.split('=', 1)
        if not isinstance(value, six.text_type):
            value = value.decode('utf-8')
        attribs[key] = value
        print('key', key, 'value', value)
    priv = PrivateKey.load(filename=args.privatekey)
    cert = priv.self_signed_cert(attribs)
    cert.save(args.certfile)
    out('wrote', args.certfile)


def main(args=None):
    parsed = ap.parse_args(args)
    parsed.func(parsed)
