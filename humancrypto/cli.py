from __future__ import print_function
import argparse
import sys

from humancrypto import PrivateKey


def do(parser):
    def deco(f):
        parser.set_defaults(func=f)
        return f
    return deco


def out(*x):
    print(*x)


ap = argparse.ArgumentParser()


@do(ap)
def not_implemented(args):
    print('Command not implemented')
    sys.exit(1)


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


def main(args=None):
    parsed = ap.parse_args(args)
    parsed.func(parsed)
