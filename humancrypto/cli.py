from __future__ import print_function
import argparse

import six
import sys
import contextlib
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

# ========================================================
# Passwords
# ========================================================
pw_parser = sp.add_parser(
    'pw',
    help='Password storage/verification')

pw = pw_parser.add_subparsers(
    title='subcommands',
    dest='subcommand')

p = pw.add_parser(
    'verify',
    help='Verify that a password matches a stored password.'
         '  Password is read from stdin.')
p.add_argument(
    'stored',
    help='Stored password.')


@do(p)
def verify(args):
    from humancrypto.current import verify_password
    pw = sys.stdin.read().encode()
    if isinstance(args.stored, six.binary_type):
        args.stored = args.stored.decode()
    if verify_password(args.stored, pw):
        out('ok')


# --------------------------------------------------------
# 44 B.C.
# --------------------------------------------------------
p = pw.add_parser(
    'store44BC',
    help='DEPRECATED.'
         '  Store a password using 44 B.C. best practices.'
         '  Password is read from stdin.')


@do(p)
def store44BC(args):
    from humancrypto.y44bc import store_password
    pw = sys.stdin.read().encode()
    out(store_password(pw))

# --------------------------------------------------------
# 2016
# --------------------------------------------------------
p = pw.add_parser(
    'store2016',
    help='Store a password using 2016 best practices.'
         '  Password is read from stdin.')


@do(p)
def store2016(args):
    from humancrypto.y2016 import store_password
    pw = sys.stdin.read().encode()
    out(store_password(pw))

# ========================================================
# RSA
# ========================================================
rsa_parser = sp.add_parser(
    'rsa',
    help='RSA pub/priv key commands')

rsa = rsa_parser.add_subparsers(
    title='subcommands',
    dest='subcommand')

# --------------------------------------------------------
# create-private
# --------------------------------------------------------
p = rsa.add_parser(
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
p = rsa.add_parser(
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
p = rsa.add_parser(
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
p = rsa.add_parser(
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
p = rsa.add_parser(
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


@contextlib.contextmanager
def redirect(stdin=None, stdout=None, stderr=None):
    former = sys.stdin, sys.stdout, sys.stderr
    sys.stdin = stdin or sys.stdin
    sys.stdout = stdout or sys.stdout
    sys.stderr = stderr or sys.stderr
    yield
    sys.stdin, sys.stdout, sys.stderr = former


def main(args=None, stdin=None, stdout=None, stderr=None):
    parsed = ap.parse_args(args)
    with redirect(stdin=stdin, stdout=stdout, stderr=stderr):
        parsed.func(parsed)
