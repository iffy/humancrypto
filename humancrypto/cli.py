from __future__ import print_function
import argparse

import six
import sys
import contextlib
from humancrypto import PrivateKey, Certificate, CSR
from humancrypto import pki, yearutil


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
# Year-based stuff
# ========================================================
def add_year(parser, name, key, deprecated=False):
    helptext = 'Crypto for year {name}'.format(**locals())
    if deprecated:
        helptext = 'DEPRECATED. ' + helptext

    year_parser = parser.add_parser(name, help=helptext)
    year_sp = year_parser.add_subparsers(title='actions', dest='action')

    # ---------------------------
    # Passwords
    # ---------------------------
    pw = year_sp.add_parser(
        'pw',
        help='Password storage/verification')

    pw_subs = pw.add_subparsers(
        title='action',
        dest='subsubcommand')

    p = pw_subs.add_parser(
        'store',
        help='Hash a password for later verification.',
        description='Read a password'
             ' from stdin and write a hash of the password to stdout.')

    @do(p)
    def store_password(args):
        module = yearutil.get_module(key)
        pw = sys.stdin.read().encode()
        out(module.store_password(pw))

    p = pw_subs.add_parser(
            'verify',
            help='Verify that a password matches a stored hash.',
            description='Read a password from stdin'
                 ' and compare with the given stored password.')
    p.add_argument(
        'stored',
        help='Stored password.')

    @do(p)
    def verify_password(args):
        module = yearutil.get_module(key)
        pw = sys.stdin.read().encode()
        if isinstance(args.stored, six.binary_type):
            args.stored = args.stored.decode()
        if module.verify_password(args.stored, pw):
            out('ok')

    # ---------------------------
    # Tokens
    # ---------------------------
    token = year_sp.add_parser(
        'token',
        description='Writes a secure random token to stdout.'
                    '  By default, output is binary.',
        help='Generate a secure random token')

    token.add_argument(
        '-H',
        '--hex',
        action='store_true',
        help='Output in hexadecimal format')
    token.add_argument(
        '-U',
        '--urlsafe',
        action='store_true',
        help='Output in a URL safe format')
    token.add_argument(
        '-L',
        '--length',
        type=int,
        default=None,
        help="Byte size of token to generate."
             "  Defaults to a secure amount.")

    @do(token)
    def make_token(args):
        module = yearutil.get_module(key)
        ret = None
        if args.hex:
            ret = module.random_hex_token(args.length)
        elif args.urlsafe:
            ret = module.random_urlsafe_token(args.length)
        else:
            ret = module.random_token(args.length)
        out(ret)


add_year(sp, '2016', '2016')
add_year(sp, '44bc', '44bc', deprecated=True)


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
