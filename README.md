# Cryptography for humans

[![Build Status](https://travis-ci.org/iffy/humancrypto.svg?branch=master)](https://travis-ci.org/iffy/humancrypto)

## tl;dr

**DON'T USE THIS IN PRODUCTION!  It's just an idea right now.**

Use cryptographic best practices:

- If it's 2016, use the `y2016` module.
- If it's 44 B.C., use the `y44bc` module.

Use it for:

- [password hashing](#password-hashing)
- [random token generation](#random-tokens)
- [RSA certificates and keys](#RSA)

## Installation

Stable:

    pip install humancrypto

Latest:

    pip install git+https://github.com/iffy/humancrypto.git


## Motivation

Do you want to do something cryptographic, but have a hard time keeping up with changing best practices?  This cryptography library makes it easy to know if you're following current best practices.

For instance, in 44 B.C. it was okay to use things like [ROT13](https://en.wikipedia.org/wiki/ROT13) to store your passwords.  So the `y44bc` module is provided for that level of password-storage security:

    >>> from humancrypto import y44bc
    >>> stored_44bc = y44bc.store_password(b'password')

Verify that a given password matches the stored version:

    >>> y44bc.verify_password(stored_44bc, b'password')
    True
    >>> y44bc.verify_password(stored_44bc, b'WRONG')
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "humancrypto/pwutil.py", line 73, in verify_password
        raise VerifyMismatchError()
    humancrypto.error.VerifyMismatchError

But it's not 44 B.C., it's 2016.  We should store passwords using 2016 methods:

    >>> from humancrypto import y2016
    >>> stored_2016 = y2016.store_password(b'password')

And when we encounter 44 B.C. passwords in 2016, we should upgrade them:

    >>> from humancrypto.error import PasswordMatchesWrongYear
    >>> password = b'password'
    >>> try:
    ...     y2016.verify_password(stored_44bc, password)
    ... except PasswordMatchesWrongYear:
    ...     converted_to_2016 = y2016.store_password(password)
    ...

Using this library, it's obvious from looking at your code how old your crypto is.


# Password Hashing

## Library

Store a password using 2016 best practices:

    >>> from humancrypto.y2016 import store_password
    >>> stored = store_password(b'this is my password')

Check a password hash (for any year):

    >>> from humancrypto.y2016 import verify_password
    >>> verify_password(stored, b'WRONG PASSWORD')
    Traceback (most recent call last):
      File "<stdin>", line 1, in <module>
      File "humancrypto/pwutil.py", line 73, in verify_password
        raise VerifyMismatchError()
    humancrypto.error.VerifyMismatchError
    >>> verify_password(stored, b'this is my password')
    True

Typical usage for verifying might look like this:

    from humancrypto import y2016
    from humancrypto.error import PasswordMatchesWrongYear
    from humancrypto.error import VerifyMismatchError

    def verify_password(stored, password):
        try:
            y2016.verify_password(stored, password)
        except PasswordMatchesWrongYear:
            stored = y2016.store_password(password)
            # ... store the password for the user
        except VerifyMismatchError(Error):
            raise Exception('Bad password')

## Command line

Store a password using 2016 best practices:

    $ echo 'mypassword' | humancrypto y2016 pw store > stored.out

Verify a password (for any year):

    $ echo 'mypassword' | humancrypto y2016 pw verify "$(cat stored.out)"
    ok

See `humancrypto y2016 pw verify --help` for additional information and possible return codes.


# Random tokens

## Library

Generate a 2016-secure random token:

    >>> from humancrypto import y2016
    >>> token = y2016.random_bytes()
    >>> web_token = y2016.random_urlsafe_token()
    >>> hex_token = y2016.random_hex_token()

## Command line

Generate a 2016-secure random token:

    $ humancrypto y2016 token > token.txt
    $ humancrypto y2016 token --urlsafe > urlsafe_token.txt 
    $ humancrypto y2016 token --hex > hex_token.txt


# RSA

The RSA part of the code is essentially [pyca's cryptography](https://pypi.python.org/pypi/cryptography) + sane defaults.
By default, 2048-bit RSA keys are used.

## Command line

Create a private key:

    humancrypto rsa create-private ca.key

Extract a public key:

    humancrypto rsa extract-public ca.key ca.pub

Create a self-signed CA certificate:

    humancrypto rsa self-signed-cert ca.key ca.crt --common-name jim

Create a signed certificate for a server key:

    humancrypto rsa create-private server.key
    humancrypto rsa create-csr server.key server.csr --common-name bob --server
    humancrypto rsa sign-csr ca.key ca.crt server.csr server.crt

(And use `--client` for a client key).


## Library

Create a private key:

    >>> from humancrypto import PrivateKey
    >>> key = PrivateKey.create()
    >>> key.save('private.key')

Load a private key from a file (these are all equivalent).  There are equivalent methods for CSRs, Certs, Public Keys:

    >>> key = PrivateKey.load(filename='private.key')
    >>> key = PrivateKey.load(open('private.key', 'rb').read())
    >>> key = PrivateKey.load(key.dump())

Create a self-signed Certificate:

    >>> root_cert = key.self_signed_cert({'common_name': u'bob'})
    >>> root_cert.subject.attribs['common_name']
    u'bob'

Create a server-friendly Certificate Signing Request (CSR):

    >>> from humancrypto import CSR
    >>> csr = CSR.create(key, {'common_name': u'bob'}, server=True)
    >>> csr = key.signing_request({'common_name': u'bob'}, server=True) # equivalent
    >>> csr.attribs['common_name']
    u'bob'
    >>> csr.save('ca.csr')

Use `client=True` instead of `server=True` if you want a client.

Sign a CSR:

    >>> cert = key.sign_csr(csr, root_cert)
    >>> cert.subject.attribs['common_name']
    u'bob'
    >>> cert.save('ca.cert')

