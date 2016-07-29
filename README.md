# Cryptography for humans

[![Build Status](https://travis-ci.org/iffy/humancrypto.svg?branch=master)](https://travis-ci.org/iffy/humancrypto)

**DON'T USE THIS IN PRODUCTION!  It's just an idea right now.**

# tl;dr

Stay up to date with cryptography best practices:

- If it's 2016, use the `y2016` module.
- If it's 44 B.C., use the `y44bc` module.


## Introduction

Do you want to do something cryptographic, but have a hard time keeping up with changing best practices?  This cryptography library makes it easy to know if you're following current best practices.

For instance, in 44 B.C. it was okay to use [ROT13](https://en.wikipedia.org/wiki/ROT13) to store your passwords.  So the `y44bc` module is provided for doing ROT128 (a just-as-secure variation of ROT13):

```python
>>> from humancrypto.y44bc import store_password
>>> stored_44bc = store_password(b'password')
...
```

Verify that a given password matches the stored version with the `current` module:

```python
>>> from humancrypto.current import verify_password
>>> verify_password(stored_44bc, b'password')
True
```

But it's not 44 B.C., it's 2016.  We should store passwords using 2016 methods:

```python
>>> from humancrypto.y2016 import store_password
>>> stored_2016 = store_password(b'password')
...
```

And when we encounter passwords stored in the old way, we should upgrade them:

```python
>>> from humancrypto.current import verify_and_upgrade_password
>>> new_stored_2016 = verify_and_upgrade_password(stored_44bc, b'password')
```


## Components


There are two components to this library:

1. [pyca's cryptography](https://pypi.python.org/pypi/cryptography) + sane defaults for RSA.

2. Year-defined best-practice cryptography.




## Installation

    pip install git+https://github.com/iffy/humancrypto.git


## Command line usage

### Password Hashing/Storage

*See below for library usage, since command line usage is mostly for testing.*

Store a password using 2016 best practices:

    echo 'mypassword' | humancrypto pw store2016 > stored.out

Verify a password (for any year):

    $ echo 'mypassword' | humancrypto pw verify "$(cat stored.out)"


### RSA Keys

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


## Library usage

### Password Hashing/Storage

Store a password using 2016 best practices:

```python
>>> from humancrypto.y2016 import store_password
>>> stored = store_password(b'this is my password')
```

Check a password hash (for any year):

```python
>>> from humancrypto.current import verify_password
>>> verify_password(stored, b'WRONG PASSWORD')
...
humancrypto.error.VerifyMismatchError
>>> verify_password(stored, b'this is my password')
True
```

### RSA Keys

Create a private key:

```python
>>> from humancrypto import PrivateKey
>>> key = PrivateKey.create()
>>> key.save('private.key')
```

Load a private key from a file (these are all equivalent).  There are equivalent methods for CSRs, Certs, Public Keys:

```python
>>> key = PrivateKey.load(filename='private.key')
>>> key = PrivateKey.load(open('private.key', 'rb').read())
>>> key = PrivateKey.load(key.dumps())
```

Create a self-signed Certificate:

```python
>>> root_cert = key.self_signed_cert({'common_name': u'bob'})
>>> root_cert.subject.attribs['common_name']
u'bob'
```

Create a server-friendly Certificate Signing Request (CSR):

```python
>>> from humancrypto import CSR
>>> csr = CSR(key, {'common_name': u'bob'}, server=True)
>>> csr = key.signing_request({'common_name': u'bob'}, server=True) # equivalent
>>> csr.attribs['common_name']
u'bob'
>>> csr.save('ca.csr')
```

Use `client=True` instead of `server=True` if you want a client.

Sign a CSR:

```python
>>> cert = key.sign_csr(csr, root_cert)
>>> cert.subject.attribs['common_name']
u'bob'
>>> cert.save('ca.cert')
```


## Notes

By default, 2048-bit RSA keys are used.
