# Cryptography for humans

**DON'T USE THIS IN PRODUCTION SYSTEMS.  It's just an idea right now.**

[![Build Status](https://travis-ci.org/iffy/humancrypto.svg?branch=master)](https://travis-ci.org/iffy/humancrypto)

## Installation

    pip install git+https://github.com/iffy/humancrypto.git


## Usage

Create a private key:

```python
>>> from humancrypto import PrivateKey
>>> key = PrivateKey.create()
>>> with open('private.key', 'wb') as fh:
...     fh.write(key.dump())
```

Load a private key from a file (these are both equivalent).  There are equivalent methods for CSRs, Certs, Public Keys:

```python
>>> key = PrivateKey.load(filename='private.key')
>>> key = PrivateKey.load(open('private.key', 'rb').read())
```

Create a self-signed Certificate:

```python
>>> root_cert = key.self_signed_cert({'common_name': u'bob'})
>>> root_cert.attribs['common_name']
u'bob'
```

Create a Certificate Signing Request (CSR):

```python
>>> from humancrypto import CSR
>>> csr = CSR(key.public_key, common_name=u'bob', ca=True)
>>> csr.attribs['common_name']
u'bob'
>>> with open('ca.csr', 'wb') as fh:
...     fh.write(csr.dump())
```

Sign a CSR:

```python
>>> cert = key.sign_csr(csr, root_cert)
>>> cert.attribs['common_name']
u'bob'
>>> with open('ca.cert', 'wb') as fh:
...     fh.write(cert.dump())
```

XXX Verify that a certificate was signed by a private key:

```python
>>> key.verify(cert)
```

Encrypt some data:

```python
>>> ciphertext = key.public_key.encrypt('something')
```

Decrypt it:

```python
>>> key.decrypt(ciphertext)
'something'
```

XXX Verify a certificate with a CA certificate:

```python
>>> ca_cert.did_sign(presented_cert)
True
>>> presented_cert.attribs['common_name']
'foo'
```

## Notes

By default, 2048-bit RSA keys are used.
