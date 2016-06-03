# Cryptography for humans

Based on [pyca's cryptography](https://pypi.python.org/pypi/cryptography).

**DON'T USE THIS IN PRODUCTION!  It's just an idea right now.**

[![Build Status](https://travis-ci.org/iffy/humancrypto.svg?branch=master)](https://travis-ci.org/iffy/humancrypto)

## Installation

    pip install git+https://github.com/iffy/humancrypto.git


## Command line usage

Create a private key:

```sh
humancrypto create-private foo.key
```

Extract a public key:

```sh
humancrypto extract-public foo.key foo.pub
```

Create a self-signed certificate:

```sh
humancrypto self-signed-cert foo.key foo.crt -d common_name=jim
```

## Library usage

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

Create a Certificate Signing Request (CSR):

```python
>>> from humancrypto import CSR
>>> csr = CSR(key, {'common_name': u'bob'})
>>> csr = key.signing_request({'common_name': u'bob'}) # equivalent
>>> csr.attribs['common_name']
u'bob'
>>> csr.save('ca.csr')
```

Sign a CSR:

```python
>>> cert = key.sign_csr(csr, root_cert)
>>> cert.subject.attribs['common_name']
u'bob'
>>> cert.save('ca.cert')
```

<!--
XXX Verify that a certificate was signed by a private key:

```python
>>> key.verify(cert)
```

-->

Encrypt some data:

```python
>>> ciphertext = key.public_key.encrypt('something')
```

Decrypt it:

```python
>>> key.decrypt(ciphertext)
'something'
```

<!--
XXX Verify a certificate with a CA certificate:

```python
>>> ca_cert.did_sign(presented_cert)
True
>>> presented_cert.attribs['common_name']
'foo'
```
-->


## Notes

By default, 2048-bit RSA keys are used.
