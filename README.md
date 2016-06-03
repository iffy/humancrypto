# Cryptography for humans

**DON'T USE THIS IN PRODUCTION SYSTEMS.  It's just an idea right now.**

![](https://travis-ci.org/iffy/humancrypto.svg?branch=master)

By default, 2048-bit RSA keys are used.

## Usage

Create a private key:

```
>>> from humancrypto import PrivateKey
>>> key = PrivateKey.create()
>>> with open('private.key', 'wb') as fh:
...     fh.write(key.serialize())
```

Load a private key from a file (these are both equivalent).  There are equivalent methods for CSRs, Certs, Public Keys:

```
>>> key = PrivateKey.load(filename='private.key')
>>> key = PrivateKey.load(open('private.key', 'rb').read())
```

Create a Certificate Signing Request (CSR):

```
>>> from humancrypto import CSR
>>> csr = CSR(key.public_key, common_name=u'bob', ca=True)
>>> csr.attribs['common_name']
u'bob'
>>> with open('ca.csr', 'wb') as fh:
...     fh.write(csr.serialize())
```

XXX Sign a CSR:

```
>>> cert = key.sign_csr(csr)
>>> cert.attribs['common_name']
u'bob'
>>> with open('ca.cert', 'wb') as fh:
...     fh.write(cert.serialize())
```

XXX Verify that a certificate was signed by a private key:

```
>>> key.verify(cert)
```

Encrypt some data:

```
>>> ciphertext = key.public_key.encrypt('something')
```

Decrypt it:

```
>>> key.decrypt(ciphertext)
'something'
```

XXX Verify a certificate with a CA certificate:

```
>>> ca_cert.did_sign(presented_cert)
True
>>> presented_cert.attribs['common_name']
'foo'
```
