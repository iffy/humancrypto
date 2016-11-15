#!/bin/bash

hc=${1:-$(which humancrypto)}

if [ -z "$hc" ]; then
    echo "usage: $0 path-to-humancrypto-executable"
    exit 1
fi

set -xe
TMPDIR=$(mktemp -d -t rsa)

cat <<EOF > "${TMPDIR}/ca.crt"
-----BEGIN CERTIFICATE-----
MIIC7zCCAligAwIBAgIJANuC2ji3uLw/MA0GCSqGSIb3DQEBBQUAMFkxCzAJBgNV
BAYTAkFEMQswCQYDVQQIEwJLWTEMMAoGA1UEBxMDZm9vMQswCQYDVQQKEwJiYTEO
MAwGA1UEAxMFYmEgQ0ExEjAQBgkqhkiG9w0BCQEWA2JhcjAeFw0xNjExMTUyMTQ4
NTZaFw0yNjExMTMyMTQ4NTZaMFkxCzAJBgNVBAYTAkFEMQswCQYDVQQIEwJLWTEM
MAoGA1UEBxMDZm9vMQswCQYDVQQKEwJiYTEOMAwGA1UEAxMFYmEgQ0ExEjAQBgkq
hkiG9w0BCQEWA2JhcjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA2UXCNWyI
YN0+HxHW8q9/kouXTByk/Vg3feY+XjukPkRZHGi6hJkEqBAV21hfVpijZOR6YJU7
fbDzINcTD7i9oZCbufvjyITjvo4XQkV2BXHNp0cxAgQyjSXrFrJyFYfFQzgb7VgQ
fe0Y7L/+JKzS3PKyhKPXMabo9ETuN+eO8hsCAwEAAaOBvjCBuzAdBgNVHQ4EFgQU
SHBM0vcdnjSQiNswfDxfVu6m7hAwgYsGA1UdIwSBgzCBgIAUSHBM0vcdnjSQiNsw
fDxfVu6m7hChXaRbMFkxCzAJBgNVBAYTAkFEMQswCQYDVQQIEwJLWTEMMAoGA1UE
BxMDZm9vMQswCQYDVQQKEwJiYTEOMAwGA1UEAxMFYmEgQ0ExEjAQBgkqhkiG9w0B
CQEWA2JhcoIJANuC2ji3uLw/MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQAD
gYEAi0dRSS349L4x9XkJby1FXwO7hPp+J4X9eivAwmMQXRXDb1ZwanEU7yknrDqn
RiGZoGkyX0ksbkSMI7KoHq2C3g3qpdBt4fAdi8mV6TbTqMoq4gzWatsHO4uUu9up
aNpxL364SklFf8tPzsXCQlv/DghbpaVgwGJdX7xWdvfhdjo=
-----END CERTIFICATE-----
EOF

cat <<EOF > "${TMPDIR}/ca.key"
-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANlFwjVsiGDdPh8R
1vKvf5KLl0wcpP1YN33mPl47pD5EWRxouoSZBKgQFdtYX1aYo2TkemCVO32w8yDX
Ew+4vaGQm7n748iE476OF0JFdgVxzadHMQIEMo0l6xaychWHxUM4G+1YEH3tGOy/
/iSs0tzysoSj1zGm6PRE7jfnjvIbAgMBAAECgYAgFPHZS55TlzeOBOdVTF6s99mu
Tmh6VCVVfMLmzS2yWAtEa55m5+VNH5rqmYDyW3V891OuoTp4k8FCrx9Maf3t8KqL
Jjt2rATv869pdoDoYGjLFtEMd0A3kvh/y7zws8HLazZLHdLGrvuj+VTYxxHn2/iS
h8VnJD+gzP/aszJWmQJBAPNZElYYW9qRv06eR9eO6bELneMYaG1qcgL9+NNRK5U4
9WdkY5tYjnpq7Gt+P6HWBzkQkVskF0auxaOPosmc+0UCQQDkkaBaJSJXhzKh7TBY
hIrM7CpdFP6jHirEHId/gKrcjR6RQqCC6xW75amjtYPZ8wxvrlFY1q/GB7tuUkoC
6F3fAkAMKv8EuREWu8TyHG4BNE8xICCT82t9VR5AUgy4HE3ulzuGIPnuEZ6GNoR9
14E9CWOxEcgC46oaSbDuPcdpB2V1AkEAm/MMUFUj0EqLblXx9YNBXL4JzYakklDj
5vh8Lq9wZJjYcU3fTFPveUsianNPaeZd5tkt4YphVaEy7fuxSbiXSwJBAPKMiZ6W
vZ0SUv795gk01Y2KL7yDyOqftouEz5Dsw0nqwvwmpb6/YOjZWt5a/DD71/qHRpcd
IXeYM2YnQrURypc=
-----END PRIVATE KEY-----
EOF

# verify the modulus matches
[ $(openssl x509 -noout -modulus -in ./ca.crt) = $(openssl rsa -noout -modulus -in ./ca.key) ] || (echo modulus does not match && exit 1)

$hc rsa create-private "${TMPDIR}/1.key"
$hc rsa create-csr "${TMPDIR}/1.key" "${TMPDIR}/1.csr"
$hc rsa sign-csr "${TMPDIR}/ca.key" "${TMPDIR}/ca.crt" "${TMPDIR}/1.csr" "${TMPDIR}/1.crt"
openssl verify -verbose -CAfile "${TMPDIR}/ca.crt" "${TMPDIR}/1.crt"
