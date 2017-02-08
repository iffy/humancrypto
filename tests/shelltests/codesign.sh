#!/bin/bash

hc=${1:-$(which humancrypto)}

if [ -z "$hc" ]; then
    echo "usage: $0 path-to-humancrypto-executable"
    exit 1
fi

set -xe
TMPDIR=$(mktemp -d -t codesign)

$hc rsa create-private "${TMPDIR}/ca.key"
$hc rsa self-signed-cert "${TMPDIR}/ca.key" "${TMPDIR}/ca.crt" --common-name "bob"

$hc rsa create-private "${TMPDIR}/codesign.key"
$hc rsa create-csr --codesign "${TMPDIR}/codesign.key" "${TMPDIR}/codesign.csr"
$hc rsa sign-csr "${TMPDIR}/ca.key" "${TMPDIR}/ca.crt" "${TMPDIR}/codesign.csr" "${TMPDIR}/codesign.crt"
