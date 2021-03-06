#!/bin/bash

hc=${1:-$(which humancrypto)}

if [ -z "$hc" ]; then
    echo "usage: $0 path-to-humancrypto-executable"
    exit 1
fi

set -xe
$hc --help
echo 'mypassword' | $hc y2016 pw store > /tmp/stored.txt
echo 'mypassword' | $hc y2016 pw verify "$(cat /tmp/stored.txt)"

$hc y2016 token
$hc y2016 token --hex
$hc y2016 token --urlsafe
