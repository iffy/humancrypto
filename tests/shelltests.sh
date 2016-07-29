#!/bin/bash

hc=${1:-$(which humancrypto)}

set -xe
$hc --help
echo 'mypassword' | $hc pw store2016 > /tmp/stored.txt
echo 'mypassword' | $hc pw verify "$(cat /tmp/stored.txt)"
