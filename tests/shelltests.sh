#!/bin/bash

hc=${1:-$(which humancrypto)}

set -xe
$hc --help
echo 'mypassword' | $hc pw 2016 store > /tmp/stored.txt
echo 'mypassword' | $hc pw 2016 verify "$(cat /tmp/stored.txt)"
