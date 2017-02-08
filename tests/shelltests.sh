#!/bin/bash

hc=${1:-$(which humancrypto)}

if [ -z "$hc" ]; then
    echo "usage: $0 path-to-humancrypto-executable"
    exit 1
fi

rc=0
testdir=$(dirname $0)/shelltests
for i in $(ls "$testdir"); do
    fp="${testdir}/${i}"
    
    if $fp $hc; then
        echo ------------------
        echo PASS $i
        echo
    else
        echo ------------------
        echo FAIL $i
        echo
        rc=1
    fi
    
    
done

exit $rc