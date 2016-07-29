#!/bin/bash

if ! which twine; then
    echo "install twine with 'pip install twine'"
    exit 1
fi

rm -r dist
python setup.py sdist bdist_wheel
twine upload dist/*
