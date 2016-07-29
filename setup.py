#!/usr/bin/env python
from setuptools import setup
import os

_version_filename = os.path.join(
    os.path.dirname(__file__), 'humancrypto/VERSION')
version = open(_version_filename, 'rb').read().strip().decode('ascii')


setup(
    name='humancrypto',
    version=version,
    description='Cryptography for Humans',
    author='Matt Haggard',
    author_email='haggardii@gmail.com',
    url='https://github.com/iffy/humancrypto',
    packages=[
        'humancrypto',
    ],
    package_data={'humancrypto': ['VERSION']},
    include_package_data=True,
    install_requires=[
        'cryptography',
        'six',
        'argon2_cffi==16.1.0',
    ],
    scripts=[
        'scripts/humancrypto',
    ]
)
