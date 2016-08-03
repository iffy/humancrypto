#!/usr/bin/env python
from setuptools import setup

setup(
    name='humancrypto',
    version='0.3.0',
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
