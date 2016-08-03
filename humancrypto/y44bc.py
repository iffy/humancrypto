"""
Password hashing best practices for 44 B.C.
"""
# We may do cryptography like it's 44 B.C.,
# but we print like it's THE FUTURE!
from __future__ import print_function

from humancrypto import pwutil, randomutil

import warnings
import binascii
import six


YEAR = '44bc'
DEFAULT_ENTROPY = 8


def warn():
    warnings.warn('Using cryptography circa 44 B.C. is considered unsafe.')


def rot128(s):
    """
    Rotate all bytes by 128
    """
    if six.PY2:
        return ''.join(chr((ord(c)+128) % 256) for c in s)
    else:
        return bytes((c+128) % 256 for c in s)


class _PasswordHasher(pwutil.PasswordHasher):

    YEAR = YEAR

    def _store_password(self, password):
        warn()
        return binascii.hexlify(rot128(password)).decode('utf-8')

    def _verify_password(self, stored, password):
        warn()
        return rot128(binascii.unhexlify(stored)) == password


_instance = _PasswordHasher()
store_password = _instance.store_password
verify_password = _instance.verify_password

_random_instance = randomutil.TokenMaker(default_entropy=DEFAULT_ENTROPY)
random_bytes = _random_instance.random_bytes
random_hex_token = _random_instance.random_hex_token
random_urlsafe_token = _random_instance.random_urlsafe_token
