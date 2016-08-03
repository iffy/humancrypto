"""
Password hashing best practices for 44 B.C.
"""
# We may do cryptography like it's 44 B.C.,
# but we print like it's THE FUTURE!
from __future__ import print_function

from humancrypto import pwutil, randomutil, yearutil

import binascii
import six


YEAR = '44bc'
DEFAULT_ENTROPY = 8
warnold = yearutil.for_year(
    -44,
    'Using cryptography circa 44 B.C. is considered unsafe.')


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

    @warnold
    def _store_password(self, password):
        return binascii.hexlify(rot128(password)).decode('utf-8')

    @warnold
    def _verify_password(self, stored, password):
        return rot128(binascii.unhexlify(stored)) == password


_instance = _PasswordHasher()
store_password = _instance.store_password
verify_password = _instance.verify_password

_random_instance = randomutil.TokenMaker(default_entropy=DEFAULT_ENTROPY)
random_bytes = warnold(_random_instance.random_bytes)
random_hex_token = warnold(_random_instance.random_hex_token)
random_urlsafe_token = warnold(_random_instance.random_urlsafe_token)
