"""
Password hashing best practices for 44 B.C.
"""
from __future__ import print_function

from humancrypto import error

import warnings
import binascii
import six


def warn():
    warnings.warn('Using cryptography from 44 B.C. is considered unsafe.')


def rot128(s):
    """
    Rotate all bytes by 128
    """
    if six.PY2:
        return ''.join(chr((ord(c)+128) % 256) for c in s)
    else:
        return bytes((c+128) % 256 for c in s)


def store_password(password):
    warn()

    if not isinstance(password, six.binary_type):
        raise TypeError(
            'Password must be binary not {0}'.format(type(password)))

    h = binascii.hexlify(rot128(password)).decode('utf-8')
    return six.u('44bc:{0}').format(h)


def verify_password(stored, password):
    warn()

    if not isinstance(password, six.binary_type):
        raise TypeError(
            'Password must be binary not {0}'.format(type(password)))

    if not isinstance(stored, six.text_type):
        raise TypeError(
            'Stored password must be text not {0}'.format(type(stored)))

    year, h = stored.strip().split(six.u(':'), 1)
    if rot128(binascii.unhexlify(h)) == password:
        return True
    else:
        raise error.VerifyMismatchError()
