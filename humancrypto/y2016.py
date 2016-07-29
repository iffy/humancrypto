from argon2 import PasswordHasher, exceptions

import six

from humancrypto import error


def store_password(password):
    if not isinstance(password, six.binary_type):
        raise TypeError(
            'Password must be binary not {0}'.format(type(password)))

    ph = PasswordHasher()
    h = ph.hash(password)
    return six.u('2016:{0}').format(h)


def verify_password(stored, password):
    if not isinstance(password, six.binary_type):
        raise TypeError(
            'Password must be binary not {0}'.format(type(password)))

    if not isinstance(stored, six.text_type):
        raise TypeError(
            'Stored password must be text not {0}'.format(type(stored)))

    year, h = stored.strip().split(':', 1)
    ph = PasswordHasher()
    try:
        ph.verify(h, password)
        return True
    except (exceptions.VerifyMismatchError, exceptions.VerificationError):
        raise error.VerifyMismatchError()
