import humancrypto
from humancrypto.error import UnknownCryptography

import six

LATEST_YEAR = '2016'


def _getmodule(year):
    if year == '2016':
        return humancrypto.y2016
    elif year == '44bc':
        return humancrypto.y44bc
    else:
        raise UnknownCryptography()


def _store_password(password):
    """
    DO NOT USE THIS.  THIS IS FOR TESTING AND INTERNAL USE ONLY.

    Instead use the yYYYY module appropriate for
    the given year.  If you use this, you will likely have the
    false impression that you are using the latest best practices
    but aren't because you haven't upgraded the humancrypto
    library.
    """
    return _getmodule(LATEST_YEAR).store_password(password)


def verify_password(stored, password, upgrade_if_old=False):
    """
    Will raise UnknownCryptography or VerifyMismatchError
    or return a value as described in upgrade_if_old below.

    stored: The result of a prior `store_password` call.

    password: A binary string password to verify.

    upgrade_if_old:

        True: If the password is correct and the current
            stored password is older than the latest version,
            then return a new storable password using the
            latest version.

            If the stored password is already the latest,
            return None.

        False: Return True if the password matches, or
            raise an exception if it doesn't.
    """
    if not isinstance(password, six.binary_type):
        raise TypeError(
            'Password must be binary not {0}'.format(type(password)))

    if not isinstance(stored, six.text_type):
        raise TypeError(
            'Stored password must be text not {0}'.format(type(stored)))

    try:
        year, h = stored.split(':', 1)
    except Exception:
        raise UnknownCryptography(stored)

    mod = _getmodule(year)
    mod.verify_password(stored, password)

    if upgrade_if_old:
        if year != LATEST_YEAR:
            return _store_password(password)
        else:
            return None
    else:
        return True
