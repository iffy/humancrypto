from humancrypto.error import UnknownCryptography

import six


def verify_password(stored, password):
    """
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

    if year == '2016':
        from humancrypto import y2016
        return y2016.verify_password(stored, password)
    elif year == '44bc':
        from humancrypto import y44bc
        return y44bc.verify_password(stored, password)
    else:
        raise UnknownCryptography(stored)
