from humancrypto.error import UnknownCryptography


def verify_password(stored, password):
    """
    """
    try:
        year, h = stored.split(':', 1)
    except Exception:
        raise UnknownCryptography(stored)

    if year == '2016':
        from humancrypto import y2016
        return y2016.verify_password(stored, password)
    else:
        raise UnknownCryptography(stored)
