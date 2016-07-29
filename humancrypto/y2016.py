from argon2 import PasswordHasher, exceptions


from humancrypto import error


def store_password(password):
    ph = PasswordHasher()
    h = ph.hash(password)
    return '2016:{0}'.format(h)


def verify_password(stored, password):
    year, h = stored.strip().split(':', 1)
    ph = PasswordHasher()
    try:
        ph.verify(h, password)
        return True
    except (exceptions.VerifyMismatchError, exceptions.VerificationError):
        raise error.VerifyMismatchError()
