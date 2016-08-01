from argon2 import PasswordHasher, exceptions
from humancrypto import pwutil


YEAR = '2016'


class _PasswordHasher(pwutil.PasswordHasher):

    YEAR = YEAR

    def _store_password(self, password):
        return PasswordHasher().hash(password)

    def _verify_password(self, stored, password):
        ph = PasswordHasher()
        try:
            ph.verify(stored, password)
            return True
        except (exceptions.VerifyMismatchError, exceptions.VerificationError):
            return False


_instance = _PasswordHasher()
store_password = _instance.store_password
verify_password = _instance.verify_password
