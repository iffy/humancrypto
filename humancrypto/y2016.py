from argon2 import PasswordHasher, exceptions
from humancrypto import pwutil, randomutil

DEFAULT_ENTROPY = 32
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

# Copied from python 3.6 stdlib secrets.py

_random_instance = randomutil.TokenMaker(default_entropy=DEFAULT_ENTROPY)
random_bytes = _random_instance.random_bytes
random_hex_token = _random_instance.random_hex_token
random_urlsafe_token = _random_instance.random_urlsafe_token
