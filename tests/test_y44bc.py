
from humancrypto.y44bc import store_password, verify_password

from tests.util import PasswordHashingMixin


class TestPasswordHashing(PasswordHashingMixin):

    def store_password(self, *args, **kwargs):
        return store_password(*args, **kwargs)

    def verify_password(self, *args, **kwargs):
        return verify_password(*args, **kwargs)
