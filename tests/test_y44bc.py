
from humancrypto import y44bc

from tests.util import PasswordHashingMixin, RandomTokenMixin


class TestPasswordHashing(PasswordHashingMixin):

    def get_module(self):
        return y44bc


class TestRandomToken(RandomTokenMixin):

    def get_module(self):
        return y44bc
