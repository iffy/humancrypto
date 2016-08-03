
from humancrypto import y2016

from tests.util import PasswordHashingMixin, RandomTokenMixin


class TestPasswordHashing(PasswordHashingMixin):

    def get_module(self):
        return y2016


class TestRandomToken(RandomTokenMixin):

    def get_module(self):
        return y2016
