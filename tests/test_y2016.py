
from humancrypto import y2016

from tests.util import PasswordHashingMixin


class TestPasswordHashing(PasswordHashingMixin):

    def get_module(self):
        return y2016
