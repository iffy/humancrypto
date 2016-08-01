
from humancrypto import y44bc

from tests.util import PasswordHashingMixin


class TestPasswordHashing(PasswordHashingMixin):

    def get_module(self):
        return y44bc
