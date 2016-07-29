import pytest

from humancrypto.y2016 import store_password, verify_password
from humancrypto import current
from humancrypto.error import VerifyMismatchError


class TestPasswordHashing(object):

    def test_functional(self):
        """
        You should be able to store and verify passwords.
        """
        password = b'something'
        stored = store_password(password)
        assert verify_password(stored, b'something') is True
        with pytest.raises(VerifyMismatchError):
            verify_password(stored, b'wrong')

    def test_works_with_current(self):
        """
        You can store in 2016 format and verify with the
        current verifier.
        """
        password = b'something'
        stored = store_password(password)
        assert current.verify_password(stored, b'something') is True
        with pytest.raises(VerifyMismatchError):
            current.verify_password(stored, b'wrong')
