import pytest
import six

from humancrypto import current
from humancrypto.error import VerifyMismatchError


class PasswordHashingMixin(object):

    def store_password(self, *args, **kwargs):
        raise NotImplementedError(
            "You must implement store_password"
            " to use the PasswordHashingMixin")

    def verify_password(self, *args, **kwargs):
        raise NotImplementedError(
            "You must implement verify_password"
            " to use the PasswordHashingMixin")

    def test_functional(self):
        """
        You should be able to store and verify passwords.
        """
        password = b'something'
        stored = self.store_password(password)
        assert isinstance(stored, six.text_type) is True
        assert self.verify_password(stored, b'something') is True
        with pytest.raises(VerifyMismatchError):
            self.verify_password(stored, b'wrong')

    def test_works_with_current(self):
        """
        You can store in 2016 format and verify with the
        current verifier.
        """
        password = b'something'
        stored = self.store_password(password)
        assert isinstance(stored, six.text_type) is True
        assert current.verify_password(stored, b'something') is True
        with pytest.raises(VerifyMismatchError):
            current.verify_password(stored, b'wrong')

    def test_binary(self):
        """
        Data must be provided in binary.
        """
        with pytest.raises(TypeError):
            self.store_password(six.u('unicode string'))

        stored = self.store_password(b'hey')
        assert isinstance(stored, six.text_type) is True
        with pytest.raises(TypeError):
            current.verify_password(b'binary_is_bad_here', b'something')

        with pytest.raises(TypeError):
            current.verify_password(stored, six.u('something'))

    def test_upgrade(self):
        """
        Password hashes can be upgraded if they're not the latest.
        """
        password = b'something'
        stored = self.store_password(password)
        year, _ = stored.split(':', 1)
        new_stored = current.verify_and_upgrade_password(stored, b'something')
        if year == current.LATEST_YEAR:
            assert new_stored is None, "Already latest"
        else:
            assert isinstance(new_stored, six.text_type) is True
            year, _ = new_stored.split(':', 1)
            assert year == current.LATEST_YEAR

    def test_upgrade_wrong_password(self):
        """
        Don't upgrade if they're old.
        """
        password = b'something'
        stored = self.store_password(password)
        with pytest.raises(VerifyMismatchError):
            current.verify_and_upgrade_password(stored, b'wrong')
