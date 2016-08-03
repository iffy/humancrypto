import pytest
import six

from humancrypto import yearutil, pwutil
from humancrypto.error import VerifyMismatchError, PasswordMatchesWrongYear
from humancrypto.error import InsecureLength


class PasswordHashingMixin(object):

    def get_module(self):
        raise NotImplementedError(
            "You must implement get_module"
            " to use the PasswordHasingMixin")

    def store_password(self, *args, **kwargs):
        return self.get_module().store_password(*args, **kwargs)

    def verify_password(self, *args, **kwargs):
        return self.get_module().verify_password(*args, **kwargs)

    def test_module_has_YEAR(self):
        assert self.get_module().YEAR is not None

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
        current = list(yearutil.list_modules())[0]

        password = b'something'
        stored = self.store_password(password)
        assert isinstance(stored, six.text_type) is True
        if current == self.get_module():
            current.verify_password(stored, b'something')
        else:
            with pytest.raises(PasswordMatchesWrongYear):
                current.verify_password(stored, b'something')
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
            self.verify_password(b'binary_is_bad_here', b'something')

        with pytest.raises(TypeError):
            self.verify_password(stored, six.u('something'))

    def test_PasswordMatchesWrongYear(self):
        """
        Password hashes can be changed to a new year's standard when verified.
        """
        modules = list(yearutil.list_modules())
        assert len(modules) > 0
        password = b'something'
        for module in modules:
            # store using a different module
            stored = module.store_password(password)
            year = pwutil.getYear(stored)

            if year == self.get_module().YEAR:
                # same version
                self.verify_password(stored, password)
            else:
                # different version
                with pytest.raises(PasswordMatchesWrongYear):
                    self.verify_password(stored, password)
                with pytest.raises(VerifyMismatchError):
                    self.verify_password(stored, b'wrong password')


class RandomTokenMixin(object):

    def get_module(self):
        raise NotImplementedError(
            "You must implement get_module"
            " to use the RandomTokenMixin")

    def test_bytes(self):
        token1 = self.get_module().random_bytes()
        token2 = self.get_module().random_bytes()
        assert token1 != token2
        assert isinstance(token1, six.binary_type)

    def test_token(self):
        token = self.get_module().random_token()
        assert isinstance(token, six.binary_type)

    def test_hex(self):
        token = self.get_module().random_hex_token()
        assert isinstance(token, six.text_type)

    def test_urlsafe(self):
        token = self.get_module().random_urlsafe_token()
        assert isinstance(token, six.text_type)

    def test_too_short(self):
        m = self.get_module()
        with pytest.raises(InsecureLength):
            m.random_hex_token(1)
        with pytest.raises(InsecureLength):
            m.random_token(1)
        with pytest.raises(InsecureLength):
            m.random_urlsafe_token(1)
