import six
from humancrypto.error import PasswordMatchesWrongYear, VerifyMismatchError


def list_modules():
    from humancrypto import y2016
    yield y2016
    from humancrypto import y44bc
    yield y44bc


_modules = {}


def get_module(year):
    global _modules
    if not _modules:
        for m in list_modules():
            _modules[m.YEAR] = m
    return _modules.get(year)


def getYear(ciphertext):
    year, _ = ciphertext.split(':', 1)
    return year


class PasswordHasher(object):

    YEAR = None

    def _store_password(self, password):
        raise NotImplementedError()

    def _verify_password(self, stored, password):
        raise NotImplementedError()

    def store_password(self, password):
        if not isinstance(password, six.binary_type):
            raise TypeError(
                'Password must be binary not {0}'.format(type(password)))
        h = self._store_password(password)
        return six.u('{0}:{1}').format(self.YEAR, h)

    def verify_password(self, stored, password):
        """
        Verify that a previously-stored password matches the given password.

        @param stored: The previously stored value as returned by
            `store_password`
        @param password: The plaintext password to test against the
            stored version.

        @raise humancrypto.error.VerifyMismatchError: If the password
            does not match.
        @raise humancrypto.error.PasswordMatchesWrongYear: If the
            password DOES match but it was stored using an older
            password storage method.
        """
        if not isinstance(password, six.binary_type):
            raise TypeError(
                'Password must be binary not {0}'.format(type(password)))

        if not isinstance(stored, six.text_type):
            raise TypeError(
                'Stored password must be text not {0}'.format(type(stored)))

        year, h = stored.strip().split(':', 1)
        if year == self.YEAR:
            if self._verify_password(h, password):
                return True
            else:
                raise VerifyMismatchError()
        else:
            # Password was stored using a different year's algorithm
            module = get_module(year)
            module.verify_password(stored, password)
            raise PasswordMatchesWrongYear()
