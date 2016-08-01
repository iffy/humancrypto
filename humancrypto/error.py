class Error(Exception):
    pass


class PasswordMatchesWrongYear(Error):
    pass


class VerifyMismatchError(Error):
    pass


class UnknownCryptography(Error):
    pass
