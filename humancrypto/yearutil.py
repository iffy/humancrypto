import warnings
from functools import wraps
from datetime import date


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


_current_year = date.today().year


def for_year(year, msg=None):
    """
    Decorate a function so that it will emit warnings once
    the given year is in the past.
    """
    msg = msg or (
        'You are using cryptography designed for the year {0}.'
        '  Consider updating.'.format(year))

    def deco(f):
        @wraps(f)
        def inner(*args, **kwargs):
            if year < _current_year:
                warnings.warn(msg)
            return f(*args, **kwargs)
        return inner
    return deco
