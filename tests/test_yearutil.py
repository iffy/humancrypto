import pytest
from datetime import date
from humancrypto.yearutil import for_year


class Test_for_year(object):

    def test_this_year(self):
        this_year = date.today().year

        @for_year(this_year)
        def f():
            return None

        f()

    def test_last_year(self):
        last_year = date.today().year - 1

        @for_year(last_year)
        def f():
            return None

        with pytest.warns(UserWarning):
            f()
