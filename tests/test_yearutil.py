from datetime import date
from humancrypto.yearutil import for_year


class Test_for_year(object):

    def test_this_year(self):
        this_year = date.today().year

        @for_year(this_year)
        def f():
            return None

        f()
