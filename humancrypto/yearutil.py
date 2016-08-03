
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
