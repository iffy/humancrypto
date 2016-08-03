import os
import binascii
import base64


# Copied from python 3.6 stdlib secrets.py

class TokenMaker(object):

    def __init__(self, default_entropy):
        self.default_entropy = default_entropy

    def random_bytes(self, nbytes=None):
        """Return a random byte string containing *nbytes* bytes.

        If *nbytes* is ``None`` or not supplied, a reasonable
        default is used.
        """
        if nbytes is None:
            nbytes = self.default_entropy
        return os.urandom(nbytes)

    def random_hex_token(self, nbytes=None):
        """Return a random text string, in hexadecimal.

        The string has *nbytes* random bytes, each byte converted to two
        hex digits.  If *nbytes* is ``None`` or not supplied, a reasonable
        default is used.
        """
        return binascii.hexlify(self.random_bytes(nbytes)).decode('ascii')

    def random_urlsafe_token(self, nbytes=None):
        """Return a random URL-safe text string, in Base64 encoding.

        The string has *nbytes* random bytes.  If *nbytes* is ``None``
        or not supplied, a reasonable default is used.
        """
        tok = self.random_bytes(nbytes)
        return base64.urlsafe_b64encode(tok).rstrip(b'=').decode('ascii')
