import os
import binascii
import base64

from humancrypto.error import InsecureLength


# Copied from python 3.6 stdlib secrets.py

class TokenMaker(object):

    def __init__(self, min_entropy):
        self.min_entropy = min_entropy

    def random_bytes(self, nbytes=None):
        """Return a random byte string containing *nbytes* bytes.

        If *nbytes* is ``None`` or not supplied, a reasonable
        default is used.
        """
        if nbytes is None:
            nbytes = self.min_entropy
        return os.urandom(nbytes)

    def assert_secure_length(self, nbytes):
        if nbytes is not None and nbytes < self.min_entropy:
            raise InsecureLength(nbytes)

    def random_token(self, nbytes=None):
        """Return a random bytestring for use as a token.
        """
        self.assert_secure_length(nbytes)
        return self.random_bytes(nbytes)

    def random_hex_token(self, nbytes=None):
        """Return a random text string, in hexadecimal.

        The string has *nbytes* random bytes, each byte converted to two
        hex digits.  If *nbytes* is ``None`` or not supplied, a reasonable
        default is used.
        """
        self.assert_secure_length(nbytes)
        return binascii.hexlify(self.random_bytes(nbytes)).decode('ascii')

    def random_urlsafe_token(self, nbytes=None):
        """Return a random URL-safe text string, in Base64 encoding.

        The string has *nbytes* random bytes.  If *nbytes* is ``None``
        or not supplied, a reasonable default is used.
        """
        self.assert_secure_length(nbytes)
        tok = self.random_bytes(nbytes)
        return base64.urlsafe_b64encode(tok).rstrip(b'=').decode('ascii')
