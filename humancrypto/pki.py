from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


class PrivateKey(object):

    def __init__(self, _key):
        self._key = _key

    @property
    def key_size(self):
        return self._key.key_size

    _public_key = None

    @property
    def public_key(self):
        if self._public_key is None:
            self._public_key = PublicKey(self._key.public_key())
        return self._public_key

    @classmethod
    def create(cls):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        return PrivateKey(private_key)

    @classmethod
    def load(cls, data=None, filename=None):
        if filename is not None:
            with open(filename, 'rb') as fh:
                data = fh.read()
        private_key = serialization.load_pem_private_key(
            data, None, default_backend())
        return PrivateKey(private_key)

    def serialize(self):
        return self._key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def decrypt(self, ciphertext):
        return self._key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            )
        )

    def sign(self, message):
        signer = self._key.signer(
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        signer.update(message)
        return signer.finalize()


class PublicKey(object):

    def __init__(self, _key):
        self._key = _key

    @classmethod
    def load(cls, data=None, filename=None):
        if filename is not None:
            with open(filename, 'rb') as fh:
                data = fh.read()
        public_key = serialization.load_pem_public_key(
            data, default_backend())
        return PublicKey(public_key)

    def serialize(self):
        return self._key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def encrypt(self, bytes):
        return self._key.encrypt(
            bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            )
        )

    def verify(self, message, signature):
        verifier = self._key.verifier(
            signature,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        verifier.update(message)
        verifier.verify()
        return True
