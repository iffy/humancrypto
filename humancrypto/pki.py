from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.x509.general_name import DirectoryName
from cryptography.x509 import KeyUsage, ExtendedKeyUsage

import os
import stat
from datetime import datetime, timedelta
from uuid import uuid4

from .error import Error

OID_MAPPING = {
    'common_name': NameOID.COMMON_NAME,
    'country': NameOID.COUNTRY_NAME,
    'state': NameOID.STATE_OR_PROVINCE_NAME,
    'city': NameOID.LOCALITY_NAME,
    'org_name': NameOID.ORGANIZATION_NAME,
    'org_unit': NameOID.ORGANIZATIONAL_UNIT_NAME,
    'name': NameOID.GIVEN_NAME,
    'email': NameOID.EMAIL_ADDRESS,
}

EXT_OID_MAPPING = {
    'basic_constraints': ExtensionOID.BASIC_CONSTRAINTS,
    'key_usage': ExtensionOID.KEY_USAGE,
    'subject_alternative_name': ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
    'issuer_alternative_name': ExtensionOID.ISSUER_ALTERNATIVE_NAME,
    'subject_key_identifier': ExtensionOID.SUBJECT_KEY_IDENTIFIER,
    'name_constraints': ExtensionOID.NAME_CONSTRAINTS,
    'crl_distribution_points': ExtensionOID.CRL_DISTRIBUTION_POINTS,
    'certificate_policies': ExtensionOID.CERTIFICATE_POLICIES,
    'authority_key_identifier': ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
    'extended_key_usage': ExtensionOID.EXTENDED_KEY_USAGE,
    'authority_information_access': ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
    'inhibit_any_policy': ExtensionOID.INHIBIT_ANY_POLICY,
    'ocsp_no_check': ExtensionOID.OCSP_NO_CHECK,
    'crl_number': ExtensionOID.CRL_NUMBER,
    'policy_constraints': ExtensionOID.POLICY_CONSTRAINTS,
}

KEY_USAGE_ATTRS = [
    'digital_signature',
    'content_commitment',
    'key_encipherment',
    'data_encipherment',
    'key_agreement',
    'key_cert_sign',
    'crl_sign',
    'encipher_only',
    'decipher_only',
]

def base_key_usage():
    return {
        'digital_signature': False,
        'content_commitment': False,
        'key_encipherment': False,
        'data_encipherment': False,
        'key_agreement': False,
        'key_cert_sign': False,
        'crl_sign': False,
        'encipher_only': False,
        'decipher_only': False,
    }

EXT_KEY_USAGE_MAPPING = {
    'server_auth': ExtendedKeyUsageOID.SERVER_AUTH,
    'client_auth': ExtendedKeyUsageOID.CLIENT_AUTH,
    'code_signing': ExtendedKeyUsageOID.CODE_SIGNING,
    'email_protection': ExtendedKeyUsageOID.EMAIL_PROTECTION,
    'time_stamping': ExtendedKeyUsageOID.TIME_STAMPING,
    'ocsp_signing': ExtendedKeyUsageOID.OCSP_SIGNING,
}


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

    def save(self, filename):
        with open(filename, 'wb') as fh:
            fh.write(self.dump())
        os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)

    def dump(self):
        return self._key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
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

    def _sign_csr(self, csr, signing_cert=None, is_ca=False):
        if not csr._csr.is_signature_valid:
            raise Error('CSR signature is invalid')

        new_serial = int(uuid4())
        subject_attrs = csr.attribs
        pubkey = csr.public_key.raw

        if signing_cert is None:
            # self-signed cert
            issuer_attrs = subject_attrs
            signing_serial = new_serial
            signing_pubkey = pubkey
        else:
            issuer_attrs = signing_cert.subject.attribs
            signing_serial = signing_cert.serial_number
            signing_pubkey = signing_cert.public_key.raw

        builder = x509.CertificateBuilder()
        subject_list = _attribDict2x509List(subject_attrs)
        issuer_list = _attribDict2x509List(issuer_attrs)

        builder = builder.subject_name(x509.Name(subject_list))
        issuer_name = x509.Name(issuer_list)
        builder = builder.issuer_name(issuer_name)
        builder = builder.not_valid_before(
            datetime.today() - timedelta(days=1))
        builder = builder.not_valid_after(
            datetime.today() + timedelta(days=2 * 365))
        builder = builder.serial_number(new_serial)
        builder = builder.public_key(pubkey)

        # Subject Key Identifier
        ski = x509.SubjectKeyIdentifier.from_public_key(pubkey)
        builder = builder.add_extension(ski, False)

        # AuthorityKeyIdentifier
        cert_ski = x509.SubjectKeyIdentifier.from_public_key(signing_pubkey)
        aki = x509.AuthorityKeyIdentifier(
            key_identifier=cert_ski.digest,
            authority_cert_issuer=[DirectoryName(issuer_name)],
            authority_cert_serial_number=signing_serial)
        builder = builder.add_extension(aki, False)

        # KeyUsage
        key_usage = base_key_usage()
        key_usage.update(csr.extensions.get('key_usage', {}))
        builder = builder.add_extension(KeyUsage(**key_usage), False)

        # ExtendedKeyUsage
        ext_key_usage = {}
        ext_key_usage.update(csr.extensions.get('extended_key_usage', {}))
        if ext_key_usage:
            oid_list = [EXT_KEY_USAGE_MAPPING[k] for k,v in ext_key_usage.items() if v]
            builder = builder.add_extension(ExtendedKeyUsage(oid_list), False)

        path_length = None
        if is_ca:
            path_length = 0
        builder = builder.add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=path_length),
            critical=False,
        )
        certificate = builder.sign(
            private_key=self._key, algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        return Certificate(certificate)

    def self_signed_cert(self, attribs=None):
        # for a CA
        csr = CSR.create(self, attribs, key_usage={
            'crl_sign': True,
            'key_cert_sign': True,
        })
        return self._sign_csr(csr, is_ca=True)

    def sign_csr(self, csr, cert):
        return self._sign_csr(csr, cert)

    def signing_request(self, *args, **kwargs):
        return CSR.create(self, *args, **kwargs)


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

    @property
    def raw(self):
        return self._key

    def save(self, filename):
        with open(filename, 'wb') as fh:
            fh.write(self.dump())

    def dump(self):
        return self._key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
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


def _attribDict2x509List(attribs):
    attribs = attribs or {}
    attrib_list = []
    for nice_name, values in attribs.items():
        oid = OID_MAPPING[nice_name]
        if not isinstance(values, list):
            values = [values]
        for single_value in values:
            attrib_list.append(x509.NameAttribute(oid, single_value))
    return attrib_list

def _x509Name2attribDict(instance):
    a = {}
    for name, oid in OID_MAPPING.items():
        values = instance.get_attributes_for_oid(oid)
        if len(values) == 1:
            a[name] = values[0].value
        else:
            a[name] = [x.value for x in values]
    return a

def _x509Ext2Dict(extensions):
    ret = {}
    for name, oid in EXT_OID_MAPPING.items():
        try:
            value = extensions.get_extension_for_oid(oid)
        except x509.ExtensionNotFound:
            continue
        if value:
            val = value.value
            
            if name == 'basic_constraints':
                val = _basicConstraints2Dict(val)
            elif name == 'subject_key_identifier':
                val = val.digest
            elif name == 'authority_key_identifier':
                issuer = [_CertificateNameHolder(x.value).attribs for x in val.authority_cert_issuer]
                val = {
                    'keyid': val.key_identifier,
                    'serial': val.authority_cert_serial_number,
                    'issuer': issuer,
                }
                if len(val['issuer']) == 1:
                    val['issuer'] = val['issuer'][0]
            elif name == 'key_usage':
                tmp = {}
                for k in KEY_USAGE_ATTRS:
                    try:
                        tmp[k] = getattr(val, k, False)
                    except ValueError:
                        tmp[k] = None
                val = tmp
            elif name == 'extended_key_usage':
                tmp = {}
                for k,v in EXT_KEY_USAGE_MAPPING.items():
                    if v in val:
                        tmp[k] = True
                    else:
                        tmp[k] = False
                val = tmp
            ret[name] = val
    return ret

def _basicConstraints2Dict(basic_constraints):
    return {
        'ca': basic_constraints.ca,
        'path_length': basic_constraints.path_length,
    }


class CSR(object):

    def __init__(self, _csr):
        self._csr = _csr

    @classmethod
    def create(cls, private_key, attribs=None, key_usage=None, extended_key_usage=None,
            server=None, client=None):
        """
        @param private_key: A PrivateKey instance
        @param attribs: A dictionary of attributes to put in the certificate's subject
        @param key_usage: A dictionary of key usage properties.  Keys
            come from KEY_USAGE_ATTRS and values are True/False.
        @param extended_key_usage: A dictionary of extended key usage properties.
            Keys come from EXT_KEY_USAGE_MAPPING and values are True/False.

        @param server: If True, this certificate is for a server and key_usage,extended_key_usage
            will be set to sane defaults.

        @param client: If True, this certificate is for a web client and key_usage,extended_key_usage
            will be set to sane defaults.
        """
        attrib_list = _attribDict2x509List(attribs)
        key_usage = key_usage or {}
        extended_key_usage = extended_key_usage or {}

        if server:
            key_usage['key_encipherment'] = True
            key_usage['digital_signature'] = True
            extended_key_usage['server_auth'] = True

        if client:
            key_usage['digital_signature'] = True
            extended_key_usage['client_auth'] = True

        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name(attrib_list))

        # Subject Key Identifier
        ski = x509.SubjectKeyIdentifier.from_public_key(
            private_key._key.public_key())
        builder = builder.add_extension(ski, False)

        # KeyUsage
        if key_usage:
            ku = base_key_usage()
            ku.update(key_usage)
            builder = builder.add_extension(KeyUsage(**ku), False)

        if extended_key_usage:
            oid_list = [EXT_KEY_USAGE_MAPPING[k] for k,v in extended_key_usage.items() if v]
            builder = builder.add_extension(ExtendedKeyUsage(oid_list), False)
        
        csr = builder.sign(private_key._key, hashes.SHA256(), default_backend())
        return CSR(csr)

    @classmethod
    def load(cls, data=None, filename=None):
        if filename is not None:
            with open(filename, 'rb') as fh:
                data = fh.read()
        csr = x509.load_pem_x509_csr(
            data, default_backend())
        return CSR(csr)

    def save(self, filename):
        with open(filename, 'wb') as fh:
            fh.write(self.dump())

    def dump(self):
        return self._csr.public_bytes(serialization.Encoding.PEM)

    _attribs = None
    @property
    def attribs(self):
        if self._attribs is None:
            self._attribs = _x509Name2attribDict(self._csr.subject)
        return self._attribs

    _public_key = None
    @property
    def public_key(self):
        if self._public_key is None:
            self._public_key = PublicKey(self._csr.public_key())
        return self._public_key

    _extensions = None
    @property
    def extensions(self):
        if self._extensions is None:
            self._extensions = _x509Ext2Dict(self._csr.extensions)
        return self._extensions


class Certificate(object):

    def __init__(self, _cert):
        self._cert = _cert
        self.subject = _CertificateNameHolder(_cert.subject)
        self.issuer = _CertificateNameHolder(_cert.issuer)
        self.serial_number = _cert.serial

    _public_key = None
    @property
    def public_key(self):
        if self._public_key is None:
            self._public_key = PublicKey(self._cert.public_key())
        return self._public_key

    @classmethod
    def load(cls, data=None, filename=None):
        if filename is not None:
            with open(filename, 'rb') as fh:
                data = fh.read()
        return Certificate(
            x509.load_pem_x509_certificate(data, default_backend())
        )

    def save(self, filename):
        with open(filename, 'wb') as fh:
            fh.write(self.dump())

    def dump(self):
        return self._cert.public_bytes(serialization.Encoding.PEM)

    _extensions = None
    @property
    def extensions(self):
        if self._extensions is None:
            self._extensions = _x509Ext2Dict(self._cert.extensions)
        return self._extensions


class _CertificateNameHolder(object):

    def __init__(self, _base):
        self._base = _base
        self.attribs = _x509Name2attribDict(self._base)
