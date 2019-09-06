from OpenSSL.SSL import Context, SSLv23_METHOD, VERIFY_NONE, Connection
from idna import encode
from custom_json_logger import getLogger
from cryptography.x509.oid import NameOID
from OpenSSL.crypto import load_certificate as load_server_certificate, \
    FILETYPE_PEM
from ssl import get_server_certificate as get_ssl_server_certificate


class SSLSocket:

    def __init__(self, domain, port, socket):
        self._domain = domain
        self._port = port
        self._ssl_socket = socket
        self._ssl_socket.settimeout(20)

    def __enter__(self):
        return self

    def connect(self):
        try:
            self._ssl_socket.connect((self._domain, self._port))
            self._ssl_socket.setblocking(True)
        except Exception as connect_error:
            self._ssl_socket.close()
            getLogger().error('socket not connected to domain %s, cause %s',
                              self._domain,
                              connect_error,
                              exc_info=1)

    def get_domain(self):
        return self._domain

    def get_socket(self):
        return self._ssl_socket

    def close(self):
        self._ssl_socket.close()

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


def get_sslv23_method_context():
    context = Context(SSLv23_METHOD)
    context.check_hostname = False
    context.verify_mode = VERIFY_NONE
    return context


def get_ssl_connection(context, domain, socket):
    connection = Connection(context, socket)
    connection.set_connect_state()
    connection.set_tlsext_host_name(encode(domain))
    return connection


def get_peer_certificate(ssl_connection):
    return ssl_connection.get_peer_certificate()


def get_cryptography_certificate(peer_certificate):
    return peer_certificate.to_cryptography()


def get_certificate_issuer(cryptography_certificate):
    return cryptography_certificate.issuer


def get_issuer_oid_common_name(issuer):
    oid_common_name = issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    if oid_common_name:
        return oid_common_name[0].value
    return None


def get_server_certificate(domain, port):
    return get_ssl_server_certificate((encode(domain), port))


def load_certificate(server_certificate):
    return load_server_certificate(FILETYPE_PEM, server_certificate)


def get_cert_organization_name(certificate):
    return certificate.get_subject().organizationName


def get_cert_cn(certificate):
    return certificate.get_subject().CN


def get_cert_issuer(loaded_certificate):
    return f'{get_cert_organization_name(loaded_certificate)} - ' \
        f'{get_cert_cn(loaded_certificate)}'


def get_cert_not_valid_after_attribute(cryptography_certificate):
    return cryptography_certificate.not_valid_after


def get_cert_not_after_attribute(loaded_certificate):
    return loaded_certificate.get_notAfter()
