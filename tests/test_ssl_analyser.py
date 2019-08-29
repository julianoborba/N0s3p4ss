from unittest import TestCase
from ssl_analyser import SSLSocket, \
    get_sslv23_method_context, \
    get_ssl_connection, \
    get_peer_certificate, \
    get_cryptography_certificate, \
    get_certificate_issuer, \
    get_issuer_oid_common_name, \
    get_server_certificate, \
    load_certificate, \
    get_cert_issuer, \
    get_cert_not_after_attribute, \
    get_cert_not_valid_after_attribute
from socket import AF_INET, SOCK_STREAM, socket
from OpenSSL.SSL import VERIFY_NONE
from datetime import datetime
from idna import decode
from threading import Thread
from socketserver import TCPServer, ThreadingMixIn, StreamRequestHandler
from ssl import wrap_socket
from os.path import abspath, dirname

HOST = '127.0.0.1'
PORT = 9192
TESTS_PATH = abspath(dirname(__file__))


class Server(ThreadingMixIn, TCPServer):

    def start(self):
        Thread(target=self.serve_forever).start()

    # run the command below in terminal to generate a new cert if needed
    #
    # openssl req -x509 \
    #     -newkey rsa:4096 \
    #     -keyout key.pem \
    #     -out cert.pem \
    #     -days 365 \
    #     -nodes \
    #     -subj '/CN=127.0.0.1/O=Localhost Co'

    def get_request(self):
        new_socket, client_ip = TCPServer.get_request(self)

        return wrap_socket(
            new_socket,
            keyfile=f'{TESTS_PATH}/resources/key.pem',
            certfile=f'{TESTS_PATH}/resources/cert.pem',
            server_side=True
        ), client_ip

    def stop(self):
        self.server_close()
        self.shutdown()


class SslAnalyserTest(TestCase):
    _ssl_server = Server((HOST, PORT), StreamRequestHandler)

    @classmethod
    def setUpClass(cls):
        cls._ssl_server.start()

    @classmethod
    def tearDownClass(cls):
        cls._ssl_server.stop()

    @staticmethod
    def get_ssl_socket():
        return SSLSocket(HOST, PORT, socket(AF_INET, SOCK_STREAM))

    def test_that_should_connect_ssl_socket(self):
        with self.get_ssl_socket() as ssl_socket:
            ssl_socket.connect()

            self.assertFalse(ssl_socket.get_socket()._closed)

    def test_that_should_close_ssl_socket(self):
        with self.get_ssl_socket() as ssl_socket:
            ssl_socket.connect()

            ssl_socket.close()

            self.assertTrue(ssl_socket.get_socket()._closed)

    def test_that_should_get_sslv23_method_context(self):
        context = get_sslv23_method_context()

        self.assertIsNotNone(context)
        self.assertFalse(context.check_hostname)
        self.assertEqual(VERIFY_NONE, context.verify_mode)

    def test_that_should_get_ssl_connection(self):
        with self.get_ssl_socket() as ssl_socket:
            ssl_socket.connect()
            context = get_sslv23_method_context()

            ssl_connection = get_ssl_connection(context,
                                                ssl_socket.get_domain(),
                                                ssl_socket.get_socket())

            ssl_connection.do_handshake()
            self.assertIsNotNone(ssl_connection)

    def test_that_should_get_cert_issuer_from_ssl_connection(self):
        with self.get_ssl_socket() as ssl_socket:
            ssl_socket.connect()
            context = get_sslv23_method_context()
            ssl_connection = get_ssl_connection(context,
                                                ssl_socket.get_domain(),
                                                ssl_socket.get_socket())
            ssl_connection.do_handshake()

            peer_cert = get_peer_certificate(ssl_connection)
            crypto_cert = get_cryptography_certificate(peer_cert)
            cert_issuer = get_certificate_issuer(crypto_cert)
            issuer = get_issuer_oid_common_name(cert_issuer)

            self.assertIsNotNone(issuer)
            self.assertEqual('127.0.0.1', issuer)

    def test_that_should_get_cert_issuer_from_domain_name(self):
        server_cert = get_server_certificate(HOST, PORT)
        loaded_cert = load_certificate(server_cert)
        issuer = get_cert_issuer(loaded_cert)

        self.assertIsNotNone(issuer)
        self.assertEqual('Localhost Co - 127.0.0.1', issuer)

    def test_that_should_get_cert_expiration_from_domain_name(self):
        server_cert = get_server_certificate(HOST, PORT)
        loaded_cert = load_certificate(server_cert)
        expiration = get_cert_not_after_attribute(loaded_cert)

        self.assertIsNotNone(expiration)
        self.assertIsNotNone(
            datetime.strptime(decode(expiration)[:-1], '%Y%m%d%H%M%S')
        )

    def test_that_should_get_cert_expiration_from_ssl_connection(self):
        with self.get_ssl_socket() as ssl_socket:
            ssl_socket.connect()
            context = get_sslv23_method_context()
            ssl_connection = get_ssl_connection(context,
                                                ssl_socket.get_domain(),
                                                ssl_socket.get_socket())
            ssl_connection.do_handshake()

            peer_cert = get_peer_certificate(ssl_connection)
            crypto_cert = get_cryptography_certificate(peer_cert)
            expiration = get_cert_not_valid_after_attribute(crypto_cert)

            self.assertIsNotNone(expiration)
            self.assertIsNotNone(
                expiration.strftime('%d/%m/%Y %H:%M:%S')
            )
