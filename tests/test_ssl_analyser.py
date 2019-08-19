from unittest import TestCase
from unittest.mock import patch
from ssl_analyser import SSLSocket, \
    get_sslv23_method_context, \
    get_ssl_connection
from socket import AF_INET, SOCK_STREAM, socket
from OpenSSL.SSL import VERIFY_NONE, Context, SSLv23_METHOD


class SslAnalyserTest(TestCase):

    @patch('socket.socket.setblocking')
    @patch('socket.socket.connect')
    def test_that_should_connect_ssl_socket(self, connect, setblocking):
        new_socket = socket(AF_INET, SOCK_STREAM)
        new_socket.settimeout(20)
        ssl_socket = SSLSocket('dodo.minion', new_socket)

        ssl_socket.connect()

        connect.assert_called_once_with(('dodo.minion', 443))
        setblocking.assert_called_once_with(True)
        self.assertFalse(ssl_socket.get_socket()._closed)
        ssl_socket.close()

    @patch('socket.socket.setblocking')
    @patch('socket.socket.connect')
    def test_that_should_close_ssl_socket(self, connect, setblocking):
        new_socket = socket(AF_INET, SOCK_STREAM)
        new_socket.settimeout(20)
        ssl_socket = SSLSocket('dodo.minion', new_socket)
        ssl_socket.connect()

        ssl_socket.close()

        connect.assert_called_once_with(('dodo.minion', 443))
        setblocking.assert_called_once_with(True)
        self.assertTrue(ssl_socket.get_socket()._closed)

    def test_that_should_get_sslv23_method_context(self):
        context = get_sslv23_method_context()

        self.assertIsNotNone(context)
        self.assertFalse(context.check_hostname)
        self.assertEqual(VERIFY_NONE, context.verify_mode)

    @patch('OpenSSL.SSL.Connection.do_handshake')
    @patch('OpenSSL.SSL.Connection.set_tlsext_host_name')
    @patch('OpenSSL.SSL.Connection.set_connect_state')
    def test_that_should_get_ssl_connection(self,
                                            set_connect_state,
                                            set_tlsext_host_name,
                                            do_handshake):
        context = Context(SSLv23_METHOD)
        context.check_hostname = False
        context.verify_mode = VERIFY_NONE

        new_socket = socket(AF_INET, SOCK_STREAM)
        new_socket.settimeout(20)

        connection = get_ssl_connection(context, new_socket, 'dodo.minion')

        self.assertIsNotNone(connection)
        set_connect_state.assert_called_once_with()
        set_tlsext_host_name.assert_called_once_with(b'dodo.minion')
        do_handshake.assert_called_once_with()
        new_socket.close()
