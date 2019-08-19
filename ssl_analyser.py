from OpenSSL.SSL import Context, SSLv23_METHOD, VERIFY_NONE, Connection
from idna import encode
from custom_json_logger import getLogger


class SSLSocket:

    def __init__(self, subdomain, socket):
        self.ssl_socket = socket
        self.subdomain = subdomain

    def connect(self):
        try:
            self.ssl_socket.connect((self.subdomain, 443))
            self.ssl_socket.setblocking(True)
        except Exception as connect_error:
            self.ssl_socket.close()
            getLogger().error("socket not connected to subdomain %s, cause %s",
                              self.subdomain, connect_error,
                              exc_info=1)

    def close(self):
        self.ssl_socket.close()

    def get_socket(self):
        return self.ssl_socket


def get_sslv23_method_context():
    context = Context(SSLv23_METHOD)
    context.check_hostname = False
    context.verify_mode = VERIFY_NONE
    return context


def get_ssl_connection(context, socket, subdomain):
    connection = Connection(context, socket)
    connection.set_connect_state()
    connection.set_tlsext_host_name(encode(subdomain))
    connection.do_handshake()
    return connection
