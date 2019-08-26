from unittest import TestCase
from tor_session_connector import TorSession
from requests import session
from unittest.mock import patch


class TorSessionConnectorTest(TestCase):

    def test_that_should_return_tor_proxies(self):
        current_session = session()
        tor_connection = TorSession(current_session, 'user-agent')
        tor_proxies = getattr(tor_connection, 'tor_session').proxies
        self.assertIsNotNone(tor_proxies)
        self.assertEqual({'http': 'socks5://127.0.0.1:9150',
                          'https': 'socks5://127.0.0.1:9150'}, tor_proxies)

    @patch('requests.session')
    def test_that_should_check_if_get_request_return_something(self,
                                                               session):
        current_session = session
        tor_connection = TorSession(current_session, 'user-agent')
        tor_connection.get('https://check.torproject.org')
        session.get.assert_called_once_with('https://check.torproject.org',
                                            headers='user-agent', timeout=20,
                                            verify=False)

    @patch('requests.session')
    def test_that_should_close_tor_session(self, session):
        current_session = session
        tor_connection = TorSession(current_session, 'user-agent')
        tor_connection.close()
        session.close.assert_called_once_with()
