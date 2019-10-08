from unittest import TestCase
from unittest.mock import patch
from n0s3p4ss.tor_session_connector import TorSession
from requests.sessions import Session
from requests.models import Response

USER_AGENT = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) '
                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/50.0.2661.102 '
                  'Safari/537.36'
}


class TorSessionConnectorTest(TestCase):

    def test_that_should_set_tor_proxies_to_session(self):
        with Session() as session:
            TorSession(session, USER_AGENT)

            self.assertEqual(
                {
                    'http': 'socks5://127.0.0.1:9150',
                    'https': 'socks5://127.0.0.1:9150'
                },
                session.proxies
            )

    @patch.object(Session, 'get')
    def test_that_should_get_response_from_tor_session_request(self, get):
        with Session() as session:
            check_tor_response = Response()
            check_tor_response.status_code = 200
            get.return_value = check_tor_response
            tor_connection = TorSession(session, USER_AGENT)

            response = tor_connection.get('https://check.torproject.org', 40)

            get.assert_called_once_with(
                'https://check.torproject.org',
                headers=USER_AGENT,
                timeout=40,
                verify=False
            )
            self.assertEqual(200, response.status_code)

    @patch.object(Session, 'close')
    def test_that_should_close_tor_session(self, close):
        with Session() as session:
            tor_connection = TorSession(session, USER_AGENT)

            tor_connection.close()

            close.assert_called_once_with()
