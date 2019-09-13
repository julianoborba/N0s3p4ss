from unittest import TestCase
from unittest.mock import patch
from requests.models import Response
from requests.sessions import Session
from requests.exceptions import ConnectionError
from nosepass.http_requestor import do_get

USER_AGENT = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) '
                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/50.0.2661.102 '
                  'Safari/537.36'
}

PROXIES = {
    'http': 'http://18.229.145.152:8888',
    'https': 'http://18.229.145.152:8888'
}


class HTTPRequestorTest(TestCase):

    @patch.object(Session, 'get')
    def test_that_should_successful_request_url(self, get):
        response = Response()
        response.status_code = 200
        get.return_value = response

        response = do_get('www.google.com')
        get.assert_called_once_with(
            headers=USER_AGENT,
            proxies=PROXIES,
            timeout=10,
            url='http://www.google.com',
            verify=False
        )
        self.assertEqual(200, response.status_code)

    @patch.object(Session, 'get', side_effect=ConnectionError)
    def test_that_should_not_raises_connection_error(self, get):
        response = do_get('www.google.com')

        self.assertIsNotNone(response)
