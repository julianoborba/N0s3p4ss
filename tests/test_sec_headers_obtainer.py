from unittest import TestCase
from nosepass.sec_headers_obtainer import retrieve_set_cookie
from nosepass.sec_headers_obtainer import retrieve_x_content_type_options
from nosepass.sec_headers_obtainer import retrieve_x_xss_protection
from nosepass.sec_headers_obtainer import retrieve_content_security_policy
from nosepass.sec_headers_obtainer import retrieve_access_control_allow_origin
from nosepass.sec_headers_obtainer import retrieve_strict_transport_security
from nosepass.sec_headers_obtainer import retrieve_x_frame_options


class SecHeadersAnalyserTest(TestCase):

    def test_that_should_retrieve_x_frame_options_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'X-Frame-Options': 'SAMEORIGIN'
        }

        is_none = retrieve_x_frame_options(headers) is None

        self.assertEqual(False, is_none)

    def test_that_should_not_retrieve_x_frame_options_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'W-Frame-Options': 'SAMEORIGIN'
        }

        is_none = retrieve_x_frame_options(headers) is None

        self.assertEqual(True, is_none)

    def test_that_should_retrieve_strict_transport_security_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
        }

        is_none = retrieve_strict_transport_security(headers) is None

        self.assertEqual(False, is_none)

    def test_that_should_not_retrieve_strict_transport_security_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'Strift-Transport-Security': 'max-age=31536000; includeSubDomains'
        }

        is_none = retrieve_strict_transport_security(headers) is None

        self.assertEqual(True, is_none)

    def test_that_should_retrieve_access_control_allow_origin_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'Access-Control-Allow-Origin': '*'
        }

        is_none = retrieve_access_control_allow_origin(headers) is None

        self.assertEqual(False, is_none)

    def test_that_should_not_retrieve_access_control_allow_origin_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'Access-Control-Allow-Origim': '*'
        }

        is_none = retrieve_access_control_allow_origin(headers) is None

        self.assertEqual(True, is_none)

    def test_that_should_retrieve_content_security_policy_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'Content-Security-Policy': 'default-src https:'
        }

        is_none = retrieve_content_security_policy(headers) is None

        self.assertEqual(False, is_none)

    def test_that_should_not_retrieve_content_security_policy_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'Content-Security-Polici': 'default-src https:'
        }

        is_none = retrieve_content_security_policy(headers) is None

        self.assertEqual(True, is_none)

    def test_that_should_retrieve_x_xss_protection_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'X-XSS-Protection': '1; mode=block'
        }

        is_none = retrieve_x_xss_protection(headers) is None

        self.assertEqual(False, is_none)

    def test_that_should_not_retrieve_x_xss_protection_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'X-XSC-Protection': '1; mode=block'
        }

        is_none = retrieve_x_xss_protection(headers) is None

        self.assertEqual(True, is_none)

    def test_that_should_retrieve_x_content_type_options_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'X-Content-Type-Options': 'nosniff'
        }

        is_none = retrieve_x_content_type_options(headers) is None

        self.assertEqual(False, is_none)

    def test_that_should_not_retrieve_x_content_type_options_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'X-Content-Type-0ptions': 'nosniff'
        }

        is_none = retrieve_x_content_type_options(headers) is None

        self.assertEqual(True, is_none)

    def test_that_should_retrieve_set_cookie_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'Set-Cookie': 'sessionid=38afes7a8; HttpOnly; Path=/'
        }

        is_none = retrieve_set_cookie(headers) is None

        self.assertEqual(False, is_none)

    def test_that_should_not_retrieve_set_cookie_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'Set-Coukie': 'sessionid=38afes7a8; HttpOnly; Path=/'
        }

        is_none = retrieve_set_cookie(headers) is None

        self.assertEqual(True, is_none)
