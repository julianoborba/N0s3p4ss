from unittest import TestCase
from n0s3p4ss.sec_headers_obtainer import retrieve_set_cookie
from n0s3p4ss.sec_headers_obtainer import retrieve_x_content_type_options
from n0s3p4ss.sec_headers_obtainer import retrieve_x_xss_protection
from n0s3p4ss.sec_headers_obtainer import retrieve_content_security_policy
from n0s3p4ss.sec_headers_obtainer import retrieve_access_control_allow_origin
from n0s3p4ss.sec_headers_obtainer import retrieve_strict_transport_security
from n0s3p4ss.sec_headers_obtainer import retrieve_x_frame_options


class SecHeadersAnalyserTest(TestCase):

    def test_that_should_retrieve_x_frame_options_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'X-Frame-Options': 'SAMEORIGIN'
        }

        is_empty = retrieve_x_frame_options(headers) == ''

        self.assertEqual(False, is_empty)

    def test_that_should_not_retrieve_x_frame_options_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'W-Frame-Options': 'SAMEORIGIN'
        }

        is_empty = retrieve_x_frame_options(headers) == ''

        self.assertEqual(True, is_empty)

    def test_that_should_retrieve_strict_transport_security_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
        }

        is_empty = retrieve_strict_transport_security(headers) == ''

        self.assertEqual(False, is_empty)

    def test_that_should_not_retrieve_strict_transport_security_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'Strift-Transport-Security': 'max-age=31536000; includeSubDomains'
        }

        is_empty = retrieve_strict_transport_security(headers) == ''

        self.assertEqual(True, is_empty)

    def test_that_should_retrieve_access_control_allow_origin_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'Access-Control-Allow-Origin': '*'
        }

        is_empty = retrieve_access_control_allow_origin(headers) == ''

        self.assertEqual(False, is_empty)

    def test_that_should_not_retrieve_access_control_allow_origin_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'Access-Control-Allow-Origim': '*'
        }

        is_empty = retrieve_access_control_allow_origin(headers) == ''

        self.assertEqual(True, is_empty)

    def test_that_should_retrieve_content_security_policy_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'Content-Security-Policy': 'default-src https:'
        }

        is_empty = retrieve_content_security_policy(headers) == ''

        self.assertEqual(False, is_empty)

    def test_that_should_not_retrieve_content_security_policy_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'Content-Security-Polici': 'default-src https:'
        }

        is_empty = retrieve_content_security_policy(headers) == ''

        self.assertEqual(True, is_empty)

    def test_that_should_retrieve_x_xss_protection_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'X-XSS-Protection': '1; mode=block'
        }

        is_empty = retrieve_x_xss_protection(headers) == ''

        self.assertEqual(False, is_empty)

    def test_that_should_not_retrieve_x_xss_protection_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'X-XSC-Protection': '1; mode=block'
        }

        is_empty = retrieve_x_xss_protection(headers) == ''

        self.assertEqual(True, is_empty)

    def test_that_should_retrieve_x_content_type_options_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'X-Content-Type-Options': 'nosniff'
        }

        is_empty = retrieve_x_content_type_options(headers) == ''

        self.assertEqual(False, is_empty)

    def test_that_should_not_retrieve_x_content_type_options_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'X-Content-Type-0ptions': 'nosniff'
        }

        is_empty = retrieve_x_content_type_options(headers) == ''

        self.assertEqual(True, is_empty)

    def test_that_should_retrieve_set_cookie_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'Set-Cookie': 'sessionid=38afes7a8; HttpOnly; Path=/'
        }

        is_empty = retrieve_set_cookie(headers) == ''

        self.assertEqual(False, is_empty)

    def test_that_should_not_retrieve_set_cookie_header(self):
        headers = {
            'Server': 'nginx/1.15.6',
            'Set-Coukie': 'sessionid=38afes7a8; HttpOnly; Path=/'
        }

        is_empty = retrieve_set_cookie(headers) == ''

        self.assertEqual(True, is_empty)
