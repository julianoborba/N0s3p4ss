from unittest import TestCase
from n0s3p4ss.header_validator import is_access_control_allow_origin_sameorigin
from n0s3p4ss.header_validator import is_cookie_path_slash
from n0s3p4ss.header_validator import is_cookie_http_only_present
from n0s3p4ss.header_validator import is_x_xss_protection_mode_block
from n0s3p4ss.header_validator import is_amazon_s3
from n0s3p4ss.header_validator import is_nginx_an_older_version


class HeaderValidatorTest(TestCase):

    def test_that_should_recognize_S3_server_header_with_version(self):
        server_header = 'AmazonS3/1.15.7'

        self.assertEqual(True, is_amazon_s3(server_header))

    def test_that_should_recognize_S3_server_header_without_version(self):
        server_header = 'AmazonS3'

        self.assertEqual(True, is_amazon_s3(server_header))

    def test_that_should_not_recognize_aws_header(self):
        server_header = 'nginx/1.15.6'

        self.assertEqual(False, is_amazon_s3(server_header))

    def test_that_should_compare_nginx_versions_as_the_same(self):
        nginx_version = '1.16.1'
        server_header = 'nginx/1.16.1'

        self.assertEqual(
            False, is_nginx_an_older_version(server_header, nginx_version))

    def test_that_should_not_compare_nginx_versions_as_lesser(self):
        nginx_version = '1.16.1'
        server_header = 'nginx/1.14.1'

        self.assertEqual(
            True, is_nginx_an_older_version(server_header, nginx_version))

    def test_that_should_confirm_sameorigin_value(self):
        allow_origin = {'Access-Control-Allow-Origin': 'SAMEORIGIN'}

        self.assertEqual(
            True, is_access_control_allow_origin_sameorigin(allow_origin))

    def test_that_should_not_confirm_sameorigin_value(self):
        allow_origin = {'Access-Control-Allow-Origin': 'DENY'}

        self.assertEqual(
            False, is_access_control_allow_origin_sameorigin(allow_origin))

    def test_that_should_not_confirm_mode_block_value(self):
        x_xss_protection = {'X-XSS-Protection': 'report=reporting-uri'}

        self.assertEqual(
            False, is_x_xss_protection_mode_block(x_xss_protection))

    def test_that_should_confirm_mode_block_value(self):
        x_xss_protection = {'X-XSS-Protection': 'mode=block'}

        self.assertEqual(
            True, is_x_xss_protection_mode_block(x_xss_protection))

    def test_that_should_confirm_path_with_slash_value(self):
        set_cookie = {'Set-Cookie': 'path=/'}

        self.assertEqual(
            True, is_cookie_path_slash(set_cookie))

    def test_that_should_not_confirm_path_with_slash_value(self):
        set_cookie = {'Set-Cookie': 'Secure'}

        self.assertEqual(
            False, is_cookie_path_slash(set_cookie))

    def test_that_should_confirm_httponly_value(self):
        set_cookie = {'Set-Cookie': 'HttpOnly'}

        self.assertEqual(
            True, is_cookie_http_only_present(set_cookie))

    def test_that_should_not_confirm_httponly_value(self):
        set_cookie = {'Set-Cookie': 'Secure'}

        self.assertEqual(
            False, is_cookie_http_only_present(set_cookie))
