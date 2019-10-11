from unittest import TestCase
from n0s3p4ss.header_validator import is_amazon_s3, \
    compare_nginx_version, is_cookie_http_only_defined, \
    is_x_xss_protection_mode_block, is_cookie_path_denifed_as_slash, \
    is_access_control_allow_origin_with_sameorigin


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

        self.assertEqual('The server Nginx version is the same '
                         'as the expected Nginx version; '
                         'The expected version is 1.16.1',
                         compare_nginx_version(server_header, nginx_version))

    def test_that_should_not_compare_nginx_versions_as_the_same(self):
        nginx_version = '1.16.1'
        server_header = 'nginx/1.14.1'

        self.assertEqual('The server Nginx version is lesser than '
                         'Nginx expected version; '
                         'The expected version is 1.16.1',
                         compare_nginx_version(server_header, nginx_version))

    def test_that_should_recoginize_sameorigin_from_allow_origin(self):
        allow_origin = {'Access-Control-Allow-Origin': 'SAMEORIGIN'}
        self.assertEqual('"Allow-origin" present with value: SAMEORIGIN',
                         is_access_control_allow_origin_with_sameorigin(
                             allow_origin
                             )
                         )

    def test_that_should_not_recoginize_sameorigin_from_allow_origin(self):
        allow_origin = {'Access-Control-Allow-Origin': 'DENY'}
        self.assertEqual('"Allow-origin" present with value: DENY',
                         is_access_control_allow_origin_with_sameorigin(
                             allow_origin
                             )
                         )

    def test_that_should_return_null_from_allow_origin(self):
        allow_origin = {'Access-Control-Allow-Origin': None}
        self.assertEquals(
            '',
            is_access_control_allow_origin_with_sameorigin(allow_origin)
            )

    def test_that_should_not_recognize_mode_block_in_x_xss_protection(self):
        x_xss_protection = {'X-XSS-Protection': 'report=reporting-uri'}
        self.assertEqual('"X-XSS-protection" is not set as "mode=block"',
                         is_x_xss_protection_mode_block(x_xss_protection))

    def test_that_should_recognize_mode_block_in_x_xss_protection(self):
        x_xss_protection = {'X-XSS-Protection': 'mode=block'}
        self.assertEqual('"X-XSS-protection" is set as "mode=block"',
                         is_x_xss_protection_mode_block(x_xss_protection))

    def test_that_should_return_null_from_x_xss_protection(self):
        x_xss_protection = {'X-XSS-Protection': None}
        self.assertEquals('', is_x_xss_protection_mode_block(x_xss_protection))

    def test_that_should_recognize_path_in_set_cookie_path(self):
        set_cookie = {'Set-Cookie': 'path=/'}
        self.assertEqual('"Path" defined as "/"',
                         is_cookie_path_denifed_as_slash(set_cookie))

    def test_that_should_not_recognize_path_in_set_cookie_path(self):
        set_cookie = {'Set-Cookie': 'Secure'}
        self.assertEqual('"Path" not defined as "/"',
                         is_cookie_path_denifed_as_slash(set_cookie))

    def test_that_should_return_null_from_set_cookie_path(self):
        set_cookie = {'Set-Cookie': None}
        self.assertEquals('', is_cookie_path_denifed_as_slash(set_cookie))

    def test_that_should_recognize_path_in_set_cookie_http_only(self):
        set_cookie = {'Set-Cookie': 'HttpOnly'}
        self.assertEqual('"HttpOnly" is present',
                         is_cookie_http_only_defined(set_cookie))

    def test_that_should_not_recognize_path_in_set_cookie_http_only(self):
        set_cookie = {'Set-Cookie': 'Secure'}
        self.assertEqual('"HttpOnly" is not present',
                         is_cookie_http_only_defined(set_cookie))

    def test_that_should_return_null_from_set_cookie_http_only(self):
        set_cookie = {'Set-Cookie': None}
        self.assertEquals('', is_cookie_http_only_defined(set_cookie))
