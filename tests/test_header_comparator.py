from unittest import TestCase
from n0s3p4ss.header_comparator import is_amazon_s3, \
    compare_nginx_version, compare_access_control_allow_origin


class HeaderComparatorTest(TestCase):

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
        allow_origin = 'SAMEORIGIN'
        self.assertEqual('"Allow-origin" present with value: SAMEORIGIN',
                         compare_access_control_allow_origin(allow_origin))

    def test_that_should_not_recoginize_sameorigin_from_allow_origin(self):
        allow_origin = 'DENY'
        self.assertEqual('"Allow-origin" present with value: DENY',
                         compare_access_control_allow_origin(allow_origin))

    def test_that_should_return_null_from_allow_origin(self):
        allow_origin = None
        self.assertEquals(
            '',
            compare_access_control_allow_origin(allow_origin)
            )
