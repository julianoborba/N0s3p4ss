from unittest import TestCase
from server_header_comparator import is_amazon_s3, compare_nginx_version


class ServerHeaderComparatorTest(TestCase):

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
