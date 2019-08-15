from unittest import TestCase
from check_versions import is_amazon_s3_server, compare_nginx_version


class CheckVersionTest(TestCase):

    def test_that_should_recognize_aws_header_with_version(self):
        amazon_s3_version = 'AmazonS3/1.15.7'
        self.assertEqual(is_amazon_s3_server(amazon_s3_version), True)

    def test_that_should_recognize_aws_header_without_version(self):
        amazon_s3 = 'AmazonS3'
        self.assertEqual(is_amazon_s3_server(amazon_s3), True)

    def test_that_should_not_recognize_aws_header(self):
        nginx = 'nginx/1.15.6'
        self.assertEqual(is_amazon_s3_server(nginx), False)

    def test_that_should_recognize_nginx_last_version_header(self):
        nginx_last_version = '1.16.1'
        nginx_header_application = 'nginx/1.16.1'
        self.assertEqual(compare_nginx_version(
            nginx_header_application, nginx_last_version),
            'The server nginx version is the same as expected version; \
The expected version is 1.16.1')

    def test_that_should_not_recognize_nginx_last_version_header(self):
        nginx_last_version = '1.16.1'
        nginx_header_application = 'nginx/1.14.1'
        self.assertEqual(compare_nginx_version(
            nginx_header_application, nginx_last_version),
            'The server nginx version is lesser than nginx expected version; \
The expected version is 1.16.1')
