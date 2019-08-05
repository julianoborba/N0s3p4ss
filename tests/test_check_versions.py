from unittest import TestCase
from check_versions import is_amazon_s3_server


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
