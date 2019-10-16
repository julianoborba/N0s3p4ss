from unittest import TestCase
from n0s3p4ss.report import ReportSchema
from os.path import abspath, dirname
from json import loads
from marshmallow.exceptions import ValidationError

TESTS_PATH = abspath(dirname(__file__))


class ReportTest(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.certificate_informations = dict(
            issuer='RapidSSL RSA CA 2018',
            expiration='2020-10-21'
        )

        cls.report = dict(
            subdomain='account-api.grupozap.com',
            url='https://account-api.grupozap.com/',
            ip='104.17.160.19',
            status=403,
            cert_info=cls.certificate_informations,
            server='cloudflare',
            tor_reachable=False,
            detected_waf=['Cloudflare (Cloudflare Inc.)'],
            open_ports=[80, 443, 8080, 8443],
            alerts=[
                '"Access-control-allow-origin" not present!',
                '"Content-security-policy" not present!',
                '"Path" defined as "/"!'
            ]
        )

        cls.bad_report = dict(
            subdomain='account-api.grupozap.com',
            url='https://account-api.grupozap.com/',
            ipipuhaa='104.17.160.19',
            status=403,
            cert_info=cls.certificate_informations,
            serverus='cloudflare',
            tor_reachable=False,
            wafestruz=['Cloudflare (Cloudflare Inc.)'],
            open_ports=[80, 443, 8080, 8443],
            alerts=[
                '"Access-control-allow-origin" not present!',
                '"Content-security-policy" not present!',
                '"Path" defined as "/"!'
            ]
        )

        cls.report_schema = ReportSchema()

        with open(f'{TESTS_PATH}/resources/report.json') as json_file:
            cls.json = json_file.read()

        with open(f'{TESTS_PATH}/resources/bad_report.json') as bad_json_file:
            cls.bad_json = bad_json_file.read()

    def test_that_should_serialize_report_to_json(self):
        json = self.report_schema.dumps(self.report)

        self.assertEqual(loads(self.json), loads(json))

    def test_that_should_not_serialize_missing_fields_to_json(self):
        json = self.report_schema.dumps(self.bad_report)

        self.assertNotEqual(loads(self.json), loads(json))
        self.assertNotIn('waf', json)
        self.assertNotIn('server', json)
        self.assertNotIn('ip', json)

    def test_that_should_deserialize_json_to_report(self):
        new_report = self.report_schema.loads(self.json)

        self.assertEqual(self.report, new_report)

    def test_that_should_not_deserialize_json_to_report(self):
        with self.assertRaises(ValidationError):
            self.report_schema.loads(self.bad_json)
