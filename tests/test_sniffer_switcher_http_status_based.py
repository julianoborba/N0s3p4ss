from unittest import TestCase
from n0s3p4ss.sniffer_switcher_http_status_based import apply_flow_for
from n0s3p4ss.attack_surface_discoverer import HostAttackSurface
from n0s3p4ss.report import ReportSchema, CertificateInformationsSchema
from requests.models import Response


class SnifferSwitcherHTTPStatusBasedTest(TestCase):

    def test_that_should_apply_http_404_flow_for_nginx_server(self):
        response = Response()
        response.status_code = 404
        attack_surface = HostAttackSurface(
            domain='www.grupozap.com',
            http_response=response,
            server_header='nginx/1.16.0',
            response_url_location='https://www.grupozap.com:443/',
            host='107.178.254.45',
            open_ports=[80, 110, 143, 443, 465, 587, 700, 993, 995, 3389, 5900]
        )
        expected_http_404_flow_result = ReportSchema().load(dict(
            subdomain=attack_surface.domain,
            url=attack_surface.response_url_location,
            ip=attack_surface.host,
            status=attack_surface.http_response.status_code,
            cert_info=CertificateInformationsSchema().load(dict()),
            server=attack_surface.server_header,
            tor=False,
            waf=[],
            open_ports=attack_surface.open_ports,
            alerts=['Server disclosed!',
                    'The server Nginx version is lesser than '
                    'Nginx expected version; '
                    'The expected version is 1.16.1']
        ))

        http_404_flow_result = apply_flow_for(attack_surface)

        self.assertEqual(expected_http_404_flow_result, http_404_flow_result)

    def test_that_should_apply_http_404_flow_for_S3_server(self):
        response = Response()
        response.status_code = 404
        attack_surface = HostAttackSurface(
            domain='www.grupozap.com',
            http_response=response,
            server_header='AmazonS3',
            response_url_location='https://www.grupozap.com:443/',
            host='107.178.254.45',
            open_ports=[80, 110, 143, 443, 465, 587, 700, 993, 995, 3389, 5900]
        )
        expected_http_404_flow_result = ReportSchema().load(dict(
            subdomain=attack_surface.domain,
            url=attack_surface.response_url_location,
            ip=attack_surface.host,
            status=attack_surface.http_response.status_code,
            cert_info=CertificateInformationsSchema().load(dict()),
            server=attack_surface.server_header,
            tor=False,
            waf=[],
            open_ports=attack_surface.open_ports,
            alerts=['Server disclosed!', 'Bucket vulnerable to hijacking!']
        ))

        http_404_flow_result = apply_flow_for(attack_surface)

        self.assertEqual(expected_http_404_flow_result, http_404_flow_result)

    def test_that_should_use_invalid_flow(self):
        response = Response()
        response.status_code = 666
        attack_surface = HostAttackSurface(
            domain='www.grupozap.com',
            http_response=response,
            server_header='openresty',
            response_url_location='https://www.grupozap.com:443/',
            host='107.178.254.45',
            open_ports=[80, 110, 143, 443, 465, 587, 700, 993, 995, 3389, 5900]
        )
        expected_invalid_flow_result = ReportSchema().load(dict(
            subdomain=attack_surface.domain,
            url=attack_surface.response_url_location,
            ip=attack_surface.host,
            status=attack_surface.http_response.status_code,
            cert_info=CertificateInformationsSchema().load(dict()),
            server=attack_surface.server_header,
            tor=False,
            waf=[],
            open_ports=attack_surface.open_ports,
            alerts=[]
        ))

        invalid_flow_result = apply_flow_for(attack_surface)

        self.assertEqual(expected_invalid_flow_result, invalid_flow_result)

    def test_that_should_not_return_invalid_when_http_status_200(self):
        response = Response()
        response.status_code = 200

        attack_surface = HostAttackSurface(
            domain='www.grupozap.com',
            http_response=response,
            server_header='openresty',
            response_url_location='https://www.grupozap.com:443/',
            host='107.178.254.45',
            open_ports=[80, 110, 143, 443, 465, 587, 700, 993, 995, 3389, 5900]
        )
        invalid_flow_result = ReportSchema().load(dict(
            subdomain=attack_surface.domain,
            url=attack_surface.response_url_location,
            ip=attack_surface.host,
            status=attack_surface.http_response.status_code,
            cert_info=CertificateInformationsSchema().load(dict()),
            server=attack_surface.server_header,
            tor=False,
            waf=[],
            open_ports=attack_surface.open_ports,
            alerts=[]
        ))

        http_200_flow_result = apply_flow_for(attack_surface)

        self.assertNotEqual(invalid_flow_result, http_200_flow_result)

    def test_that_should_return_alerts_when_http_status_200(self):
        response = Response()
        response.status_code = 200
        response.headers = {
            'X-Frame-Options': 'SAMEORIGIN',
            'Access-Control-Allow-Origin': 'DENY',
            'X-XSS-Protection': 'mode=block',
            'X-Content-Type-Options': 'nosniff'
        }

        attack_surface = HostAttackSurface(
            domain='www.grupozap.com',
            http_response=response,
            server_header='openresty',
            response_url_location='https://www.grupozap.com:443/',
            host='107.178.254.45',
            open_ports=[80, 110, 143, 443, 465, 587, 700, 993, 995, 3389, 5900]
        )

        expected_flow_result = ReportSchema().load(dict(
            subdomain=attack_surface.domain,
            url=attack_surface.response_url_location,
            ip=attack_surface.host,
            status=attack_surface.http_response.status_code,
            cert_info=CertificateInformationsSchema().load(dict()),
            server=attack_surface.server_header,
            tor=False,
            waf=[],
            open_ports=attack_surface.open_ports,
            alerts=['Server disclosed!',
                    '"Strict-transport-security" not present!',
                    '"Allow-origin" present with value: DENY',
                    '"Content-security-policy" not present!'
                    ]
        ))

        http_200_flow_result = apply_flow_for(attack_surface)

        self.assertEqual(expected_flow_result, http_200_flow_result)
