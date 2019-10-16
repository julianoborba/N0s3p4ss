from unittest import TestCase
from unittest.mock import patch
from n0s3p4ss.sniffer_switcher_http_status_based import apply_flow_for
from n0s3p4ss.sniffer_switcher_http_status_based import WebServerBannerGrabber
from n0s3p4ss.attack_surface_discoverer import HostAttackSurface
from n0s3p4ss.report import ReportSchema, CertificateInformationsSchema
from n0s3p4ss.tor_session_connector import TorSession
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
            tor_reachable=False,
            detected_waf=[],
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
            tor_reachable=False,
            detected_waf=[],
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
            tor_reachable=False,
            detected_waf=[],
            open_ports=attack_surface.open_ports,
            alerts=[]
        ))

        invalid_flow_result = apply_flow_for(attack_surface)

        self.assertEqual(expected_invalid_flow_result, invalid_flow_result)

    @patch('n0s3p4ss.sniffer_switcher_http_status_based.detect')
    @patch.object(WebServerBannerGrabber, 'is_accessible_through_tor')
    @patch.object(WebServerBannerGrabber, 'get_certificate_info')
    def test_that_should_return_alerts_when_http_status_200(
            self,
            get_certificate_info,
            is_accessible_through_tor,
            detect):
        get_certificate_info.return_value = {
            'issuer': "Let's Encrypt Authority X3",
            'expiration': '2019-10-18'
        }
        detect.return_value = []
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
            cert_info={
                'issuer': "Let's Encrypt Authority X3",
                'expiration': '2019-10-18'
            },
            server=attack_surface.server_header,
            tor_reachable=True,
            detected_waf=[],
            open_ports=attack_surface.open_ports,
            alerts=['Server disclosed!',
                    '"Strict-transport-security" not present!',
                    '"Access Control Allow Origin" '
                    'is not set as "SAMEORIGIN"!',
                    '"Content-security-policy" not present!',
                    'Cookie flag "HttpOnly" is not present!',
                    'Domain accessible via TOR!']

        ))

        http_200_flow_result = apply_flow_for(attack_surface)

        self.assertEqual(expected_flow_result, http_200_flow_result)

    @patch('n0s3p4ss.sniffer_switcher_http_status_based.detect')
    @patch.object(WebServerBannerGrabber, 'is_accessible_through_tor')
    def test_that_https_is_not_implemented(self,
                                           is_accessible_through_tor,
                                           detect):
        response = Response()
        detect.return_value = []
        response.status_code = 200
        attack_surface = HostAttackSurface(
            domain='www.grupozap.com',
            http_response=response,
            server_header='openresty',
            response_url_location='http://www.grupozap.com:443/',
            host='107.178.254.45',
            open_ports=[80, 110, 143, 443, 465, 587, 700, 993, 995, 3389, 5900]
        )
        expected_http_alert = 'HTTPS is not implemented!'

        http_200_flow_result = apply_flow_for(attack_surface)

        self.assertIn(expected_http_alert, http_200_flow_result['alerts'])

    @patch('n0s3p4ss.sniffer_switcher_http_status_based.detect')
    @patch.object(WebServerBannerGrabber, 'is_accessible_through_tor')
    def test_that_https_is_implemented(self,
                                       is_accessible_through_tor,
                                       detect):
        response = Response()
        detect.return_value = []
        response.status_code = 200
        attack_surface = HostAttackSurface(
            domain='www.grupozap.com',
            http_response=response,
            server_header='openresty',
            response_url_location='https://www.grupozap.com:443/',
            host='107.178.254.45',
            open_ports=[80, 110, 143, 443, 465, 587, 700, 993, 995, 3389, 5900]
        )

        http_alert = '"HTTPS is not implemented"'

        http_200_flow_result = apply_flow_for(attack_surface)

        self.assertNotIn(http_alert, http_200_flow_result['alerts'])

    @patch.object(TorSession, 'get')
    def test_that_should_get_no_response_through_tor(self, get):
        get.return_value = None
        domain = 'www.grupozap.com'

        is_accessible = WebServerBannerGrabber() \
            .is_accessible_through_tor(domain)

        self.assertFalse(is_accessible)

    @patch.object(TorSession, 'get')
    def test_that_should_get_200_response_through_tor(self, get):
        response = Response()
        response.status_code = 200
        get.return_value = response
        domain = 'www.grupozap.com'

        is_accessible = WebServerBannerGrabber() \
            .is_accessible_through_tor(domain)

        self.assertTrue(is_accessible)

    @patch.object(TorSession, 'get')
    def test_that_should_get_blocked_access_response_through_tor(self, get):
        response = Response()
        response.status_code = 300
        response._content = b'captcha'
        response.headers = {
            'connection': 'close'
        }
        get.return_value = response
        domain = 'www.grupozap.com'

        is_accessible = WebServerBannerGrabber() \
            .is_accessible_through_tor(domain)

        self.assertFalse(is_accessible)

    @patch.object(TorSession, 'get')
    def test_that_should_get_not_accessible_response_through_tor(self, get):
        response = Response()
        response.status_code = 300
        response.headers = {
            'connection': 'close'
        }
        get.return_value = response
        domain = 'www.grupozap.com'

        is_accessible = WebServerBannerGrabber() \
            .is_accessible_through_tor(domain)

        self.assertFalse(is_accessible)
