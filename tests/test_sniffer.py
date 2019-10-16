from unittest import TestCase
from unittest.mock import patch
from n0s3p4ss.sniffer import sniff
from n0s3p4ss.domain_list import SubdomainList
from n0s3p4ss.attack_surface_discoverer import HostAttackSurface
from requests.models import Response


class SnifferTest(TestCase):

    @patch('n0s3p4ss.sniffer.discover')
    @patch.object(SubdomainList, 'list_each_domain_subdomains')
    def test_that_should_retrieve_attack_surfaces(self,
                                                  list_each_domain_subdomains,
                                                  discover):
        list_each_domain_subdomains.return_value = [
            'www.grupozap.com', 'www.grupozap.com'
        ]
        response = Response()
        response.status_code = 404
        host_attack_surface = HostAttackSurface(
            domain='www.grupozap.com',
            http_response=response,
            server_header='openresty',
            response_url_location='https://www.grupozap.com:443/',
            host='107.178.254.45',
            open_ports=[80, 110, 143, 443, 465, 587, 700, 993, 995, 3389, 5900]
        )
        discover.return_value = host_attack_surface
        report = dict({'alerts': ['Server disclosed!'],
                       'cert_info': {},
                       'ip': '107.178.254.45',
                       'open_ports': [80, 110, 143, 443, 465, 587,
                                      700, 993, 995, 3389, 5900],
                       'server': 'openresty',
                       'status': 404,
                       'subdomain': 'www.grupozap.com',
                       'tor_reachable': False,
                       'url': 'https://www.grupozap.com:443/',
                       'detected_waf': []})
        expected_sniffer_reports = [report, report]

        sniffer_reports = sniff(['grupozap.com'])

        self.assertEqual(expected_sniffer_reports, sniffer_reports)
