from unittest import TestCase
from unittest.mock import patch
from nosepass.sniffer import sniff
from nosepass.domain_list import SubdomainList
from nosepass.attack_surface_discoverer import HostAttackSurface
from requests.models import Response


class SnifferTest(TestCase):

    @patch('nosepass.sniffer.discover')
    @patch.object(SubdomainList, 'list_each_domain_subdomains')
    def test_that_should_retrieve_attack_surfaces(self,
                                                  list_each_domain_subdomains,
                                                  discover):
        host_attack_surface = HostAttackSurface(
            http_response=Response(),
            server_header='openresty',
            response_url_location='https://www.grupozap.com:443/',
            host='107.178.254.45',
            open_ports=[80, 110, 143, 443, 465, 587, 700, 993, 995, 3389, 5900]
        )
        expected_attack_surfaces = [host_attack_surface, host_attack_surface]
        list_each_domain_subdomains.return_value = [
            'www.grupozap.com', 'www.grupozap.com'
        ]
        discover.return_value = host_attack_surface

        attack_surfaces = sniff(['grupozap.com'])

        self.assertEqual(expected_attack_surfaces, attack_surfaces)
